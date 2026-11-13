import {
  createHash,
  createPrivateKey,
  createPublicKey,
  decapsulate,
  encapsulate,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  type KeyObject,
} from "node:crypto";
import { aesOpen, aesSeal } from "./aead.js";

// Cifratura dei referti a riposo, con uno schema a busta (envelope encryption):
// - ogni documento è cifrato con una propria chiave casuale (DEK) e AES-256-GCM;
// - la DEK è a sua volta cifrata con una chiave (KEK) ottenuta da due KEM insieme:
//   ML-KEM-768 (post-quantistico, FIPS 203) e X25519 (classico, DHKEM di RFC 9180).
// Un avversario deve rompere entrambi per leggere un referto: se uno dei due
// cedesse, l'altro continuerebbe a proteggere i dati (cifratura ibrida).

const VERSION = 1;
const KEK_INFO = Buffer.from("cartella-clinica/kek/v1");
const b64 = (b: Buffer) => b.toString("base64");
const unb64 = (s: string) => Buffer.from(s, "base64");

export interface SealedDocument {
  v: number;
  kemCiphertext: string; // ML-KEM-768: 1088 byte
  ecCiphertext: string; // X25519: chiave pubblica effimera, 32 byte
  wrappedKey: string; // DEK cifrata con la KEK (iv | testo cifrato | tag)
  iv: string;
  ciphertext: string;
  tag: string;
}

interface KeyPair {
  mlkem: KeyObject;
  x25519: KeyObject;
}

// Combina i due segreti condivisi con HKDF-SHA256. Nell'info entra anche l'hash dei due
// testi cifrati, così la KEK dipende da tutto ciò che è stato scambiato.
// (L'hash serve perché HKDF in Node accetta al massimo 1024 byte di info.)
function deriveKek(mlkemSecret: Buffer, ecSecret: Buffer, kemCt: Buffer, ecCt: Buffer): Buffer {
  const ikm = Buffer.concat([mlkemSecret, ecSecret]);
  const transcript = createHash("sha256").update(kemCt).update(ecCt).digest();
  const info = Buffer.concat([KEK_INFO, transcript]);
  return Buffer.from(hkdfSync("sha256", ikm, Buffer.alloc(0), info, 32));
}

export class Vault {
  private constructor(
    private readonly publicKeys: KeyPair,
    private readonly privateKeys: KeyPair,
  ) {}

  // Nuove chiavi dell'archivio (usata dai test e dallo script npm run chiavi).
  static generate(): Vault {
    const mlkem = generateKeyPairSync("ml-kem-768");
    const x25519 = generateKeyPairSync("x25519");
    return new Vault(
      { mlkem: mlkem.publicKey, x25519: x25519.publicKey },
      { mlkem: mlkem.privateKey, x25519: x25519.privateKey },
    );
  }

  // Le chiavi private in forma serializzata (PKCS#8). Servono solo a keyfile.ts,
  // che le salva cifrate con la passphrase o le divide in quote per il backup.
  exportSecret(): Buffer {
    const der = (k: KeyObject) => k.export({ format: "der", type: "pkcs8" }).toString("base64");
    return Buffer.from(JSON.stringify({ mlkem: der(this.privateKeys.mlkem), x25519: der(this.privateKeys.x25519) }));
  }

  static fromSecret(secret: Buffer): Vault {
    const { mlkem, x25519 } = JSON.parse(secret.toString("utf8"));
    const key = (b64: string) => createPrivateKey({ key: Buffer.from(b64, "base64"), format: "der", type: "pkcs8" });
    const priv = { mlkem: key(mlkem), x25519: key(x25519) };
    if (priv.mlkem.asymmetricKeyType !== "ml-kem-768" || priv.x25519.asymmetricKeyType !== "x25519") {
      throw new Error("Chiavi dell'archivio non valide");
    }
    return new Vault({ mlkem: createPublicKey(priv.mlkem), x25519: createPublicKey(priv.x25519) }, priv);
  }

  // Impronta delle chiavi pubbliche: permette di controllare che due copie siano le stesse chiavi.
  fingerprint(): string {
    const spki = (k: KeyObject) => k.export({ format: "der", type: "spki" });
    return createHash("sha256")
      .update(spki(this.publicKeys.mlkem))
      .update(spki(this.publicKeys.x25519))
      .digest("hex")
      .slice(0, 16);
  }

  // Cifra un documento. "context" identifica documento e paziente e finisce nell'AAD.
  seal(plaintext: Buffer, context: string): SealedDocument {
    const aad = Buffer.from(context);
    const dek = randomBytes(32);
    const body = aesSeal(dek, plaintext, aad);

    const kem = encapsulate(this.publicKeys.mlkem);
    const ec = encapsulate(this.publicKeys.x25519);
    const kek = deriveKek(kem.sharedKey, ec.sharedKey, kem.ciphertext, ec.ciphertext);
    const wrapped = aesSeal(kek, dek, aad);
    dek.fill(0);
    kek.fill(0);

    return {
      v: VERSION,
      kemCiphertext: b64(kem.ciphertext),
      ecCiphertext: b64(ec.ciphertext),
      wrappedKey: b64(Buffer.concat([wrapped.iv, wrapped.ciphertext, wrapped.tag])),
      iv: b64(body.iv),
      ciphertext: b64(body.ciphertext),
      tag: b64(body.tag),
    };
  }

  // Decifra; lancia un errore se il documento, la chiave cifrata o il contesto sono stati alterati.
  open(sealed: SealedDocument, context: string): Buffer {
    if (sealed.v !== VERSION) throw new Error(`Versione di cifratura non supportata: ${sealed.v}`);
    const aad = Buffer.from(context);
    const kemCt = unb64(sealed.kemCiphertext);
    const ecCt = unb64(sealed.ecCiphertext);
    const kek = deriveKek(
      decapsulate(this.privateKeys.mlkem, kemCt),
      decapsulate(this.privateKeys.x25519, ecCt),
      kemCt,
      ecCt,
    );
    const w = unb64(sealed.wrappedKey);
    const wrapped = { iv: w.subarray(0, 12), ciphertext: w.subarray(12, w.length - 16), tag: w.subarray(w.length - 16) };
    const dek = aesOpen(kek, wrapped, aad);
    kek.fill(0);
    try {
      const body = { iv: unb64(sealed.iv), ciphertext: unb64(sealed.ciphertext), tag: unb64(sealed.tag) };
      return aesOpen(dek, body, aad);
    } finally {
      dek.fill(0);
    }
  }
}
