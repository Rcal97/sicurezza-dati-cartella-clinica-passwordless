import {
  createCipheriv,
  createDecipheriv,
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
import { readFileSync, writeFileSync } from "node:fs";

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

// AES-256-GCM: confidenzialità e integrità. L'AAD lega il testo cifrato al suo contesto
// (documento e paziente): spostarlo su un altro paziente fa fallire la decifratura.
function aesSeal(key: Buffer, plaintext: Buffer, aad: Buffer) {
  const iv = randomBytes(12); // mai riusato con la stessa chiave: ogni chiave cifra una volta sola
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { iv, ciphertext, tag: cipher.getAuthTag() };
}

function aesOpen(key: Buffer, iv: Buffer, ciphertext: Buffer, tag: Buffer, aad: Buffer): Buffer {
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
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

  // Nuova coppia di chiavi dell'archivio (usata dai test e dallo script npm run chiavi).
  static generate(): Vault {
    const mlkem = generateKeyPairSync("ml-kem-768");
    const x25519 = generateKeyPairSync("x25519");
    return new Vault(
      { mlkem: mlkem.publicKey, x25519: x25519.publicKey },
      { mlkem: mlkem.privateKey, x25519: x25519.privateKey },
    );
  }

  // Le chiavi private sono salvate in un file PEM fuori da Git, leggibile solo dal proprietario.
  // In produzione starebbero in un modulo hardware (HSM) o in un servizio di gestione delle chiavi.
  static load(path: string): Vault {
    const pems = readFileSync(path, "utf8").match(/-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----/g);
    if (!pems || pems.length !== 2) throw new Error(`File delle chiavi non valido: ${path}`);
    const [mlkem, x25519] = pems.map((pem) => createPrivateKey(pem));
    if (mlkem!.asymmetricKeyType !== "ml-kem-768" || x25519!.asymmetricKeyType !== "x25519") {
      throw new Error(`File delle chiavi non valido: ${path}`);
    }
    return new Vault(
      { mlkem: createPublicKey(mlkem!), x25519: createPublicKey(x25519!) },
      { mlkem: mlkem!, x25519: x25519! },
    );
  }

  save(path: string): void {
    const pem = [this.privateKeys.mlkem, this.privateKeys.x25519]
      .map((k) => k.export({ format: "pem", type: "pkcs8" }))
      .join("");
    writeFileSync(path, pem, { mode: 0o600, flag: "wx" }); // "wx": non sovrascrive chiavi esistenti
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
    const dek = aesOpen(kek, w.subarray(0, 12), w.subarray(12, w.length - 16), w.subarray(w.length - 16), aad);
    kek.fill(0);
    try {
      return aesOpen(dek, unb64(sealed.iv), unb64(sealed.ciphertext), unb64(sealed.tag), aad);
    } finally {
      dek.fill(0);
    }
  }
}
