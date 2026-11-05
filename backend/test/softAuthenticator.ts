import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";
import { isoBase64URL, isoCBOR } from "@simplewebauthn/server/helpers";

// Autenticatore FIDO2 simulato in software: genera una coppia di chiavi ES256 o ML-DSA-44
// e costruisce le risposte che un browser invierebbe al server. Serve solo per i test.

const sha256 = (data: Uint8Array): Buffer => createHash("sha256").update(data).digest();
const b64 = (data: Uint8Array): string => isoBase64URL.fromBuffer(new Uint8Array(data));

// Flag dei dati dell'autenticatore: UP = utente presente, UV = utente verificato,
// AT = sono inclusi i dati della nuova credenziale (solo in registrazione).
export const FLAG_UP = 0x01;
export const FLAG_UV = 0x04;
export const FLAG_AT = 0x40;

// Algoritmi supportati: ES256 (ECDSA su P-256, classico) e ML-DSA-44 (FIPS 204, post-quantistico).
export type Algorithm = "ES256" | "ML-DSA-44";

export class SoftAuthenticator {
  readonly credentialId = randomBytes(16);
  counter = 0;
  private readonly privateKey: KeyObject;
  private readonly cosePublicKey: Uint8Array;

  constructor(readonly algorithm: Algorithm = "ES256") {
    if (algorithm === "ML-DSA-44") {
      const { privateKey, publicKey } = generateKeyPairSync("ml-dsa-44");
      this.privateKey = privateKey;
      const jwk = publicKey.export({ format: "jwk" }) as { pub: string };
      // Chiave pubblica COSE (RFC 9964): kty=AKP, alg=ML-DSA-44 (-48), pub = chiave pubblica grezza.
      this.cosePublicKey = isoCBOR.encode(
        new Map<number, number | Uint8Array>([
          [1, 7],
          [3, -48],
          [-1, isoBase64URL.toBuffer(jwk.pub)],
        ]),
      );
      return;
    }
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    this.privateKey = privateKey;
    const jwk = publicKey.export({ format: "jwk" });
    // Chiave pubblica in formato COSE: kty=EC2, alg=ES256, crv=P-256, coordinate x e y.
    this.cosePublicKey = isoCBOR.encode(
      new Map<number, number | Uint8Array>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, isoBase64URL.toBuffer(jwk.x!)],
        [-3, isoBase64URL.toBuffer(jwk.y!)],
      ]),
    );
  }

  get id(): string {
    return b64(this.credentialId);
  }

  private authenticatorData(rpID: string, flags: number, attested?: Buffer): Buffer {
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(this.counter);
    const parts = [sha256(Buffer.from(rpID)), Buffer.from([flags]), counter];
    if (attested) parts.push(attested);
    return Buffer.concat(parts);
  }

  register(options: { challenge: string; rp: { id?: string } }, origin: string, flags = FLAG_UP | FLAG_UV | FLAG_AT) {
    const clientDataJSON = Buffer.from(
      JSON.stringify({ type: "webauthn.create", challenge: options.challenge, origin, crossOrigin: false }),
    );
    const idLength = Buffer.alloc(2);
    idLength.writeUInt16BE(this.credentialId.length);
    const attested = Buffer.concat([Buffer.alloc(16), idLength, this.credentialId, Buffer.from(this.cosePublicKey)]);
    const authData = this.authenticatorData(options.rp.id!, flags, attested);
    const attestationObject = isoCBOR.encode(
      new Map<string, string | Map<never, never> | Uint8Array>([
        ["fmt", "none"],
        ["attStmt", new Map<never, never>()],
        ["authData", new Uint8Array(authData)],
      ]),
    );
    return {
      id: this.id,
      rawId: this.id,
      type: "public-key",
      response: { clientDataJSON: b64(clientDataJSON), attestationObject: b64(attestationObject), transports: ["internal"] },
      clientExtensionResults: {},
    };
  }

  authenticate(options: { challenge: string; rpId?: string }, origin: string) {
    this.counter += 1;
    const clientDataJSON = Buffer.from(
      JSON.stringify({ type: "webauthn.get", challenge: options.challenge, origin, crossOrigin: false }),
    );
    const authData = this.authenticatorData(options.rpId!, FLAG_UP | FLAG_UV);
    // Firma su authenticatorData || SHA-256(clientDataJSON), come da specifica WebAuthn.
    // ECDSA usa SHA-256; ML-DSA firma direttamente il messaggio (per questo l'hash è null).
    const signedData = Buffer.concat([authData, sha256(clientDataJSON)]);
    const signature = sign(this.algorithm === "ES256" ? "sha256" : null, signedData, this.privateKey);
    return {
      id: this.id,
      rawId: this.id,
      type: "public-key",
      response: { clientDataJSON: b64(clientDataJSON), authenticatorData: b64(authData), signature: b64(signature) },
      clientExtensionResults: {},
    };
  }
}
