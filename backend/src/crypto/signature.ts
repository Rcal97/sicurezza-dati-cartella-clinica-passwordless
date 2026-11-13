import { createHash, randomBytes } from "node:crypto";
import { verifyAuthenticationResponse, type AuthenticationResponseJSON } from "@simplewebauthn/server";
import { isoBase64URL } from "@simplewebauthn/server/helpers";
import { config } from "../config.js";

// Firma di un referto con la passkey del medico.
// L'idea: la challenge WebAuthn non è un numero casuale ma l'impronta SHA-256 del referto.
// Quando l'autenticatore firma la challenge, firma quindi il contenuto del referto, con la
// stessa chiave privata (e, se la passkey è ML-DSA, con lo stesso algoritmo post-quantistico)
// usata per l'accesso. Non serve una seconda chiave da custodire.

// Ciò che il medico firma: paziente, autore, titolo, testo, data e un valore casuale.
export interface SignedPayload {
  patient: string;
  author: string;
  title: string;
  body: string;
  signedAt: string;
  nonce: string;
}

// Prova della firma, conservata (cifrata) insieme al referto. Contiene la chiave pubblica
// usata in quel momento: la firma resta verificabile anche se la passkey viene poi revocata.
export interface DocumentSignature {
  author: string;
  signedAt: string;
  nonce: string;
  credentialId: string;
  publicKey: string; // chiave pubblica COSE, base64url
  response: AuthenticationResponseJSON;
}

export function newPayload(patient: string, author: string, title: string, body: string): SignedPayload {
  return { patient, author, title, body, signedAt: new Date().toISOString(), nonce: randomBytes(16).toString("hex") };
}

// Impronta del contenuto da firmare. Il prefisso separa queste impronte da qualunque altro
// uso; l'array fissa l'ordine dei campi, così la stessa firma non vale per un altro contenuto.
export function payloadDigest(p: SignedPayload): Uint8Array<ArrayBuffer> {
  const canonical = JSON.stringify(["cartella-clinica/referto/v1", p.patient, p.author, p.title, p.body, p.signedAt, p.nonce]);
  return Uint8Array.from(createHash("sha256").update(canonical).digest());
}

export const challengeFor = (p: SignedPayload): string => isoBase64URL.fromBuffer(payloadDigest(p));

// Verifica, anche a distanza di tempo, che il referto sia stato firmato da quella passkey
// e che il contenuto non sia cambiato da allora.
export async function verifyDocumentSignature(
  patient: string,
  title: string,
  body: string,
  sig: DocumentSignature,
): Promise<boolean> {
  try {
    if (sig.response.id !== sig.credentialId) return false;
    const payload = { patient, author: sig.author, title, body, signedAt: sig.signedAt, nonce: sig.nonce };
    const result = await verifyAuthenticationResponse({
      response: sig.response,
      expectedChallenge: challengeFor(payload),
      expectedOrigin: config.origin,
      expectedRPID: config.rpID,
      // Contatore 0: qui non si controlla la clonazione (già fatto al momento della firma),
      // ma solo l'autenticità della firma.
      credential: { id: sig.credentialId, publicKey: isoBase64URL.toBuffer(sig.publicKey), counter: 0 },
      requireUserVerification: true,
    });
    return result.verified;
  } catch {
    return false;
  }
}
