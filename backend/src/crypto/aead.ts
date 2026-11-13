import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

// AES-256-GCM: confidenzialità e integrità. I dati associati (AAD) legano il testo
// cifrato al suo contesto: con un contesto diverso la decifratura fallisce.

export interface Sealed {
  iv: Buffer;
  ciphertext: Buffer;
  tag: Buffer;
}

export function aesSeal(key: Buffer, plaintext: Buffer, aad: Buffer): Sealed {
  const iv = randomBytes(12); // 96 bit casuali; ogni chiave nel progetto cifra pochissimi messaggi
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { iv, ciphertext, tag: cipher.getAuthTag() };
}

// Lancia un errore se il testo cifrato, il tag o il contesto sono stati alterati.
export function aesOpen(key: Buffer, s: Sealed, aad: Buffer): Buffer {
  const decipher = createDecipheriv("aes-256-gcm", key, s.iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(s.tag);
  return Buffer.concat([decipher.update(s.ciphertext), decipher.final()]);
}
