import { argon2Sync, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { combine, split } from "shamir-secret-sharing";
import { aesOpen, aesSeal } from "./aead.js";
import { Vault } from "./vault.js";

// Custodia delle chiavi dell'archivio dei referti.
//
// 1. Sul disco le chiavi private sono cifrate con una chiave derivata da una passphrase
//    tramite Argon2id (RFC 9106). Chi copia il file senza conoscere la passphrase non
//    ottiene nulla; Argon2id rende lento e costoso in memoria ogni tentativo di indovinarla.
// 2. Il backup è diviso con lo schema a soglia di Shamir: le chiavi sono cifrate con una
//    chiave casuale, e questa viene divisa in 5 quote, di cui ne bastano 3 per ricostruirla.
//    Le quote vanno a custodi diversi: meno di 3 non rivelano nulla della chiave.

const b64 = (b: Buffer | Uint8Array) => Buffer.from(b).toString("base64");
const unb64 = (s: string) => Buffer.from(s, "base64");

// Parametri della seconda configurazione raccomandata da RFC 9106 (64 MiB, 3 passate).
const ARGON2 = { memory: 64 * 1024, passes: 3, parallelism: 4 };
export const MIN_PASSPHRASE = 12;
const KEYFILE_AAD = Buffer.from("cartella-clinica/archive-key/v1");
const BACKUP_AAD = Buffer.from("cartella-clinica/archive-backup/v1");

interface KeyFile {
  v: 1;
  kdf: { name: "argon2id"; memory: number; passes: number; parallelism: number; salt: string };
  fingerprint: string;
  iv: string;
  ciphertext: string;
  tag: string;
}

function passphraseKey(passphrase: string, salt: Buffer, p = ARGON2): Buffer {
  return argon2Sync("argon2id", {
    message: passphrase.normalize("NFKC"),
    nonce: salt,
    tagLength: 32,
    memory: p.memory,
    passes: p.passes,
    parallelism: p.parallelism,
  });
}

export function writeKeyFile(path: string, vault: Vault, passphrase: string): void {
  if (passphrase.length < MIN_PASSPHRASE) {
    throw new Error(`La passphrase deve avere almeno ${MIN_PASSPHRASE} caratteri`);
  }
  const salt = randomBytes(16);
  const key = passphraseKey(passphrase, salt);
  const secret = vault.exportSecret();
  const sealed = aesSeal(key, secret, KEYFILE_AAD);
  key.fill(0);
  secret.fill(0);
  const file: KeyFile = {
    v: 1,
    kdf: { name: "argon2id", ...ARGON2, salt: b64(salt) },
    fingerprint: vault.fingerprint(),
    iv: b64(sealed.iv),
    ciphertext: b64(sealed.ciphertext),
    tag: b64(sealed.tag),
  };
  // Permessi 600 e "wx": il file non si sovrascrive, per non perdere chiavi esistenti.
  writeFileSync(path, JSON.stringify(file, null, 2) + "\n", { mode: 0o600, flag: "wx" });
}

// Parametri di Argon2id accettati in lettura: un file manipolato non deve poter imporre
// costi enormi (blocco all'avvio) né costi troppo bassi da rendere inutile la derivazione.
function validKdf(k: KeyFile["kdf"]): boolean {
  const inRange = (v: unknown, min: number, max: number) => Number.isInteger(v) && (v as number) >= min && (v as number) <= max;
  return (
    k?.name === "argon2id" &&
    inRange(k.memory, 19 * 1024, 1024 * 1024) && // da 19 MiB (minimo OWASP) a 1 GiB
    inRange(k.passes, 2, 10) &&
    inRange(k.parallelism, 1, 16) &&
    typeof k.salt === "string"
  );
}

export function readKeyFile(path: string, passphrase: string): Vault {
  const file: KeyFile = JSON.parse(readFileSync(path, "utf8"));
  if (file.v !== 1 || !validKdf(file.kdf)) throw new Error(`File delle chiavi non valido: ${path}`);
  const key = passphraseKey(passphrase, unb64(file.kdf.salt), file.kdf);
  let secret: Buffer;
  try {
    secret = aesOpen(key, { iv: unb64(file.iv), ciphertext: unb64(file.ciphertext), tag: unb64(file.tag) }, KEYFILE_AAD);
  } catch {
    throw new Error("Passphrase errata o file delle chiavi alterato");
  } finally {
    key.fill(0);
  }
  const vault = Vault.fromSecret(secret);
  secret.fill(0);
  if (vault.fingerprint() !== file.fingerprint) throw new Error(`File delle chiavi non valido: ${path}`);
  return vault;
}

// Backup: le chiavi cifrate (blob) si possono copiare ovunque; le quote no.
export interface Backup {
  v: 1;
  threshold: number;
  shares: number;
  fingerprint: string;
  iv: string;
  ciphertext: string;
  tag: string;
}

export async function createBackup(
  vault: Vault,
  shares = 5,
  threshold = 3,
): Promise<{ backup: Backup; shares: string[] }> {
  // Si divide una chiave casuale e non le chiavi stesse: Shamir va applicato
  // a un segreto uniformemente casuale, come raccomandano gli autori della libreria.
  const backupKey = randomBytes(32);
  const secret = vault.exportSecret();
  const sealed = aesSeal(backupKey, secret, BACKUP_AAD);
  secret.fill(0);
  const parts = await split(new Uint8Array(backupKey), shares, threshold);
  backupKey.fill(0);
  return {
    backup: {
      v: 1,
      threshold,
      shares,
      fingerprint: vault.fingerprint(),
      iv: b64(sealed.iv),
      ciphertext: b64(sealed.ciphertext),
      tag: b64(sealed.tag),
    },
    shares: parts.map((p) => Buffer.from(p).toString("hex")),
  };
}

// Ricostruisce le chiavi dalle quote. La libreria non si accorge di quote sbagliate o
// insufficienti (restituisce un valore errato): ce ne accorgiamo noi, perché con una
// chiave errata AES-GCM rifiuta il blob.
export async function restoreBackup(backup: Backup, shares: string[]): Promise<Vault> {
  if (shares.length < backup.threshold) {
    throw new Error(`Servono almeno ${backup.threshold} quote, ne sono state fornite ${shares.length}`);
  }
  const key = Buffer.from(await combine(shares.map((s) => new Uint8Array(Buffer.from(s, "hex")))));
  let secret: Buffer;
  try {
    secret = aesOpen(key, { iv: unb64(backup.iv), ciphertext: unb64(backup.ciphertext), tag: unb64(backup.tag) }, BACKUP_AAD);
  } catch {
    throw new Error("Quote non valide o backup alterato");
  } finally {
    key.fill(0);
  }
  const vault = Vault.fromSecret(secret);
  secret.fill(0);
  if (vault.fingerprint() !== backup.fingerprint) throw new Error("Le chiavi ricostruite non corrispondono al backup");
  return vault;
}
