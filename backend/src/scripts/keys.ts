import { existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { archiveKeyFile } from "../config.js";
import { MIN_PASSPHRASE, writeKeyFile } from "../crypto/keyfile.js";
import { Vault } from "../crypto/vault.js";
import { askNewPassphrase } from "./prompt.js";

// Genera le chiavi dell'archivio dei referti (ML-KEM-768 + X25519) e le salva cifrate
// con una passphrase. Da eseguire una volta sola: se il file esiste non viene toccato,
// perché perdere le chiavi vorrebbe dire perdere tutti i referti cifrati con esse.
// Uso: npm run chiavi
const path = archiveKeyFile();
if (existsSync(path)) {
  console.error(`Le chiavi esistono già in ${path}: non le sovrascrivo.`);
  process.exit(1);
}
const passphrase = await askNewPassphrase(MIN_PASSPHRASE);
mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
const vault = Vault.generate();
writeKeyFile(path, vault, passphrase);
console.log(`Chiavi create in ${path}, cifrate con la passphrase (impronta ${vault.fingerprint()}).`);
console.log("Prepara subito il backup: npm run backup-chiavi -- <cartella>");
