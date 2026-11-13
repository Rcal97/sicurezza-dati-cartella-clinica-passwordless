import { existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { archiveKeyFile } from "../config.js";
import { Vault } from "../crypto/vault.js";

// Genera le chiavi dell'archivio dei referti (ML-KEM-768 + X25519). Da eseguire una volta:
// se il file esiste già non viene toccato, perché perdere le chiavi vorrebbe dire
// perdere tutti i referti cifrati con esse.
// Uso: npm run chiavi
const path = archiveKeyFile();
if (existsSync(path)) {
  console.error(`Le chiavi esistono già in ${path}: non le sovrascrivo.`);
  process.exit(1);
}
mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
Vault.generate().save(path);
console.log(`Chiavi dell'archivio create in ${path} (leggibili solo dal proprietario).`);
