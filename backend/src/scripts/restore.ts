import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { archiveKeyFile } from "../config.js";
import { MIN_PASSPHRASE, restoreBackup, writeKeyFile, type Backup } from "../crypto/keyfile.js";
import { askNewPassphrase } from "./prompt.js";

// Ripristina le chiavi dell'archivio da backup.json e da almeno 3 quote.
// Uso: npm run ripristino-chiavi -- <backup.json> <quota> <quota> <quota> [...]
const [backupFile, ...shareFiles] = process.argv.slice(2);
if (!backupFile || shareFiles.length === 0) {
  console.error("Uso: npm run ripristino-chiavi -- <backup.json> <quota> <quota> <quota>");
  process.exit(1);
}
const path = archiveKeyFile();
if (existsSync(path)) {
  console.error(`Esiste già un file di chiavi in ${path}: non lo sovrascrivo.`);
  process.exit(1);
}

const backup: Backup = JSON.parse(readFileSync(backupFile, "utf8"));
// In ogni file la quota è l'ultima riga non vuota.
const shares = shareFiles.map((f) => readFileSync(f, "utf8").trim().split("\n").at(-1)!.trim());
let vault;
try {
  vault = await restoreBackup(backup, shares);
} catch (err) {
  console.error((err as Error).message);
  process.exit(1);
}
console.log(`Quote valide: chiavi ricostruite (impronta ${vault.fingerprint()}).`);
const passphrase = await askNewPassphrase(MIN_PASSPHRASE);
mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
writeKeyFile(path, vault, passphrase);
console.log(`Chiavi ripristinate in ${path}.`);
