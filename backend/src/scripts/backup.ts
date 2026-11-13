import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { archiveKeyFile } from "../config.js";
import { createBackup, readKeyFile } from "../crypto/keyfile.js";
import { unlockOrExit } from "./prompt.js";

// Backup delle chiavi dell'archivio con lo schema a soglia di Shamir (3 quote su 5).
// Produce backup.json (le chiavi cifrate, copiabile ovunque) e cinque file quota-N.txt,
// ognuno da consegnare a un custode diverso (per esempio direzione sanitaria, DPO,
// responsabile IT, cassaforte, sede di disaster recovery).
// Uso: npm run backup-chiavi -- <cartella di destinazione, che non deve esistere>
const dir = process.argv[2];
if (!dir) {
  console.error("Uso: npm run backup-chiavi -- <cartella di destinazione>");
  process.exit(1);
}
if (existsSync(dir)) {
  console.error(`${dir} esiste già: scegli una cartella nuova.`);
  process.exit(1);
}

const vault = await unlockOrExit((p) => readKeyFile(archiveKeyFile(), p));
const { backup, shares } = await createBackup(vault);
mkdirSync(dir, { mode: 0o700 });
writeFileSync(join(dir, "backup.json"), JSON.stringify(backup, null, 2) + "\n", { mode: 0o600 });
shares.forEach((share, i) => {
  const text = [
    `Quota ${i + 1} di ${backup.shares} del backup delle chiavi dell'archivio dei referti.`,
    `Per il ripristino servono ${backup.threshold} quote. Impronta delle chiavi: ${backup.fingerprint}`,
    share,
    "",
  ].join("\n");
  writeFileSync(join(dir, `quota-${i + 1}.txt`), text, { mode: 0o600 });
});
console.log(`Backup creato in ${dir}: backup.json e ${backup.shares} quote (ne servono ${backup.threshold}).`);
console.log("Consegna ogni quota a un custode diverso e cancella le copie da questo computer.");
