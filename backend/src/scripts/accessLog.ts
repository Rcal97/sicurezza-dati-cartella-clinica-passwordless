import { archiveKeyFile, mongoUrl } from "../config.js";
import { USERNAME } from "../controllers/registration.js";
import { readKeyFile } from "../crypto/keyfile.js";
import { openAccessLog } from "../crypto/records.js";
import { MongoStore } from "../models/mongoStore.js";
import { unlockOrExit } from "./prompt.js";

// Consultazione del registro degli accessi (per il responsabile della protezione dei dati
// o per rispondere a un paziente che chiede chi ha visto la sua cartella, art. 15 GDPR).
// Le voci sono cifrate: servono la passphrase delle chiavi dell'archivio.
// Ogni voce viene verificata: i dettagli devono corrispondere all'impronta scritta sulla catena.
// Uso: npm run registro-accessi -- [paziente]
const patient = process.argv[2];
if (patient !== undefined && !USERNAME.test(patient)) {
  console.error("Uso: npm run registro-accessi -- [paziente]");
  process.exit(1);
}

const vault = await unlockOrExit((p) => readKeyFile(archiveKeyFile(), p));
const store = await MongoStore.connect(mongoUrl());
try {
  for (const entry of await store.listAccessLog()) {
    let d;
    try {
      d = openAccessLog(vault, entry);
    } catch {
      console.log(`${entry.createdAt}  VOCE ALTERATA O NON DECIFRABILE (impronta ${entry.recordHash})`);
      continue;
    }
    if (patient && d.patient !== patient) continue;
    const onChain = entry.entryId === null ? "non registrato sulla catena" : `voce on-chain n. ${entry.entryId}`;
    const what =
      d.kind === "ordinary"
        ? `accesso ${d.outcome === "granted" ? "CONCESSO" : "NEGATO"} per finalità ${d.purpose}`
        : d.kind === "emergency"
          ? `ACCESSO D'EMERGENZA, motivazione: "${d.reason}"`
          : `TENTATIVO D'EMERGENZA RESPINTO, motivazione: "${d.reason}"`;
    console.log(`${d.at}  ${d.requester} -> ${d.patient}: ${what} (${onChain})`);
  }
} finally {
  await store.close();
}
