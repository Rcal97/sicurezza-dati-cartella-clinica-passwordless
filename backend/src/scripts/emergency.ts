import { archiveKeyFile, ledgerConfig, mongoUrl } from "../config.js";
import { USERNAME } from "../controllers/registration.js";
import { staffAnchor } from "../crypto/consent.js";
import { readKeyFile } from "../crypto/keyfile.js";
import { setEmergencyStaff } from "../models/ethersLedger.js";
import { MongoStore } from "../models/mongoStore.js";
import { askHidden, unlockOrExit } from "./prompt.js";

// Abilita (o disabilita) un medico agli accessi d'emergenza. È un'operazione
// dell'amministratore dei contratti, non del backend: la sua chiave si chiede ora,
// senza mostrarla e senza salvarla. Sulla catena va solo l'ancora del medico.
// Uso: npm run emergenza -- <medico> [--disabilita]
const args = process.argv.slice(2);
const doctor = args.find((a) => !a.startsWith("--"));
const disable = args.includes("--disabilita");
if (!doctor || !USERNAME.test(doctor) || args.some((a) => a.startsWith("--") && a !== "--disabilita")) {
  console.error("Uso: npm run emergenza -- <medico> [--disabilita]");
  process.exit(1);
}

const store = await MongoStore.connect(mongoUrl());
try {
  if ((await store.getProfile(doctor))?.role !== "doctor") {
    console.error(`${doctor} non è un medico registrato.`);
    process.exit(1);
  }
} finally {
  await store.close();
}

const vault = await unlockOrExit((p) => readKeyFile(archiveKeyFile(), p), "Passphrase delle chiavi dei referti: ");
const adminKey = await askHidden("Chiave privata dell'amministratore dei contratti: ");
const { rpcUrl, consentRegistry, auditLog } = ledgerConfig();
const staffId = staffAnchor(vault, doctor);
try {
  await setEmergencyStaff({ rpcUrl, consentRegistry, auditLog }, adminKey.trim(), staffId, !disable);
} catch (err) {
  console.error(`Operazione non riuscita: ${(err as Error).message}`);
  process.exit(1);
}
console.log(`${doctor} ${disable ? "non è più abilitato" : "è abilitato"} agli accessi d'emergenza (ancora ${staffId}).`);
