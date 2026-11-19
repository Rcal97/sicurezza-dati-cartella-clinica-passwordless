import { createInterface } from "node:readline/promises";
import { mongoUrl } from "../config.js";
import { USERNAME } from "../controllers/registration.js";
import { MongoStore } from "../models/mongoStore.js";

// Cancellazione di un utente su sua richiesta (art. 17 GDPR), eseguita dalla struttura dopo
// averlo identificato. Cancella l'identità digitale (passkey, sessioni, inviti) e il profilo,
// compreso il segreto da cui derivano le ancore dei suoi consensi: le ancore e le impronte
// rimaste sulla catena non si possono più ricollegare a lui, nemmeno con la chiave della struttura.
// I referti restano, cifrati, perché la documentazione clinica ha obblighi di conservazione:
// si cancellano solo con --referti, quando la conservazione non è più dovuta.
// Il registro cifrato degli accessi e le ricevute cifrate dei consensi restano, per poter
// rispondere di chi ha fatto cosa e dimostrare su quale base (art. 5.2 GDPR).
// Uso: npm run cancella-utente -- <username> [--referti]
const args = process.argv.slice(2);
const username = args.find((a) => !a.startsWith("--"));
const documents = args.includes("--referti");
if (!username || !USERNAME.test(username) || args.some((a) => a.startsWith("--") && a !== "--referti")) {
  console.error("Uso: npm run cancella-utente -- <username> [--referti]");
  process.exit(1);
}

// Operazione irreversibile: si chiede di riscrivere lo username per conferma.
console.log(`Stai per cancellare ${username}: passkey, sessioni, inviti e profilo.`);
console.log(documents ? "Verranno cancellati anche i suoi REFERTI." : "I referti saranno conservati (usa --referti per cancellarli).");
const rl = createInterface({ input: process.stdin, output: process.stdout });
const conferma = await rl.question("Per confermare, riscrivi lo username: ");
rl.close();
if (conferma.trim() !== username) {
  console.error("Conferma non corrispondente: nessuna modifica.");
  process.exit(1);
}

const store = await MongoStore.connect(mongoUrl());
try {
  const r = await store.eraseUser(username, { documents });
  console.log(`Cancellati: passkey ${r.account ? "sì" : "nessuna"}, profilo ${r.profile ? "sì" : "nessuno"}, ` +
    `${r.sessions} sessioni, ${r.invitations} inviti, ${r.documents} referti.`);
  if (r.documentsKept > 0) console.log(`Referti conservati: ${r.documentsKept}.`);
  console.log("Lo username non potrà essere assegnato a un'altra persona.");
  console.log("Senza profilo nessun accesso alla cartella è possibile; le ancore sulla catena non sono più");
  console.log("ricollegabili alla persona perché il segreto da cui derivavano è stato cancellato.");
} finally {
  await store.close();
}
