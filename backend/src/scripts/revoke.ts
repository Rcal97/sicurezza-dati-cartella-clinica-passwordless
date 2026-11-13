import { mongoUrl } from "../config.js";
import { USERNAME } from "../controllers/registration.js";
import { MongoStore } from "../models/mongoStore.js";

// Revoca d'ufficio, per chi ha perso i propri dispositivi e quindi non può più accedere:
// toglie tutte le passkey dell'utente e chiude tutte le sue sessioni. Per rientrare
// serve un nuovo invito (npm run invito), rilasciato dopo una nuova identificazione.
// Uso: npm run revoca -- <username>
const username = process.argv[2];
if (!username || !USERNAME.test(username)) {
  console.error("Uso: npm run revoca -- <username>");
  process.exit(1);
}
const store = await MongoStore.connect(mongoUrl());
try {
  if (!(await store.getUser(username))) {
    console.error(`${username} non ha passkey registrate.`);
    process.exit(1);
  }
  await store.removeAllCredentials(username);
  await store.deleteSessionsOf(username);
  console.log(`Passkey e sessioni di ${username} revocate. Per rientrare serve un nuovo invito.`);
} finally {
  await store.close();
}
