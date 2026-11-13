import { readFileSync } from "node:fs";
import { archiveKeyFile, mongoUrl } from "../config.js";
import { USERNAME } from "../controllers/registration.js";
import { sealDocument } from "../crypto/records.js";
import { Vault } from "../crypto/vault.js";
import { MongoStore } from "../models/mongoStore.js";

// Carica un referto nella cartella di un paziente, cifrandolo prima di salvarlo.
// Simula il sistema del laboratorio o del reparto che produce i documenti.
// Uso: npm run referto -- <paziente> "<titolo>" <file di testo>
const [patient, title, file] = process.argv.slice(2);
if (!patient || !USERNAME.test(patient) || !title || !file) {
  console.error('Uso: npm run referto -- <paziente> "<titolo>" <file di testo>');
  process.exit(1);
}

const store = await MongoStore.connect(mongoUrl());
try {
  const profile = await store.getProfile(patient);
  if (profile?.role !== "patient") {
    console.error(`${patient} non è un paziente registrato.`);
    process.exit(1);
  }
  const doc = sealDocument(Vault.load(archiveKeyFile()), patient, {
    title,
    body: readFileSync(file, "utf8"),
  });
  await store.addDocument(doc);
  console.log(`Referto ${doc.id} cifrato e salvato nella cartella di ${patient}.`);
} finally {
  await store.close();
}
