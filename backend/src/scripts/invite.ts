import { randomBytes } from "node:crypto";
import { config, mongoUrl } from "../config.js";
import { USERNAME } from "../controllers/registration.js";
import { hashToken } from "../middleware/session.js";
import { MongoStore } from "../models/mongoStore.js";

// Rilascia un invito alla registrazione. Simula l'ufficio che, dopo aver identificato
// la persona, le consegna un codice monouso per registrare la sua prima passkey.
// Uso: npm run invito -- <username>
const username = process.argv[2];
if (!username || !USERNAME.test(username)) {
  console.error("Uso: npm run invito -- <username>");
  process.exit(1);
}

const code = randomBytes(16).toString("base64url"); // 128 bit casuali
const store = await MongoStore.connect(mongoUrl());
await store.createInvitation(hashToken(code), username, config.invitationTtlMs);
await store.close();

const scadenza = new Date(Date.now() + config.invitationTtlMs).toLocaleString("it-IT");
console.log(`Invito per ${username}: ${code}`);
console.log(`Valido una sola volta, fino al ${scadenza}.`);
