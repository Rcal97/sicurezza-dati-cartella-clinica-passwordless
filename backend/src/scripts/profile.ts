import { getAddress, isAddress } from "ethers";
import { mongoUrl } from "../config.js";
import { USERNAME } from "../controllers/registration.js";
import { MongoStore } from "../models/mongoStore.js";
import type { Role } from "../models/store.js";

// Assegna a un utente il ruolo e l'indirizzo blockchain. Come l'invito, simula l'ufficio
// che lo fa dopo aver identificato la persona. Per un paziente l'indirizzo è lo pseudonimo
// creato apposta per il registro dei consensi (un account dedicato nel suo wallet).
// Uso: npm run profilo -- <username> <medico|paziente> <indirizzo>
const ROLES: Record<string, Role> = { medico: "doctor", paziente: "patient" };
const [username, roleName, address] = process.argv.slice(2);
const role = roleName === "medico" || roleName === "paziente" ? ROLES[roleName] : undefined;
if (!username || !USERNAME.test(username) || !role || !address || !isAddress(address)) {
  console.error("Uso: npm run profilo -- <username> <medico|paziente> <indirizzo>");
  process.exit(1);
}

const store = await MongoStore.connect(mongoUrl());
const result = await store.setProfile(username, { role, address: getAddress(address) });
await store.close();

if (result === "duplicate") {
  console.error(`L'indirizzo ${address} appartiene già a un altro utente.`);
  process.exit(1);
}
console.log(`${username}: ${roleName}, indirizzo ${getAddress(address)}`);
