import { randomBytes } from "node:crypto";
import { getAddress, isAddress } from "ethers";
import { mongoUrl } from "../config.js";
import { USERNAME } from "../controllers/registration.js";
import { MongoStore } from "../models/mongoStore.js";

// Assegna a un utente il ruolo. Come l'invito, simula l'ufficio che lo fa dopo aver
// identificato la persona.
// - Medico: basta il ruolo; sulla catena non compare mai il suo indirizzo.
// - Paziente: serve l'indirizzo del suo wallet, con cui firmerà i consensi (resta off-chain).
//   Il profilo riceve anche un segreto casuale di 32 byte da cui derivano le ancore dei suoi
//   consensi; se il paziente esiste già, il segreto si conserva (le ancore non cambiano).
// Uso: npm run profilo -- <username> medico
//      npm run profilo -- <username> paziente <indirizzo del wallet>
const [username, roleName, address] = process.argv.slice(2);
const valid =
  username !== undefined &&
  USERNAME.test(username) &&
  ((roleName === "medico" && address === undefined) || (roleName === "paziente" && address !== undefined && isAddress(address)));
if (!valid) {
  console.error("Uso: npm run profilo -- <username> medico");
  console.error("     npm run profilo -- <username> paziente <indirizzo del wallet>");
  process.exit(1);
}

const store = await MongoStore.connect(mongoUrl());
try {
  if (roleName === "medico") {
    await store.setProfile(username, { role: "doctor" });
    console.log(`${username}: medico`);
  } else {
    const existing = await store.getProfile(username);
    const secret = existing?.role === "patient" && existing.secret ? existing.secret : randomBytes(32).toString("hex");
    const result = await store.setProfile(username, { role: "patient", address: getAddress(address!), secret });
    if (result === "duplicate") {
      console.error(`Il wallet ${address} appartiene già a un altro utente.`);
      process.exit(1);
    }
    console.log(`${username}: paziente, wallet ${getAddress(address!)}`);
  }
} finally {
  await store.close();
}
