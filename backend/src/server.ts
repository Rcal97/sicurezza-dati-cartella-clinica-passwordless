import { createApp } from "./app.js";
import { archiveKeyFile, ledgerConfig, mongoUrl } from "./config.js";
import { Vault } from "./crypto/vault.js";
import { EthersLedger } from "./models/ethersLedger.js";
import { MongoStore } from "./models/mongoStore.js";

const PORT = Number(process.env.PORT ?? 3000);

const store = await MongoStore.connect(mongoUrl());
const ledger = await EthersLedger.connect(ledgerConfig());
const vault = Vault.load(archiveKeyFile());
const server = createApp(store, ledger, vault).listen(PORT, "127.0.0.1", () => {
  console.log(`Backend in ascolto su http://localhost:${PORT}`);
});

// Chiusura ordinata: termina le richieste in corso e la connessione al database.
for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, () => {
    server.close(() => {
      ledger.close();
      void store.close().then(() => process.exit(0));
    });
  });
}
