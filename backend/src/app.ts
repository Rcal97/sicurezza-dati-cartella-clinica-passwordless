import express, { type Express } from "express";
import type { Vault } from "./crypto/vault.js";
import type { Ledger } from "./models/ledger.js";
import type { Store } from "./models/store.js";
import { recordsRoutes } from "./routes/records.js";
import { sessionRoutes } from "./routes/session.js";
import { webauthnRoutes } from "./routes/webauthn.js";

// Crea l'applicazione con il Model ricevuto: MongoStore ed EthersLedger nel server,
// MemoryStore e MemoryLedger nei test. Il Vault custodisce le chiavi dell'archivio dei referti.
export function createApp(store: Store, ledger: Ledger, vault: Vault): Express {
  const app = express();

  app.disable("x-powered-by");
  app.use(express.json({ limit: "100kb" }));

  app.get("/health", (_req, res) => {
    res.json({ status: "ok" });
  });

  app.use("/webauthn", webauthnRoutes(store));
  app.use("/session", sessionRoutes(store));
  app.use("/records", recordsRoutes(store, ledger, vault));
  return app;
}
