import express, { type Express, type Request } from "express";
import type { Vault } from "./crypto/vault.js";
import type { Ledger } from "./models/ledger.js";
import type { Store } from "./models/store.js";
import { errorHandler, securityHeaders } from "./middleware/security.js";
import { recordsRoutes } from "./routes/records.js";
import { sessionRoutes } from "./routes/session.js";
import { webauthnRoutes } from "./routes/webauthn.js";

export interface AppOptions {
  // Richieste al minuto consentite per client (WebAuthn) e per utente (cartelle).
  maxRequestsPerMinute?: number;
  // Come si identifica il client che fa la richiesta: di norma il suo indirizzo IP.
  clientKey?: (req: Request) => string;
}

// Crea l'applicazione con il Model ricevuto: MongoStore ed EthersLedger nel server,
// MemoryStore e MemoryLedger nei test. Il Vault custodisce le chiavi dell'archivio dei referti.
export function createApp(store: Store, ledger: Ledger, vault: Vault, options: AppOptions = {}): Express {
  const limits = {
    max: options.maxRequestsPerMinute ?? 60,
    clientKey: options.clientKey ?? ((req: Request) => req.ip ?? "sconosciuto"),
  };
  const app = express();

  app.disable("x-powered-by");
  app.use(securityHeaders);
  app.use(express.json({ limit: "100kb" }));

  app.get("/health", (_req, res) => {
    res.json({ status: "ok" });
  });

  app.use("/webauthn", webauthnRoutes(store, limits));
  app.use("/session", sessionRoutes(store));
  app.use("/records", recordsRoutes(store, ledger, vault, limits));
  app.use(errorHandler);
  return app;
}
