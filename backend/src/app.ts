import express, { type Express } from "express";
import type { Store } from "./models/store.js";
import { sessionRoutes } from "./routes/session.js";
import { webauthnRoutes } from "./routes/webauthn.js";

// Crea l'applicazione con il Model ricevuto: MongoStore nel server, MemoryStore nei test.
export function createApp(store: Store): Express {
  const app = express();

  app.disable("x-powered-by");
  app.use(express.json({ limit: "100kb" }));

  app.get("/health", (_req, res) => {
    res.json({ status: "ok" });
  });

  app.use("/webauthn", webauthnRoutes(store));
  app.use("/session", sessionRoutes(store));
  return app;
}
