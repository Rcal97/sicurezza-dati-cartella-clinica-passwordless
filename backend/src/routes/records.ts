import { Router } from "express";
import { rateLimit } from "../middleware/security.js";
import { recordsController } from "../controllers/records.js";
import { requireSession } from "../middleware/session.js";
import type { Vault } from "../crypto/vault.js";
import type { Ledger } from "../models/ledger.js";
import type { Store } from "../models/store.js";

export function recordsRoutes(store: Store, ledger: Ledger, vault: Vault, limits: { max: number }): Router {
  const router = Router();
  const records = recordsController(store, ledger, vault);

  // Ogni richiesta passa prima dal controllo della sessione.
  router.use(requireSession(store));
  // Limite per utente: ogni accesso a una cartella è anche una transazione sulla blockchain.
  router.use(rateLimit(limits.max, (_req, res) => res.locals.username as string));
  router.post("/access", records.access);
  router.post("/emergency", records.emergency);
  return router;
}
