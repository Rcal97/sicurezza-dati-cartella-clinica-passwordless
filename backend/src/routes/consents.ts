import { Router } from "express";
import { consentsController } from "../controllers/consents.js";
import { rateLimit } from "../middleware/security.js";
import { requireSession } from "../middleware/session.js";
import type { Vault } from "../crypto/vault.js";
import type { Ledger } from "../models/ledger.js";
import type { Store } from "../models/store.js";

export function consentsRoutes(store: Store, ledger: Ledger, vault: Vault, limits: { max: number }): Router {
  const router = Router();
  const consents = consentsController(store, ledger, vault);

  router.use(requireSession(store));
  // Limite per utente: ogni concessione o revoca è una transazione sulla blockchain.
  router.use(rateLimit(limits.max, (_req, res) => res.locals.username as string));
  router.get("/", consents.mine);
  router.post("/options", consents.options);
  router.post("/verify", consents.verify);
  return router;
}
