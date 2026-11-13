import { Router } from "express";
import { directoryController } from "../controllers/directory.js";
import { requireSession } from "../middleware/session.js";
import type { Ledger } from "../models/ledger.js";
import type { Store } from "../models/store.js";

export function directoryRoutes(store: Store, ledger: Ledger): Router {
  const router = Router();
  const directory = directoryController(store, ledger);

  router.use(requireSession(store));
  router.get("/profile", directory.profile);
  router.get("/doctors", directory.doctors);
  router.get("/chain", directory.chain);
  return router;
}
