import { Router } from "express";
import { sessionController } from "../controllers/session.js";
import { requireSession } from "../middleware/session.js";
import type { Store } from "../models/store.js";

export function sessionRoutes(store: Store): Router {
  const router = Router();
  const session = sessionController(store);

  router.get("/me", requireSession(store), session.me);
  router.post("/logout", session.logout);
  return router;
}
