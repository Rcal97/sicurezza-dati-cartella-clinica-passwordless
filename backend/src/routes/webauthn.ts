import { Router, type Request } from "express";
import { authenticationController } from "../controllers/authentication.js";
import { registrationController } from "../controllers/registration.js";
import type { Store } from "../models/store.js";
import { rateLimit } from "../middleware/security.js";

// Rotte WebAuthn: collegano gli URL ai controller, senza logica propria.
export function webauthnRoutes(store: Store, limits: { max: number; clientKey: (req: Request) => string }): Router {
  const router = Router();
  // Le rotte sono pubbliche: il limite si applica per client.
  router.use(rateLimit(limits.max, (req) => limits.clientKey(req)));
  const registration = registrationController(store);
  const authentication = authenticationController(store);

  router.post("/register/options", registration.options);
  router.post("/register/verify", registration.verify);
  router.post("/authenticate/options", authentication.options);
  router.post("/authenticate/verify", authentication.verify);
  return router;
}
