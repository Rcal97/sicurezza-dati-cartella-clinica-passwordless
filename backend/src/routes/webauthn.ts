import { Router } from "express";
import { authenticationController } from "../controllers/authentication.js";
import { registrationController } from "../controllers/registration.js";
import type { Store } from "../models/store.js";

// Rotte WebAuthn: collegano gli URL ai controller, senza logica propria.
export function webauthnRoutes(store: Store): Router {
  const router = Router();
  const registration = registrationController(store);
  const authentication = authenticationController(store);

  router.post("/register/options", registration.options);
  router.post("/register/verify", registration.verify);
  router.post("/authenticate/options", authentication.options);
  router.post("/authenticate/verify", authentication.verify);
  return router;
}
