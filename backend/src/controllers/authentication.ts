import type { Request, Response } from "express";
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type AuthenticationResponseJSON,
} from "@simplewebauthn/server";
import { config } from "../config.js";
import { SESSION_COOKIE, cookieOptions, hashToken, newSessionToken } from "../middleware/session.js";
import type { Store } from "../models/store.js";
import { USERNAME } from "./registration.js";

// Controller del login con passkey.
export function authenticationController(store: Store) {
  return {
    async options(req: Request, res: Response): Promise<void> {
      const username = req.body?.username;
      if (typeof username !== "string" || !USERNAME.test(username)) {
        res.status(400).json({ error: "username non valido" });
        return;
      }

      // Anche per un utente inesistente rispondiamo con delle opzioni,
      // così l'errore arriva solo alla verifica (limita la user enumeration).
      const user = await store.getUser(username);
      const options = await generateAuthenticationOptions({
        rpID: config.rpID,
        allowCredentials: user?.credentials.map((c) => ({ id: c.id, transports: c.transports })) ?? [],
        userVerification: "required",
      });

      await store.saveLoginChallenge(username, options.challenge, config.challengeTtlMs);
      res.json(options);
    },

    async verify(req: Request, res: Response): Promise<void> {
      const username = req.body?.username;
      const response = req.body?.response;
      if (typeof username !== "string" || !USERNAME.test(username) || typeof response?.id !== "string") {
        res.status(400).json({ error: "richiesta non valida" });
        return;
      }

      const challenge = await store.takeLoginChallenge(username);
      if (!challenge) {
        res.status(400).json({ error: "challenge assente o scaduta" });
        return;
      }

      // Stesso messaggio per utente inesistente, credenziale sconosciuta o firma errata.
      const credential = (await store.getUser(username))?.credentials.find((c) => c.id === response.id);
      if (!credential) {
        res.status(401).json({ error: "autenticazione non valida" });
        return;
      }

      let verification;
      try {
        verification = await verifyAuthenticationResponse({
          response: response as AuthenticationResponseJSON,
          expectedChallenge: challenge,
          expectedOrigin: config.origin,
          expectedRPID: config.rpID,
          credential,
          requireUserVerification: true,
        });
      } catch (err) {
        console.warn(`Login rifiutato per ${username}: ${(err as Error).message}`);
        res.status(401).json({ error: "autenticazione non valida" });
        return;
      }

      if (!verification.verified) {
        res.status(401).json({ error: "autenticazione non valida" });
        return;
      }

      // Salviamo il nuovo signCount: un clone che riusa un valore vecchio verrà rifiutato.
      await store.updateCounter(username, credential.id, verification.authenticationInfo.newCounter);

      // Login riuscito: un token nuovo a ogni accesso (niente session fixation).
      const token = newSessionToken();
      await store.createSession(hashToken(token), username, config.sessionIdleMs);
      res.cookie(SESSION_COOKIE, token, cookieOptions);
      res.json({ verified: true });
    },
  };
}
