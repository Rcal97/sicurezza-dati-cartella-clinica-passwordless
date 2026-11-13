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

// Challenge contenuta nella risposta dell'autenticatore, oppure null se il formato non è valido.
function challengeOf(response: { response?: { clientDataJSON?: unknown } }): string | null {
  const data = response.response?.clientDataJSON;
  if (typeof data !== "string" || data.length > 4096) return null;
  try {
    const challenge = JSON.parse(Buffer.from(data, "base64url").toString("utf8")).challenge;
    return typeof challenge === "string" ? challenge : null;
  } catch {
    return null;
  }
}

// Controller del login con passkey.
export function authenticationController(store: Store) {
  return {
    async options(req: Request, res: Response): Promise<void> {
      const username = req.body?.username;
      if (typeof username !== "string" || !USERNAME.test(username)) {
        res.status(400).json({ error: "username non valido" });
        return;
      }

      // Le opzioni sono identiche per qualsiasi username: niente elenco delle credenziali
      // (allowCredentials vuoto), è il dispositivo a proporre le passkey che conserva.
      // Così la risposta non rivela se l'utente esiste (user enumeration).
      const options = await generateAuthenticationOptions({
        rpID: config.rpID,
        allowCredentials: [],
        userVerification: "required",
      });

      await store.saveLoginChallenge(options.challenge, config.challengeTtlMs);
      res.json(options);
    },

    async verify(req: Request, res: Response): Promise<void> {
      const username = req.body?.username;
      const response = req.body?.response;
      if (typeof username !== "string" || !USERNAME.test(username) || typeof response?.id !== "string") {
        res.status(400).json({ error: "richiesta non valida" });
        return;
      }

      // La challenge si legge dai dati firmati dal browser (clientDataJSON) e si consuma
      // in modo atomico: vale una sola volta ed era stata emessa da questo server.
      const challenge = challengeOf(response);
      if (!challenge || !(await store.takeLoginChallenge(challenge))) {
        res.status(400).json({ error: "challenge assente o scaduta" });
        return;
      }

      // Stesso messaggio per utente inesistente, credenziale sconosciuta o firma errata.
      const credential = (await store.getUser(username))?.credentials.find((c) => c.id === response.id);
      if (!credential) {
        res.status(401).json({ error: "autenticazione non valida" });
        return;
      }
      // Valore del contatore letto ora, prima della verifica: è quello che ci aspettiamo
      // di trovare ancora nel database al momento dell'aggiornamento.
      const expectedCounter = credential.counter;

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

      // Salviamo il nuovo signCount solo se nessun altro login lo ha cambiato nel frattempo:
      // un clone usato in parallelo all'originale viene rifiutato.
      const updated = await store.updateCounter(
        username,
        credential.id,
        expectedCounter,
        verification.authenticationInfo.newCounter,
      );
      if (!updated) {
        console.warn(`Login rifiutato per ${username}: uso contemporaneo della stessa credenziale`);
        res.status(401).json({ error: "autenticazione non valida" });
        return;
      }

      // Login riuscito: un token nuovo a ogni accesso (niente session fixation).
      const token = newSessionToken();
      await store.createSession(hashToken(token), username, config.sessionIdleMs, config.sessionMaxMs);
      res.cookie(SESSION_COOKIE, token, cookieOptions);
      res.json({ verified: true });
    },
  };
}
