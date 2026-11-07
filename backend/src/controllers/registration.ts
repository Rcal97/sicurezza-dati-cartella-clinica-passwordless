import type { Request, Response } from "express";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { isoBase64URL } from "@simplewebauthn/server/helpers";
import { config } from "../config.js";
import { hashToken, sessionUser } from "../middleware/session.js";
import type { Store } from "../models/store.js";

export const USERNAME = /^[a-z0-9._-]{3,32}$/;

// Chi può registrare una passkey per "username":
// - l'utente stesso, già autenticato con un'altra passkey (aggiunta di un dispositivo);
// - chi presenta un invito valido per quello username (prima registrazione o recupero dell'accesso).
type Autorizzazione = { tipo: "sessione" } | { tipo: "invito"; codeHash: string };

async function autorizza(store: Store, req: Request, username: string): Promise<Autorizzazione | null> {
  if ((await sessionUser(store, req)) === username) return { tipo: "sessione" };
  const invitation = req.body?.invitation;
  if (typeof invitation === "string" && invitation.length > 0) {
    const codeHash = hashToken(invitation);
    if (await store.hasInvitation(codeHash, username)) return { tipo: "invito", codeHash };
  }
  return null;
}

// Controller della registrazione di una passkey.
export function registrationController(store: Store) {
  return {
    async options(req: Request, res: Response): Promise<void> {
      const username = req.body?.username;
      if (typeof username !== "string" || !USERNAME.test(username)) {
        res.status(400).json({ error: "username non valido" });
        return;
      }
      if (!(await autorizza(store, req, username))) {
        res.status(403).json({ error: "registrazione non autorizzata" });
        return;
      }

      const user = await store.getUser(username);
      const options = await generateRegistrationOptions({
        rpName: config.rpName,
        rpID: config.rpID,
        userName: username,
        userID: user ? isoBase64URL.toBuffer(user.webauthnUserID) : undefined,
        attestationType: "none",
        excludeCredentials: user?.credentials.map((c) => ({ id: c.id, transports: c.transports })) ?? [],
        authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
      });

      await store.savePendingRegistration(
        username,
        { challenge: options.challenge, webauthnUserID: options.user.id },
        config.challengeTtlMs,
      );
      res.json(options);
    },

    async verify(req: Request, res: Response): Promise<void> {
      const username = req.body?.username;
      const response = req.body?.response;
      if (typeof username !== "string" || !USERNAME.test(username) || typeof response !== "object" || response === null) {
        res.status(400).json({ error: "richiesta non valida" });
        return;
      }

      // La challenge viene consumata subito: anche un tentativo fallito la invalida.
      const pending = await store.takePendingRegistration(username);
      if (!pending) {
        res.status(400).json({ error: "challenge assente o scaduta" });
        return;
      }

      // L'autorizzazione si controlla di nuovo: tra le due richieste la sessione può essere scaduta.
      const autorizzazione = await autorizza(store, req, username);
      if (!autorizzazione) {
        res.status(403).json({ error: "registrazione non autorizzata" });
        return;
      }

      let verification;
      try {
        verification = await verifyRegistrationResponse({
          response: response as RegistrationResponseJSON,
          expectedChallenge: pending.challenge,
          expectedOrigin: config.origin,
          expectedRPID: config.rpID,
          requireUserVerification: true,
        });
      } catch (err) {
        console.warn(`Registrazione rifiutata per ${username}: ${(err as Error).message}`);
        res.status(400).json({ error: "registrazione non valida" });
        return;
      }

      if (!verification.verified) {
        res.status(400).json({ error: "registrazione non valida" });
        return;
      }

      // L'invito si consuma solo a registrazione riuscita, in modo atomico: vale una volta sola.
      if (autorizzazione.tipo === "invito" && !(await store.takeInvitation(autorizzazione.codeHash, username))) {
        res.status(403).json({ error: "registrazione non autorizzata" });
        return;
      }

      const result = await store.addCredential(username, pending.webauthnUserID, verification.registrationInfo.credential);
      if (result === "duplicate") {
        res.status(409).json({ error: "credenziale già registrata" });
        return;
      }
      res.json({ verified: true });
    },
  };
}
