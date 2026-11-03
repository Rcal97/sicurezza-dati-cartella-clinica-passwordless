import { Router } from "express";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { isoBase64URL } from "@simplewebauthn/server/helpers";
import { config } from "../config.js";
import { credentialExists, getUser, saveUser, savePending, takePending } from "../store.js";

export const webauthnRouter = Router();

const USERNAME = /^[a-z0-9._-]{3,32}$/;

webauthnRouter.post("/register/options", async (req, res) => {
  const username = req.body?.username;
  if (typeof username !== "string" || !USERNAME.test(username)) {
    res.status(400).json({ error: "username non valido" });
    return;
  }

  const user = getUser(username);
  const options = await generateRegistrationOptions({
    rpName: config.rpName,
    rpID: config.rpID,
    userName: username,
    userID: user ? isoBase64URL.toBuffer(user.webauthnUserID) : undefined,
    attestationType: "none",
    excludeCredentials: user?.credentials.map((c) => ({ id: c.id, transports: c.transports })) ?? [],
    authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
  });

  savePending(username, options.challenge, options.user.id, config.challengeTtlMs);
  res.json(options);
});

webauthnRouter.post("/register/verify", async (req, res) => {
  const username = req.body?.username;
  const response = req.body?.response;
  if (typeof username !== "string" || !USERNAME.test(username) || typeof response !== "object" || response === null) {
    res.status(400).json({ error: "richiesta non valida" });
    return;
  }

  // La challenge viene consumata subito: anche un tentativo fallito la invalida.
  const entry = takePending(username);
  if (!entry) {
    res.status(400).json({ error: "challenge assente o scaduta" });
    return;
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: response as RegistrationResponseJSON,
      expectedChallenge: entry.challenge,
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

  const { credential } = verification.registrationInfo;
  if (credentialExists(credential.id)) {
    res.status(409).json({ error: "credenziale già registrata" });
    return;
  }

  const user = getUser(username) ?? { username, webauthnUserID: entry.webauthnUserID, credentials: [] };
  user.credentials.push(credential);
  saveUser(user);
  res.json({ verified: true });
});
