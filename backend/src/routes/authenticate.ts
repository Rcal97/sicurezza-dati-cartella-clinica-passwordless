import { Router } from "express";
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type AuthenticationResponseJSON,
} from "@simplewebauthn/server";
import { config } from "../config.js";
import { SESSION_COOKIE, createSession } from "../sessions.js";
import { getUser, saveLoginChallenge, takeLoginChallenge } from "../store.js";
import { USERNAME } from "./webauthn.js";

export const authRouter = Router();

authRouter.post("/authenticate/options", async (req, res) => {
  const username = req.body?.username;
  if (typeof username !== "string" || !USERNAME.test(username)) {
    res.status(400).json({ error: "username non valido" });
    return;
  }

  // Anche per un utente inesistente rispondiamo con delle opzioni,
  // così l'errore arriva solo alla verifica (limita la user enumeration).
  const user = getUser(username);
  const options = await generateAuthenticationOptions({
    rpID: config.rpID,
    allowCredentials: user?.credentials.map((c) => ({ id: c.id, transports: c.transports })) ?? [],
    userVerification: "required",
  });

  saveLoginChallenge(username, options.challenge, config.challengeTtlMs);
  res.json(options);
});

authRouter.post("/authenticate/verify", async (req, res) => {
  const username = req.body?.username;
  const response = req.body?.response;
  if (typeof username !== "string" || !USERNAME.test(username) || typeof response?.id !== "string") {
    res.status(400).json({ error: "richiesta non valida" });
    return;
  }

  const challenge = takeLoginChallenge(username);
  if (!challenge) {
    res.status(400).json({ error: "challenge assente o scaduta" });
    return;
  }

  // Stesso messaggio per utente inesistente, credenziale sconosciuta o firma errata.
  const credential = getUser(username)?.credentials.find((c) => c.id === response.id);
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
  credential.counter = verification.authenticationInfo.newCounter;

  // Login riuscito: un token nuovo a ogni accesso (niente session fixation).
  const token = createSession(username);
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: "strict",
    secure: config.secureCookies,
    path: "/",
  });
  res.json({ verified: true });
});
