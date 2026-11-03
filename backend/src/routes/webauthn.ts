import { Router } from "express";
import { generateRegistrationOptions } from "@simplewebauthn/server";
import { isoBase64URL } from "@simplewebauthn/server/helpers";
import { config } from "../config.js";
import { getUser, savePending } from "../store.js";

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
