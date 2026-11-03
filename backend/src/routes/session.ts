import { Router } from "express";
import { config } from "../config.js";
import { SESSION_COOKIE, destroySession, readSessionCookie, requireSession } from "../sessions.js";

export const sessionRouter = Router();

sessionRouter.get("/me", requireSession, (_req, res) => {
  res.json({ username: res.locals.username });
});

sessionRouter.post("/logout", (req, res) => {
  const token = readSessionCookie(req);
  if (token) destroySession(token);
  res.clearCookie(SESSION_COOKIE, { httpOnly: true, sameSite: "strict", secure: config.secureCookies, path: "/" });
  res.json({ loggedOut: true });
});
