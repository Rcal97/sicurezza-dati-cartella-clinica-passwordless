import { createHash, randomBytes } from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import { config } from "./config.js";

export const SESSION_COOKIE = "sid";

// Sul server salviamo solo l'hash del token: se l'archivio venisse letto da un attaccante,
// non troverebbe token utilizzabili (stessa idea delle password salvate come hash).
const sessions = new Map<string, { username: string; expiresAt: number }>();

const hashToken = (token: string): string => createHash("sha256").update(token).digest("hex");

export function createSession(username: string): string {
  const token = randomBytes(32).toString("base64url"); // 256 bit casuali
  sessions.set(hashToken(token), { username, expiresAt: Date.now() + config.sessionIdleMs });
  return token;
}

export function destroySession(token: string): void {
  sessions.delete(hashToken(token));
}

// Restituisce l'utente della sessione e ne rinnova la scadenza (timeout per inattività).
function touchSession(token: string): string | undefined {
  const key = hashToken(token);
  const entry = sessions.get(key);
  if (!entry) return undefined;
  if (entry.expiresAt < Date.now()) {
    sessions.delete(key);
    return undefined;
  }
  entry.expiresAt = Date.now() + config.sessionIdleMs;
  return entry.username;
}

export function readSessionCookie(req: Request): string | undefined {
  const header = req.headers.cookie;
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const [name, ...value] = part.trim().split("=");
    if (name === SESSION_COOKIE) return value.join("=");
  }
  return undefined;
}

// Middleware: lascia passare solo le richieste con una sessione valida.
export function requireSession(req: Request, res: Response, next: NextFunction): void {
  const token = readSessionCookie(req);
  const username = token ? touchSession(token) : undefined;
  if (!username) {
    res.status(401).json({ error: "sessione assente o scaduta" });
    return;
  }
  res.locals.username = username;
  next();
}
