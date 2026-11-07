import { createHash, randomBytes } from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import { config } from "../config.js";
import type { Store } from "../models/store.js";

export const SESSION_COOKIE = "sid";

// Il token viaggia solo nel cookie; nel database ne salviamo l'hash SHA-256.
export const newSessionToken = (): string => randomBytes(32).toString("base64url"); // 256 bit casuali
export const hashToken = (token: string): string => createHash("sha256").update(token).digest("hex");

export const cookieOptions = {
  httpOnly: true,
  sameSite: "strict",
  secure: config.secureCookies,
  path: "/",
} as const;

export function readSessionCookie(req: Request): string | undefined {
  const header = req.headers.cookie;
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const [name, ...value] = part.trim().split("=");
    if (name === SESSION_COOKIE) return value.join("=");
  }
  return undefined;
}

// Utente della sessione allegata alla richiesta, oppure null.
export async function sessionUser(store: Store, req: Request): Promise<string | null> {
  const token = readSessionCookie(req);
  return token ? store.touchSession(hashToken(token), config.sessionIdleMs) : null;
}

// Middleware: lascia passare solo le richieste con una sessione valida (complete mediation).
export function requireSession(store: Store) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const username = await sessionUser(store, req);
    if (!username) {
      res.status(401).json({ error: "sessione assente o scaduta" });
      return;
    }
    res.locals.username = username;
    next();
  };
}
