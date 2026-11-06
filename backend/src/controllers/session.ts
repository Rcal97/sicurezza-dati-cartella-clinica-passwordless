import type { Request, Response } from "express";
import { SESSION_COOKIE, cookieOptions, hashToken, readSessionCookie } from "../middleware/session.js";
import type { Store } from "../models/store.js";

// Controller della sessione: utente corrente e logout.
export function sessionController(store: Store) {
  return {
    me(_req: Request, res: Response): void {
      res.json({ username: res.locals.username });
    },

    async logout(req: Request, res: Response): Promise<void> {
      const token = readSessionCookie(req);
      if (token) await store.deleteSession(hashToken(token));
      res.clearCookie(SESSION_COOKIE, cookieOptions);
      res.json({ loggedOut: true });
    },
  };
}
