import type { Request, Response } from "express";
import { SESSION_COOKIE, cookieOptions, hashToken, readSessionCookie } from "../middleware/session.js";
import type { Store } from "../models/store.js";

// Controller della sessione: utente corrente, logout, gestione delle proprie passkey.
export function sessionController(store: Store) {
  // Chiude tutte le sessioni dell'utente, compresa quella della richiesta.
  async function closeAll(username: string, res: Response): Promise<void> {
    await store.deleteSessionsOf(username);
    res.clearCookie(SESSION_COOKIE, cookieOptions);
  }

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

    // "Esci da tutti i dispositivi".
    async logoutAll(_req: Request, res: Response): Promise<void> {
      await closeAll(res.locals.username, res);
      res.json({ loggedOut: true });
    },

    // Elenco delle proprie passkey (solo identificativo e tipo di collegamento).
    async passkeys(_req: Request, res: Response): Promise<void> {
      const user = await store.getUser(res.locals.username);
      res.json((user?.credentials ?? []).map((c) => ({ id: c.id, transports: c.transports ?? [] })));
    },

    // Revoca di una propria passkey, per esempio di un dispositivo perso. Per prudenza
    // si chiudono tutte le sessioni: quella aperta dal dispositivo perso compresa.
    async revokePasskey(req: Request, res: Response): Promise<void> {
      const id = req.body?.id;
      if (typeof id !== "string" || id.length === 0 || id.length > 1024) {
        res.status(400).json({ error: "richiesta non valida" });
        return;
      }
      const result = await store.removeCredential(res.locals.username, id);
      if (result === "missing") {
        res.status(404).json({ error: "passkey non trovata" });
        return;
      }
      if (result === "last") {
        res.status(409).json({ error: "non puoi revocare l'ultima passkey: chiedi un nuovo invito" });
        return;
      }
      await closeAll(res.locals.username, res);
      res.json({ revoked: true });
    },
  };
}
