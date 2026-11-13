import type { NextFunction, Request, Response } from "express";
import { config } from "../config.js";

// Intestazioni di sicurezza per tutte le risposte dell'API.
export function securityHeaders(_req: Request, res: Response, next: NextFunction): void {
  // Le risposte contengono dati personali e sanitari: né il browser né un proxy devono conservarle.
  res.setHeader("Cache-Control", "no-store");
  // Il browser non deve "indovinare" un tipo diverso da quello dichiarato.
  res.setHeader("X-Content-Type-Options", "nosniff");
  // L'API restituisce solo JSON: niente script, niente inclusione in frame (clickjacking).
  res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  // In produzione il browser deve usare sempre HTTPS (HSTS).
  if (config.secureCookies) res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  next();
}

// Limite di frequenza a finestra fissa: al massimo "max" richieste al minuto per chiave
// (indirizzo del client o utente autenticato). Oltre il limite si risponde 429.
export function rateLimit(max: number, key: (req: Request, res: Response) => string, windowMs = 60_000) {
  const windows = new Map<string, { count: number; resetAt: number }>();
  return (req: Request, res: Response, next: NextFunction): void => {
    const now = Date.now();
    // Pulizia delle finestre scadute, per non far crescere la memoria all'infinito.
    if (windows.size > 10_000) {
      for (const [k, w] of windows) if (w.resetAt <= now) windows.delete(k);
    }
    const k = key(req, res);
    let w = windows.get(k);
    if (!w || w.resetAt <= now) {
      w = { count: 0, resetAt: now + windowMs };
      windows.set(k, w);
    }
    if (++w.count > max) {
      res.setHeader("Retry-After", String(Math.ceil((w.resetAt - now) / 1000)));
      res.status(429).json({ error: "troppe richieste, riprova tra poco" });
      return;
    }
    next();
  };
}

// Gestore finale degli errori: l'utente riceve solo un messaggio generico,
// i dettagli (stack trace, percorsi, messaggi del database) restano nel log del server.
export function errorHandler(err: unknown, _req: Request, res: Response, _next: NextFunction): void {
  const status = (err as { status?: number }).status;
  if (typeof status === "number" && status >= 400 && status < 500) {
    // Errori del client rilevati da Express (JSON malformato, corpo troppo grande).
    res.status(status).json({ error: status === 413 ? "richiesta troppo grande" : "richiesta non valida" });
    return;
  }
  console.error("Errore interno:", err);
  res.status(500).json({ error: "errore interno" });
}
