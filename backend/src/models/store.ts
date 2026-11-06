import type { WebAuthnCredential } from "@simplewebauthn/server";

// Model dell'architettura MVC: l'unico punto di accesso ai dati off-chain.
// Le implementazioni sono due: in memoria (test) e su MongoDB (server).

export interface User {
  username: string;
  webauthnUserID: string;
  credentials: WebAuthnCredential[];
}

export interface PendingRegistration {
  challenge: string;
  webauthnUserID: string;
}

export interface Store {
  getUser(username: string): Promise<User | null>;
  // Aggiunge una credenziale all'utente (creandolo se serve).
  // Restituisce "duplicate" se l'ID della credenziale è già registrato.
  addCredential(username: string, webauthnUserID: string, credential: WebAuthnCredential): Promise<"ok" | "duplicate">;
  updateCounter(username: string, credentialID: string, counter: number): Promise<void>;

  // Challenge monouso: "take" le legge e le cancella in un'unica operazione.
  savePendingRegistration(username: string, pending: PendingRegistration, ttlMs: number): Promise<void>;
  takePendingRegistration(username: string): Promise<PendingRegistration | null>;
  saveLoginChallenge(username: string, challenge: string, ttlMs: number): Promise<void>;
  takeLoginChallenge(username: string): Promise<string | null>;

  // Sessioni indicizzate dall'hash del token, mai dal token in chiaro.
  createSession(tokenHash: string, username: string, idleMs: number): Promise<void>;
  // Restituisce l'utente e rinnova la scadenza; null se la sessione non esiste o è scaduta.
  touchSession(tokenHash: string, idleMs: number): Promise<string | null>;
  deleteSession(tokenHash: string): Promise<void>;

  close(): Promise<void>;
}
