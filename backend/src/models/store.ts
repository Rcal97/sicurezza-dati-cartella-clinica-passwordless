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

// Ruolo e indirizzo blockchain di un utente, assegnati dopo l'identificazione.
// Per un paziente l'indirizzo è uno pseudonimo usato solo per il registro dei consensi.
export type Role = "doctor" | "patient";
export interface Profile {
  role: Role;
  address: string;
}

// Dettagli di un accesso, conservati off-chain: sulla catena va solo la loro impronta.
export type AccessDetails =
  | {
      kind: "ordinary";
      requester: string;
      patient: string;
      purpose: string;
      outcome: "granted" | "denied";
      at: string;
      nonce: string;
    }
  | {
      kind: "emergency";
      requester: string;
      patient: string;
      reason: string;
      at: string;
      nonce: string;
    };

export interface AccessLogEntry {
  entryId: string; // identificativo della voce sul registro di audit on-chain
  recordHash: string;
  details: AccessDetails;
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

  // Inviti alla registrazione, rilasciati dopo l'identificazione dell'utente (identity proofing).
  // Sono legati a uno username, monouso e indicizzati dall'hash del codice.
  createInvitation(codeHash: string, username: string, ttlMs: number): Promise<void>;
  hasInvitation(codeHash: string, username: string): Promise<boolean>;
  // Consuma l'invito in modo atomico: restituisce true una sola volta.
  takeInvitation(codeHash: string, username: string): Promise<boolean>;

  // Sessioni indicizzate dall'hash del token, mai dal token in chiaro.
  createSession(tokenHash: string, username: string, idleMs: number): Promise<void>;
  // Restituisce l'utente e rinnova la scadenza; null se la sessione non esiste o è scaduta.
  touchSession(tokenHash: string, idleMs: number): Promise<string | null>;
  deleteSession(tokenHash: string): Promise<void>;

  // Profili: un indirizzo blockchain appartiene a un solo utente ("duplicate" altrimenti).
  setProfile(username: string, profile: Profile): Promise<"ok" | "duplicate">;
  getProfile(username: string): Promise<Profile | null>;

  // Copia off-chain dei dettagli degli accessi registrati sulla catena.
  addAccessLog(entry: AccessLogEntry): Promise<void>;

  close(): Promise<void>;
}
