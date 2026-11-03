import type { WebAuthnCredential } from "@simplewebauthn/server";

// Archivio in memoria: più avanti lo sostituiremo con MongoDB.
export interface User {
  username: string;
  webauthnUserID: string;
  credentials: WebAuthnCredential[];
}

interface PendingRegistration {
  challenge: string;
  webauthnUserID: string;
  expiresAt: number;
}

const users = new Map<string, User>();
const pending = new Map<string, PendingRegistration>();

export function getUser(username: string): User | undefined {
  return users.get(username);
}

export function saveUser(user: User): void {
  users.set(user.username, user);
}

export function savePending(username: string, challenge: string, webauthnUserID: string, ttlMs: number): void {
  pending.set(username, { challenge, webauthnUserID, expiresAt: Date.now() + ttlMs });
}

// Una challenge vale una sola volta: la cancelliamo appena letta (anti-replay).
export function takePending(username: string): PendingRegistration | undefined {
  const entry = pending.get(username);
  pending.delete(username);
  if (!entry || entry.expiresAt < Date.now()) return undefined;
  return entry;
}

// Un ID di credenziale deve appartenere a un solo utente.
export function credentialExists(credentialID: string): boolean {
  for (const user of users.values()) {
    if (user.credentials.some((c) => c.id === credentialID)) return true;
  }
  return false;
}

// Challenge in attesa per il login, anch'esse monouso e a scadenza.
const pendingLogin = new Map<string, { challenge: string; expiresAt: number }>();

export function saveLoginChallenge(username: string, challenge: string, ttlMs: number): void {
  pendingLogin.set(username, { challenge, expiresAt: Date.now() + ttlMs });
}

export function takeLoginChallenge(username: string): string | undefined {
  const entry = pendingLogin.get(username);
  pendingLogin.delete(username);
  if (!entry || entry.expiresAt < Date.now()) return undefined;
  return entry.challenge;
}
