import type { WebAuthnCredential } from "@simplewebauthn/server";
import type { PendingRegistration, Store, User } from "./store.js";

// Implementazione in memoria: usata dai test, non conserva nulla tra un avvio e l'altro.
export class MemoryStore implements Store {
  private readonly users = new Map<string, User>();
  private readonly registrations = new Map<string, PendingRegistration & { expiresAt: number }>();
  private readonly logins = new Map<string, { challenge: string; expiresAt: number }>();
  private readonly sessions = new Map<string, { username: string; expiresAt: number }>();

  async getUser(username: string): Promise<User | null> {
    return this.users.get(username) ?? null;
  }

  async addCredential(username: string, webauthnUserID: string, credential: WebAuthnCredential) {
    for (const user of this.users.values()) {
      if (user.credentials.some((c) => c.id === credential.id)) return "duplicate" as const;
    }
    const user = this.users.get(username) ?? { username, webauthnUserID, credentials: [] };
    user.credentials.push(credential);
    this.users.set(username, user);
    return "ok" as const;
  }

  async updateCounter(username: string, credentialID: string, counter: number): Promise<void> {
    const credential = this.users.get(username)?.credentials.find((c) => c.id === credentialID);
    if (credential) credential.counter = counter;
  }

  async savePendingRegistration(username: string, pending: PendingRegistration, ttlMs: number): Promise<void> {
    this.registrations.set(username, { ...pending, expiresAt: Date.now() + ttlMs });
  }

  async takePendingRegistration(username: string): Promise<PendingRegistration | null> {
    const entry = this.registrations.get(username);
    this.registrations.delete(username);
    if (!entry || entry.expiresAt < Date.now()) return null;
    return { challenge: entry.challenge, webauthnUserID: entry.webauthnUserID };
  }

  async saveLoginChallenge(username: string, challenge: string, ttlMs: number): Promise<void> {
    this.logins.set(username, { challenge, expiresAt: Date.now() + ttlMs });
  }

  async takeLoginChallenge(username: string): Promise<string | null> {
    const entry = this.logins.get(username);
    this.logins.delete(username);
    if (!entry || entry.expiresAt < Date.now()) return null;
    return entry.challenge;
  }

  async createSession(tokenHash: string, username: string, idleMs: number): Promise<void> {
    this.sessions.set(tokenHash, { username, expiresAt: Date.now() + idleMs });
  }

  async touchSession(tokenHash: string, idleMs: number): Promise<string | null> {
    const entry = this.sessions.get(tokenHash);
    if (!entry) return null;
    if (entry.expiresAt < Date.now()) {
      this.sessions.delete(tokenHash);
      return null;
    }
    entry.expiresAt = Date.now() + idleMs;
    return entry.username;
  }

  async deleteSession(tokenHash: string): Promise<void> {
    this.sessions.delete(tokenHash);
  }

  async close(): Promise<void> {}
}
