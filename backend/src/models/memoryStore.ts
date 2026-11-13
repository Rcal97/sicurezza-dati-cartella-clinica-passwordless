import type { WebAuthnCredential } from "@simplewebauthn/server";
import type { AccessLogEntry, PendingRegistration, Profile, SignatureRequest, Store, StoredDocument, User } from "./store.js";

// Implementazione in memoria: usata dai test, non conserva nulla tra un avvio e l'altro.
export class MemoryStore implements Store {
  private readonly users = new Map<string, User>();
  private readonly registrations = new Map<string, PendingRegistration & { expiresAt: number }>();
  private readonly logins = new Map<string, number>(); // challenge -> scadenza
  private readonly signatures = new Map<string, SignatureRequest & { expiresAt: number }>();
  private readonly sessions = new Map<string, { username: string; expiresAt: number; absoluteExpiresAt: number }>();
  private readonly invitations = new Map<string, { username: string; expiresAt: number }>();
  private readonly profiles = new Map<string, Profile>();
  // Pubblico per permettere ai test di controllarne il contenuto.
  readonly accessLog: AccessLogEntry[] = [];
  readonly documents: StoredDocument[] = [];

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

  async updateCounter(username: string, credentialID: string, expected: number, counter: number): Promise<boolean> {
    const credential = this.users.get(username)?.credentials.find((c) => c.id === credentialID);
    if (!credential || credential.counter !== expected) return false;
    credential.counter = counter;
    return true;
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

  async saveLoginChallenge(challenge: string, ttlMs: number): Promise<void> {
    this.logins.set(challenge, Date.now() + ttlMs);
  }

  async saveSignatureRequest(challenge: string, request: SignatureRequest, ttlMs: number): Promise<void> {
    this.signatures.set(challenge, { ...request, expiresAt: Date.now() + ttlMs });
  }

  async takeSignatureRequest(challenge: string, username: string): Promise<SignatureRequest | null> {
    const entry = this.signatures.get(challenge);
    if (entry?.username !== username) return null;
    this.signatures.delete(challenge);
    if (!entry || entry.expiresAt < Date.now()) return null;
    return { username: entry.username, payload: entry.payload };
  }

  async takeLoginChallenge(challenge: string): Promise<boolean> {
    const expiresAt = this.logins.get(challenge);
    this.logins.delete(challenge);
    return expiresAt !== undefined && expiresAt >= Date.now();
  }

  async createInvitation(codeHash: string, username: string, ttlMs: number): Promise<void> {
    this.invitations.set(codeHash, { username, expiresAt: Date.now() + ttlMs });
  }

  async hasInvitation(codeHash: string, username: string): Promise<boolean> {
    const entry = this.invitations.get(codeHash);
    return entry !== undefined && entry.username === username && entry.expiresAt >= Date.now();
  }

  async takeInvitation(codeHash: string, username: string): Promise<boolean> {
    const valid = await this.hasInvitation(codeHash, username);
    if (valid) this.invitations.delete(codeHash);
    return valid;
  }

  async createSession(tokenHash: string, username: string, idleMs: number, maxMs: number): Promise<void> {
    const now = Date.now();
    this.sessions.set(tokenHash, { username, expiresAt: now + idleMs, absoluteExpiresAt: now + maxMs });
  }

  async touchSession(tokenHash: string, idleMs: number): Promise<string | null> {
    const entry = this.sessions.get(tokenHash);
    if (!entry) return null;
    const now = Date.now();
    if (entry.expiresAt <= now || entry.absoluteExpiresAt <= now) {
      this.sessions.delete(tokenHash);
      return null;
    }
    entry.expiresAt = Math.min(now + idleMs, entry.absoluteExpiresAt);
    return entry.username;
  }

  async deleteSession(tokenHash: string): Promise<void> {
    this.sessions.delete(tokenHash);
  }

  async deleteSessionsOf(username: string): Promise<void> {
    for (const [hash, s] of this.sessions) if (s.username === username) this.sessions.delete(hash);
  }

  async removeCredential(username: string, credentialID: string) {
    const user = this.users.get(username);
    const index = user?.credentials.findIndex((c) => c.id === credentialID) ?? -1;
    if (!user || index < 0) return "missing" as const;
    if (user.credentials.length === 1) return "last" as const;
    user.credentials.splice(index, 1);
    return "ok" as const;
  }

  async removeAllCredentials(username: string): Promise<void> {
    const user = this.users.get(username);
    if (user) user.credentials = [];
  }

  async setProfile(username: string, profile: Profile) {
    for (const [other, p] of this.profiles) {
      if (other !== username && p.address.toLowerCase() === profile.address.toLowerCase()) {
        return "duplicate" as const;
      }
    }
    this.profiles.set(username, { ...profile });
    return "ok" as const;
  }

  async getProfile(username: string): Promise<Profile | null> {
    return this.profiles.get(username) ?? null;
  }

  async addAccessLog(entry: AccessLogEntry): Promise<void> {
    this.accessLog.push(entry);
  }

  async listAccessLog(): Promise<AccessLogEntry[]> {
    return [...this.accessLog];
  }

  async addDocument(doc: StoredDocument): Promise<void> {
    this.documents.push(doc);
  }

  async listDocuments(patient: string): Promise<StoredDocument[]> {
    return this.documents.filter((d) => d.patient === patient);
  }

  async close(): Promise<void> {}
}
