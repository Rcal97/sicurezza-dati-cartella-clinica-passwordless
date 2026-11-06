import { Binary, MongoClient, MongoServerError, type Collection, type Db } from "mongodb";
import type { WebAuthnCredential } from "@simplewebauthn/server";
import type { PendingRegistration, Store, User } from "./store.js";

interface CredentialDoc {
  id: string;
  publicKey: Binary;
  counter: number;
  transports?: WebAuthnCredential["transports"];
}
interface UserDoc {
  _id: string; // username
  webauthnUserID: string;
  credentials: CredentialDoc[];
}
interface ChallengeDoc {
  _id: string; // "registrazione:<username>" oppure "login:<username>"
  challenge: string;
  webauthnUserID?: string;
  expiresAt: Date;
}
interface SessionDoc {
  _id: string; // hash SHA-256 del token
  username: string;
  expiresAt: Date;
}

const DUPLICATE_KEY = 11000;

export class MongoStore implements Store {
  private constructor(
    private readonly client: MongoClient,
    private readonly users: Collection<UserDoc>,
    private readonly challenges: Collection<ChallengeDoc>,
    private readonly sessions: Collection<SessionDoc>,
  ) {}

  static async connect(url: string): Promise<MongoStore> {
    const client = new MongoClient(url, { serverSelectionTimeoutMS: 5000 });
    await client.connect();
    const db: Db = client.db();
    const store = new MongoStore(
      client,
      db.collection<UserDoc>("users"),
      db.collection<ChallengeDoc>("challenges"),
      db.collection<SessionDoc>("sessions"),
    );
    await store.createIndexes();
    return store;
  }

  private async createIndexes(): Promise<void> {
    // Una credenziale può appartenere a un solo utente: lo garantisce il database.
    await this.users.createIndex(
      { "credentials.id": 1 },
      { unique: true, partialFilterExpression: { "credentials.id": { $exists: true } } },
    );
    // Indici TTL: MongoDB cancella da solo challenge e sessioni scadute.
    await this.challenges.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
    await this.sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  }

  async getUser(username: string): Promise<User | null> {
    const doc = await this.users.findOne({ _id: username });
    if (!doc) return null;
    return {
      username: doc._id,
      webauthnUserID: doc.webauthnUserID,
      credentials: doc.credentials.map((c) => ({
        id: c.id,
        publicKey: new Uint8Array(c.publicKey.value()),
        counter: c.counter,
        transports: c.transports,
      })),
    };
  }

  async addCredential(username: string, webauthnUserID: string, credential: WebAuthnCredential) {
    if (await this.users.findOne({ "credentials.id": credential.id }, { projection: { _id: 1 } })) {
      return "duplicate" as const;
    }
    const doc: CredentialDoc = {
      id: credential.id,
      publicKey: new Binary(credential.publicKey),
      counter: credential.counter,
      transports: credential.transports,
    };
    try {
      await this.users.updateOne(
        { _id: username },
        { $setOnInsert: { webauthnUserID }, $push: { credentials: doc } },
        { upsert: true },
      );
      return "ok" as const;
    } catch (err) {
      // Due registrazioni contemporanee della stessa credenziale: vince la prima.
      if (err instanceof MongoServerError && err.code === DUPLICATE_KEY) return "duplicate" as const;
      throw err;
    }
  }

  async updateCounter(username: string, credentialID: string, counter: number): Promise<void> {
    await this.users.updateOne(
      { _id: username, "credentials.id": credentialID },
      { $set: { "credentials.$.counter": counter } },
    );
  }

  async savePendingRegistration(username: string, pending: PendingRegistration, ttlMs: number): Promise<void> {
    await this.challenges.replaceOne(
      { _id: `registrazione:${username}` },
      { ...pending, expiresAt: new Date(Date.now() + ttlMs) },
      { upsert: true },
    );
  }

  async takePendingRegistration(username: string): Promise<PendingRegistration | null> {
    // Lettura e cancellazione atomiche: due richieste parallele non possono usare la stessa challenge.
    const doc = await this.challenges.findOneAndDelete({ _id: `registrazione:${username}` });
    if (!doc || doc.expiresAt.getTime() < Date.now() || !doc.webauthnUserID) return null;
    return { challenge: doc.challenge, webauthnUserID: doc.webauthnUserID };
  }

  async saveLoginChallenge(username: string, challenge: string, ttlMs: number): Promise<void> {
    await this.challenges.replaceOne(
      { _id: `login:${username}` },
      { challenge, expiresAt: new Date(Date.now() + ttlMs) },
      { upsert: true },
    );
  }

  async takeLoginChallenge(username: string): Promise<string | null> {
    const doc = await this.challenges.findOneAndDelete({ _id: `login:${username}` });
    if (!doc || doc.expiresAt.getTime() < Date.now()) return null;
    return doc.challenge;
  }

  async createSession(tokenHash: string, username: string, idleMs: number): Promise<void> {
    await this.sessions.insertOne({ _id: tokenHash, username, expiresAt: new Date(Date.now() + idleMs) });
  }

  async touchSession(tokenHash: string, idleMs: number): Promise<string | null> {
    const now = Date.now();
    const doc = await this.sessions.findOneAndUpdate(
      { _id: tokenHash, expiresAt: { $gt: new Date(now) } },
      { $set: { expiresAt: new Date(now + idleMs) } },
    );
    return doc?.username ?? null;
  }

  async deleteSession(tokenHash: string): Promise<void> {
    await this.sessions.deleteOne({ _id: tokenHash });
  }

  async close(): Promise<void> {
    await this.client.close();
  }
}
