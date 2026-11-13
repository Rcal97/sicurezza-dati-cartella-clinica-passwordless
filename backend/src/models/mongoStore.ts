import { Binary, MongoClient, MongoServerError, type Collection, type Db } from "mongodb";
import type { WebAuthnCredential } from "@simplewebauthn/server";
import type { AccessLogEntry, PendingRegistration, Profile, Role, Store, StoredDocument, User } from "./store.js";

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
  _id: string; // "registrazione:<username>" oppure "login:<challenge>"
  challenge?: string;
  webauthnUserID?: string;
  expiresAt: Date;
}
interface SessionDoc {
  _id: string; // hash SHA-256 del token
  username: string;
  expiresAt: Date; // scadenza per inattività, rinnovata a ogni richiesta
  absoluteExpiresAt: Date; // scadenza massima, fissata alla creazione
}
interface InvitationDoc {
  _id: string; // hash SHA-256 del codice d'invito
  username: string;
  expiresAt: Date;
}

interface DocumentDoc extends Omit<StoredDocument, "id"> {
  _id: string; // identificativo del referto
}

interface ProfileDoc {
  _id: string; // username
  role: Role;
  address: string; // in minuscolo, per il controllo di unicità
}

const DUPLICATE_KEY = 11000;

export class MongoStore implements Store {
  private constructor(
    private readonly client: MongoClient,
    private readonly users: Collection<UserDoc>,
    private readonly challenges: Collection<ChallengeDoc>,
    private readonly sessions: Collection<SessionDoc>,
    private readonly invitations: Collection<InvitationDoc>,
    private readonly profiles: Collection<ProfileDoc>,
    private readonly accessLog: Collection<AccessLogEntry>,
    private readonly documents: Collection<DocumentDoc>,
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
      db.collection<InvitationDoc>("invitations"),
      db.collection<ProfileDoc>("profiles"),
      db.collection<AccessLogEntry>("access_log"),
      db.collection<DocumentDoc>("documents"),
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
    await this.invitations.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
    // Un indirizzo blockchain appartiene a un solo utente.
    await this.profiles.createIndex({ address: 1 }, { unique: true });
    await this.documents.createIndex({ patient: 1, createdAt: 1 });
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

  async updateCounter(username: string, credentialID: string, expected: number, counter: number): Promise<boolean> {
    // Il filtro include il valore atteso: l'aggiornamento riesce solo se nessun altro login
    // ha cambiato il contatore nel frattempo ($elemMatch: stessa credenziale, stesso valore).
    const result = await this.users.updateOne(
      { _id: username, credentials: { $elemMatch: { id: credentialID, counter: expected } } },
      { $set: { "credentials.$.counter": counter } },
    );
    return result.modifiedCount === 1 || (result.matchedCount === 1 && expected === counter);
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
    if (!doc || doc.expiresAt.getTime() < Date.now() || !doc.challenge || !doc.webauthnUserID) return null;
    return { challenge: doc.challenge, webauthnUserID: doc.webauthnUserID };
  }

  async saveLoginChallenge(challenge: string, ttlMs: number): Promise<void> {
    await this.challenges.insertOne({ _id: `login:${challenge}`, expiresAt: new Date(Date.now() + ttlMs) });
  }

  async takeLoginChallenge(challenge: string): Promise<boolean> {
    const doc = await this.challenges.findOneAndDelete({ _id: `login:${challenge}` });
    return doc !== null && doc.expiresAt.getTime() >= Date.now();
  }

  async createInvitation(codeHash: string, username: string, ttlMs: number): Promise<void> {
    await this.invitations.insertOne({ _id: codeHash, username, expiresAt: new Date(Date.now() + ttlMs) });
  }

  async hasInvitation(codeHash: string, username: string): Promise<boolean> {
    const count = await this.invitations.countDocuments({ _id: codeHash, username, expiresAt: { $gt: new Date() } });
    return count === 1;
  }

  async takeInvitation(codeHash: string, username: string): Promise<boolean> {
    const doc = await this.invitations.findOneAndDelete({ _id: codeHash, username, expiresAt: { $gt: new Date() } });
    return doc !== null;
  }

  async createSession(tokenHash: string, username: string, idleMs: number, maxMs: number): Promise<void> {
    const now = Date.now();
    await this.sessions.insertOne({
      _id: tokenHash,
      username,
      expiresAt: new Date(now + idleMs),
      absoluteExpiresAt: new Date(now + maxMs),
    });
  }

  async touchSession(tokenHash: string, idleMs: number): Promise<string | null> {
    const now = new Date();
    // Rinnovo con una pipeline: la nuova scadenza non supera mai quella massima.
    const doc = await this.sessions.findOneAndUpdate(
      { _id: tokenHash, expiresAt: { $gt: now }, absoluteExpiresAt: { $gt: now } },
      [{ $set: { expiresAt: { $min: [new Date(now.getTime() + idleMs), "$absoluteExpiresAt"] } } }],
    );
    return doc?.username ?? null;
  }

  async deleteSession(tokenHash: string): Promise<void> {
    await this.sessions.deleteOne({ _id: tokenHash });
  }

  async deleteSessionsOf(username: string): Promise<void> {
    await this.sessions.deleteMany({ username });
  }

  async removeCredential(username: string, credentialID: string) {
    // Rimozione atomica, solo se l'utente ha almeno due passkey ("credentials.1" esiste):
    // due revoche contemporanee non possono lasciarlo senza nessuna passkey.
    const result = await this.users.updateOne(
      { _id: username, "credentials.id": credentialID, "credentials.1": { $exists: true } },
      { $pull: { credentials: { id: credentialID } } },
    );
    if (result.modifiedCount === 1) return "ok" as const;
    const owns = await this.users.countDocuments({ _id: username, "credentials.id": credentialID });
    return owns === 1 ? ("last" as const) : ("missing" as const);
  }

  async removeAllCredentials(username: string): Promise<void> {
    await this.users.updateOne({ _id: username }, { $set: { credentials: [] } });
  }

  async setProfile(username: string, profile: Profile) {
    try {
      await this.profiles.updateOne(
        { _id: username },
        { $set: { role: profile.role, address: profile.address.toLowerCase() } },
        { upsert: true },
      );
      return "ok" as const;
    } catch (err) {
      if (err instanceof MongoServerError && err.code === DUPLICATE_KEY) return "duplicate" as const;
      throw err;
    }
  }

  async getProfile(username: string): Promise<Profile | null> {
    const doc = await this.profiles.findOne({ _id: username });
    return doc ? { role: doc.role, address: doc.address } : null;
  }

  async addAccessLog(entry: AccessLogEntry): Promise<void> {
    // Copia: il driver aggiungerebbe _id all'oggetto ricevuto.
    await this.accessLog.insertOne({ ...entry });
  }

  async listAccessLog(): Promise<AccessLogEntry[]> {
    const docs = await this.accessLog.find({}, { projection: { _id: 0 } }).sort({ createdAt: 1 }).toArray();
    return docs as AccessLogEntry[];
  }

  async addDocument(doc: StoredDocument): Promise<void> {
    const { id, ...rest } = doc;
    await this.documents.insertOne({ _id: id, ...rest });
  }

  async listDocuments(patient: string): Promise<StoredDocument[]> {
    const docs = await this.documents.find({ patient }).sort({ createdAt: 1 }).toArray();
    return docs.map(({ _id, ...rest }) => ({ id: _id, ...rest }));
  }

  async close(): Promise<void> {
    await this.client.close();
  }
}
