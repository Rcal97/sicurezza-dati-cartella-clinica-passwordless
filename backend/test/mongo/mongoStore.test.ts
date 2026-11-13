import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { MongoClient } from "mongodb";
import { Wallet } from "ethers";
import { createApp } from "../../src/app.js";
import { openAccessLog, openDocument, sealAccessLog, sealDocument } from "../../src/crypto/records.js";
import { Vault } from "../../src/crypto/vault.js";
import { config, mongoUrl } from "../../src/config.js";
import { MemoryLedger } from "../../src/models/memoryLedger.js";
import { MongoStore } from "../../src/models/mongoStore.js";
import { invite } from "../helpers.js";
import { SoftAuthenticator } from "../softAuthenticator.js";

// Test di integrazione: richiedono MongoDB acceso (docker compose up -d) e il file .env.
// Gli utenti di prova hanno un prefisso casuale e vengono cancellati alla fine.
const run = randomBytes(4).toString("hex");
const name = (s: string) => `it.${run}.${s}`;

let store: MongoStore;
let admin: MongoClient;
const createdLogs: string[] = [];

before(async () => {
  store = await MongoStore.connect(mongoUrl());
  admin = await new MongoClient(mongoUrl()).connect();
});

after(async () => {
  const db = admin.db();
  const prefix = { $regex: `^it\\.${run}\\.` };
  await db.collection("users").deleteMany({ _id: prefix } as never);
  await db.collection("sessions").deleteMany({ username: prefix });
  await db.collection("challenges").deleteMany({ _id: { $regex: `:it\\.${run}\\.` } } as never);
  await db.collection("invitations").deleteMany({ username: prefix });
  await db.collection("profiles").deleteMany({ _id: prefix } as never);
  await db.collection("access_log").deleteMany({ recordHash: { $in: createdLogs } });
  await db.collection("documents").deleteMany({ patient: prefix });
  await admin.close();
  await store.close();
});

async function start(s: MongoStore): Promise<{ server: Server; url: string }> {
  const server = createApp(s, new MemoryLedger(), Vault.generate()).listen(0);
  await new Promise((resolve) => server.once("listening", resolve));
  return { server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

async function call(url: string, path: string, body?: unknown, cookie?: string) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (cookie) headers.Cookie = cookie;
  const res = await fetch(url + path, { method: body ? "POST" : "GET", headers, body: body ? JSON.stringify(body) : undefined });
  return { status: res.status, setCookie: res.headers.get("set-cookie") ?? "", body: await res.json() };
}

async function registerAndLogin(url: string, username: string, auth: SoftAuthenticator) {
  const invitation = await invite(store, username);
  const reg = await call(url, "/webauthn/register/options", { username, invitation });
  await call(url, "/webauthn/register/verify", { username, invitation, response: auth.register(reg.body, config.origin) });
  const opt = await call(url, "/webauthn/authenticate/options", { username });
  const res = await call(url, "/webauthn/authenticate/verify", { username, response: auth.authenticate(opt.body, config.origin) });
  return { status: res.status, token: res.setCookie.split(";")[0].replace("sid=", "") };
}

describe("MongoStore (MongoDB reale)", () => {
  it("passkey e sessione sopravvivono al riavvio del server", async () => {
    const auth = new SoftAuthenticator();
    const first = await start(store);
    const { status, token } = await registerAndLogin(first.url, name("anna"), auth);
    assert.equal(status, 200);
    first.server.close();

    // Nuova connessione al database, come dopo un riavvio del backend.
    const restarted = await MongoStore.connect(mongoUrl());
    const second = await start(restarted);
    try {
      assert.equal((await call(second.url, "/session/me", undefined, `sid=${token}`)).status, 200);
      const opt = await call(second.url, "/webauthn/authenticate/options", { username: name("anna") });
      const login = await call(second.url, "/webauthn/authenticate/verify", {
        username: name("anna"),
        response: auth.authenticate(opt.body, config.origin),
      });
      assert.equal(login.status, 200);
    } finally {
      second.server.close();
      await restarted.close();
    }
  });

  it("il signCount salvato blocca un clone anche dopo il riavvio", async () => {
    const auth = new SoftAuthenticator();
    const { url, server } = await start(store);
    try {
      await registerAndLogin(url, name("bruno"), auth);
      auth.counter = 0; // il clone riparte da uno stato vecchio
      const opt = await call(url, "/webauthn/authenticate/options", { username: name("bruno") });
      const res = await call(url, "/webauthn/authenticate/verify", {
        username: name("bruno"),
        response: auth.authenticate(opt.body, config.origin),
      });
      assert.equal(res.status, 401);
    } finally {
      server.close();
    }
  });

  it("nel database c'è solo l'hash del token di sessione", async () => {
    const { url, server } = await start(store);
    try {
      const { token } = await registerAndLogin(url, name("carla"), new SoftAuthenticator());
      const sessions = admin.db().collection("sessions");
      assert.equal(await sessions.countDocuments({ _id: token } as never), 0);
      const hash = createHash("sha256").update(token).digest("hex");
      assert.equal(await sessions.countDocuments({ _id: hash } as never), 1);
    } finally {
      server.close();
    }
  });

  it("la stessa credenziale non può appartenere a due utenti", async () => {
    const credential = { id: `cred-${run}`, publicKey: new Uint8Array([1, 2, 3]), counter: 0 };
    assert.equal(await store.addCredential(name("dario"), "uid-1", credential), "ok");
    assert.equal(await store.addCredential(name("elena"), "uid-2", credential), "duplicate");
  });

  it("una challenge si usa una sola volta", async () => {
    await store.saveLoginChallenge(name("challenge-di-prova"), config.challengeTtlMs);
    assert.equal(await store.takeLoginChallenge(name("challenge-di-prova")), true);
    assert.equal(await store.takeLoginChallenge(name("challenge-di-prova")), false);
  });

  it("due richieste parallele non possono usare la stessa challenge", async () => {
    await store.saveLoginChallenge(name("challenge-condivisa"), config.challengeTtlMs);
    const c = name("challenge-condivisa");
    const results = await Promise.all([store.takeLoginChallenge(c), store.takeLoginChallenge(c)]);
    assert.equal(results.filter((r) => r).length, 1);
  });

  it("il contatore si aggiorna solo se nessuno lo ha cambiato nel frattempo", async () => {
    const credential = { id: `cred-cas-${run}`, publicKey: new Uint8Array([1, 2, 3]), counter: 5 };
    await store.addCredential(name("cas"), "uid-cas", credential);
    // Due login paralleli che hanno letto entrambi il valore 5: ne passa uno solo.
    const results = await Promise.all([
      store.updateCounter(name("cas"), credential.id, 5, 6),
      store.updateCounter(name("cas"), credential.id, 5, 6),
    ]);
    assert.deepEqual(results.sort(), [false, true]);
    assert.equal((await store.getUser(name("cas")))?.credentials[0]?.counter, 6);
  });

  it("un invito non può essere usato da due registrazioni parallele", async () => {
    const hash = createHash("sha256").update(await invite(store, name("ivo"))).digest("hex");
    const results = await Promise.all([store.takeInvitation(hash, name("ivo")), store.takeInvitation(hash, name("ivo"))]);
    assert.equal(results.filter(Boolean).length, 1);
  });

  it("una sessione scaduta viene rifiutata", async () => {
    await store.createSession(`hash-${run}`, name("ugo"), 1, config.sessionMaxMs);
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(await store.touchSession(`hash-${run}`, config.sessionIdleMs), null);
  });

  it("challenge, sessioni e inviti hanno un indice TTL", async () => {
    for (const collection of ["challenges", "sessions", "invitations"]) {
      const indexes = await admin.db().collection(collection).indexes();
      assert.ok(indexes.some((i) => i.key.expiresAt === 1 && i.expireAfterSeconds === 0), collection);
    }
  });

  it("un indirizzo blockchain appartiene a un solo utente", async () => {
    const address = Wallet.createRandom().address;
    assert.equal(await store.setProfile(name("medico"), { role: "doctor", address }), "ok");
    // Stesso indirizzo scritto in minuscolo: per Ethereum è lo stesso account.
    const copy = { role: "patient" as const, address: address.toLowerCase() };
    assert.equal(await store.setProfile(name("altro"), copy), "duplicate");
    assert.equal((await store.getProfile(name("medico")))?.role, "doctor");
    assert.equal(await store.getProfile(name("altro")), null);
  });

  it("i dettagli di un accesso vengono conservati off-chain, cifrati", async () => {
    const vault = Vault.generate();
    const entry = sealAccessLog(vault, 1n, {
      kind: "emergency",
      requester: name("medico"),
      patient: name("paziente"),
      reason: "Paziente incosciente, sospetto ictus",
      at: new Date().toISOString(),
      nonce: "00",
    });
    createdLogs.push(entry.recordHash);
    await store.addAccessLog(entry);

    const raw = await admin.db().collection("access_log").findOne({ recordHash: entry.recordHash });
    assert.ok(!JSON.stringify(raw).includes("ictus"));
    assert.ok(!JSON.stringify(raw).includes(name("paziente")));
    const saved = (await store.listAccessLog()).find((e) => e.recordHash === entry.recordHash)!;
    assert.equal(openAccessLog(vault, saved).kind, "emergency");
  });

  it("una sessione non dura oltre la durata massima, anche se usata", async () => {
    await store.createSession(`max-${run}`, name("max"), config.sessionIdleMs, 300);
    assert.equal(await store.touchSession(`max-${run}`, config.sessionIdleMs), name("max"));
    // Il rinnovo non porta la scadenza oltre il limite massimo.
    const doc = await admin.db().collection("sessions").findOne({ _id: `max-${run}` } as never);
    assert.ok(doc!.expiresAt.getTime() <= doc!.absoluteExpiresAt.getTime());
    await new Promise((resolve) => setTimeout(resolve, 350));
    assert.equal(await store.touchSession(`max-${run}`, config.sessionIdleMs), null);
  });

  it("si possono chiudere tutte le sessioni di un utente", async () => {
    for (const i of [1, 2, 3]) await store.createSession(`all-${i}-${run}`, name("tutte"), 60_000, 60_000);
    await store.deleteSessionsOf(name("tutte"));
    for (const i of [1, 2, 3]) assert.equal(await store.touchSession(`all-${i}-${run}`, 60_000), null);
  });

  it("revoca delle passkey: mai l'ultima, nemmeno con due revoche contemporanee", async () => {
    const cred = (id: string) => ({ id: `${id}-${run}`, publicKey: new Uint8Array([1]), counter: 0 });
    await store.addCredential(name("revoca"), "uid-rev", cred("a"));
    await store.addCredential(name("revoca"), "uid-rev", cred("b"));
    assert.equal(await store.removeCredential(name("revoca"), `x-${run}`), "missing");
    const results = await Promise.all([
      store.removeCredential(name("revoca"), `a-${run}`),
      store.removeCredential(name("revoca"), `b-${run}`),
    ]);
    assert.deepEqual(results.sort(), ["last", "ok"]);
    assert.equal((await store.getUser(name("revoca")))?.credentials.length, 1);
  });

  it("i referti si salvano cifrati e si rileggono nell'ordine di creazione", async () => {
    const vault = Vault.generate();
    const first = sealDocument(vault, name("paziente"), { title: "Emocromo", body: "Nella norma" });
    const second = sealDocument(vault, name("paziente"), { title: "RX torace", body: "Negativa" });
    await store.addDocument(first);
    await store.addDocument(second);

    const docs = await store.listDocuments(name("paziente"));
    assert.deepEqual(docs.map((d) => openDocument(vault, d).title), ["Emocromo", "RX torace"]);
    const raw = await admin.db().collection("documents").findOne({ _id: first.id } as never);
    assert.ok(!JSON.stringify(raw).includes("Emocromo"));
  });
});
