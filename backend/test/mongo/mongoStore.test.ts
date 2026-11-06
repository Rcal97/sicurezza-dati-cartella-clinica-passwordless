import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { MongoClient } from "mongodb";
import { createApp } from "../../src/app.js";
import { config, mongoUrl } from "../../src/config.js";
import { MongoStore } from "../../src/models/mongoStore.js";
import { SoftAuthenticator } from "../softAuthenticator.js";

// Test di integrazione: richiedono MongoDB acceso (docker compose up -d) e il file .env.
// Gli utenti di prova hanno un prefisso casuale e vengono cancellati alla fine.
const run = randomBytes(4).toString("hex");
const name = (s: string) => `it.${run}.${s}`;

let store: MongoStore;
let admin: MongoClient;

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
  await admin.close();
  await store.close();
});

async function start(s: MongoStore): Promise<{ server: Server; url: string }> {
  const server = createApp(s).listen(0);
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
  const reg = await call(url, "/webauthn/register/options", { username });
  await call(url, "/webauthn/register/verify", { username, response: auth.register(reg.body, config.origin) });
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
    await store.saveLoginChallenge(name("fabio"), "challenge-di-prova", config.challengeTtlMs);
    assert.equal(await store.takeLoginChallenge(name("fabio")), "challenge-di-prova");
    assert.equal(await store.takeLoginChallenge(name("fabio")), null);
  });

  it("due richieste parallele non possono usare la stessa challenge", async () => {
    await store.saveLoginChallenge(name("gina"), "challenge-condivisa", config.challengeTtlMs);
    const results = await Promise.all([store.takeLoginChallenge(name("gina")), store.takeLoginChallenge(name("gina"))]);
    assert.equal(results.filter((r) => r !== null).length, 1);
  });

  it("una sessione scaduta viene rifiutata", async () => {
    await store.createSession(`hash-${run}`, name("ugo"), 1);
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(await store.touchSession(`hash-${run}`, config.sessionIdleMs), null);
  });

  it("challenge e sessioni hanno un indice TTL", async () => {
    for (const collection of ["challenges", "sessions"]) {
      const indexes = await admin.db().collection(collection).indexes();
      assert.ok(indexes.some((i) => i.key.expiresAt === 1 && i.expireAfterSeconds === 0), collection);
    }
  });
});
