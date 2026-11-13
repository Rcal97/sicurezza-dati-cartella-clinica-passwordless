import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createApp } from "../src/app.js";
import { config } from "../src/config.js";
import { Vault } from "../src/crypto/vault.js";
import { MemoryLedger } from "../src/models/memoryLedger.js";
import { MemoryStore } from "../src/models/memoryStore.js";
import { invite } from "./helpers.js";
import { SoftAuthenticator } from "./softAuthenticator.js";

// Prove delle correzioni emerse dall'audit di sicurezza.

const store = new MemoryStore();
let server: Server;
let baseUrl: string;

before(async () => {
  // Nei test il "client" si legge da un'intestazione, per simulare indirizzi diversi.
  // Nel server vero si usa l'indirizzo della connessione (req.ip), che il client non sceglie.
  server = createApp(store, new MemoryLedger(), Vault.generate(), {
    maxRequestsPerMinute: 5,
    clientKey: (req) => String(req.headers["x-test-client"]),
  }).listen(0);
  await new Promise((resolve) => server.once("listening", resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => {
  server.close();
});

// Ogni richiesta arriva da un client diverso, così il limite di frequenza
// non interferisce con le altre prove.
let client = 0;
async function post(path: string, body: unknown, ip = `10.0.0.${++client % 250}`) {
  const res = await fetch(baseUrl + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Test-Client": ip },
    body: JSON.stringify(body),
  });
  return { status: res.status, headers: res.headers, text: await res.text() };
}
const json = (r: { text: string }) => JSON.parse(r.text);

async function register(username: string, auth = new SoftAuthenticator()) {
  const invitation = await invite(store, username);
  const options = json(await post("/webauthn/register/options", { username, invitation }));
  await post("/webauthn/register/verify", { username, invitation, response: auth.register(options, config.origin) });
  return auth;
}

describe("Login: niente blocchi e niente enumerazione", () => {
  it("le richieste di login di un altro non invalidano la challenge dell'utente", async () => {
    const auth = await register("dr.bloccato");
    const mine = json(await post("/webauthn/authenticate/options", { username: "dr.bloccato" }));
    // L'attaccante chiede opzioni per lo stesso utente, più volte.
    for (let i = 0; i < 3; i++) await post("/webauthn/authenticate/options", { username: "dr.bloccato" });
    const res = await post("/webauthn/authenticate/verify", {
      username: "dr.bloccato",
      response: auth.authenticate(mine, config.origin),
    });
    assert.equal(res.status, 200);
  });

  it("le opzioni di login non rivelano se l'utente esiste", async () => {
    await register("dr.esistente");
    const a = json(await post("/webauthn/authenticate/options", { username: "dr.esistente" }));
    const b = json(await post("/webauthn/authenticate/options", { username: "dr.inesistente" }));
    assert.deepEqual(Object.keys(a).sort(), Object.keys(b).sort());
    assert.deepEqual(a.allowCredentials ?? [], []);
    assert.deepEqual(b.allowCredentials ?? [], []);
  });

  it("la nuova passkey deve essere individuabile dal dispositivo (resident key)", async () => {
    const invitation = await invite(store, "dr.resident");
    const options = json(await post("/webauthn/register/options", { username: "dr.resident", invitation }));
    assert.equal(options.authenticatorSelection.residentKey, "required");
  });

  it("clone usato in parallelo all'originale: passa al massimo uno dei due", async () => {
    const auth = await register("dr.clonato");
    // Copia esatta dell'autenticatore, contatore compreso (come un clone della chiave).
    const clone = Object.assign(Object.create(Object.getPrototypeOf(auth)), auth) as SoftAuthenticator;
    const o1 = json(await post("/webauthn/authenticate/options", { username: "dr.clonato" }));
    const o2 = json(await post("/webauthn/authenticate/options", { username: "dr.clonato" }));
    const results = await Promise.all([
      post("/webauthn/authenticate/verify", { username: "dr.clonato", response: auth.authenticate(o1, config.origin) }),
      post("/webauthn/authenticate/verify", { username: "dr.clonato", response: clone.authenticate(o2, config.origin) }),
    ]);
    assert.deepEqual(results.map((r) => r.status).sort(), [200, 401]);
  });

  it("una challenge di login si usa una sola volta", async () => {
    const auth = await register("dr.replay");
    const options = json(await post("/webauthn/authenticate/options", { username: "dr.replay" }));
    const response = auth.authenticate(options, config.origin);
    assert.equal((await post("/webauthn/authenticate/verify", { username: "dr.replay", response })).status, 200);
    assert.equal((await post("/webauthn/authenticate/verify", { username: "dr.replay", response })).status, 400);
  });
});

describe("Errori e intestazioni", () => {
  it("un errore interno non mostra dettagli all'utente", async () => {
    const original = store.saveLoginChallenge.bind(store);
    store.saveLoginChallenge = async () => {
      throw new Error("connessione rifiutata 127.0.0.1:27017 /home/utente/progetto");
    };
    try {
      const res = await post("/webauthn/authenticate/options", { username: "dr.errore" });
      assert.equal(res.status, 500);
      assert.match(res.headers.get("content-type") ?? "", /application\/json/);
      assert.deepEqual(json(res), { error: "errore interno" });
    } finally {
      store.saveLoginChallenge = original;
    }
  });

  it("un JSON malformato riceve un 400 senza dettagli", async () => {
    const res = await fetch(baseUrl + "/webauthn/authenticate/options", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Test-Client": "10.9.9.9" },
      body: '{"username": ',
    });
    assert.equal(res.status, 400);
    assert.deepEqual(await res.json(), { error: "richiesta non valida" });
  });

  it("le risposte non finiscono nella cache e hanno le intestazioni di sicurezza", async () => {
    const res = await fetch(baseUrl + "/health");
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.equal(res.headers.get("x-content-type-options"), "nosniff");
    assert.equal(res.headers.get("x-frame-options"), "DENY");
    assert.match(res.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
    assert.equal(res.headers.get("referrer-policy"), "no-referrer");
  });
});

describe("Limite di frequenza", () => {
  it("oltre il limite le richieste dallo stesso indirizzo ricevono 429", async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 7; i++) {
      statuses.push((await post("/webauthn/authenticate/options", { username: "dr.flood" }, "10.66.66.66")).status);
    }
    assert.deepEqual(statuses, [200, 200, 200, 200, 200, 429, 429]);
  });

  it("un altro indirizzo non viene bloccato", async () => {
    const res = await post("/webauthn/authenticate/options", { username: "dr.flood" }, "10.77.77.77");
    assert.equal(res.status, 200);
  });
});
