import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createHash } from "node:crypto";
import { Wallet } from "ethers";
import { createApp } from "../src/app.js";
import { config } from "../src/config.js";
import { Vault } from "../src/crypto/vault.js";
import { MemoryLedger } from "../src/models/memoryLedger.js";
import { MemoryStore } from "../src/models/memoryStore.js";
import { NOTICE_VERSION } from "../src/privacy.js";
import { invite } from "./helpers.js";
import { SoftAuthenticator } from "./softAuthenticator.js";

const store = new MemoryStore();
const ledger = new MemoryLedger();
let server: Server;
let baseUrl: string;

before(async () => {
  server = createApp(store, ledger, Vault.generate(), { maxRequestsPerMinute: 10_000 }).listen(0);
  await new Promise((resolve) => server.once("listening", resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => {
  server.close();
});

async function call(method: string, path: string, body?: unknown, cookie?: string) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (cookie) headers.Cookie = cookie;
  const res = await fetch(baseUrl + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  return { status: res.status, setCookie: res.headers.get("set-cookie") ?? "", body: await res.json() };
}

async function login(username: string) {
  const auth = new SoftAuthenticator();
  const invitation = await invite(store, username);
  const reg = await call("POST", "/webauthn/register/options", { username, invitation });
  await call("POST", "/webauthn/register/verify", { username, invitation, response: auth.register(reg.body, config.origin) });
  const o = await call("POST", "/webauthn/authenticate/options", { username });
  const r = await call("POST", "/webauthn/authenticate/verify", { username, response: auth.authenticate(o.body, config.origin) });
  return r.setCookie.split(";")[0];
}

describe("Informazioni per il frontend", () => {
  it("senza sessione non si ottiene nulla", async () => {
    for (const path of ["/directory/profile", "/directory/doctors", "/directory/chain"]) {
      assert.equal((await call("GET", path)).status, 401);
    }
  });

  it("il profilo restituisce ruolo e wallet dell'utente, in forma EIP-55, ma non il segreto delle ancore", async () => {
    const address = Wallet.createRandom().address;
    const secret = "ab".repeat(32);
    await store.setProfile("paz.profilo", { role: "patient", address: address.toLowerCase(), secret });
    const cookie = await login("paz.profilo");
    const res = await call("GET", "/directory/profile", undefined, cookie);
    assert.deepEqual(res.body, { username: "paz.profilo", role: "patient", address });
  });

  it("l'informativa si legge senza sessione, con versione e impronta del testo", async () => {
    const res = await call("GET", "/privacy");
    assert.equal(res.status, 200);
    assert.equal(res.body.version, NOTICE_VERSION);
    assert.equal(res.body.hash, "0x" + createHash("sha256").update(res.body.text).digest("hex"));
    assert.match(res.body.text, /cookie tecnico/);
  });

  it("un utente senza profilo riceve ruolo e indirizzo nulli", async () => {
    const cookie = await login("senza.profilo");
    const res = await call("GET", "/directory/profile", undefined, cookie);
    assert.deepEqual(res.body, { username: "senza.profilo", role: null, address: null });
  });

  it("l'elenco dei medici contiene solo medici", async () => {
    await store.setProfile("dr.elenco", { role: "doctor" });
    await store.setProfile("paz.elenco", { role: "patient", address: Wallet.createRandom().address, secret: "cd".repeat(32) });
    const cookie = await login("paz.elenco");
    const res = await call("GET", "/directory/doctors", undefined, cookie);
    assert.ok(res.body.includes("dr.elenco"));
    assert.ok(!res.body.some((d: string) => d.startsWith("paz.")));
  });

  it("i dati della rete indicano dove firmare i consensi", async () => {
    const cookie = await login("paz.rete");
    const res = await call("GET", "/directory/chain", undefined, cookie);
    assert.deepEqual(res.body, ledger.chain);
  });
});
