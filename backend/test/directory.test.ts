import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { Wallet } from "ethers";
import { createApp } from "../src/app.js";
import { config } from "../src/config.js";
import { Vault } from "../src/crypto/vault.js";
import { MemoryLedger } from "../src/models/memoryLedger.js";
import { MemoryStore } from "../src/models/memoryStore.js";
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

  it("il profilo restituisce ruolo e indirizzo dell'utente, in forma EIP-55", async () => {
    const address = Wallet.createRandom().address;
    await store.setProfile("paz.profilo", { role: "patient", address: address.toLowerCase() });
    const cookie = await login("paz.profilo");
    const res = await call("GET", "/directory/profile", undefined, cookie);
    assert.deepEqual(res.body, { username: "paz.profilo", role: "patient", address });
  });

  it("un utente senza profilo riceve ruolo e indirizzo nulli", async () => {
    const cookie = await login("senza.profilo");
    const res = await call("GET", "/directory/profile", undefined, cookie);
    assert.deepEqual(res.body, { username: "senza.profilo", role: null, address: null });
  });

  it("l'elenco dei medici contiene solo medici", async () => {
    const d1 = Wallet.createRandom().address;
    await store.setProfile("dr.elenco", { role: "doctor", address: d1 });
    await store.setProfile("paz.elenco", { role: "patient", address: Wallet.createRandom().address });
    const cookie = await login("paz.elenco");
    const res = await call("GET", "/directory/doctors", undefined, cookie);
    assert.ok(res.body.some((d: { username: string; address: string }) => d.username === "dr.elenco" && d.address === d1));
    assert.ok(!res.body.some((d: { username: string }) => d.username.startsWith("paz.")));
  });

  it("i dati della rete indicano dove firmare i consensi", async () => {
    const cookie = await login("paz.rete");
    const res = await call("GET", "/directory/chain", undefined, cookie);
    assert.deepEqual(res.body, ledger.chain);
  });
});
