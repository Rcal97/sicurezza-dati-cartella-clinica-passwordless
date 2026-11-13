import { after, before, describe, it, mock } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createApp } from "../src/app.js";
import { Vault } from "../src/crypto/vault.js";
import { MemoryLedger } from "../src/models/memoryLedger.js";
import { MemoryStore } from "../src/models/memoryStore.js";
import { invite } from "./helpers.js";
import { config } from "../src/config.js";
import { SoftAuthenticator } from "./softAuthenticator.js";

const store = new MemoryStore();
let server: Server;
let baseUrl: string;

before(async () => {
  server = createApp(store, new MemoryLedger(), Vault.generate()).listen(0);
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

// Registra un utente, fa il login e restituisce il cookie di sessione ricevuto.
async function loginAndGetCookie(username: string) {
  const auth = new SoftAuthenticator();
  const invitation = await invite(store, username);
  const regOptions = await call("POST", "/webauthn/register/options", { username, invitation });
  await call("POST", "/webauthn/register/verify", { username, invitation, response: auth.register(regOptions.body, config.origin) });
  const options = await call("POST", "/webauthn/authenticate/options", { username });
  const res = await call("POST", "/webauthn/authenticate/verify", {
    username,
    response: auth.authenticate(options.body, config.origin),
  });
  return { setCookie: res.setCookie, cookie: res.setCookie.split(";")[0] };
}

describe("Sessioni", () => {
  it("il login rilascia un cookie HttpOnly e SameSite=Strict", async () => {
    const { setCookie } = await loginAndGetCookie("paola.conti");
    assert.match(setCookie, /^sid=/);
    assert.match(setCookie, /HttpOnly/);
    assert.match(setCookie, /SameSite=Strict/);
  });

  it("con il cookie /me restituisce l'utente", async () => {
    const { cookie } = await loginAndGetCookie("rino.basso");
    const res = await call("GET", "/session/me", undefined, cookie);
    assert.equal(res.status, 200);
    assert.equal(res.body.username, "rino.basso");
  });

  it("senza cookie o con un token inventato l'accesso è negato", async () => {
    assert.equal((await call("GET", "/session/me")).status, 401);
    assert.equal((await call("GET", "/session/me", undefined, "sid=token-inventato")).status, 401);
  });

  it("due login dello stesso utente producono token diversi", async () => {
    const a = await loginAndGetCookie("sara.longo");
    const b = await loginAndGetCookie("sara.longo");
    assert.notEqual(a.cookie, b.cookie);
  });

  it("dopo il logout il vecchio cookie non vale più", async () => {
    const { cookie } = await loginAndGetCookie("teo.marini");
    assert.equal((await call("POST", "/session/logout", undefined, cookie)).status, 200);
    assert.equal((await call("GET", "/session/me", undefined, cookie)).status, 401);
  });

  it("la sessione scade dopo 15 minuti di inattività", async () => {
    const { cookie } = await loginAndGetCookie("ugo.serra");
    mock.timers.enable({ apis: ["Date"], now: Date.now() });
    try {
      mock.timers.tick(config.sessionIdleMs - 60_000); // 14 minuti: ancora valida, e si rinnova
      assert.equal((await call("GET", "/session/me", undefined, cookie)).status, 200);
      mock.timers.tick(config.sessionIdleMs + 1); // oltre 15 minuti senza attività
      assert.equal((await call("GET", "/session/me", undefined, cookie)).status, 401);
    } finally {
      mock.timers.reset();
    }
  });
});
