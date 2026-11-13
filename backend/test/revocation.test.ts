import { after, before, describe, it, mock } from "node:test";
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

const store = new MemoryStore();
let server: Server;
let baseUrl: string;

before(async () => {
  server = createApp(store, new MemoryLedger(), Vault.generate(), { maxRequestsPerMinute: 10_000 }).listen(0);
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

async function register(username: string, auth: SoftAuthenticator, cookie?: string) {
  const invitation = cookie ? undefined : await invite(store, username);
  const options = await call("POST", "/webauthn/register/options", { username, invitation }, cookie);
  return call("POST", "/webauthn/register/verify", { username, invitation, response: auth.register(options.body, config.origin) }, cookie);
}

async function login(username: string, auth: SoftAuthenticator) {
  const options = await call("POST", "/webauthn/authenticate/options", { username });
  const res = await call("POST", "/webauthn/authenticate/verify", { username, response: auth.authenticate(options.body, config.origin) });
  return { status: res.status, cookie: res.setCookie.split(";")[0] };
}

const me = async (cookie: string) => (await call("GET", "/session/me", undefined, cookie)).status;

describe("Sessioni: durata massima e uscita da tutti i dispositivi", () => {
  it("una sessione usata di continuo scade comunque dopo 8 ore", async () => {
    const auth = new SoftAuthenticator();
    await register("ida.turno", auth);
    const { cookie } = await login("ida.turno", auth);
    mock.timers.enable({ apis: ["Date"], now: Date.now() });
    try {
      // Una richiesta ogni 10 minuti per quasi 8 ore: la sessione resta valida.
      for (let t = 0; t < config.sessionMaxMs - 10 * 60_000; t += 10 * 60_000) {
        mock.timers.tick(10 * 60_000);
        assert.equal(await me(cookie), 200);
      }
      mock.timers.tick(10 * 60_000 + 1);
      assert.equal(await me(cookie), 401);
    } finally {
      mock.timers.reset();
    }
  });

  it("\"esci da tutti i dispositivi\" chiude ogni sessione dell'utente", async () => {
    const auth = new SoftAuthenticator();
    await register("leo.dispositivi", auth);
    const pc = await login("leo.dispositivi", auth);
    const phone = await login("leo.dispositivi", auth);
    assert.equal((await call("POST", "/session/logout-all", {}, pc.cookie)).status, 200);
    assert.equal(await me(pc.cookie), 401);
    assert.equal(await me(phone.cookie), 401);
  });

  it("senza sessione non si chiudono le sessioni altrui", async () => {
    assert.equal((await call("POST", "/session/logout-all", {})).status, 401);
  });
});

describe("Revoca delle passkey", () => {
  it("l'utente vede solo le proprie passkey", async () => {
    const a = new SoftAuthenticator();
    const b = new SoftAuthenticator();
    await register("max.uno", a);
    await register("max.due", b);
    const { cookie } = await login("max.uno", a);
    const list = (await call("GET", "/session/passkeys", undefined, cookie)).body;
    assert.deepEqual(list.map((p: { id: string }) => p.id), [a.credentialId.toString("base64url")]);
  });

  it("una passkey revocata non entra più e le sessioni vengono chiuse", async () => {
    const pc = new SoftAuthenticator();
    const lost = new SoftAuthenticator();
    await register("nora.persa", pc);
    const first = await login("nora.persa", pc);
    await register("nora.persa", lost, first.cookie); // secondo dispositivo
    const thief = await login("nora.persa", lost); // sessione aperta dal dispositivo perso
    const current = await login("nora.persa", pc);

    const res = await call("POST", "/session/passkeys/revoke", { id: lost.credentialId.toString("base64url") }, current.cookie);
    assert.equal(res.status, 200);
    assert.equal(await me(thief.cookie), 401);
    assert.equal(await me(current.cookie), 401);
    assert.equal((await login("nora.persa", lost)).status, 401);
    assert.equal((await login("nora.persa", pc)).status, 200);
  });

  it("l'ultima passkey non si può revocare", async () => {
    const auth = new SoftAuthenticator();
    await register("olga.unica", auth);
    const { cookie } = await login("olga.unica", auth);
    const res = await call("POST", "/session/passkeys/revoke", { id: auth.credentialId.toString("base64url") }, cookie);
    assert.equal(res.status, 409);
    assert.equal(await me(cookie), 200);
  });

  it("non si può revocare la passkey di un altro utente", async () => {
    const mine = new SoftAuthenticator();
    const other = new SoftAuthenticator();
    const extra = new SoftAuthenticator();
    await register("pia.attaccante", mine);
    await register("rita.vittima", other);
    const victim = await login("rita.vittima", other);
    await register("rita.vittima", extra, victim.cookie);
    const { cookie } = await login("pia.attaccante", mine);
    const res = await call("POST", "/session/passkeys/revoke", { id: other.credentialId.toString("base64url") }, cookie);
    assert.equal(res.status, 404);
    assert.equal((await login("rita.vittima", other)).status, 200);
  });

  it("dopo la revoca d'ufficio di tutte le passkey serve un nuovo invito", async () => {
    const auth = new SoftAuthenticator();
    await register("ugo.perso", auth);
    const session = await login("ugo.perso", auth);
    await store.removeAllCredentials("ugo.perso"); // quello che fa npm run revoca
    await store.deleteSessionsOf("ugo.perso");
    assert.equal(await me(session.cookie), 401);
    assert.equal((await login("ugo.perso", auth)).status, 401);
    const fresh = new SoftAuthenticator();
    assert.equal((await register("ugo.perso", fresh)).status, 200);
    assert.equal((await login("ugo.perso", fresh)).status, 200);
  });
});
