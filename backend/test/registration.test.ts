import { after, before, describe, it, mock } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createApp } from "../src/app.js";
import { Vault } from "../src/crypto/vault.js";
import { config } from "../src/config.js";
import { MemoryLedger } from "../src/models/memoryLedger.js";
import { MemoryStore } from "../src/models/memoryStore.js";
import { invite } from "./helpers.js";
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

async function call(path: string, body: unknown, cookie?: string) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (cookie) headers.Cookie = cookie;
  const res = await fetch(baseUrl + path, { method: "POST", headers, body: JSON.stringify(body) });
  return { status: res.status, setCookie: res.headers.get("set-cookie") ?? "", body: await res.json() };
}

// Registrazione completa; "invitation" e "cookie" indicano con quale autorizzazione si prova.
async function register(username: string, auth: SoftAuthenticator, opts: { invitation?: string; cookie?: string } = {}) {
  const options = await call("/webauthn/register/options", { username, invitation: opts.invitation }, opts.cookie);
  if (options.status !== 200) return options;
  return call(
    "/webauthn/register/verify",
    { username, invitation: opts.invitation, response: auth.register(options.body, config.origin) },
    opts.cookie,
  );
}

async function login(username: string, auth: SoftAuthenticator) {
  const options = await call("/webauthn/authenticate/options", { username });
  const res = await call("/webauthn/authenticate/verify", { username, response: auth.authenticate(options.body, config.origin) });
  return { status: res.status, cookie: res.setCookie.split(";")[0] };
}

describe("Registrazione: chi può registrare una passkey", () => {
  it("senza invito non ci si può registrare", async () => {
    assert.equal((await register("nuovo.utente", new SoftAuthenticator())).status, 403);
  });

  it("con un invito valido la prima registrazione riesce", async () => {
    const res = await register("anna.invitata", new SoftAuthenticator(), { invitation: await invite(store, "anna.invitata") });
    assert.equal(res.status, 200);
  });

  it("account takeover: un estraneo non può aggiungere la sua passkey a un utente esistente", async () => {
    await register("vittima.takeover", new SoftAuthenticator(), { invitation: await invite(store, "vittima.takeover") });
    const attaccante = new SoftAuthenticator();
    assert.equal((await register("vittima.takeover", attaccante)).status, 403);
    assert.equal((await login("vittima.takeover", attaccante)).status, 401);
  });

  it("un invito si usa una sola volta", async () => {
    const invitation = await invite(store, "bruno.monouso");
    assert.equal((await register("bruno.monouso", new SoftAuthenticator(), { invitation })).status, 200);
    assert.equal((await register("bruno.monouso", new SoftAuthenticator(), { invitation })).status, 403);
  });

  it("un invito vale solo per l'utente a cui è stato rilasciato", async () => {
    const invitation = await invite(store, "carla.destinataria");
    assert.equal((await register("dario.altro", new SoftAuthenticator(), { invitation })).status, 403);
  });

  it("un invito scaduto viene rifiutato", async () => {
    const invitation = await invite(store, "elena.scaduta");
    mock.timers.enable({ apis: ["Date"], now: Date.now() });
    try {
      mock.timers.tick(config.invitationTtlMs + 1);
      assert.equal((await register("elena.scaduta", new SoftAuthenticator(), { invitation })).status, 403);
    } finally {
      mock.timers.reset();
    }
  });

  it("se la registrazione fallisce l'invito resta valido", async () => {
    const invitation = await invite(store, "fabio.riprova");
    const options = await call("/webauthn/register/options", { username: "fabio.riprova", invitation });
    const auth = new SoftAuthenticator();
    const fallita = await call("/webauthn/register/verify", {
      username: "fabio.riprova",
      invitation,
      response: auth.register(options.body, "https://cartella-clinica.evil.example"),
    });
    assert.equal(fallita.status, 400);
    assert.equal((await register("fabio.riprova", auth, { invitation })).status, 200);
  });

  it("un utente autenticato può aggiungere una seconda passkey", async () => {
    const telefono = new SoftAuthenticator();
    await register("gina.due", telefono, { invitation: await invite(store, "gina.due") });
    const { cookie } = await login("gina.due", telefono);

    const chiavetta = new SoftAuthenticator();
    assert.equal((await register("gina.due", chiavetta, { cookie })).status, 200);
    assert.equal((await login("gina.due", chiavetta)).status, 200);
  });

  it("un utente autenticato non può aggiungere passkey a un altro utente", async () => {
    const auth = new SoftAuthenticator();
    await register("ugo.autenticato", auth, { invitation: await invite(store, "ugo.autenticato") });
    await register("vera.altra", new SoftAuthenticator(), { invitation: await invite(store, "vera.altra") });
    const { cookie } = await login("ugo.autenticato", auth);
    assert.equal((await register("vera.altra", new SoftAuthenticator(), { cookie })).status, 403);
  });
});
