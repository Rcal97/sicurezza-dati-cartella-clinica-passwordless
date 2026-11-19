import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createApp } from "../src/app.js";
import { config } from "../src/config.js";
import { sealDocument } from "../src/crypto/records.js";
import { Vault } from "../src/crypto/vault.js";
import { hashToken } from "../src/middleware/session.js";
import { MemoryLedger } from "../src/models/memoryLedger.js";
import { MemoryStore } from "../src/models/memoryStore.js";
import type { Role } from "../src/models/store.js";
import { invite, makeProfile, signConsent } from "./helpers.js";
import { SoftAuthenticator } from "./softAuthenticator.js";

const store = new MemoryStore();
const ledger = new MemoryLedger();
const vault = Vault.generate();
let server: Server;
let baseUrl: string;

before(async () => {
  server = createApp(store, ledger, vault, { maxRequestsPerMinute: 10_000 }).listen(0);
  await new Promise((resolve) => server.once("listening", resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => {
  server.close();
});

async function call(method: "GET" | "POST", path: string, body?: unknown, cookie?: string) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (cookie) headers.Cookie = cookie;
  const res = await fetch(baseUrl + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: res.status, setCookie: res.headers.get("set-cookie") ?? "", body: await res.json() };
}

async function user(username: string, role: Role) {
  const wallet = await makeProfile(store, username, role);
  const auth = new SoftAuthenticator();
  const invitation = await invite(store, username);
  const reg = await call("POST", "/webauthn/register/options", { username, invitation });
  await call("POST", "/webauthn/register/verify", { username, invitation, response: auth.register(reg.body, config.origin) });
  const options = await call("POST", "/webauthn/authenticate/options", { username });
  const res = await call("POST", "/webauthn/authenticate/verify", {
    username,
    response: auth.authenticate(options.body, config.origin),
  });
  return { username, wallet, auth, cookie: res.setCookie.split(";")[0] };
}

describe("Cancellazione su richiesta (art. 17 GDPR)", () => {
  it("dopo la cancellazione la sessione è chiusa e la passkey non entra più", async () => {
    const p = await user("paz.oblio", "patient");
    await store.eraseUser(p.username, { documents: false });
    assert.equal((await call("GET", "/session/me", undefined, p.cookie)).status, 401);
    const options = await call("POST", "/webauthn/authenticate/options", { username: p.username });
    const res = await call("POST", "/webauthn/authenticate/verify", {
      username: p.username,
      response: p.auth.authenticate(options.body, config.origin),
    });
    assert.notEqual(res.status, 200);
    assert.equal(await store.getUser(p.username), null);
  });

  it("il legame con l'indirizzo sulla catena sparisce: nessun medico può più aprire la cartella", async () => {
    const doctor = await user("dr.oblio", "doctor");
    const p = await user("paz.legame", "patient");
    await signConsent(store, ledger, vault, p, doctor.username, "care");
    assert.equal((await call("POST", "/records/access", { patient: p.username, purpose: "care" }, doctor.cookie)).status, 200);
    await store.eraseUser(p.username, { documents: false });
    assert.equal(await store.getProfile(p.username), null);
    const res = await call("POST", "/records/access", { patient: p.username, purpose: "care" }, doctor.cookie);
    assert.equal(res.status, 404);
  });

  it("i referti sono conservati, salvo richiesta esplicita", async () => {
    await store.addDocument(sealDocument(vault, "paz.conserva", { title: "Esame", body: "Valori nella norma" }));
    await store.addDocument(sealDocument(vault, "paz.cancella", { title: "Esame", body: "Valori nella norma" }));
    const kept = await store.eraseUser("paz.conserva", { documents: false });
    assert.deepEqual([kept.documents, kept.documentsKept], [0, 1]);
    const removed = await store.eraseUser("paz.cancella", { documents: true });
    assert.deepEqual([removed.documents, removed.documentsKept], [1, 0]);
    assert.equal((await store.listDocuments("paz.cancella")).length, 0);
  });

  it("il registro cifrato degli accessi resta, per l'accountability", async () => {
    const doctor = await user("dr.registro.oblio", "doctor");
    const p = await user("paz.registro.oblio", "patient");
    await call("POST", "/records/access", { patient: p.username, purpose: "care" }, doctor.cookie);
    const prima = store.accessLog.length;
    await store.eraseUser(p.username, { documents: true });
    assert.equal(store.accessLog.length, prima);
  });

  it("lo username di un utente cancellato non può essere riassegnato", async () => {
    await user("paz.riuso", "patient");
    await store.eraseUser("paz.riuso", { documents: false });
    assert.equal(await store.createInvitation(hashToken("codice"), "paz.riuso", config.invitationTtlMs), "erased");
    const reg = await call("POST", "/webauthn/register/options", { username: "paz.riuso", invitation: "codice" });
    assert.notEqual(reg.status, 200);
  });

  it("un medico cancellato non compare più tra quelli a cui dare il consenso", async () => {
    const doctor = await user("dr.uscente", "doctor");
    const p = await user("paz.elenco", "patient");
    await store.eraseUser(doctor.username, { documents: false });
    const res = await call("GET", "/directory/doctors", undefined, p.cookie);
    assert.ok(!res.body.some((d: { username: string }) => d.username === doctor.username));
  });
});
