import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createApp } from "../src/app.js";
import { config } from "../src/config.js";
import { staffAnchor } from "../src/crypto/consent.js";
import { Vault } from "../src/crypto/vault.js";
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
  return { username, wallet, cookie: res.setCookie.split(";")[0] };
}

describe("Registro degli accessi per il paziente", () => {
  it("senza sessione non si ottiene nulla", async () => {
    const res = await call("GET", "/records/access-log");
    assert.equal(res.status, 401);
  });

  it("un medico non può leggere il registro come se fosse il paziente", async () => {
    const doctor = await user("dr.registro", "doctor");
    const res = await call("GET", "/records/access-log", undefined, doctor.cookie);
    assert.equal(res.status, 403);
  });

  it("il paziente vede chi ha consultato la sua cartella, con esito e finalità, dal più recente", async () => {
    const doctor = await user("dr.visita", "doctor");
    const patient = await user("paz.registro", "patient");
    await call("POST", "/records/access", { patient: patient.username, purpose: "research" }, doctor.cookie);
    await signConsent(store, ledger, vault, patient, doctor.username, "care");
    await call("POST", "/records/access", { patient: patient.username, purpose: "care" }, doctor.cookie);

    const res = await call("GET", "/records/access-log", undefined, patient.cookie);
    assert.equal(res.status, 200);
    assert.equal(res.body.length, 2);
    const [ultimo, primo] = res.body;
    assert.deepEqual(
      { requester: ultimo.requester, kind: ultimo.kind, outcome: ultimo.outcome, purpose: ultimo.purpose },
      { requester: "dr.visita", kind: "ordinary", outcome: "granted", purpose: "care" },
    );
    assert.equal(primo.outcome, "denied");
    assert.equal(primo.purpose, "research");
    // Ogni voce indica dove verificarla sulla catena.
    assert.match(ultimo.recordHash, /^0x[0-9a-f]{64}$/);
    assert.equal(ultimo.entryId, ledger.entries.at(-1)!.entryId.toString());
    assert.equal(ultimo.recordHash, ledger.entries.at(-1)!.recordHash);
  });

  it("un paziente non vede gli accessi alla cartella di un altro", async () => {
    const doctor = await user("dr.altro", "doctor");
    const a = await user("paz.uno", "patient");
    const b = await user("paz.due", "patient");
    await call("POST", "/records/access", { patient: a.username, purpose: "care" }, doctor.cookie);
    const res = await call("GET", "/records/access-log", undefined, b.cookie);
    assert.equal(res.status, 200);
    assert.deepEqual(res.body, []);
  });

  it("vede anche gli accessi d'emergenza, con la motivazione", async () => {
    const doctor = await user("dr.urgenza", "doctor");
    const patient = await user("paz.urgenza", "patient");
    ledger.emergencyStaff.add(staffAnchor(vault, doctor.username));
    const reason = "paziente incosciente in pronto soccorso";
    await call("POST", "/records/emergency", { patient: patient.username, reason }, doctor.cookie);
    const res = await call("GET", "/records/access-log", undefined, patient.cookie);
    assert.equal(res.body[0].kind, "emergency");
    assert.equal(res.body[0].reason, reason);
  });

  it("una voce spostata nella cartella di un altro paziente non ne rivela il contenuto", async () => {
    const doctor = await user("dr.spostato", "doctor");
    const vittima = await user("paz.vittima", "patient");
    const curioso = await user("paz.ficcanaso", "patient");
    await call("POST", "/records/access", { patient: vittima.username, purpose: "care" }, doctor.cookie);
    // Chi controlla il database e ha visto l'etichetta di un altro paziente sposta lì la voce.
    const voce = (await store.listAccessLogOf(vault.indexTag(vittima.username)))[0];
    voce.patientTag = vault.indexTag(curioso.username);
    const res = await call("GET", "/records/access-log", undefined, curioso.cookie);
    assert.equal(res.body.length, 1);
    assert.equal(res.body[0].altered, true);
    assert.equal(res.body[0].requester, undefined);
  });

  it("una voce alterata viene segnalata, le altre restano leggibili", async () => {
    const doctor = await user("dr.alterato", "doctor");
    const patient = await user("paz.alterato", "patient");
    await call("POST", "/records/access", { patient: patient.username, purpose: "care" }, doctor.cookie);
    await call("POST", "/records/access", { patient: patient.username, purpose: "research" }, doctor.cookie);
    const [prima] = await store.listAccessLogOf(vault.indexTag(patient.username));
    const ct = Buffer.from(prima.sealed.ciphertext, "base64");
    ct[0] ^= 1;
    prima.sealed.ciphertext = ct.toString("base64");
    const res = await call("GET", "/records/access-log", undefined, patient.cookie);
    assert.equal(res.body.length, 2);
    assert.equal(res.body[1].altered, true);
    assert.equal(res.body[0].purpose, "research");
  });
});
