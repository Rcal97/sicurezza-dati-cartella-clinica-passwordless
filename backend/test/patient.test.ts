import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createApp } from "../src/app.js";
import { config } from "../src/config.js";
import { sealDocument } from "../src/crypto/records.js";
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

async function call(method: string, path: string, body?: unknown, cookie?: string) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (cookie) headers.Cookie = cookie;
  const res = await fetch(baseUrl + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  return { status: res.status, headers: res.headers, body: await res.json(), setCookie: res.headers.get("set-cookie") ?? "" };
}

async function user(username: string, role: Role) {
  const wallet = await makeProfile(store, username, role);
  const auth = new SoftAuthenticator();
  const invitation = await invite(store, username);
  const reg = await call("POST", "/webauthn/register/options", { username, invitation });
  await call("POST", "/webauthn/register/verify", { username, invitation, response: auth.register(reg.body, config.origin) });
  const o = await call("POST", "/webauthn/authenticate/options", { username });
  const r = await call("POST", "/webauthn/authenticate/verify", { username, response: auth.authenticate(o.body, config.origin) });
  return { username, wallet, cookie: r.setCookie.split(";")[0] };
}

describe("Diritti del paziente sulla propria cartella", () => {
  it("senza sessione non si ottiene nulla; un medico non usa queste funzioni", async () => {
    assert.equal((await call("GET", "/records/mine")).status, 401);
    const doctor = await user("dr.propria", "doctor");
    assert.equal((await call("GET", "/records/mine", undefined, doctor.cookie)).status, 403);
    assert.equal((await call("GET", "/records/mine/export", undefined, doctor.cookie)).status, 403);
  });

  it("il paziente legge i propri referti e solo quelli (art. 15)", async () => {
    const patient = await user("paz.lettore", "patient");
    const other = await user("paz.estraneo2", "patient");
    await store.addDocument(sealDocument(vault, patient.username, { title: "Emocromo", body: "Nella norma." }));
    await store.addDocument(sealDocument(vault, other.username, { title: "Altrui", body: "Riservato." }));
    const res = await call("GET", "/records/mine", undefined, patient.cookie);
    assert.equal(res.status, 200);
    assert.deepEqual(res.body.map((d: { title: string }) => d.title), ["Emocromo"]);
  });

  it("l'esportazione contiene referti, ricevute firmate dei consensi e registro degli accessi (art. 20)", async () => {
    const doctor = await user("dr.export", "doctor");
    const patient = await user("paz.export", "patient");
    await store.addDocument(sealDocument(vault, patient.username, { title: "RX", body: "Nessun reperto." }));
    await signConsent(store, ledger, vault, patient, doctor.username, "care");
    await call("POST", "/records/access", { patient: patient.username, purpose: "care" }, doctor.cookie);

    const res = await call("GET", "/records/mine/export", undefined, patient.cookie);
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-disposition") ?? "", /attachment; filename="cartella-paz\.export\.json"/);
    assert.equal(res.body.patient, patient.username);
    assert.equal(res.body.documents[0].title, "RX");
    assert.equal(res.body.consents.length, 1);
    assert.equal(res.body.consents[0].signer, patient.wallet!.address);
    assert.equal(res.body.consents[0].message.doctor, doctor.username);
    assert.equal(res.body.accessLog[0].requester, doctor.username);
  });
});
