import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { Wallet } from "ethers";
import { createApp } from "../src/app.js";
import { config } from "../src/config.js";
import { consentAnchor, openConsentReceipt } from "../src/crypto/consent.js";
import { Vault } from "../src/crypto/vault.js";
import { MemoryLedger } from "../src/models/memoryLedger.js";
import { MemoryStore } from "../src/models/memoryStore.js";
import type { Role } from "../src/models/store.js";
import { NOTICE_HASH, NOTICE_VERSION } from "../src/privacy.js";
import { invite, makeProfile } from "./helpers.js";
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
  return { status: res.status, body: await res.json(), setCookie: res.headers.get("set-cookie") ?? "" };
}

async function user(username: string, role: Role) {
  const wallet = await makeProfile(store, username, role);
  const auth = new SoftAuthenticator();
  const invitation = await invite(store, username);
  const reg = await call("POST", "/webauthn/register/options", { username, invitation });
  await call("POST", "/webauthn/register/verify", { username, invitation, response: auth.register(reg.body, config.origin) });
  const o = await call("POST", "/webauthn/authenticate/options", { username });
  const r = await call("POST", "/webauthn/authenticate/verify", { username, response: auth.authenticate(o.body, config.origin) });
  return { username, wallet: wallet!, cookie: r.setCookie.split(";")[0] };
}

// Il paziente chiede il messaggio da firmare, lo firma con il wallet (come fa MetaMask) e lo invia.
async function consent(
  patient: { cookie: string; wallet: Wallet },
  request: { action: "grant" | "revoke"; doctor: string; purpose: string; days?: number },
  signer: Wallet = patient.wallet,
) {
  const options = await call("POST", "/consents/options", request, patient.cookie);
  assert.equal(options.status, 200, JSON.stringify(options.body));
  const { domain, types, message } = options.body;
  const signature = await signer.signTypedData(domain, types, message);
  return { options: options.body, res: await call("POST", "/consents/verify", { nonce: message.nonce, signature }, patient.cookie) };
}

const json = (v: unknown) => JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? String(x) : x));

describe("Consensi: richieste non ammesse", () => {
  it("senza sessione non si ottiene nulla", async () => {
    assert.equal((await call("GET", "/consents")).status, 401);
    assert.equal((await call("POST", "/consents/options", { action: "grant" })).status, 401);
  });

  it("un medico non può gestire consensi", async () => {
    const doctor = await user("dr.noconsenso", "doctor");
    const res = await call("POST", "/consents/options", { action: "grant", doctor: doctor.username, purpose: "care", days: 1 }, doctor.cookie);
    assert.equal(res.status, 403);
  });

  it("operazione, medico, finalità e durata devono essere validi", async () => {
    await user("dr.valido", "doctor");
    const other = await user("paz.nonmedico", "patient");
    const patient = await user("paz.validazione", "patient");
    const ok = { action: "grant", doctor: "dr.valido", purpose: "care", days: 30 };
    const cases = [
      { ...ok, action: "delete" },
      { ...ok, doctor: "nessuno" },
      { ...ok, doctor: other.username }, // un paziente non è un medico
      { ...ok, purpose: "marketing" },
      { ...ok, purpose: "toString" },
      { ...ok, purpose: "__proto__" },
      { ...ok, days: 0 },
      { ...ok, days: 366 },
      { ...ok, days: 1.5 },
      { ...ok, days: "30" },
    ];
    for (const c of cases) {
      const res = await call("POST", "/consents/options", c, patient.cookie);
      assert.equal(res.status, 400, JSON.stringify(c));
    }
  });
});

describe("Consensi: concessione firmata dal paziente", () => {
  it("il messaggio da firmare indica medico, finalità, scadenza e informativa", async () => {
    await user("dr.messaggio", "doctor");
    const patient = await user("paz.messaggio", "patient");
    const res = await call("POST", "/consents/options", { action: "grant", doctor: "dr.messaggio", purpose: "research", days: 30 }, patient.cookie);
    const m = res.body.message;
    assert.equal(m.patient, patient.username);
    assert.equal(m.doctor, "dr.messaggio");
    assert.equal(m.purpose, "research");
    assert.equal(m.expiresAt - m.issuedAt, 30 * 86_400);
    assert.equal(m.noticeVersion, NOTICE_VERSION);
    assert.equal(m.noticeHash, NOTICE_HASH);
    assert.equal(res.body.domain.chainId, ledger.chain.chainId);
    assert.equal(res.body.domain.verifyingContract, ledger.chain.consentRegistry);
  });

  it("dopo la firma il consenso vale e il medico accede alla cartella", async () => {
    const doctor = await user("dr.firmato", "doctor");
    const patient = await user("paz.firmato", "patient");
    const { res } = await consent(patient, { action: "grant", doctor: doctor.username, purpose: "care", days: 30 });
    assert.equal(res.status, 200, JSON.stringify(res.body));

    const list = await call("GET", "/consents", undefined, patient.cookie);
    assert.equal(list.body.length, 1);
    assert.equal(list.body[0].doctor, doctor.username);
    assert.equal(list.body[0].valid, true);

    const access = await call("POST", "/records/access", { patient: patient.username, purpose: "care" }, doctor.cookie);
    assert.equal(access.status, 200);
  });

  it("sulla catena finiscono solo l'ancora, la scadenza e l'impronta della ricevuta", async () => {
    const doctor = await user("dr.catena", "doctor");
    const patient = await user("paz.catena", "patient");
    const { res } = await consent(patient, { action: "grant", doctor: doctor.username, purpose: "care", days: 1 });
    const event = ledger.consentEvents.at(-1)!;
    assert.equal(event.receiptHash, res.body.receiptHash);
    const onChain = json(ledger.consentEvents) + json(ledger.entries);
    for (const secretValue of [patient.username, doctor.username, patient.wallet.address, patient.wallet.address.toLowerCase(), "care"]) {
      assert.ok(!onChain.includes(secretValue), secretValue);
    }
  });

  it("la ricevuta è conservata cifrata e contiene la firma del paziente", async () => {
    const doctor = await user("dr.ricevuta", "doctor");
    const patient = await user("paz.ricevuta", "patient");
    await consent(patient, { action: "grant", doctor: doctor.username, purpose: "care", days: 1 });
    const stored = store.consents.at(-1)!;
    assert.ok(!JSON.stringify(stored).includes(patient.username));
    assert.ok(!JSON.stringify(stored).includes(doctor.username));
    const receipt = openConsentReceipt(vault, stored);
    assert.equal(receipt.signer, patient.wallet.address);
    assert.equal(receipt.message.noticeHash, NOTICE_HASH);
    assert.equal(stored.receiptHash, ledger.consentEvents.at(-1)!.receiptHash);
  });

  it("la stessa coppia medico-finalità ha ancore diverse per pazienti diversi", async () => {
    const doctor = await user("dr.ancore", "doctor");
    const a = await user("paz.ancora1", "patient");
    const b = await user("paz.ancora2", "patient");
    const anchor = async (p: string, purpose: string) =>
      consentAnchor(vault, (await store.getProfile(p))!.secret!, doctor.username, purpose);
    assert.notEqual(await anchor(a.username, "care"), await anchor(b.username, "care"));
    assert.notEqual(await anchor(a.username, "care"), await anchor(a.username, "research"));
  });
});

describe("Consensi: firme non valide e riuso", () => {
  it("una firma di un altro wallet viene rifiutata", async () => {
    const doctor = await user("dr.wallet", "doctor");
    const patient = await user("paz.wallet", "patient");
    const before = ledger.consentEvents.length;
    const { res } = await consent(patient, { action: "grant", doctor: doctor.username, purpose: "care", days: 1 }, new Wallet(Wallet.createRandom().privateKey));
    assert.equal(res.status, 401);
    assert.equal(ledger.consentEvents.length, before);
  });

  it("un messaggio modificato dopo la richiesta non corrisponde alla firma", async () => {
    const doctor = await user("dr.modifica", "doctor");
    const patient = await user("paz.modifica", "patient");
    const options = await call("POST", "/consents/options", { action: "grant", doctor: doctor.username, purpose: "care", days: 1 }, patient.cookie);
    const { domain, types, message } = options.body;
    // Il paziente firma una durata più lunga di quella richiesta al server.
    const signature = await patient.wallet.signTypedData(domain, types, { ...message, expiresAt: message.expiresAt + 86_400 * 300 });
    const res = await call("POST", "/consents/verify", { nonce: message.nonce, signature }, patient.cookie);
    assert.equal(res.status, 401);
  });

  it("una richiesta di firma vale una volta sola", async () => {
    const doctor = await user("dr.replay", "doctor");
    const patient = await user("paz.replay", "patient");
    const options = await call("POST", "/consents/options", { action: "grant", doctor: doctor.username, purpose: "care", days: 1 }, patient.cookie);
    const { domain, types, message } = options.body;
    const signature = await patient.wallet.signTypedData(domain, types, message);
    assert.equal((await call("POST", "/consents/verify", { nonce: message.nonce, signature }, patient.cookie)).status, 200);
    assert.equal((await call("POST", "/consents/verify", { nonce: message.nonce, signature }, patient.cookie)).status, 400);
  });

  it("un paziente non può usare la richiesta aperta da un altro", async () => {
    const doctor = await user("dr.altrui", "doctor");
    const victim = await user("paz.titolare", "patient");
    const attacker = await user("paz.intruso", "patient");
    const options = await call("POST", "/consents/options", { action: "grant", doctor: doctor.username, purpose: "care", days: 1 }, victim.cookie);
    const { domain, types, message } = options.body;
    const signature = await attacker.wallet.signTypedData(domain, types, message);
    assert.equal((await call("POST", "/consents/verify", { nonce: message.nonce, signature }, attacker.cookie)).status, 400);
  });

  it("richieste malformate vengono rifiutate", async () => {
    const patient = await user("paz.malformata", "patient");
    for (const body of [{}, { nonce: "abc", signature: "0x00" }, { nonce: "0x" + "00".repeat(32), signature: 42 }]) {
      assert.equal((await call("POST", "/consents/verify", body, patient.cookie)).status, 400);
    }
  });
});

describe("Consensi: revoca e coerenza tra catena e ricevute", () => {
  it("dopo la revoca firmata l'accesso è negato", async () => {
    const doctor = await user("dr.revocato", "doctor");
    const patient = await user("paz.revoca", "patient");
    await consent(patient, { action: "grant", doctor: doctor.username, purpose: "care", days: 30 });
    const { res } = await consent(patient, { action: "revoke", doctor: doctor.username, purpose: "care" });
    assert.equal(res.status, 200);
    assert.equal(ledger.consentEvents.at(-1)!.kind, "revoked");

    const access = await call("POST", "/records/access", { patient: patient.username, purpose: "care" }, doctor.cookie);
    assert.equal(access.status, 403);
    const list = await call("GET", "/consents", undefined, patient.cookie);
    assert.equal(list.body[0].action, "revoke");
    assert.equal(list.body[0].valid, false);
  });

  it("un'ancora valida sulla catena senza ricevuta firmata non basta (fail-closed)", async () => {
    const doctor = await user("dr.senzaricevuta", "doctor");
    const patient = await user("paz.senzaricevuta", "patient");
    // Chi controlla la chiave del backend scrive un consenso sulla catena senza la firma del paziente.
    const consentId = consentAnchor(vault, (await store.getProfile(patient.username))!.secret!, doctor.username, "care");
    await ledger.grantConsent(consentId, Math.floor(Date.now() / 1000) + 3600, "0x" + "ab".repeat(32));
    const access = await call("POST", "/records/access", { patient: patient.username, purpose: "care" }, doctor.cookie);
    assert.equal(access.status, 403);
  });

  it("una ricevuta di concessione senza l'ancora sulla catena non basta", async () => {
    const doctor = await user("dr.senzancora", "doctor");
    const patient = await user("paz.senzancora", "patient");
    await consent(patient, { action: "grant", doctor: doctor.username, purpose: "care", days: 30 });
    // La revoca è sulla catena ma la sua ricevuta non è stata salvata (scrittura interrotta).
    const consentId = consentAnchor(vault, (await store.getProfile(patient.username))!.secret!, doctor.username, "care");
    await ledger.revokeConsent(consentId, "0x" + "cd".repeat(32));
    const access = await call("POST", "/records/access", { patient: patient.username, purpose: "care" }, doctor.cookie);
    assert.equal(access.status, 403);
  });

  it("se la catena non risponde il consenso non si registra", async () => {
    const doctor = await user("dr.offline3", "doctor");
    const patient = await user("paz.offline3", "patient");
    const before = store.consents.length;
    const original = ledger.grantConsent.bind(ledger);
    ledger.grantConsent = async () => {
      throw new Error("connect ECONNREFUSED 127.0.0.1:8545");
    };
    try {
      const { res } = await consent(patient, { action: "grant", doctor: doctor.username, purpose: "care", days: 1 });
      assert.equal(res.status, 503);
      assert.equal(store.consents.length, before);
    } finally {
      ledger.grantConsent = original;
    }
  });
});
