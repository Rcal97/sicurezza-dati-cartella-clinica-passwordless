import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { Wallet } from "ethers";
import { createApp } from "../src/app.js";
import { config } from "../src/config.js";
import { openAccessLog, openDocument, sealDocument } from "../src/crypto/records.js";
import { verifyDocumentSignature } from "../src/crypto/signature.js";
import { Vault } from "../src/crypto/vault.js";
import { Outcome, Purpose } from "../src/models/ledger.js";
import { MemoryLedger } from "../src/models/memoryLedger.js";
import { MemoryStore } from "../src/models/memoryStore.js";
import type { Role } from "../src/models/store.js";
import { invite } from "./helpers.js";
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

async function call(path: string, body: unknown, cookie?: string) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (cookie) headers.Cookie = cookie;
  const res = await fetch(baseUrl + path, { method: "POST", headers, body: JSON.stringify(body) });
  return { status: res.status, setCookie: res.headers.get("set-cookie") ?? "", body: await res.json() };
}

async function user(username: string, role: Role, auth = new SoftAuthenticator()) {
  const address = Wallet.createRandom().address;
  await store.setProfile(username, { role, address });
  const invitation = await invite(store, username);
  const reg = await call("/webauthn/register/options", { username, invitation });
  await call("/webauthn/register/verify", { username, invitation, response: auth.register(reg.body, config.origin) });
  const options = await call("/webauthn/authenticate/options", { username });
  const res = await call("/webauthn/authenticate/verify", { username, response: auth.authenticate(options.body, config.origin) });
  return { username, address, auth, cookie: res.setCookie.split(";")[0] };
}

type User = Awaited<ReturnType<typeof user>>;
const report = { title: "Visita cardiologica", body: "Ritmo sinusale, nessuna anomalia." };

// Firma completa: richiesta delle opzioni, firma con la passkey, verifica.
async function sign(doctor: User, patient: string, content = report, signer = doctor.auth) {
  const options = await call("/records/documents/options", { patient, ...content }, doctor.cookie);
  if (options.status !== 200) return options;
  return call("/records/documents/verify", { response: signer.authenticate(options.body, config.origin) }, doctor.cookie);
}

async function readRecord(doctor: User, patient: User) {
  return call("/records/access", { patient: patient.username, purpose: "care" }, doctor.cookie);
}

describe("Referti firmati dal medico con la passkey", () => {
  it("il medico che ha in cura il paziente firma un referto, che risulta firmato e valido", async () => {
    const doctor = await user("dr.firma", "doctor");
    const patient = await user("paz.firma", "patient");
    ledger.grantConsent(patient.address, doctor.address, Purpose.Care);

    const res = await sign(doctor, patient.username);
    assert.equal(res.status, 200);
    const record = await readRecord(doctor, patient);
    const doc = record.body.documents.find((d: { id: string }) => d.id === res.body.id);
    assert.equal(doc.title, report.title);
    assert.equal(doc.signature.author, "dr.firma");
    assert.equal(doc.signature.valid, true);
  });

  it("funziona anche con una passkey post-quantistica ML-DSA-44", async () => {
    const doctor = await user("dr.pq", "doctor", new SoftAuthenticator("ML-DSA-44"));
    const patient = await user("paz.pq", "patient");
    ledger.grantConsent(patient.address, doctor.address, Purpose.Care);
    assert.equal((await sign(doctor, patient.username)).status, 200);
    const docs = (await readRecord(doctor, patient)).body.documents;
    assert.equal(docs[0].signature.valid, true);
  });

  it("la scrittura è registrata nell'audit, on-chain e nel registro cifrato", async () => {
    const doctor = await user("dr.traccia", "doctor");
    const patient = await user("paz.traccia", "patient");
    ledger.grantConsent(patient.address, doctor.address, Purpose.Care);
    const res = await sign(doctor, patient.username);
    const entry = ledger.entries.at(-1)!;
    assert.equal("outcome" in entry && entry.outcome, Outcome.Granted);
    const details = openAccessLog(vault, store.accessLog.at(-1)!);
    assert.equal(details.kind, "document-signed");
    assert.equal("documentId" in details && details.documentId, res.body.id);
  });

  it("un referto caricato dal laboratorio risulta non firmato", async () => {
    const doctor = await user("dr.lettore", "doctor");
    const patient = await user("paz.laboratorio", "patient");
    await store.addDocument(sealDocument(vault, patient.username, { title: "Emocromo", body: "Nella norma" }));
    ledger.grantConsent(patient.address, doctor.address, Purpose.Care);
    const docs = (await readRecord(doctor, patient)).body.documents;
    assert.equal(docs[0].signature, null);
  });
});

describe("Referti firmati: attacchi", () => {
  it("senza consenso per la cura non si scrive nella cartella", async () => {
    const doctor = await user("dr.estraneo", "doctor");
    const patient = await user("paz.estraneo", "patient");
    ledger.grantConsent(patient.address, doctor.address, Purpose.Research); // solo ricerca
    assert.equal((await sign(doctor, patient.username)).status, 403);
  });

  it("un paziente non può scrivere referti", async () => {
    const p1 = await user("paz.autore", "patient");
    const p2 = await user("paz.altro2", "patient");
    assert.equal((await sign(p1, p2.username)).status, 403);
  });

  it("un medico non può firmare con la passkey di un altro", async () => {
    const doctor = await user("dr.vero", "doctor");
    const other = await user("dr.complice", "doctor");
    const patient = await user("paz.contesa", "patient");
    ledger.grantConsent(patient.address, doctor.address, Purpose.Care);
    // La richiesta è di dr.vero, ma la firma viene dalla passkey di dr.complice.
    assert.equal((await sign(doctor, patient.username, report, other.auth)).status, 401);
  });

  it("una richiesta di firma vale una volta sola e solo per chi l'ha aperta", async () => {
    const doctor = await user("dr.riuso", "doctor");
    const other = await user("dr.intruso", "doctor");
    const patient = await user("paz.riuso", "patient");
    ledger.grantConsent(patient.address, doctor.address, Purpose.Care);
    const options = await call("/records/documents/options", { patient: patient.username, ...report }, doctor.cookie);
    const response = doctor.auth.authenticate(options.body, config.origin);
    // Un altro medico autenticato prova a usare la firma intercettata: respinto,
    // e senza consumare la richiesta del collega.
    assert.equal((await call("/records/documents/verify", { response }, other.cookie)).status, 400);
    assert.equal((await call("/records/documents/verify", { response }, doctor.cookie)).status, 200);
    // La stessa firma non si può presentare una seconda volta.
    assert.equal((await call("/records/documents/verify", { response }, doctor.cookie)).status, 400);
  });

  it("la firma di un login non vale come firma di un referto", async () => {
    const doctor = await user("dr.login", "doctor");
    const patient = await user("paz.login", "patient");
    ledger.grantConsent(patient.address, doctor.address, Purpose.Care);
    await call("/records/documents/options", { patient: patient.username, ...report }, doctor.cookie);
    const loginOptions = await call("/webauthn/authenticate/options", { username: doctor.username });
    const response = doctor.auth.authenticate(loginOptions.body, config.origin);
    assert.equal((await call("/records/documents/verify", { response }, doctor.cookie)).status, 400);
  });

  it("un testo modificato dopo la firma non risulta più firmato", async () => {
    const doctor = await user("dr.integro", "doctor");
    const patient = await user("paz.integro", "patient");
    ledger.grantConsent(patient.address, doctor.address, Purpose.Care);
    const res = await sign(doctor, patient.username);
    const stored = store.documents.find((d) => d.id === res.body.id)!;
    const content = openDocument(vault, stored);
    assert.equal(await verifyDocumentSignature(patient.username, content.title, content.body, content.signature!), true);
    // Chi possedesse le chiavi dell'archivio potrebbe riscrivere il testo, ma non la firma.
    assert.equal(await verifyDocumentSignature(patient.username, content.title, "Nessuna anomalia.", content.signature!), false);
    assert.equal(await verifyDocumentSignature("paz.altro", content.title, content.body, content.signature!), false);
    assert.equal(
      await verifyDocumentSignature(patient.username, content.title, content.body, { ...content.signature!, author: "dr.altro" }),
      false,
    );
  });

  it("se la blockchain non risponde il referto non viene salvato", async () => {
    const doctor = await user("dr.offline2", "doctor");
    const patient = await user("paz.offline2", "patient");
    ledger.grantConsent(patient.address, doctor.address, Purpose.Care);
    const before = store.documents.length;
    const original = ledger.recordAccess.bind(ledger);
    ledger.recordAccess = async () => {
      throw new Error("connect ECONNREFUSED 127.0.0.1:8545");
    };
    try {
      assert.equal((await sign(doctor, patient.username)).status, 503);
      assert.equal(store.documents.length, before);
    } finally {
      ledger.recordAccess = original;
    }
  });

  it("titolo o testo mancanti o troppo lunghi vengono rifiutati", async () => {
    const doctor = await user("dr.lungo", "doctor");
    const patient = await user("paz.lungo", "patient");
    ledger.grantConsent(patient.address, doctor.address, Purpose.Care);
    for (const content of [
      { title: "", body: "x" },
      { title: "x", body: "" },
      { title: "x".repeat(201), body: "x" },
      { title: "x", body: "x".repeat(20_001) },
    ]) {
      const res = await call("/records/documents/options", { patient: patient.username, ...content }, doctor.cookie);
      assert.equal(res.status, 400);
    }
  });
});
