import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { Wallet } from "ethers";
import { createApp } from "../src/app.js";
import { config } from "../src/config.js";
import { fingerprint } from "../src/controllers/records.js";
import { sealDocument } from "../src/crypto/records.js";
import { Vault } from "../src/crypto/vault.js";
import { Outcome, Purpose, type AccessEntry } from "../src/models/ledger.js";
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
  server = createApp(store, ledger, vault).listen(0);
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

// Crea un utente con ruolo e indirizzo, registra la sua passkey e fa il login.
async function user(username: string, role: Role) {
  const address = Wallet.createRandom().address;
  await store.setProfile(username, { role, address });
  const auth = new SoftAuthenticator();
  const invitation = await invite(store, username);
  const reg = await call("/webauthn/register/options", { username, invitation });
  await call("/webauthn/register/verify", { username, invitation, response: auth.register(reg.body, config.origin) });
  const options = await call("/webauthn/authenticate/options", { username });
  const res = await call("/webauthn/authenticate/verify", {
    username,
    response: auth.authenticate(options.body, config.origin),
  });
  return { username, address, cookie: res.setCookie.split(";")[0] };
}

const lastEntry = () => ledger.entries.at(-1) as AccessEntry & { entryId: bigint };

describe("Accesso alla cartella: controlli preliminari", () => {
  it("senza sessione l'accesso è negato", async () => {
    const res = await call("/records/access", { patient: "chiunque", purpose: "care" });
    assert.equal(res.status, 401);
  });

  it("un paziente non può consultare le cartelle", async () => {
    const patient = await user("paz.curioso", "patient");
    const other = await user("paz.altro", "patient");
    const res = await call("/records/access", { patient: other.username, purpose: "care" }, patient.cookie);
    assert.equal(res.status, 403);
  });

  it("un paziente inesistente non viene trovato", async () => {
    const doctor = await user("dr.cerca", "doctor");
    const res = await call("/records/access", { patient: "nessuno", purpose: "care" }, doctor.cookie);
    assert.equal(res.status, 404);
  });

  it("una finalità sconosciuta viene rifiutata, anche se è un nome ereditato", async () => {
    const doctor = await user("dr.finalita", "doctor");
    const patient = await user("paz.finalita", "patient");
    for (const purpose of ["marketing", "toString", "__proto__", 0]) {
      const res = await call("/records/access", { patient: patient.username, purpose }, doctor.cookie);
      assert.equal(res.status, 400, String(purpose));
    }
  });
});

describe("Accesso alla cartella: consenso e audit", () => {
  it("senza consenso l'accesso è negato e registrato come negato", async () => {
    const doctor = await user("dr.senza", "doctor");
    const patient = await user("paz.senza", "patient");
    await store.addDocument(sealDocument(vault, patient.username, { title: "Referto riservato", body: "..." }));
    const res = await call("/records/access", { patient: patient.username, purpose: "care" }, doctor.cookie);
    assert.equal(res.status, 403);
    assert.equal(res.body.documents, undefined);
    assert.equal(lastEntry().outcome, Outcome.Denied);
    assert.equal(lastEntry().accessor, doctor.address);
  });

  it("con il consenso per la cura il medico riceve la cartella e l'accesso è registrato", async () => {
    const doctor = await user("dr.cura", "doctor");
    const patient = await user("paz.cura", "patient");
    ledger.grantConsent(patient.address, doctor.address, Purpose.Care);

    const res = await call("/records/access", { patient: patient.username, purpose: "care" }, doctor.cookie);
    assert.equal(res.status, 200);
    assert.equal(res.body.patient, patient.username);
    assert.equal(res.body.auditEntry, lastEntry().entryId.toString());
    assert.equal(lastEntry().outcome, Outcome.Granted);
  });

  it("l'impronta sulla catena corrisponde ai dettagli conservati off-chain", async () => {
    const doctor = await user("dr.impronta", "doctor");
    const patient = await user("paz.impronta", "patient");
    ledger.grantConsent(patient.address, doctor.address, Purpose.Care);
    await call("/records/access", { patient: patient.username, purpose: "care" }, doctor.cookie);

    const log = store.accessLog.at(-1)!;
    assert.equal(log.entryId, lastEntry().entryId.toString());
    assert.equal(fingerprint(log.details), lastEntry().recordHash);
    // Sulla catena ci sono solo indirizzi e impronte, nessun nome.
    assert.ok(!JSON.stringify(lastEntry(), (_k, v) => (typeof v === "bigint" ? String(v) : v)).includes(patient.username));
  });

  it("il consenso per la cura non permette l'accesso per la ricerca", async () => {
    const doctor = await user("dr.ricerca", "doctor");
    const patient = await user("paz.ricerca", "patient");
    ledger.grantConsent(patient.address, doctor.address, Purpose.Care);
    const res = await call("/records/access", { patient: patient.username, purpose: "research" }, doctor.cookie);
    assert.equal(res.status, 403);
  });

  it("dopo la revoca l'accesso è negato", async () => {
    const doctor = await user("dr.revoca", "doctor");
    const patient = await user("paz.revoca", "patient");
    ledger.grantConsent(patient.address, doctor.address, Purpose.Care);
    ledger.revokeConsent(patient.address, doctor.address, Purpose.Care);
    const res = await call("/records/access", { patient: patient.username, purpose: "care" }, doctor.cookie);
    assert.equal(res.status, 403);
  });

  it("revoca tra la lettura e la scrittura: il contratto rifiuta e l'accesso resta negato", async () => {
    const doctor = await user("dr.corsa", "doctor");
    const patient = await user("paz.corsa", "patient");
    ledger.grantConsent(patient.address, doctor.address, Purpose.Care);
    // Il paziente revoca proprio mentre il backend sta per scrivere nell'audit.
    const original = ledger.recordAccess.bind(ledger);
    ledger.recordAccess = async (e) => {
      ledger.revokeConsent(patient.address, doctor.address, Purpose.Care);
      ledger.recordAccess = original;
      return original(e);
    };

    const res = await call("/records/access", { patient: patient.username, purpose: "care" }, doctor.cookie);
    assert.equal(res.status, 403);
    assert.equal(lastEntry().outcome, Outcome.Denied);
  });

  it("se la blockchain non risponde non si consegna nulla", async () => {
    const doctor = await user("dr.offline", "doctor");
    const patient = await user("paz.offline", "patient");
    ledger.grantConsent(patient.address, doctor.address, Purpose.Care);
    const original = ledger.recordAccess.bind(ledger);
    ledger.recordAccess = async () => {
      throw new Error("connect ECONNREFUSED 127.0.0.1:8545");
    };
    try {
      const res = await call("/records/access", { patient: patient.username, purpose: "care" }, doctor.cookie);
      assert.equal(res.status, 503);
      assert.equal(res.body.documents, undefined);
    } finally {
      ledger.recordAccess = original;
    }
  });
});

describe("Referti cifrati", () => {
  it("il medico autorizzato riceve i referti decifrati", async () => {
    const doctor = await user("dr.referti", "doctor");
    const patient = await user("paz.referti", "patient");
    await store.addDocument(sealDocument(vault, patient.username, { title: "Emocromo", body: "Valori nella norma." }));
    await store.addDocument(sealDocument(vault, patient.username, { title: "RX torace", body: "Nessun reperto." }));
    ledger.grantConsent(patient.address, doctor.address, Purpose.Care);

    const res = await call("/records/access", { patient: patient.username, purpose: "care" }, doctor.cookie);
    assert.equal(res.status, 200);
    assert.deepEqual(
      res.body.documents.map((d: { title: string; body: string }) => [d.title, d.body]),
      [
        ["Emocromo", "Valori nella norma."],
        ["RX torace", "Nessun reperto."],
      ],
    );
  });

  it("nel database i referti sono solo cifrati, titolo compreso", async () => {
    const patient = await user("paz.archivio", "patient");
    await store.addDocument(sealDocument(vault, patient.username, { title: "Esame HIV", body: "Negativo." }));
    const saved = JSON.stringify(store.documents.filter((d) => d.patient === patient.username));
    assert.ok(!saved.includes("HIV"));
    assert.ok(!saved.includes("Negativo"));
  });

  it("un referto alterato nel database non viene consegnato, gli altri sì", async () => {
    const doctor = await user("dr.integrita", "doctor");
    const patient = await user("paz.integrita", "patient");
    const good = sealDocument(vault, patient.username, { title: "Glicemia", body: "95 mg/dl" });
    const bad = sealDocument(vault, patient.username, { title: "Colesterolo", body: "180 mg/dl" });
    // Chi ha accesso al database prova a sostituire il testo cifrato di un referto con quello di un altro.
    bad.sealed = { ...bad.sealed, ciphertext: good.sealed.ciphertext };
    await store.addDocument(good);
    await store.addDocument(bad);
    ledger.grantConsent(patient.address, doctor.address, Purpose.Care);

    const res = await call("/records/access", { patient: patient.username, purpose: "care" }, doctor.cookie);
    assert.equal(res.status, 200);
    assert.equal(res.body.documents[0].body, "95 mg/dl");
    assert.equal(res.body.documents[1].error, "integrità non verificata");
    assert.equal(res.body.documents[1].body, undefined);
  });

  it("un referto copiato nella cartella di un altro paziente non si decifra", async () => {
    const doctor = await user("dr.copia", "doctor");
    const victim = await user("paz.vittima", "patient");
    const other = await user("paz.destinazione", "patient");
    const doc = sealDocument(vault, victim.username, { title: "Diagnosi", body: "Riservata" });
    await store.addDocument({ ...doc, patient: other.username });
    ledger.grantConsent(other.address, doctor.address, Purpose.Care);

    const res = await call("/records/access", { patient: other.username, purpose: "care" }, doctor.cookie);
    assert.equal(res.body.documents[0].error, "integrità non verificata");
  });
});

describe("Accesso d'emergenza", () => {
  const reason = "Paziente incosciente in pronto soccorso";

  it("un medico non abilitato viene respinto", async () => {
    const doctor = await user("dr.reparto", "doctor");
    const patient = await user("paz.urgenza1", "patient");
    const res = await call("/records/emergency", { patient: patient.username, reason }, doctor.cookie);
    assert.equal(res.status, 403);
  });

  it("senza una motivazione adeguata l'accesso è rifiutato", async () => {
    const doctor = await user("dr.ps1", "doctor");
    const patient = await user("paz.urgenza2", "patient");
    ledger.emergencyStaff.add(doctor.address.toLowerCase());
    for (const r of [undefined, "", "urgente", "x".repeat(501)]) {
      const res = await call("/records/emergency", { patient: patient.username, reason: r }, doctor.cookie);
      assert.equal(res.status, 400);
    }
  });

  it("un medico abilitato accede senza consenso e l'accesso è registrato a parte", async () => {
    const doctor = await user("dr.ps2", "doctor");
    const patient = await user("paz.urgenza3", "patient");
    ledger.emergencyStaff.add(doctor.address.toLowerCase());

    const res = await call("/records/emergency", { patient: patient.username, reason }, doctor.cookie);
    assert.equal(res.status, 200);
    const entry = ledger.entries.at(-1)!;
    assert.ok("reasonHash" in entry);
    // La motivazione resta off-chain, sulla catena c'è solo la sua impronta.
    assert.equal(store.accessLog.at(-1)!.details.kind, "emergency");
    assert.ok(!JSON.stringify(entry, (_k, v) => (typeof v === "bigint" ? String(v) : v)).includes(reason));
  });
});
