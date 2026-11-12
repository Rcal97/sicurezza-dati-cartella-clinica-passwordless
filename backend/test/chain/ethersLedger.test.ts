import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { Contract, JsonRpcProvider, Wallet, id, ZeroHash } from "ethers";
import { ledgerConfig } from "../../src/config.js";
import { EthersLedger } from "../../src/models/ethersLedger.js";
import { LedgerRevert, Outcome, Purpose } from "../../src/models/ledger.js";

// Test di integrazione: richiedono il nodo locale acceso (npm run node), il deploy
// (npm run deploy:local) e il file .env. Ogni esecuzione usa medici con indirizzi nuovi.
const cfg = ledgerConfig();
let ledger: EthersLedger;
let provider: JsonRpcProvider;

// Funzioni usate solo dai test, per fare le parti del paziente e dell'amministratore.
const PATIENT_ABI = ["function grantConsent(address grantee, uint8 purpose, uint64 expiresAt)"];
const ADMIN_ABI = [
  "function EMERGENCY_ROLE() view returns (bytes32)",
  "function grantRole(bytes32 role, address account)",
];

// Vero se il contratto ha rifiutato la transazione con l'errore indicato.
const revertedWith = (name: string) => (err: unknown) =>
  err instanceof LedgerRevert && err.errorName === name;

const hash = id("dettagli dell'accesso");
const reason = id("paziente incosciente in pronto soccorso");

before(async () => {
  ledger = await EthersLedger.connect(cfg);
  provider = new JsonRpcProvider(cfg.rpcUrl);
});

after(() => {
  ledger.close();
  provider.destroy();
});

describe("EthersLedger (blockchain locale)", () => {
  it("rifiuta un indirizzo dove non c'è un contratto", async () => {
    const missing = Wallet.createRandom().address;
    await assert.rejects(
      EthersLedger.connect({ ...cfg, auditLog: missing }),
      /Nessun contratto/,
    );
  });

  it("senza consenso: lettura falsa, accesso registrato come negato", async () => {
    const patient = await provider.getSigner(2);
    const doctor = Wallet.createRandom().address;

    assert.equal(await ledger.isConsentValid(patient.address, doctor, Purpose.Care), false);

    const first = await ledger.recordAccess({
      patient: patient.address,
      accessor: doctor,
      purpose: Purpose.Care,
      outcome: Outcome.Denied,
      recordHash: hash,
    });
    const second = await ledger.recordAccess({
      patient: patient.address,
      accessor: doctor,
      purpose: Purpose.Care,
      outcome: Outcome.Denied,
      recordHash: hash,
    });
    assert.equal(second, first + 1n);
  });

  it("con consenso per la cura: accesso concesso solo per la cura", async () => {
    const patient = await provider.getSigner(2);
    const doctor = Wallet.createRandom().address;
    const registry = new Contract(cfg.consentRegistry, PATIENT_ABI, patient);
    const block = await provider.getBlock("latest");
    const tx = await registry.getFunction("grantConsent")(
      doctor,
      Purpose.Care,
      block!.timestamp + 3600,
    );
    await tx.wait();

    assert.equal(await ledger.isConsentValid(patient.address, doctor, Purpose.Care), true);
    assert.equal(await ledger.isConsentValid(patient.address, doctor, Purpose.Research), false);

    const entry = await ledger.recordAccess({
      patient: patient.address,
      accessor: doctor,
      purpose: Purpose.Care,
      outcome: Outcome.Granted,
      recordHash: hash,
    });
    assert.ok(entry > 0n);

    await assert.rejects(
      ledger.recordAccess({
        patient: patient.address,
        accessor: doctor,
        purpose: Purpose.Research,
        outcome: Outcome.Granted,
        recordHash: hash,
      }),
      revertedWith("ConsentNotValid"),
    );
  });

  it("accesso d'emergenza: solo personale abilitato e con motivazione", async () => {
    const patient = await provider.getSigner(2);
    const erDoctor = Wallet.createRandom().address;

    await assert.rejects(
      ledger.recordEmergencyAccess({
        patient: patient.address,
        accessor: erDoctor,
        reasonHash: reason,
        recordHash: hash,
      }),
      revertedWith("NotEmergencyStaff"),
    );

    // L'amministratore (account #0) abilita il medico al pronto soccorso.
    const audit = new Contract(cfg.auditLog, ADMIN_ABI, await provider.getSigner(0));
    const role = await audit.getFunction("EMERGENCY_ROLE")();
    await (await audit.getFunction("grantRole")(role, erDoctor)).wait();

    await assert.rejects(
      ledger.recordEmergencyAccess({
        patient: patient.address,
        accessor: erDoctor,
        reasonHash: ZeroHash,
        recordHash: hash,
      }),
      revertedWith("MissingReason"),
    );

    const entry = await ledger.recordEmergencyAccess({
      patient: patient.address,
      accessor: erDoctor,
      reasonHash: reason,
      recordHash: hash,
    });
    assert.ok(entry > 0n);
  });

  it("dopo una transazione rifiutata il backend continua a scrivere", async () => {
    const patient = Wallet.createRandom().address;
    const doctor = Wallet.createRandom().address;
    const entry = (outcome: Outcome) => ({
      patient,
      accessor: doctor,
      purpose: Purpose.Care,
      outcome,
      recordHash: hash,
    });

    await assert.rejects(ledger.recordAccess(entry(Outcome.Granted)), revertedWith("ConsentNotValid"));
    await assert.rejects(ledger.recordAccess(entry(Outcome.Granted)), revertedWith("ConsentNotValid"));
    assert.ok((await ledger.recordAccess(entry(Outcome.Denied))) > 0n);
  });

  it("più scritture contemporanee ricevono identificativi distinti", async () => {
    const patient = Wallet.createRandom().address;
    const doctor = Wallet.createRandom().address;
    const ids = await Promise.all(
      [1, 2, 3, 4, 5].map(() =>
        ledger.recordAccess({
          patient,
          accessor: doctor,
          purpose: Purpose.Care,
          outcome: Outcome.Denied,
          recordHash: hash,
        }),
      ),
    );
    assert.equal(new Set(ids).size, 5);
  });

  it("una chiave senza ruolo RECORDER non può scrivere nell'audit", async () => {
    // Account #3 di Hardhat: chiave pubblica, nessun ruolo sui contratti.
    const intruder = await EthersLedger.connect({
      ...cfg,
      privateKey: "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
    });
    try {
      await assert.rejects(
        intruder.recordAccess({
          patient: Wallet.createRandom().address,
          accessor: Wallet.createRandom().address,
          purpose: Purpose.Care,
          outcome: Outcome.Denied,
          recordHash: hash,
        }),
        revertedWith("AccessControlUnauthorizedAccount"),
      );
    } finally {
      intruder.close();
    }
  });
});
