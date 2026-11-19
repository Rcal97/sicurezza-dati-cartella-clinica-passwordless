import { expect } from "chai";
import { network } from "hardhat";

const { ethers } = await network.create();

// Valori dell'enum Outcome del contratto
const DENIED = 0;
const GRANTED = 1;

// Ancore opache (nel sistema: HMAC calcolati dal backend con la chiave della struttura).
const CARE = ethers.id("ancora: paziente, medico, cura");
const RESEARCH = ethers.id("ancora: paziente, medico, ricerca");
const ER_DOCTOR = ethers.id("ancora: medico del pronto soccorso");
const DOCTOR = ethers.id("ancora: medico non abilitato");
const RECEIPT = ethers.id("ricevuta del consenso");

describe("AuditLog", function () {
  async function deploy() {
    const [owner, registrar, recorder, stranger] = await ethers.getSigners();
    const consent = await ethers.deployContract("ConsentRegistry", [owner.address]);
    const audit = await ethers.deployContract("AuditLog", [owner.address, await consent.getAddress()]);
    await consent.connect(owner).grantRole(await consent.REGISTRAR_ROLE(), registrar.address);
    await audit.connect(owner).grantRole(await audit.RECORDER_ROLE(), recorder.address);
    await audit.connect(owner).setEmergencyStaff(ER_DOCTOR, true);
    const block = await ethers.provider.getBlock("latest");
    const now = block!.timestamp;
    const hash = ethers.id("dettagli dell'accesso");
    const reason = ethers.id("paziente incosciente in pronto soccorso");
    return {
      consent: consent.connect(registrar),
      audit,
      owner,
      recorder,
      stranger,
      now,
      hash,
      reason,
      a: audit.connect(recorder),
    };
  }

  describe("accessi ordinari", function () {
    it("solo chi ha il ruolo RECORDER può registrare", async function () {
      const { audit, owner, stranger, hash } = await deploy();
      for (const who of [stranger, owner]) {
        await expect(audit.connect(who).recordAccess(CARE, DENIED, hash)).to.be.revertedWithCustomError(
          audit,
          "AccessControlUnauthorizedAccount",
        );
      }
    });

    it("registra un accesso negato anche senza consenso", async function () {
      const { audit, a, hash } = await deploy();
      await expect(a.recordAccess(CARE, DENIED, hash))
        .to.emit(audit, "AccessRecorded")
        .withArgs(1n, CARE, DENIED, hash);
      expect(await audit.totalEntries()).to.equal(1n);
    });

    it("registra un accesso concesso se il consenso è valido", async function () {
      const { consent, audit, a, now, hash } = await deploy();
      await consent.grantConsent(CARE, now + 3600, RECEIPT);
      await expect(a.recordAccess(CARE, GRANTED, hash))
        .to.emit(audit, "AccessRecorded")
        .withArgs(1n, CARE, GRANTED, hash);
    });

    it("non registra come concesso un accesso senza consenso", async function () {
      const { audit, a, hash } = await deploy();
      await expect(a.recordAccess(CARE, GRANTED, hash)).to.be.revertedWithCustomError(audit, "ConsentNotValid");
    });

    it("il consenso per un'altra finalità non basta", async function () {
      const { consent, audit, a, now, hash } = await deploy();
      await consent.grantConsent(CARE, now + 3600, RECEIPT);
      await expect(a.recordAccess(RESEARCH, GRANTED, hash)).to.be.revertedWithCustomError(audit, "ConsentNotValid");
    });

    it("non registra come concesso un accesso dopo la revoca", async function () {
      const { consent, audit, a, now, hash } = await deploy();
      await consent.grantConsent(CARE, now + 3600, RECEIPT);
      await consent.revokeConsent(CARE, RECEIPT);
      await expect(a.recordAccess(CARE, GRANTED, hash)).to.be.revertedWithCustomError(audit, "ConsentNotValid");
    });
  });

  describe("accessi d'emergenza", function () {
    it("solo chi ha il ruolo RECORDER può registrarli", async function () {
      const { audit, stranger, hash, reason } = await deploy();
      await expect(
        audit.connect(stranger).recordEmergencyAccess(ER_DOCTOR, reason, hash),
      ).to.be.revertedWithCustomError(audit, "AccessControlUnauthorizedAccount");
    });

    it("rifiuta chi non fa parte del personale d'emergenza", async function () {
      const { audit, a, hash, reason } = await deploy();
      await expect(a.recordEmergencyAccess(DOCTOR, reason, hash))
        .to.be.revertedWithCustomError(audit, "NotEmergencyStaff")
        .withArgs(DOCTOR);
    });

    it("rifiuta un accesso d'emergenza senza motivazione", async function () {
      const { audit, a, hash } = await deploy();
      await expect(a.recordEmergencyAccess(ER_DOCTOR, ethers.ZeroHash, hash)).to.be.revertedWithCustomError(
        audit,
        "MissingReason",
      );
    });

    it("registra l'accesso d'emergenza anche senza consenso", async function () {
      const { audit, a, hash, reason } = await deploy();
      await expect(a.recordEmergencyAccess(ER_DOCTOR, reason, hash))
        .to.emit(audit, "EmergencyAccess")
        .withArgs(1n, ER_DOCTOR, reason, hash);
      expect(await audit.totalEntries()).to.equal(1n);
    });

    it("solo l'amministratore abilita o disabilita il personale d'emergenza", async function () {
      const { audit, owner, recorder, stranger, a, hash, reason } = await deploy();
      for (const who of [stranger, recorder]) {
        await expect(audit.connect(who).setEmergencyStaff(DOCTOR, true)).to.be.revertedWithCustomError(
          audit,
          "AccessControlUnauthorizedAccount",
        );
      }
      await expect(audit.connect(owner).setEmergencyStaff(ER_DOCTOR, false))
        .to.emit(audit, "EmergencyStaffChanged")
        .withArgs(ER_DOCTOR, false);
      expect(await audit.isEmergencyStaff(ER_DOCTOR)).to.equal(false);
      await expect(a.recordEmergencyAccess(ER_DOCTOR, reason, hash)).to.be.revertedWithCustomError(
        audit,
        "NotEmergencyStaff",
      );
    });

    it("rifiuta un'ancora vuota per il personale d'emergenza", async function () {
      const { audit, owner } = await deploy();
      await expect(audit.connect(owner).setEmergencyStaff(ethers.ZeroHash, true)).to.be.revertedWithCustomError(
        audit,
        "InvalidStaffId",
      );
    });
  });

  it("le voci ordinarie e d'emergenza condividono la stessa numerazione", async function () {
    const { audit, a, hash, reason } = await deploy();
    await a.recordAccess(CARE, DENIED, hash);
    await a.recordEmergencyAccess(ER_DOCTOR, reason, hash);
    await expect(a.recordAccess(CARE, DENIED, hash)).to.emit(audit, "AccessRecorded").withArgs(3n, CARE, DENIED, hash);
    expect(await audit.totalEntries()).to.equal(3n);
  });

  it("gli eventi non contengono indirizzi", async function () {
    const { audit } = await deploy();
    for (const name of ["AccessRecorded", "EmergencyAccess", "EmergencyStaffChanged"]) {
      const types = audit.interface.getEvent(name)!.inputs.map((i) => i.type);
      expect(types).to.not.include("address");
    }
  });
});
