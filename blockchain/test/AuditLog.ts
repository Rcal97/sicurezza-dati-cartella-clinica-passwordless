import { expect } from "chai";
import { network } from "hardhat";

const { ethers } = await network.create();

// Valori degli enum dei contratti
const CARE = 0;
const RESEARCH = 1;
const DENIED = 0;
const GRANTED = 1;

describe("AuditLog", function () {
  async function deploy() {
    const [owner, patient, doctor, recorder, stranger, erDoctor] = await ethers.getSigners();
    const consent = await ethers.deployContract("ConsentRegistry", [owner.address]);
    const audit = await ethers.deployContract("AuditLog", [
      owner.address,
      await consent.getAddress(),
    ]);
    await audit.connect(owner).grantRole(await audit.RECORDER_ROLE(), recorder.address);
    await audit.connect(owner).grantRole(await audit.EMERGENCY_ROLE(), erDoctor.address);
    const block = await ethers.provider.getBlock("latest");
    const now = block!.timestamp;
    const hash = ethers.id("dettagli dell'accesso");
    const reason = ethers.id("paziente incosciente in pronto soccorso");
    return {
      consent,
      audit,
      owner,
      patient,
      doctor,
      recorder,
      stranger,
      erDoctor,
      now,
      hash,
      reason,
    };
  }

  describe("accessi ordinari", function () {
    it("solo chi ha il ruolo RECORDER può registrare", async function () {
      const { audit, owner, patient, doctor, stranger, hash } = await deploy();
      await expect(
        audit.connect(stranger).recordAccess(patient.address, doctor.address, CARE, DENIED, hash),
      ).to.be.revertedWithCustomError(audit, "AccessControlUnauthorizedAccount");
      await expect(
        audit.connect(owner).recordAccess(patient.address, doctor.address, CARE, DENIED, hash),
      ).to.be.revertedWithCustomError(audit, "AccessControlUnauthorizedAccount");
    });

    it("registra un accesso negato anche senza consenso", async function () {
      const { audit, recorder, patient, doctor, hash } = await deploy();
      await expect(
        audit.connect(recorder).recordAccess(patient.address, doctor.address, CARE, DENIED, hash),
      )
        .to.emit(audit, "AccessRecorded")
        .withArgs(1n, patient.address, doctor.address, CARE, DENIED, hash);
      expect(await audit.totalEntries()).to.equal(1n);
    });

    it("registra un accesso concesso se il consenso è valido", async function () {
      const { consent, audit, recorder, patient, doctor, now, hash } = await deploy();
      await consent.connect(patient).grantConsent(doctor.address, CARE, now + 3600);
      await expect(
        audit.connect(recorder).recordAccess(patient.address, doctor.address, CARE, GRANTED, hash),
      )
        .to.emit(audit, "AccessRecorded")
        .withArgs(1n, patient.address, doctor.address, CARE, GRANTED, hash);
      expect(await audit.totalEntries()).to.equal(1n);
    });

    it("non registra come concesso un accesso senza consenso", async function () {
      const { audit, recorder, patient, doctor, hash } = await deploy();
      await expect(
        audit.connect(recorder).recordAccess(patient.address, doctor.address, CARE, GRANTED, hash),
      ).to.be.revertedWithCustomError(audit, "ConsentNotValid");
    });

    it("il consenso per un'altra finalità non basta", async function () {
      const { consent, audit, recorder, patient, doctor, now, hash } = await deploy();
      await consent.connect(patient).grantConsent(doctor.address, CARE, now + 3600);
      await expect(
        audit
          .connect(recorder)
          .recordAccess(patient.address, doctor.address, RESEARCH, GRANTED, hash),
      ).to.be.revertedWithCustomError(audit, "ConsentNotValid");
    });

    it("non registra come concesso un accesso dopo la revoca", async function () {
      const { consent, audit, recorder, patient, doctor, now, hash } = await deploy();
      await consent.connect(patient).grantConsent(doctor.address, CARE, now + 3600);
      await consent.connect(patient).revokeConsent(doctor.address, CARE);
      await expect(
        audit.connect(recorder).recordAccess(patient.address, doctor.address, CARE, GRANTED, hash),
      ).to.be.revertedWithCustomError(audit, "ConsentNotValid");
    });
  });

  describe("accessi d'emergenza", function () {
    it("solo chi ha il ruolo RECORDER può registrarli", async function () {
      const { audit, patient, erDoctor, hash, reason } = await deploy();
      await expect(
        audit.connect(erDoctor).recordEmergencyAccess(patient.address, erDoctor.address, reason, hash),
      ).to.be.revertedWithCustomError(audit, "AccessControlUnauthorizedAccount");
    });

    it("rifiuta chi non fa parte del personale d'emergenza", async function () {
      const { audit, recorder, patient, doctor, hash, reason } = await deploy();
      await expect(
        audit.connect(recorder).recordEmergencyAccess(patient.address, doctor.address, reason, hash),
      )
        .to.be.revertedWithCustomError(audit, "NotEmergencyStaff")
        .withArgs(doctor.address);
    });

    it("rifiuta un accesso d'emergenza senza motivazione", async function () {
      const { audit, recorder, patient, erDoctor, hash } = await deploy();
      await expect(
        audit
          .connect(recorder)
          .recordEmergencyAccess(patient.address, erDoctor.address, ethers.ZeroHash, hash),
      ).to.be.revertedWithCustomError(audit, "MissingReason");
    });

    it("registra l'accesso d'emergenza anche senza consenso", async function () {
      const { audit, recorder, patient, erDoctor, hash, reason } = await deploy();
      await expect(
        audit.connect(recorder).recordEmergencyAccess(patient.address, erDoctor.address, reason, hash),
      )
        .to.emit(audit, "EmergencyAccess")
        .withArgs(1n, patient.address, erDoctor.address, reason, hash);
      expect(await audit.totalEntries()).to.equal(1n);
    });
  });

  it("le voci ordinarie e d'emergenza condividono la stessa numerazione", async function () {
    const { audit, recorder, patient, doctor, erDoctor, hash, reason } = await deploy();
    await audit.connect(recorder).recordAccess(patient.address, doctor.address, CARE, DENIED, hash);
    await audit.connect(recorder).recordEmergencyAccess(patient.address, erDoctor.address, reason, hash);
    await expect(
      audit.connect(recorder).recordAccess(patient.address, doctor.address, CARE, DENIED, hash),
    )
      .to.emit(audit, "AccessRecorded")
      .withArgs(3n, patient.address, doctor.address, CARE, DENIED, hash);
    expect(await audit.totalEntries()).to.equal(3n);
  });
});
