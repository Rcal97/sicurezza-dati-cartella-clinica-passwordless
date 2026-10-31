import { expect } from "chai";
import { network } from "hardhat";

const { ethers } = await network.create();

describe("AuditLog", function () {
  async function deploy() {
    const [owner, patient, doctor, recorder, stranger] = await ethers.getSigners();
    const consent = await ethers.deployContract("ConsentRegistry", [owner.address]);
    const audit = await ethers.deployContract("AuditLog", [
      owner.address,
      await consent.getAddress(),
    ]);
    await audit.connect(owner).grantRole(await audit.RECORDER_ROLE(), recorder.address);
    const block = await ethers.provider.getBlock("latest");
    const now = block!.timestamp;
    const hash = ethers.id("dettagli dell'accesso");
    return { consent, audit, owner, patient, doctor, recorder, stranger, now, hash };
  }

  it("solo chi ha il ruolo RECORDER può registrare", async function () {
    const { audit, owner, patient, doctor, stranger, hash } = await deploy();
    await expect(
      audit.connect(stranger).recordAccess(patient.address, doctor.address, 0, hash),
    ).to.be.revertedWithCustomError(audit, "AccessControlUnauthorizedAccount");
    await expect(
      audit.connect(owner).recordAccess(patient.address, doctor.address, 0, hash),
    ).to.be.revertedWithCustomError(audit, "AccessControlUnauthorizedAccount");
  });

  it("registra un accesso negato anche senza consenso", async function () {
    const { audit, recorder, patient, doctor, hash } = await deploy();
    await expect(audit.connect(recorder).recordAccess(patient.address, doctor.address, 0, hash))
      .to.emit(audit, "AccessRecorded")
      .withArgs(1n, patient.address, doctor.address, 0n, hash);
    expect(await audit.totalEntries()).to.equal(1n);
  });

  it("registra un accesso concesso se il consenso è valido", async function () {
    const { consent, audit, recorder, patient, doctor, now, hash } = await deploy();
    await consent.connect(patient).grantConsent(doctor.address, now + 3600);
    await expect(audit.connect(recorder).recordAccess(patient.address, doctor.address, 1, hash))
      .to.emit(audit, "AccessRecorded")
      .withArgs(1n, patient.address, doctor.address, 1n, hash);
    expect(await audit.totalEntries()).to.equal(1n);
  });

  it("non registra come concesso un accesso senza consenso", async function () {
    const { audit, recorder, patient, doctor, hash } = await deploy();
    await expect(
      audit.connect(recorder).recordAccess(patient.address, doctor.address, 1, hash),
    ).to.be.revertedWithCustomError(audit, "ConsentNotValid");
  });

  it("non registra come concesso un accesso dopo la revoca", async function () {
    const { consent, audit, recorder, patient, doctor, now, hash } = await deploy();
    await consent.connect(patient).grantConsent(doctor.address, now + 3600);
    await consent.connect(patient).revokeConsent(doctor.address);
    await expect(
      audit.connect(recorder).recordAccess(patient.address, doctor.address, 1, hash),
    ).to.be.revertedWithCustomError(audit, "ConsentNotValid");
  });

  it("gli identificatori delle voci crescono di uno", async function () {
    const { audit, recorder, patient, doctor, hash } = await deploy();
    await audit.connect(recorder).recordAccess(patient.address, doctor.address, 0, hash);
    await expect(audit.connect(recorder).recordAccess(patient.address, doctor.address, 0, hash))
      .to.emit(audit, "AccessRecorded")
      .withArgs(2n, patient.address, doctor.address, 0n, hash);
    expect(await audit.totalEntries()).to.equal(2n);
  });
});
