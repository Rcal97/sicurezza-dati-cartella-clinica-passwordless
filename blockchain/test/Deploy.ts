import { expect } from "chai";
import { network } from "hardhat";
import CartellaClinica from "../ignition/modules/CartellaClinica.js";

const { ethers, ignition } = await network.create();

describe("Deploy (Ignition)", function () {
  it("collega l'audit al registro e dà al backend solo il ruolo RECORDER", async function () {
    const [admin, backend] = await ethers.getSigners();
    const { consentRegistry, auditLog } = await ignition.deploy(CartellaClinica);

    expect(await auditLog.consentRegistry()).to.equal(await consentRegistry.getAddress());
    expect(await consentRegistry.defaultAdmin()).to.equal(admin.address);
    expect(await auditLog.defaultAdmin()).to.equal(admin.address);
    expect(await consentRegistry.hasRole(await consentRegistry.PAUSER_ROLE(), admin.address)).to.equal(true);
    expect(await consentRegistry.hasRole(await consentRegistry.PAUSER_ROLE(), backend.address)).to.equal(false);

    const recorder = await auditLog.RECORDER_ROLE();
    const adminRole = await auditLog.DEFAULT_ADMIN_ROLE();
    expect(await auditLog.hasRole(recorder, backend.address)).to.equal(true);
    expect(await auditLog.hasRole(adminRole, backend.address)).to.equal(false);
    expect(await auditLog.hasRole(adminRole, admin.address)).to.equal(true);
  });
});
