import { expect } from "chai";
import { network } from "hardhat";

const { ethers } = await network.create();

// Valori dell'enum Purpose del contratto
const CARE = 0;
const RESEARCH = 1;

describe("ConsentRegistry", function () {
  async function deploy() {
    const [owner, patient, doctor, stranger] = await ethers.getSigners();
    const registry = await ethers.deployContract("ConsentRegistry", [owner.address]);
    const block = await ethers.provider.getBlock("latest");
    const now = block!.timestamp;
    return { registry, owner, patient, doctor, stranger, now };
  }

  it("non c'è consenso di default", async function () {
    const { registry, patient, doctor } = await deploy();
    expect(await registry.isConsentValid(patient.address, doctor.address, CARE)).to.equal(false);
  });

  it("il paziente concede il consenso ed emette l'evento", async function () {
    const { registry, patient, doctor, now } = await deploy();
    const expiresAt = now + 3600;

    await expect(registry.connect(patient).grantConsent(doctor.address, CARE, expiresAt))
      .to.emit(registry, "ConsentGranted")
      .withArgs(patient.address, doctor.address, CARE, expiresAt);

    expect(await registry.isConsentValid(patient.address, doctor.address, CARE)).to.equal(true);
  });

  it("il consenso per la cura non vale per la ricerca", async function () {
    const { registry, patient, doctor, now } = await deploy();
    await registry.connect(patient).grantConsent(doctor.address, CARE, now + 3600);

    expect(await registry.isConsentValid(patient.address, doctor.address, RESEARCH)).to.equal(
      false,
    );
  });

  it("la revoca per una finalità lascia valide le altre", async function () {
    const { registry, patient, doctor, now } = await deploy();
    await registry.connect(patient).grantConsent(doctor.address, CARE, now + 3600);
    await registry.connect(patient).grantConsent(doctor.address, RESEARCH, now + 3600);

    await registry.connect(patient).revokeConsent(doctor.address, RESEARCH);

    expect(await registry.isConsentValid(patient.address, doctor.address, RESEARCH)).to.equal(
      false,
    );
    expect(await registry.isConsentValid(patient.address, doctor.address, CARE)).to.equal(true);
  });

  it("rifiuta una finalità che non esiste", async function () {
    const { registry, patient, doctor, now } = await deploy();
    await expect(registry.connect(patient).grantConsent(doctor.address, 3, now + 3600)).to.revert(
      ethers,
    );
  });

  it("rifiuta una scadenza già passata", async function () {
    const { registry, patient, doctor, now } = await deploy();
    await expect(
      registry.connect(patient).grantConsent(doctor.address, CARE, now - 10),
    ).to.be.revertedWithCustomError(registry, "InvalidExpiry");
  });

  it("rifiuta una scadenza oltre la durata massima", async function () {
    const { registry, patient, doctor, now } = await deploy();
    const max = await registry.MAX_DURATION();
    await expect(
      registry.connect(patient).grantConsent(doctor.address, CARE, BigInt(now) + max + 3600n),
    ).to.be.revertedWithCustomError(registry, "InvalidExpiry");
  });

  it("rifiuta come destinatario l'indirizzo zero o se stessi", async function () {
    const { registry, patient, now } = await deploy();
    await expect(
      registry.connect(patient).grantConsent(ethers.ZeroAddress, CARE, now + 3600),
    ).to.be.revertedWithCustomError(registry, "InvalidGrantee");
    await expect(
      registry.connect(patient).grantConsent(patient.address, CARE, now + 3600),
    ).to.be.revertedWithCustomError(registry, "InvalidGrantee");
  });

  it("il consenso scade dopo la data indicata", async function () {
    const { registry, patient, doctor, now } = await deploy();
    await registry.connect(patient).grantConsent(doctor.address, CARE, now + 3600);

    await ethers.provider.send("evm_increaseTime", [7200]);
    await ethers.provider.send("evm_mine", []);

    expect(await registry.isConsentValid(patient.address, doctor.address, CARE)).to.equal(false);
  });

  it("il paziente revoca il consenso ed emette l'evento", async function () {
    const { registry, patient, doctor, now } = await deploy();
    await registry.connect(patient).grantConsent(doctor.address, CARE, now + 3600);

    await expect(registry.connect(patient).revokeConsent(doctor.address, CARE))
      .to.emit(registry, "ConsentRevoked")
      .withArgs(patient.address, doctor.address, CARE);

    expect(await registry.isConsentValid(patient.address, doctor.address, CARE)).to.equal(false);
  });

  it("un estraneo non può revocare il consenso di un paziente", async function () {
    const { registry, patient, doctor, stranger, now } = await deploy();
    await registry.connect(patient).grantConsent(doctor.address, CARE, now + 3600);

    await registry.connect(stranger).revokeConsent(doctor.address, CARE);

    expect(await registry.isConsentValid(patient.address, doctor.address, CARE)).to.equal(true);
  });

  it("in pausa non si concede, ma si può sempre revocare", async function () {
    const { registry, owner, patient, doctor, now } = await deploy();
    await registry.connect(patient).grantConsent(doctor.address, CARE, now + 3600);

    await registry.connect(owner).pause();

    await expect(
      registry.connect(patient).grantConsent(doctor.address, CARE, now + 7200),
    ).to.be.revertedWithCustomError(registry, "EnforcedPause");

    await registry.connect(patient).revokeConsent(doctor.address, CARE);
    expect(await registry.isConsentValid(patient.address, doctor.address, CARE)).to.equal(false);
  });

  it("solo il proprietario può mettere in pausa", async function () {
    const { registry, stranger } = await deploy();
    await expect(registry.connect(stranger).pause()).to.be.revertedWithCustomError(
      registry,
      "OwnableUnauthorizedAccount",
    );
  });
});
