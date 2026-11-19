import { expect } from "chai";
import { network } from "hardhat";

const { ethers } = await network.create();

// Le ancore sono valori opachi di 32 byte (nel sistema: HMAC calcolati dal backend).
const CARE = ethers.id("ancora: paziente, medico, cura");
const RESEARCH = ethers.id("ancora: paziente, medico, ricerca");
const RECEIPT = ethers.id("ricevuta firmata dal paziente");

describe("ConsentRegistry", function () {
  async function deploy() {
    const [owner, registrar, stranger] = await ethers.getSigners();
    const registry = await ethers.deployContract("ConsentRegistry", [owner.address]);
    await registry.connect(owner).grantRole(await registry.PAUSER_ROLE(), owner.address);
    await registry.connect(owner).grantRole(await registry.REGISTRAR_ROLE(), registrar.address);
    const block = await ethers.provider.getBlock("latest");
    const now = block!.timestamp;
    return { registry, owner, registrar, stranger, now, r: registry.connect(registrar) };
  }

  it("non c'è consenso di default", async function () {
    const { registry } = await deploy();
    expect(await registry.isConsentValid(CARE)).to.equal(false);
  });

  it("registra il consenso ed emette l'evento con la sola ancora e l'impronta della ricevuta", async function () {
    const { registry, r, now } = await deploy();
    const expiresAt = now + 3600;

    await expect(r.grantConsent(CARE, expiresAt, RECEIPT))
      .to.emit(registry, "ConsentGranted")
      .withArgs(CARE, expiresAt, RECEIPT);

    expect(await registry.isConsentValid(CARE)).to.equal(true);
  });

  it("il consenso per un'ancora non vale per un'altra (es. ricerca invece di cura)", async function () {
    const { registry, r, now } = await deploy();
    await r.grantConsent(CARE, now + 3600, RECEIPT);
    expect(await registry.isConsentValid(RESEARCH)).to.equal(false);
  });

  it("la revoca di un consenso lascia validi gli altri", async function () {
    const { registry, r, now } = await deploy();
    await r.grantConsent(CARE, now + 3600, RECEIPT);
    await r.grantConsent(RESEARCH, now + 3600, RECEIPT);

    await r.revokeConsent(RESEARCH, RECEIPT);

    expect(await registry.isConsentValid(RESEARCH)).to.equal(false);
    expect(await registry.isConsentValid(CARE)).to.equal(true);
  });

  it("solo chi ha il ruolo REGISTRAR può concedere o revocare", async function () {
    const { registry, owner, stranger, r, now } = await deploy();
    for (const who of [stranger, owner]) {
      await expect(
        registry.connect(who).grantConsent(CARE, now + 3600, RECEIPT),
      ).to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount");
    }
    await r.grantConsent(CARE, now + 3600, RECEIPT);
    await expect(registry.connect(stranger).revokeConsent(CARE, RECEIPT)).to.be.revertedWithCustomError(
      registry,
      "AccessControlUnauthorizedAccount",
    );
    expect(await registry.isConsentValid(CARE)).to.equal(true);
  });

  it("rifiuta un'ancora vuota", async function () {
    const { registry, r, now } = await deploy();
    await expect(r.grantConsent(ethers.ZeroHash, now + 3600, RECEIPT)).to.be.revertedWithCustomError(
      registry,
      "InvalidConsentId",
    );
  });

  it("rifiuta concessioni e revoche senza l'impronta della ricevuta", async function () {
    const { registry, r, now } = await deploy();
    await expect(r.grantConsent(CARE, now + 3600, ethers.ZeroHash)).to.be.revertedWithCustomError(
      registry,
      "MissingReceipt",
    );
    await expect(r.revokeConsent(CARE, ethers.ZeroHash)).to.be.revertedWithCustomError(registry, "MissingReceipt");
  });

  it("rifiuta una scadenza già passata", async function () {
    const { registry, r, now } = await deploy();
    await expect(r.grantConsent(CARE, now - 10, RECEIPT)).to.be.revertedWithCustomError(registry, "InvalidExpiry");
  });

  it("rifiuta una scadenza oltre la durata massima", async function () {
    const { registry, r, now } = await deploy();
    const max = await registry.MAX_DURATION();
    await expect(r.grantConsent(CARE, BigInt(now) + max + 3600n, RECEIPT)).to.be.revertedWithCustomError(
      registry,
      "InvalidExpiry",
    );
  });

  it("il consenso scade dopo la data indicata", async function () {
    const { registry, r, now } = await deploy();
    await r.grantConsent(CARE, now + 3600, RECEIPT);

    await ethers.provider.send("evm_increaseTime", [7200]);
    await ethers.provider.send("evm_mine", []);

    expect(await registry.isConsentValid(CARE)).to.equal(false);
  });

  it("la revoca emette l'evento e annulla il consenso", async function () {
    const { registry, r, now } = await deploy();
    const revocation = ethers.id("ricevuta della revoca");
    await r.grantConsent(CARE, now + 3600, RECEIPT);

    await expect(r.revokeConsent(CARE, revocation)).to.emit(registry, "ConsentRevoked").withArgs(CARE, revocation);

    expect(await registry.isConsentValid(CARE)).to.equal(false);
  });

  it("in pausa non si concede, ma si può sempre revocare", async function () {
    const { registry, owner, r, now } = await deploy();
    await r.grantConsent(CARE, now + 3600, RECEIPT);

    await registry.connect(owner).pause();

    await expect(r.grantConsent(CARE, now + 7200, RECEIPT)).to.be.revertedWithCustomError(registry, "EnforcedPause");

    await r.revokeConsent(CARE, RECEIPT);
    expect(await registry.isConsentValid(CARE)).to.equal(false);
  });

  it("solo chi ha il ruolo PAUSER può mettere in pausa", async function () {
    const { registry, stranger } = await deploy();
    await expect(registry.connect(stranger).pause()).to.be.revertedWithCustomError(
      registry,
      "AccessControlUnauthorizedAccount",
    );
  });

  it("le transazioni partono dal backend: nessun indirizzo di paziente o medico sulla catena", async function () {
    const { registry, registrar, r, now } = await deploy();
    const tx = await r.grantConsent(CARE, now + 3600, RECEIPT);
    const receipt = (await tx.wait())!;
    expect(receipt.from).to.equal(registrar.address);
    // L'unico evento ha come argomenti solo valori opachi e la scadenza.
    expect(receipt.logs).to.have.length(1);
    const event = registry.interface.parseLog(receipt.logs[0]!)!;
    expect(event.fragment.inputs.map((i) => i.type)).to.deep.equal(["bytes32", "uint64", "bytes32"]);
  });
});
