import { expect } from "chai";
import { network } from "hardhat";

const { ethers } = await network.create();

// Regole sull'amministrazione dei contratti: valgono per entrambi.
for (const name of ["ConsentRegistry", "AuditLog"] as const) {
  describe(`${name}: amministrazione`, function () {
    async function deploy() {
      const [admin, newAdmin, attacker] = await ethers.getSigners();
      const registry = await ethers.deployContract("ConsentRegistry", [admin.address]);
      const contract =
        name === "ConsentRegistry"
          ? registry
          : await ethers.deployContract("AuditLog", [admin.address, await registry.getAddress()]);
      const adminRole = await contract.DEFAULT_ADMIN_ROLE();
      const delay = Number(await contract.ADMIN_TRANSFER_DELAY());
      return { contract, admin, newAdmin, attacker, adminRole, delay };
    }

    async function wait(seconds: number) {
      await ethers.provider.send("evm_increaseTime", [seconds]);
      await ethers.provider.send("evm_mine", []);
    }

    it("non si può aggiungere un secondo amministratore", async function () {
      const { contract, admin, attacker, adminRole } = await deploy();
      await expect(
        contract.connect(admin).grantRole(adminRole, attacker.address),
      ).to.be.revertedWithCustomError(contract, "AccessControlEnforcedDefaultAdminRules");
    });

    it("il passaggio di consegne richiede due fasi e l'attesa di due giorni", async function () {
      const { contract, admin, newAdmin, delay } = await deploy();
      await contract.connect(admin).beginDefaultAdminTransfer(newAdmin.address);
      // Il passaggio in corso è visibile a tutti sulla catena.
      expect((await contract.pendingDefaultAdmin())[0]).to.equal(newAdmin.address);

      await expect(contract.connect(newAdmin).acceptDefaultAdminTransfer()).to.be.revertedWithCustomError(
        contract,
        "AccessControlEnforcedDefaultAdminDelay",
      );
      await wait(delay + 1);
      await contract.connect(newAdmin).acceptDefaultAdminTransfer();
      expect(await contract.defaultAdmin()).to.equal(newAdmin.address);
    });

    it("un passaggio sospetto si può annullare durante l'attesa", async function () {
      const { contract, admin, attacker, delay } = await deploy();
      await contract.connect(admin).beginDefaultAdminTransfer(attacker.address);
      await contract.connect(admin).cancelDefaultAdminTransfer();
      await wait(delay + 1);
      await expect(contract.connect(attacker).acceptDefaultAdminTransfer()).to.be.revertedWithCustomError(
        contract,
        "AccessControlInvalidDefaultAdmin",
      );
      expect(await contract.defaultAdmin()).to.equal(admin.address);
    });

    it("l'amministratore non può rinunciare al ruolo all'improvviso", async function () {
      const { contract, admin, adminRole } = await deploy();
      await expect(
        contract.connect(admin).renounceRole(adminRole, admin.address),
      ).to.be.revertedWithCustomError(contract, "AccessControlEnforcedDefaultAdminDelay");
      expect(await contract.defaultAdmin()).to.equal(admin.address);
    });

    it("chi non è amministratore non può avviare un passaggio di consegne", async function () {
      const { contract, attacker } = await deploy();
      await expect(
        contract.connect(attacker).beginDefaultAdminTransfer(attacker.address),
      ).to.be.revertedWithCustomError(contract, "AccessControlUnauthorizedAccount");
    });
  });
}

describe("ConsentRegistry: pausa", function () {
  it("l'amministratore non può mettere in pausa senza il ruolo PAUSER", async function () {
    const [admin] = await ethers.getSigners();
    const registry = await ethers.deployContract("ConsentRegistry", [admin.address]);
    await expect(registry.connect(admin).pause()).to.be.revertedWithCustomError(
      registry,
      "AccessControlUnauthorizedAccount",
    );
  });
});
