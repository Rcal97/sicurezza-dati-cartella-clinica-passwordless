import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Wallet } from "ethers";
import { assertSafeKey } from "../src/models/ethersLedger.js";

describe("Chiavi pubbliche di Hardhat", () => {
  // Account #1 di Hardhat, quello usato dal backend sulla rete locale.
  const devAddress = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

  it("sono accettate sulla rete locale", () => {
    assert.doesNotThrow(() => assertSafeKey(devAddress, 31337n));
  });

  it("sono rifiutate su una rete vera (Sepolia, Ethereum)", () => {
    assert.throws(() => assertSafeKey(devAddress, 11155111n), /chiave pubblica di Hardhat/);
    assert.throws(() => assertSafeKey(devAddress, 1n), /chiave pubblica di Hardhat/);
  });

  it("una chiave generata a caso è accettata ovunque", () => {
    assert.doesNotThrow(() => assertSafeKey(Wallet.createRandom().address, 11155111n));
  });
});
