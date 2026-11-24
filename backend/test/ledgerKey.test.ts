import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Wallet } from "ethers";
import { ledgerConfig } from "../src/config.js";
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

describe("Blocco di partenza delle ricerche sulla catena (CHAIN_FROM_BLOCK)", () => {
  // Imposta le variabili per la durata della lettura e poi ripristina quelle di prima.
  const conBlocco = (valore: string | undefined) => {
    const variabili: Record<string, string | undefined> = {
      BACKEND_PRIVATE_KEY: Wallet.createRandom().privateKey,
      CONSENT_REGISTRY_ADDRESS: Wallet.createRandom().address,
      AUDIT_LOG_ADDRESS: Wallet.createRandom().address,
      CHAIN_FROM_BLOCK: valore,
    };
    const prima = Object.fromEntries(Object.keys(variabili).map((k) => [k, process.env[k]]));
    const imposta = (valori: Record<string, string | undefined>) => {
      for (const [k, v] of Object.entries(valori)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    };
    imposta(variabili);
    try {
      return ledgerConfig().fromBlock;
    } finally {
      imposta(prima);
    }
  };

  it("vale 0 se non è indicato (rete locale)", () => {
    assert.equal(conBlocco(undefined), 0);
  });

  it("legge il numero del blocco del deploy", () => {
    assert.equal(conBlocco("9712345"), 9712345);
  });

  it("rifiuta un valore che non è un numero di blocco", () => {
    assert.throws(() => conBlocco("-1"), /CHAIN_FROM_BLOCK/);
    assert.throws(() => conBlocco("0x10"), /CHAIN_FROM_BLOCK/);
  });
});
