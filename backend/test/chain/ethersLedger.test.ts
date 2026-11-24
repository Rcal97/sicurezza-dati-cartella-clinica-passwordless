import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { hexlify, JsonRpcProvider, Wallet, id, ZeroHash } from "ethers";
import { ledgerConfig } from "../../src/config.js";
import { EthersLedger, setEmergencyStaff } from "../../src/models/ethersLedger.js";
import { LedgerRevert, Outcome } from "../../src/models/ledger.js";

// Test di integrazione: richiedono il nodo locale acceso (npm run node), il deploy
// (npm run deploy:local) e il file .env. Ogni esecuzione usa ancore nuove, casuali.
const cfg = ledgerConfig();
let ledger: EthersLedger;
let provider: JsonRpcProvider;

// Account #0 di Hardhat (amministratore dei contratti nel deploy locale): chiave pubblica.
const LOCAL_ADMIN_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

// Vero se il contratto ha rifiutato la transazione con l'errore indicato.
const revertedWith = (name: string) => (err: unknown) => err instanceof LedgerRevert && err.errorName === name;

const anchor = () => hexlify(randomBytes(32));
const hash = id("dettagli dell'accesso");
const receipt = id("ricevuta firmata dal paziente");
const reason = id("paziente incosciente in pronto soccorso");
const inOneHour = async () => (await provider.getBlock("latest"))!.timestamp + 3600;

before(async () => {
  ledger = await EthersLedger.connect(cfg);
  provider = new JsonRpcProvider(cfg.rpcUrl);
});

after(() => {
  ledger.close();
  provider.destroy();
});

describe("EthersLedger (blockchain locale)", () => {
  it("espone la rete e gli indirizzi dei due contratti", async () => {
    assert.equal(ledger.chain.chainId, 31337);
    assert.equal(ledger.chain.consentRegistry.toLowerCase(), cfg.consentRegistry.toLowerCase());
    assert.equal(ledger.chain.auditLog.toLowerCase(), cfg.auditLog.toLowerCase());
    assert.equal(ledger.chain.fromBlock, cfg.fromBlock);
  });

  it("rifiuta un indirizzo dove non c'è un contratto", async () => {
    const missing = Wallet.createRandom().address;
    await assert.rejects(EthersLedger.connect({ ...cfg, auditLog: missing }), /Nessun contratto/);
  });

  it("senza consenso: lettura falsa, accesso registrato come negato", async () => {
    const consentId = anchor();
    assert.equal(await ledger.isConsentValid(consentId), false);
    const first = await ledger.recordAccess({ consentId, outcome: Outcome.Denied, recordHash: hash });
    const second = await ledger.recordAccess({ consentId, outcome: Outcome.Denied, recordHash: hash });
    assert.equal(second, first + 1n);
  });

  it("il backend registra concessione e revoca; l'accesso concesso vale solo per quell'ancora", async () => {
    const care = anchor();
    const research = anchor();
    await ledger.grantConsent(care, await inOneHour(), receipt);
    assert.equal(await ledger.isConsentValid(care), true);
    assert.equal(await ledger.isConsentValid(research), false);

    assert.ok((await ledger.recordAccess({ consentId: care, outcome: Outcome.Granted, recordHash: hash })) > 0n);
    await assert.rejects(
      ledger.recordAccess({ consentId: research, outcome: Outcome.Granted, recordHash: hash }),
      revertedWith("ConsentNotValid"),
    );

    await ledger.revokeConsent(care, receipt);
    assert.equal(await ledger.isConsentValid(care), false);
    await assert.rejects(
      ledger.recordAccess({ consentId: care, outcome: Outcome.Granted, recordHash: hash }),
      revertedWith("ConsentNotValid"),
    );
  });

  it("il contratto rifiuta scadenze non valide e concessioni senza ricevuta", async () => {
    const block = (await provider.getBlock("latest"))!.timestamp;
    await assert.rejects(ledger.grantConsent(anchor(), block - 10, receipt), revertedWith("InvalidExpiry"));
    await assert.rejects(ledger.grantConsent(anchor(), block + 3600, ZeroHash), revertedWith("MissingReceipt"));
  });

  it("le transazioni partono dal backend e gli eventi contengono solo valori opachi", async () => {
    const consentId = anchor();
    const before = await provider.getBlockNumber();
    await ledger.grantConsent(consentId, await inOneHour(), receipt);
    const logs = await provider.getLogs({ address: cfg.consentRegistry, fromBlock: before + 1 });
    assert.equal(logs.length, 1);
    assert.equal(logs[0]!.topics[1], consentId);
    const tx = await provider.getTransaction(logs[0]!.transactionHash);
    assert.equal(tx!.from, new Wallet(cfg.privateKey).address);
  });

  it("accesso d'emergenza: solo ancore abilitate dall'amministratore e con motivazione", async () => {
    const erDoctor = anchor();
    await assert.rejects(
      ledger.recordEmergencyAccess({ staffId: erDoctor, reasonHash: reason, recordHash: hash }),
      revertedWith("NotEmergencyStaff"),
    );
    // Il backend non può abilitarsi da solo.
    await assert.rejects(
      setEmergencyStaff(cfg, cfg.privateKey, erDoctor, true),
      revertedWith("AccessControlUnauthorizedAccount"),
    );
    await setEmergencyStaff(cfg, LOCAL_ADMIN_KEY, erDoctor, true);
    await assert.rejects(
      ledger.recordEmergencyAccess({ staffId: erDoctor, reasonHash: ZeroHash, recordHash: hash }),
      revertedWith("MissingReason"),
    );
    assert.ok((await ledger.recordEmergencyAccess({ staffId: erDoctor, reasonHash: reason, recordHash: hash })) > 0n);
  });

  it("dopo una transazione rifiutata il backend continua a scrivere", async () => {
    const consentId = anchor();
    const entry = (outcome: Outcome) => ({ consentId, outcome, recordHash: hash });
    await assert.rejects(ledger.recordAccess(entry(Outcome.Granted)), revertedWith("ConsentNotValid"));
    await assert.rejects(ledger.recordAccess(entry(Outcome.Granted)), revertedWith("ConsentNotValid"));
    assert.ok((await ledger.recordAccess(entry(Outcome.Denied))) > 0n);
  });

  it("più scritture contemporanee ricevono identificativi distinti", async () => {
    const ids = await Promise.all(
      [1, 2, 3, 4, 5].map(() => ledger.recordAccess({ consentId: anchor(), outcome: Outcome.Denied, recordHash: hash })),
    );
    assert.equal(new Set(ids).size, 5);
  });

  it("una chiave senza ruoli non può scrivere né consensi né audit", async () => {
    // Account #3 di Hardhat: chiave pubblica, nessun ruolo sui contratti.
    const intruder = await EthersLedger.connect({
      ...cfg,
      privateKey: "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
    });
    try {
      await assert.rejects(
        intruder.recordAccess({ consentId: anchor(), outcome: Outcome.Denied, recordHash: hash }),
        revertedWith("AccessControlUnauthorizedAccount"),
      );
      await assert.rejects(
        intruder.grantConsent(anchor(), await inOneHour(), receipt),
        revertedWith("AccessControlUnauthorizedAccount"),
      );
    } finally {
      intruder.close();
    }
  });
});
