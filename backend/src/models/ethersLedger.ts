import {
  Contract,
  getAddress,
  HDNodeWallet,
  JsonRpcProvider,
  Wallet,
  type ContractTransactionResponse,
  type TransactionReceipt,
} from "ethers";
import { LedgerRevert, type AccessEntry, type ChainInfo, type EmergencyEntry, type Ledger } from "./ledger.js";

// Solo le funzioni, gli eventi e gli errori che il backend usa (gli enum viaggiano come uint8).
const CONSENT_ABI = [
  "function isConsentValid(bytes32 consentId) view returns (bool)",
  "function grantConsent(bytes32 consentId, uint64 expiresAt, bytes32 receiptHash)",
  "function revokeConsent(bytes32 consentId, bytes32 receiptHash)",
  "event ConsentGranted(bytes32 indexed consentId, uint64 expiresAt, bytes32 receiptHash)",
  "event ConsentRevoked(bytes32 indexed consentId, bytes32 receiptHash)",
  "error InvalidConsentId()",
  "error InvalidExpiry()",
  "error MissingReceipt()",
  "error EnforcedPause()",
  "error AccessControlUnauthorizedAccount(address account, bytes32 neededRole)",
];

const AUDIT_ABI = [
  "function recordAccess(bytes32 consentId, uint8 outcome, bytes32 recordHash) returns (uint256)",
  "function recordEmergencyAccess(bytes32 staffId, bytes32 reasonHash, bytes32 recordHash) returns (uint256)",
  "function setEmergencyStaff(bytes32 staffId, bool enabled)",
  "function isEmergencyStaff(bytes32 staffId) view returns (bool)",
  "event AccessRecorded(uint256 indexed entryId, bytes32 indexed consentId, uint8 outcome, bytes32 recordHash)",
  "event EmergencyAccess(uint256 indexed entryId, bytes32 indexed staffId, bytes32 reasonHash, bytes32 recordHash)",
  "error ConsentNotValid()",
  "error NotEmergencyStaff(bytes32 staffId)",
  "error MissingReason()",
  "error InvalidStaffId()",
  "error AccessControlUnauthorizedAccount(address account, bytes32 neededRole)",
];

// Gli account di sviluppo di Hardhat derivano da una frase mnemonica pubblicata nella
// documentazione: chiunque ne conosce le chiavi private. Vanno bene solo sulla rete locale.
const HARDHAT_MNEMONIC = "test test test test test test test test test test test junk";
const LOCAL_CHAIN_ID = 31337n;
const DEV_ADDRESSES = new Set(
  Array.from({ length: 20 }, (_, i) =>
    HDNodeWallet.fromPhrase(HARDHAT_MNEMONIC, undefined, `m/44'/60'/0'/0/${i}`).address,
  ),
);

// Rifiuta una chiave di sviluppo su una rete che non sia quella locale.
export function assertSafeKey(address: string, chainId: bigint): void {
  if (chainId !== LOCAL_CHAIN_ID && DEV_ADDRESSES.has(address)) {
    throw new Error(`La chiave ${address} è una chiave pubblica di Hardhat: non si usa sulla rete ${chainId}`);
  }
}

export interface LedgerConfig {
  rpcUrl: string;
  privateKey: string;
  consentRegistry: string;
  auditLog: string;
  fromBlock?: number;
}

export class EthersLedger implements Ledger {
  // Coda delle transazioni del backend: ne parte una alla volta (vedi send).
  private queue: Promise<unknown> = Promise.resolve();

  private constructor(
    private readonly provider: JsonRpcProvider,
    private readonly consent: Contract,
    private readonly audit: Contract,
    readonly chain: ChainInfo,
  ) {}

  static async connect(cfg: LedgerConfig): Promise<EthersLedger> {
    // cacheTimeout -1: nessuna risposta riusata dalla cache, il nonce letto è sempre aggiornato.
    const provider = new JsonRpcProvider(cfg.rpcUrl, undefined, { cacheTimeout: -1 });
    // Se agli indirizzi non c'è codice, la configurazione punta a un deploy che non esiste più.
    for (const address of [cfg.consentRegistry, cfg.auditLog]) {
      if ((await provider.getCode(address)) === "0x") {
        provider.destroy();
        throw new Error(`Nessun contratto all'indirizzo ${address}: hai eseguito il deploy?`);
      }
    }
    const signer = new Wallet(cfg.privateKey, provider);
    const chainId = (await provider.getNetwork()).chainId;
    try {
      assertSafeKey(signer.address, chainId);
    } catch (err) {
      provider.destroy();
      throw err;
    }
    return new EthersLedger(
      provider,
      new Contract(cfg.consentRegistry, CONSENT_ABI, signer),
      new Contract(cfg.auditLog, AUDIT_ABI, signer),
      {
        chainId: Number(chainId),
        consentRegistry: getAddress(cfg.consentRegistry),
        auditLog: getAddress(cfg.auditLog),
        fromBlock: cfg.fromBlock ?? 0,
      },
    );
  }

  async isConsentValid(consentId: string): Promise<boolean> {
    return await this.consent.getFunction("isConsentValid")(consentId);
  }

  async grantConsent(consentId: string, expiresAt: number, receiptHash: string): Promise<void> {
    await this.send(this.consent, "grantConsent", [consentId, expiresAt, receiptHash]);
  }

  async revokeConsent(consentId: string, receiptHash: string): Promise<void> {
    await this.send(this.consent, "revokeConsent", [consentId, receiptHash]);
  }

  async recordAccess(e: AccessEntry): Promise<bigint> {
    const receipt = await this.send(this.audit, "recordAccess", [e.consentId, e.outcome, e.recordHash]);
    return this.entryId(receipt, "AccessRecorded");
  }

  async recordEmergencyAccess(e: EmergencyEntry): Promise<bigint> {
    const receipt = await this.send(this.audit, "recordEmergencyAccess", [e.staffId, e.reasonHash, e.recordHash]);
    return this.entryId(receipt, "EmergencyAccess");
  }

  close(): void {
    this.provider.destroy();
  }

  // Invia la transazione e attende che entri in un blocco.
  // Gli invii sono messi in fila: ognuno legge il nonce dal nodo solo dopo che il precedente
  // è stato trasmesso, quindi due richieste contemporanee non ricevono lo stesso numero e una
  // transazione rifiutata non lascia buchi nella numerazione.
  private async send(contract: Contract, fn: string, args: unknown[]): Promise<TransactionReceipt> {
    const sending = this.queue.then(
      () => contract.getFunction(fn)(...args) as Promise<ContractTransactionResponse>,
    );
    this.queue = sending.catch(() => undefined);
    try {
      const tx = await sending;
      return (await tx.wait())!;
    } catch (err) {
      throw decodeRevert(contract, err);
    }
  }

  // L'identificativo della voce si legge dall'evento emesso dal contratto.
  private entryId(receipt: TransactionReceipt, eventName: string): bigint {
    for (const log of receipt.logs) {
      const parsed = this.audit.interface.parseLog(log);
      if (parsed?.name === eventName) return parsed.args.getValue("entryId");
    }
    throw new Error(`Evento ${eventName} non trovato nella ricevuta`);
  }
}

// Se il contratto rifiuta, traduce il codice dell'errore nel suo nome.
function decodeRevert(contract: Contract, err: unknown): unknown {
  const data = (err as { data?: string }).data;
  const decoded = data ? contract.interface.parseError(data) : null;
  return decoded ? new LedgerRevert(decoded.name) : err;
}

// Operazione dell'amministratore (non del backend): abilita o disabilita un medico agli
// accessi d'emergenza, identificato sulla catena solo dalla sua ancora.
export async function setEmergencyStaff(
  cfg: Omit<LedgerConfig, "privateKey">,
  adminKey: string,
  staffId: string,
  enabled: boolean,
): Promise<void> {
  const provider = new JsonRpcProvider(cfg.rpcUrl);
  try {
    const admin = new Wallet(adminKey, provider);
    assertSafeKey(admin.address, (await provider.getNetwork()).chainId);
    const audit = new Contract(cfg.auditLog, AUDIT_ABI, admin);
    try {
      await (await audit.getFunction("setEmergencyStaff")(staffId, enabled)).wait();
    } catch (err) {
      throw decodeRevert(audit, err);
    }
  } finally {
    provider.destroy();
  }
}
