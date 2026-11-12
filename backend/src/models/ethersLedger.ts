import {
  Contract,
  JsonRpcProvider,
  Wallet,
  type ContractTransactionResponse,
  type TransactionReceipt,
} from "ethers";
import type { AccessEntry, EmergencyEntry, Ledger, Purpose } from "./ledger.js";

// Solo le funzioni, gli eventi e gli errori che il backend usa (gli enum viaggiano come uint8).
const CONSENT_ABI = [
  "function isConsentValid(address patient, address grantee, uint8 purpose) view returns (bool)",
];

const AUDIT_ABI = [
  "function recordAccess(address patient, address accessor, uint8 purpose, uint8 outcome, bytes32 recordHash) returns (uint256)",
  "function recordEmergencyAccess(address patient, address accessor, bytes32 reasonHash, bytes32 recordHash) returns (uint256)",
  "event AccessRecorded(uint256 indexed entryId, address indexed patient, address indexed accessor, uint8 purpose, uint8 outcome, bytes32 recordHash)",
  "event EmergencyAccess(uint256 indexed entryId, address indexed patient, address indexed accessor, bytes32 reasonHash, bytes32 recordHash)",
  "error ConsentNotValid()",
  "error NotEmergencyStaff(address accessor)",
  "error MissingReason()",
  "error AccessControlUnauthorizedAccount(address account, bytes32 neededRole)",
];

// Rifiuto da parte di un contratto, con il nome dell'errore personalizzato (es. ConsentNotValid).
export class LedgerRevert extends Error {
  constructor(readonly errorName: string) {
    super(`Transazione rifiutata dal contratto: ${errorName}`);
  }
}

export interface LedgerConfig {
  rpcUrl: string;
  privateKey: string;
  consentRegistry: string;
  auditLog: string;
}

export class EthersLedger implements Ledger {
  // Coda delle transazioni del backend: ne parte una alla volta (vedi send).
  private queue: Promise<unknown> = Promise.resolve();

  private constructor(
    private readonly provider: JsonRpcProvider,
    private readonly consent: Contract,
    private readonly audit: Contract,
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
    return new EthersLedger(
      provider,
      new Contract(cfg.consentRegistry, CONSENT_ABI, provider),
      new Contract(cfg.auditLog, AUDIT_ABI, signer),
    );
  }

  async isConsentValid(patient: string, grantee: string, purpose: Purpose): Promise<boolean> {
    return await this.consent.getFunction("isConsentValid")(patient, grantee, purpose);
  }

  async recordAccess(e: AccessEntry): Promise<bigint> {
    const args = [e.patient, e.accessor, e.purpose, e.outcome, e.recordHash];
    return this.send("recordAccess", args, "AccessRecorded");
  }

  async recordEmergencyAccess(e: EmergencyEntry): Promise<bigint> {
    const args = [e.patient, e.accessor, e.reasonHash, e.recordHash];
    return this.send("recordEmergencyAccess", args, "EmergencyAccess");
  }

  close(): void {
    this.provider.destroy();
  }

  // Invia la transazione, attende che entri in un blocco e restituisce l'id della voce.
  // Gli invii sono messi in fila: ognuno legge il nonce dal nodo solo dopo che il precedente
  // è stato trasmesso, quindi due richieste contemporanee non ricevono lo stesso numero e una
  // transazione rifiutata non lascia buchi nella numerazione.
  private async send(fn: string, args: unknown[], eventName: string): Promise<bigint> {
    const sending = this.queue.then(
      () => this.audit.getFunction(fn)(...args) as Promise<ContractTransactionResponse>,
    );
    this.queue = sending.catch(() => undefined);
    try {
      const tx = await sending;
      return this.entryId((await tx.wait())!, eventName);
    } catch (err) {
      // Se il contratto rifiuta, traduce il codice dell'errore nel suo nome.
      const data = (err as { data?: string }).data;
      const decoded = data ? this.audit.interface.parseError(data) : null;
      if (decoded) throw new LedgerRevert(decoded.name);
      throw err;
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
