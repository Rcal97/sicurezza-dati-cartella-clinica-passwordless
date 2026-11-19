import { ZeroHash } from "ethers";
import { LedgerRevert, Outcome, type AccessEntry, type EmergencyEntry, type Ledger } from "./ledger.js";

const MAX_DURATION_S = 365 * 24 * 3600;

// Implementazione in memoria del registro on-chain, usata dai test del backend.
// Applica le stesse regole dei contratti ConsentRegistry e AuditLog.
export class MemoryLedger implements Ledger {
  readonly chain = {
    chainId: 31337,
    consentRegistry: "0x5FbDB2315678afecb367f032d93F642f64180aa3",
    auditLog: "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
  };
  private readonly consents = new Map<string, number>(); // ancora -> scadenza in secondi
  readonly emergencyStaff = new Set<string>(); // ancore abilitate (lo fa l'amministratore)
  // Tutto ciò che finirebbe sulla catena, per controllare nei test che non contenga dati personali.
  readonly consentEvents: Array<{ kind: "granted" | "revoked"; consentId: string; expiresAt?: number; receiptHash: string }> = [];
  readonly entries: Array<(AccessEntry | EmergencyEntry) & { entryId: bigint }> = [];

  private static now(): number {
    return Math.floor(Date.now() / 1000);
  }

  async isConsentValid(consentId: string): Promise<boolean> {
    return (this.consents.get(consentId) ?? 0) > MemoryLedger.now();
  }

  async grantConsent(consentId: string, expiresAt: number, receiptHash: string): Promise<void> {
    if (consentId === ZeroHash) throw new LedgerRevert("InvalidConsentId");
    if (receiptHash === ZeroHash) throw new LedgerRevert("MissingReceipt");
    const now = MemoryLedger.now();
    if (expiresAt <= now || expiresAt > now + MAX_DURATION_S) throw new LedgerRevert("InvalidExpiry");
    this.consents.set(consentId, expiresAt);
    this.consentEvents.push({ kind: "granted", consentId, expiresAt, receiptHash });
  }

  async revokeConsent(consentId: string, receiptHash: string): Promise<void> {
    if (receiptHash === ZeroHash) throw new LedgerRevert("MissingReceipt");
    this.consents.delete(consentId);
    this.consentEvents.push({ kind: "revoked", consentId, receiptHash });
  }

  async recordAccess(e: AccessEntry): Promise<bigint> {
    if (e.outcome === Outcome.Granted && !(await this.isConsentValid(e.consentId))) {
      throw new LedgerRevert("ConsentNotValid");
    }
    return this.append(e);
  }

  async recordEmergencyAccess(e: EmergencyEntry): Promise<bigint> {
    if (!this.emergencyStaff.has(e.staffId)) throw new LedgerRevert("NotEmergencyStaff");
    if (e.reasonHash === ZeroHash) throw new LedgerRevert("MissingReason");
    return this.append(e);
  }

  close(): void {}

  private append(e: AccessEntry | EmergencyEntry): bigint {
    const entryId = BigInt(this.entries.length + 1);
    this.entries.push({ ...e, entryId });
    return entryId;
  }
}
