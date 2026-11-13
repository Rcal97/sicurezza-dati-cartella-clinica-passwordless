import { ZeroHash } from "ethers";
import {
  LedgerRevert,
  Outcome,
  type AccessEntry,
  type EmergencyEntry,
  type Ledger,
  type Purpose,
} from "./ledger.js";

// Implementazione in memoria del registro on-chain, usata dai test del backend.
// Applica le stesse regole dei contratti ConsentRegistry e AuditLog.
export class MemoryLedger implements Ledger {
  readonly chain = { chainId: 31337, consentRegistry: "0x5FbDB2315678afecb367f032d93F642f64180aa3" };
  private readonly consents = new Map<string, number>(); // chiave -> scadenza in ms
  readonly emergencyStaff = new Set<string>();
  readonly entries: Array<(AccessEntry | EmergencyEntry) & { entryId: bigint }> = [];

  private static key(patient: string, grantee: string, purpose: Purpose): string {
    return `${patient.toLowerCase()}|${grantee.toLowerCase()}|${purpose}`;
  }

  // Operazioni che sulla catena fanno il paziente e l'amministratore.
  grantConsent(patient: string, grantee: string, purpose: Purpose, ttlMs = 3_600_000): void {
    this.consents.set(MemoryLedger.key(patient, grantee, purpose), Date.now() + ttlMs);
  }

  revokeConsent(patient: string, grantee: string, purpose: Purpose): void {
    this.consents.delete(MemoryLedger.key(patient, grantee, purpose));
  }

  async isConsentValid(patient: string, grantee: string, purpose: Purpose): Promise<boolean> {
    return (this.consents.get(MemoryLedger.key(patient, grantee, purpose)) ?? 0) > Date.now();
  }

  async recordAccess(e: AccessEntry): Promise<bigint> {
    if (e.outcome === Outcome.Granted && !(await this.isConsentValid(e.patient, e.accessor, e.purpose))) {
      throw new LedgerRevert("ConsentNotValid");
    }
    return this.append(e);
  }

  async recordEmergencyAccess(e: EmergencyEntry): Promise<bigint> {
    if (!this.emergencyStaff.has(e.accessor.toLowerCase())) throw new LedgerRevert("NotEmergencyStaff");
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
