// Il registro on-chain visto dal backend: lettura dei consensi e scrittura dell'audit.
// I valori numerici corrispondono agli enum dei contratti (Purpose e Outcome).

export const Purpose = { Care: 0, Research: 1, Administration: 2 } as const;
export type Purpose = (typeof Purpose)[keyof typeof Purpose];

export const Outcome = { Denied: 0, Granted: 1 } as const;
export type Outcome = (typeof Outcome)[keyof typeof Outcome];

export interface AccessEntry {
  patient: string;
  accessor: string;
  purpose: Purpose;
  outcome: Outcome;
  recordHash: string; // 32 byte in esadecimale: hash dei dettagli conservati off-chain
}

export interface EmergencyEntry {
  patient: string;
  accessor: string;
  reasonHash: string; // hash della motivazione, il cui testo resta off-chain
  recordHash: string;
}

// Rifiuto da parte di un contratto, con il nome dell'errore personalizzato (es. ConsentNotValid).
export class LedgerRevert extends Error {
  constructor(readonly errorName: string) {
    super(`Transazione rifiutata dal contratto: ${errorName}`);
  }
}

export interface Ledger {
  isConsentValid(patient: string, grantee: string, purpose: Purpose): Promise<boolean>;
  // Restituiscono l'identificativo della voce d'audit, dopo che la transazione è in un blocco.
  recordAccess(entry: AccessEntry): Promise<bigint>;
  recordEmergencyAccess(entry: EmergencyEntry): Promise<bigint>;
  close(): void;
}
