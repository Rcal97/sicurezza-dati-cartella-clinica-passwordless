// Il registro on-chain visto dal backend: consensi e audit, senza dati personali.
// Sulla catena vanno solo ancore opache (HMAC calcolati con la chiave della struttura,
// vedi Vault.anchor), scadenze e impronte di dati conservati off-chain e cifrati.

// Valori dell'enum Outcome del contratto AuditLog.
export const Outcome = { Denied: 0, Granted: 1 } as const;
export type Outcome = (typeof Outcome)[keyof typeof Outcome];

export interface AccessEntry {
  consentId: string; // ancora del consenso richiesto (paziente, medico, finalità)
  outcome: Outcome;
  recordHash: string; // 32 byte in esadecimale: hash dei dettagli conservati off-chain
}

export interface EmergencyEntry {
  staffId: string; // ancora del medico d'emergenza
  reasonHash: string; // hash della motivazione, il cui testo resta off-chain
  recordHash: string;
}

// Rifiuto da parte di un contratto, con il nome dell'errore personalizzato (es. ConsentNotValid).
export class LedgerRevert extends Error {
  constructor(readonly errorName: string) {
    super(`Transazione rifiutata dal contratto: ${errorName}`);
  }
}

// Informazioni pubbliche sulla rete: il frontend le usa come dominio della firma EIP-712
// del consenso e per verificare le voci d'audit sulla catena.
export interface ChainInfo {
  chainId: number;
  consentRegistry: string;
  auditLog: string;
}

export interface Ledger {
  readonly chain: ChainInfo;
  isConsentValid(consentId: string): Promise<boolean>;
  // Concessione e revoca: le registra il backend (ruolo REGISTRAR) dopo aver verificato la
  // firma del paziente. expiresAt in secondi; receiptHash è l'impronta della ricevuta firmata.
  grantConsent(consentId: string, expiresAt: number, receiptHash: string): Promise<void>;
  revokeConsent(consentId: string, receiptHash: string): Promise<void>;
  // Restituiscono l'identificativo della voce d'audit, dopo che la transazione è in un blocco.
  recordAccess(entry: AccessEntry): Promise<bigint>;
  recordEmergencyAccess(entry: EmergencyEntry): Promise<bigint>;
  close(): void;
}
