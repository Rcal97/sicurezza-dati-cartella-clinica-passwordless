import { fileURLToPath } from "node:url";

// Parametri della Relying Party (il nostro servizio) per WebAuthn.
export const config = {
  rpName: "Cartella Clinica Passwordless",
  rpID: process.env.RP_ID ?? "localhost",
  origin: process.env.ORIGIN ?? "http://localhost:5173",
  challengeTtlMs: 5 * 60 * 1000,
  // Una sessione scade dopo 15 minuti di inattività.
  sessionIdleMs: 15 * 60 * 1000,
  // Un invito alla registrazione vale 24 ore.
  invitationTtlMs: 24 * 60 * 60 * 1000,
  // In produzione il cookie viaggia solo su HTTPS.
  secureCookies: process.env.NODE_ENV === "production",
} as const;

// Stringa di connessione costruita dalle variabili del file .env (mai scritta nel codice).
export function mongoUrl(): string {
  const { MONGO_APP_USER, MONGO_APP_PASSWORD, MONGO_APP_DB } = process.env;
  if (!MONGO_APP_USER || !MONGO_APP_PASSWORD || !MONGO_APP_DB) {
    throw new Error("Variabili MONGO_APP_* mancanti: controlla il file .env");
  }
  const user = encodeURIComponent(MONGO_APP_USER);
  const password = encodeURIComponent(MONGO_APP_PASSWORD);
  const host = process.env.MONGO_HOST ?? "127.0.0.1:27017";
  return `mongodb://${user}:${password}@${host}/${MONGO_APP_DB}?authSource=${MONGO_APP_DB}`;
}

// File con le chiavi private dell'archivio dei referti, cifrate con una passphrase
// (fuori da Git, permessi 600).
export const archiveKeyFile = (): string =>
  process.env.ARCHIVE_KEY_FILE ?? fileURLToPath(new URL("../../secrets/archivio.key", import.meta.url));

// Collegamento alla blockchain: nodo, chiave del backend (ruolo RECORDER) e indirizzi dei contratti.
export function ledgerConfig() {
  const { CHAIN_RPC_URL, BACKEND_PRIVATE_KEY, CONSENT_REGISTRY_ADDRESS, AUDIT_LOG_ADDRESS } =
    process.env;
  if (!BACKEND_PRIVATE_KEY || !CONSENT_REGISTRY_ADDRESS || !AUDIT_LOG_ADDRESS) {
    throw new Error("Variabili della blockchain mancanti: controlla il file .env");
  }
  return {
    rpcUrl: CHAIN_RPC_URL ?? "http://127.0.0.1:8545",
    privateKey: BACKEND_PRIVATE_KEY,
    consentRegistry: CONSENT_REGISTRY_ADDRESS,
    auditLog: AUDIT_LOG_ADDRESS,
  };
}
