// Parametri della Relying Party (il nostro servizio) per WebAuthn.
export const config = {
  rpName: "Cartella Clinica Passwordless",
  rpID: process.env.RP_ID ?? "localhost",
  origin: process.env.ORIGIN ?? "http://localhost:5173",
  challengeTtlMs: 5 * 60 * 1000,
} as const;
