import { getAddress, verifyTypedData, type TypedDataDomain, type TypedDataField } from "ethers";
import type { ChainInfo } from "../models/ledger.js";
import type { StoredConsent } from "../models/store.js";
import { fingerprint } from "./records.js";
import type { Vault } from "./vault.js";

// Consenso firmato dal paziente con il proprio wallet secondo EIP-712: il wallet mostra i
// campi in chiaro prima della firma, e la firma è legata a questa applicazione, a questa
// rete e a questo contratto (dominio). Non è una transazione: non costa gas e non lascia
// traccia sulla catena. Sulla catena va solo l'impronta della ricevuta.

export type ConsentAction = "grant" | "revoke";

export interface ConsentMessage {
  action: ConsentAction;
  patient: string;
  doctor: string;
  purpose: string;
  expiresAt: number; // secondi; 0 nelle revoche
  noticeVersion: string; // versione dell'informativa letta dal paziente
  noticeHash: string; // impronta SHA-256 del testo dell'informativa
  issuedAt: number; // secondi
  nonce: string; // 32 byte casuali: ogni richiesta di firma vale una volta sola
}

export const CONSENT_TYPES: Record<string, TypedDataField[]> = {
  Consent: [
    { name: "action", type: "string" },
    { name: "patient", type: "string" },
    { name: "doctor", type: "string" },
    { name: "purpose", type: "string" },
    { name: "expiresAt", type: "uint64" },
    { name: "noticeVersion", type: "string" },
    { name: "noticeHash", type: "bytes32" },
    { name: "issuedAt", type: "uint64" },
    { name: "nonce", type: "bytes32" },
  ],
};

export function consentDomain(chain: ChainInfo): TypedDataDomain {
  return {
    name: "Cartella clinica passwordless",
    version: "1",
    chainId: chain.chainId,
    verifyingContract: chain.consentRegistry,
  };
}

// Ricevuta del consenso (sul modello delle consent receipt di ISO/IEC TS 27560): che cosa è
// stato accettato, quando, con quale informativa e la firma che lo prova. È un dato personale:
// si conserva cifrata.
export interface ConsentReceipt {
  domain: TypedDataDomain;
  message: ConsentMessage;
  signature: string;
  signer: string;
}

// Verifica la firma e restituisce l'indirizzo che l'ha prodotta (formato EIP-55).
export function recoverSigner(chain: ChainInfo, message: ConsentMessage, signature: string): string {
  return getAddress(verifyTypedData(consentDomain(chain), CONSENT_TYPES, message, signature));
}

// Ancora del consenso: HMAC con la chiave della struttura sul segreto del paziente, sul medico
// e sulla finalità. Il segreto è casuale e diverso per ogni paziente: cancellandolo, le ancore
// già scritte sulla catena non si ricollegano più a lui, nemmeno da chi possiede la chiave.
export function consentAnchor(vault: Vault, patientSecret: string, doctor: string, purpose: string): string {
  return vault.anchor("consenso", patientSecret, doctor, purpose);
}

// Ancora del medico per gli accessi d'emergenza.
export function staffAnchor(vault: Vault, doctor: string): string {
  return vault.anchor("emergenza", doctor);
}

// La ricevuta si cifra con le chiavi dell'archivio. Il contesto (AAD) la lega alla sua
// impronta, che è anche il valore scritto sulla catena: non si può scambiare con un'altra.
export function sealConsentReceipt(vault: Vault, consentId: string, receipt: ConsentReceipt): StoredConsent {
  const receiptHash = fingerprint(receipt);
  return {
    consentId,
    patientTag: vault.indexTag(receipt.message.patient),
    receiptHash,
    createdAt: new Date().toISOString(),
    sealed: vault.seal(Buffer.from(JSON.stringify(receipt)), `consent|${receiptHash}`),
  };
}

// Decifra una ricevuta e controlla che corrisponda ancora alla sua impronta.
export function openConsentReceipt(vault: Vault, stored: StoredConsent): ConsentReceipt {
  const receipt: ConsentReceipt = JSON.parse(vault.open(stored.sealed, `consent|${stored.receiptHash}`).toString("utf8"));
  if (fingerprint(receipt) !== stored.receiptHash) throw new Error("Ricevuta del consenso alterata");
  return receipt;
}
