import { createHash, randomUUID } from "node:crypto";
import type { AccessDetails, AccessLogEntry, StoredDocument } from "../models/store.js";
import type { DocumentSignature } from "./signature.js";
import type { Vault } from "./vault.js";

// Contenuto di un referto, cifrato per intero: anche il titolo è un dato sanitario.
// I referti scritti da un medico portano la sua firma; quelli caricati dal laboratorio no.
export interface DocumentContent {
  title: string;
  body: string;
  signature?: DocumentSignature;
}

// Il contesto lega il testo cifrato a un documento e a un paziente (AAD di AES-GCM).
const context = (id: string, patient: string) => `${id}|${patient}`;

export function sealDocument(vault: Vault, patient: string, content: DocumentContent, id = randomUUID()): StoredDocument {
  const sealed = vault.seal(Buffer.from(JSON.stringify(content)), context(id, patient));
  return { id, patient, createdAt: new Date().toISOString(), sealed };
}

export function openDocument(vault: Vault, doc: StoredDocument): DocumentContent {
  return JSON.parse(vault.open(doc.sealed, context(doc.id, doc.patient)).toString("utf8"));
}

// Impronta SHA-256 dei dettagli di un accesso: sulla catena va solo questa.
// I dettagli contengono un nonce casuale, quindi non si possono indovinare provando
// tutte le combinazioni di medico, paziente e finalità.
export function fingerprint(value: unknown): string {
  return "0x" + createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

// Registro degli accessi: i dettagli si cifrano con le chiavi dell'archivio. Il contesto
// (AAD) lega il testo cifrato alla sua impronta: non si può scambiare con un'altra voce.
export function sealAccessLog(vault: Vault, entryId: bigint | null, details: AccessDetails): AccessLogEntry {
  const recordHash = fingerprint(details);
  return {
    entryId: entryId === null ? null : entryId.toString(),
    recordHash,
    createdAt: details.at,
    sealed: vault.seal(Buffer.from(JSON.stringify(details)), `access-log|${recordHash}`),
  };
}

// Decifra una voce e controlla che i dettagli corrispondano ancora all'impronta.
export function openAccessLog(vault: Vault, entry: AccessLogEntry): AccessDetails {
  const details: AccessDetails = JSON.parse(
    vault.open(entry.sealed, `access-log|${entry.recordHash}`).toString("utf8"),
  );
  if (fingerprint(details) !== entry.recordHash) throw new Error("Voce del registro alterata");
  return details;
}
