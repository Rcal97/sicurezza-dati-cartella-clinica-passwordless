import { randomUUID } from "node:crypto";
import type { StoredDocument } from "../models/store.js";
import type { Vault } from "./vault.js";

// Contenuto di un referto, cifrato per intero: anche il titolo è un dato sanitario.
export interface DocumentContent {
  title: string;
  body: string;
}

// Il contesto lega il testo cifrato a un documento e a un paziente (AAD di AES-GCM).
const context = (id: string, patient: string) => `${id}|${patient}`;

export function sealDocument(vault: Vault, patient: string, content: DocumentContent): StoredDocument {
  const id = randomUUID();
  const sealed = vault.seal(Buffer.from(JSON.stringify(content)), context(id, patient));
  return { id, patient, createdAt: new Date().toISOString(), sealed };
}

export function openDocument(vault: Vault, doc: StoredDocument): DocumentContent {
  return JSON.parse(vault.open(doc.sealed, context(doc.id, doc.patient)).toString("utf8"));
}
