import type { Request, Response } from "express";
import { openAccessLog } from "../crypto/records.js";
import type { Vault } from "../crypto/vault.js";
import type { AccessDetails, Store } from "../models/store.js";

// Voce del registro come la vede il paziente. L'impronta e il numero della voce on-chain
// gli permettono di verificare con il proprio wallet che il backend non abbia alterato nulla.
type Voce =
  | {
      at: string;
      requester: string;
      kind: AccessDetails["kind"];
      outcome?: "granted" | "denied";
      purpose?: string;
      reason?: string;
      documentId?: string;
      entryId: string | null;
      recordHash: string;
    }
  | { at: string; altered: true; entryId: string | null; recordHash: string };

// Voci del registro degli accessi alla cartella di un paziente, decifrate e controllate.
export async function patientAccessLog(store: Store, vault: Vault, username: string): Promise<Voce[]> {
  const voci: Voce[] = [];
  for (const entry of await store.listAccessLogOf(vault.indexTag(username))) {
    let d: AccessDetails;
    try {
      d = openAccessLog(vault, entry);
    } catch {
      voci.push({ at: entry.createdAt, altered: true, entryId: entry.entryId, recordHash: entry.recordHash });
      continue;
    }
    // L'etichetta serve solo a cercare: fa fede il paziente dentro i dettagli cifrati.
    // Una voce spostata su un altro paziente non ne rivela il contenuto.
    if (d.patient !== username) {
      voci.push({ at: entry.createdAt, altered: true, entryId: entry.entryId, recordHash: entry.recordHash });
      continue;
    }
    voci.push({
      at: d.at,
      requester: d.requester,
      kind: d.kind,
      ...(d.kind === "ordinary" ? { outcome: d.outcome, purpose: d.purpose } : {}),
      ...(d.kind === "emergency" || d.kind === "emergency-rejected" ? { reason: d.reason } : {}),
      ...(d.kind === "document-signed" ? { documentId: d.documentId } : {}),
      entryId: entry.entryId,
      recordHash: entry.recordHash,
    });
  }
  // Dal più recente al più vecchio.
  return voci.reverse();
}

// Registro degli accessi alla propria cartella (art. 15 GDPR): chi, quando, perché e con quale esito.
export function accessLogController(store: Store, vault: Vault) {
  return {
    async mine(_req: Request, res: Response): Promise<void> {
      const username: string = res.locals.username;
      const profile = await store.getProfile(username);
      if (profile?.role !== "patient") {
        res.status(403).json({ error: "solo il paziente può consultare il registro della propria cartella" });
        return;
      }
      res.json(await patientAccessLog(store, vault, username));
    },
  };
}
