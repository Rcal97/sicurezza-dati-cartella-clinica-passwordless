import type { Request, Response } from "express";
import { openConsentReceipt } from "../crypto/consent.js";
import type { Vault } from "../crypto/vault.js";
import type { Store } from "../models/store.js";
import { NOTICE_VERSION } from "../privacy.js";
import { patientAccessLog } from "./accessLog.js";
import { deliverDocuments } from "./records.js";

// Diritti del paziente sulla propria cartella.
// - Accesso (art. 15 GDPR): i propri referti, decifrati, con lo stato della firma.
// - Portabilità (art. 20): un file JSON, in formato strutturato e leggibile da macchina, con
//   referti, ricevute firmate dei consensi e registro degli accessi.
// Il paziente non ha bisogno di consenso per leggere i propri dati: non serve la catena.
export function patientController(store: Store, vault: Vault) {
  async function isPatient(res: Response): Promise<string | null> {
    const username: string = res.locals.username;
    if ((await store.getProfile(username))?.role !== "patient") {
      res.status(403).json({ error: "solo il paziente può consultare la propria cartella" });
      return null;
    }
    return username;
  }

  return {
    async documents(_req: Request, res: Response): Promise<void> {
      const username = await isPatient(res);
      if (!username) return;
      res.json(await deliverDocuments(store, vault, username));
    },

    async export(_req: Request, res: Response): Promise<void> {
      const username = await isPatient(res);
      if (!username) return;
      const consents = [];
      for (const stored of await store.listConsentsOf(vault.indexTag(username))) {
        try {
          const receipt = openConsentReceipt(vault, stored);
          if (receipt.message.patient === username) consents.push({ ...receipt, receiptHash: stored.receiptHash, consentId: stored.consentId });
        } catch {
          consents.push({ receiptHash: stored.receiptHash, error: "ricevuta alterata o non decifrabile" });
        }
      }
      const body = {
        format: "cartella-clinica-export/1",
        exportedAt: new Date().toISOString(),
        patient: username,
        noticeVersion: NOTICE_VERSION,
        documents: await deliverDocuments(store, vault, username),
        consents,
        accessLog: await patientAccessLog(store, vault, username),
      };
      res.setHeader("Content-Disposition", `attachment; filename="cartella-${username}.json"`);
      res.json(body);
    },
  };
}
