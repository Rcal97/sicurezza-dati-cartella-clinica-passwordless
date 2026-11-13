import { randomBytes } from "node:crypto";
import type { Request, Response } from "express";
import { fingerprint, openDocument, sealAccessLog } from "../crypto/records.js";
import { verifyDocumentSignature } from "../crypto/signature.js";
import type { Vault } from "../crypto/vault.js";
import { LedgerRevert, Outcome, Purpose, type Ledger } from "../models/ledger.js";
import type { AccessDetails, Profile, Store } from "../models/store.js";
import { USERNAME } from "./registration.js";

// Finalità accettate dall'API. Una Map, non un oggetto: una chiave come "toString"
// o "__proto__" non deve trovare per sbaglio un valore ereditato.
const PURPOSES = new Map<string, Purpose>([
  ["care", Purpose.Care],
  ["research", Purpose.Research],
  ["administration", Purpose.Administration],
]);

const nonce = (): string => randomBytes(16).toString("hex");

export interface Parties {
  requester: string;
  doctor: Profile;
  patientName: string;
  patient: Profile;
}

// Controlli comuni: chi chiede deve essere un medico, il paziente deve esistere.
export async function parties(store: Store, req: Request, res: Response): Promise<Parties | null> {
  const requester: string = res.locals.username;
  const doctor = await store.getProfile(requester);
  if (doctor?.role !== "doctor") {
    res.status(403).json({ error: "solo i medici possono consultare le cartelle" });
    return null;
  }
  const patientName = req.body?.patient;
  if (typeof patientName !== "string" || !USERNAME.test(patientName)) {
    res.status(400).json({ error: "paziente non valido" });
    return null;
  }
  const patient = await store.getProfile(patientName);
  if (patient?.role !== "patient") {
    res.status(404).json({ error: "paziente non trovato" });
    return null;
  }
  return { requester, doctor, patientName, patient };
}

// Controller dell'accesso alle cartelle cliniche.
export function recordsController(store: Store, ledger: Ledger, vault: Vault) {
  // Cartella consegnata al medico autorizzato: i referti sono decifrati solo ora,
  // in memoria, e solo dopo che l'accesso è stato registrato sulla catena.
  async function record(patient: string, entryId: bigint) {
    const documents = await Promise.all(
      (await store.listDocuments(patient)).map(async (doc) => {
        let content;
        try {
          content = openDocument(vault, doc);
        } catch {
          // AES-GCM ha rilevato un'alterazione: il documento non viene consegnato.
          console.error(`Referto ${doc.id} alterato o non decifrabile`);
          return { id: doc.id, createdAt: doc.createdAt, error: "integrità non verificata" };
        }
        // La firma si verifica a ogni consegna; al medico arrivano autore, data ed esito,
        // non i dati grezzi della firma.
        const sig = content.signature;
        const signature = sig
          ? {
              author: sig.author,
              signedAt: sig.signedAt,
              valid: await verifyDocumentSignature(patient, content.title, content.body, sig),
            }
          : null;
        return { id: doc.id, createdAt: doc.createdAt, title: content.title, body: content.body, signature };
      }),
    );
    return { patient, auditEntry: entryId.toString(), documents };
  }

  return {
    // Accesso ordinario: serve un consenso valido per la finalità dichiarata.
    async access(req: Request, res: Response): Promise<void> {
      const p = await parties(store, req, res);
      if (!p) return;
      const purposeName = req.body?.purpose;
      const purpose = typeof purposeName === "string" ? PURPOSES.get(purposeName) : undefined;
      if (purpose === undefined) {
        res.status(400).json({ error: "finalità non valida" });
        return;
      }

      // Registra l'accesso con l'esito indicato e ne conserva i dettagli off-chain.
      const audit = async (granted: boolean) => {
        const details: AccessDetails = {
          kind: "ordinary",
          requester: p.requester,
          patient: p.patientName,
          purpose: purposeName,
          outcome: granted ? "granted" : "denied",
          at: new Date().toISOString(),
          nonce: nonce(),
        };
        const recordHash = fingerprint(details);
        const entryId = await ledger.recordAccess({
          patient: p.patient.address,
          accessor: p.doctor.address,
          purpose,
          outcome: granted ? Outcome.Granted : Outcome.Denied,
          recordHash,
        });
        await store.addAccessLog(sealAccessLog(vault, entryId, details));
        return entryId;
      };

      let granted: boolean;
      let entryId: bigint;
      try {
        granted = await ledger.isConsentValid(p.patient.address, p.doctor.address, purpose);
        try {
          entryId = await audit(granted);
        } catch (err) {
          // Il consenso è stato revocato tra la lettura e la scrittura: il contratto
          // rifiuta "concesso", e l'accesso viene registrato e trattato come negato.
          if (!(err instanceof LedgerRevert && err.errorName === "ConsentNotValid")) throw err;
          granted = false;
          entryId = await audit(false);
        }
      } catch (err) {
        // Senza registro di audit non si consegna nulla (fail-closed).
        console.error(`Registro di audit non disponibile: ${(err as Error).message}`);
        res.status(503).json({ error: "registro di audit non disponibile, riprova più tardi" });
        return;
      }

      if (!granted) {
        res.status(403).json({ error: "nessun consenso valido per questa finalità" });
        return;
      }
      res.json(await record(p.patientName, entryId));
    },

    // Accesso d'emergenza (break-glass): niente consenso, ma motivazione obbligatoria
    // e medico abilitato sul contratto. La decisione spetta al contratto, non al backend.
    async emergency(req: Request, res: Response): Promise<void> {
      const p = await parties(store, req, res);
      if (!p) return;
      const reason = req.body?.reason;
      if (typeof reason !== "string" || reason.trim().length < 10 || reason.length > 500) {
        res.status(400).json({ error: "motivazione obbligatoria (da 10 a 500 caratteri)" });
        return;
      }

      const details: AccessDetails = {
        kind: "emergency",
        requester: p.requester,
        patient: p.patientName,
        reason,
        at: new Date().toISOString(),
        nonce: nonce(),
      };
      const recordHash = fingerprint(details);
      let entryId: bigint;
      try {
        entryId = await ledger.recordEmergencyAccess({
          patient: p.patient.address,
          accessor: p.doctor.address,
          reasonHash: fingerprint({ reason, nonce: details.nonce }),
          recordHash,
        });
        await store.addAccessLog(sealAccessLog(vault, entryId, details));
      } catch (err) {
        if (err instanceof LedgerRevert && err.errorName === "NotEmergencyStaff") {
          // Il contratto non lascia traccia dei tentativi respinti: li conserviamo noi,
          // perché un tentativo d'emergenza non autorizzato va sempre revisionato.
          await store.addAccessLog(sealAccessLog(vault, null, { ...details, kind: "emergency-rejected" }));
          console.warn("Accesso d'emergenza respinto: medico non abilitato (dettagli nel registro cifrato)");
          res.status(403).json({ error: "non abilitato all'accesso d'emergenza" });
          return;
        }
        console.error(`Registro di audit non disponibile: ${(err as Error).message}`);
        res.status(503).json({ error: "registro di audit non disponibile, riprova più tardi" });
        return;
      }
      res.json(await record(p.patientName, entryId));
    },
  };
}
