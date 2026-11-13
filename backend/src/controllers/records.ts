import { createHash, randomBytes } from "node:crypto";
import type { Request, Response } from "express";
import { openDocument } from "../crypto/records.js";
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

// Impronta SHA-256 dei dettagli conservati off-chain: sulla catena va solo questa.
// I dettagli contengono un nonce casuale, quindi non si possono indovinare provando
// tutte le combinazioni di medico, paziente e finalità.
export function fingerprint(value: unknown): string {
  return "0x" + createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

const nonce = (): string => randomBytes(16).toString("hex");

interface Parties {
  requester: string;
  doctor: Profile;
  patientName: string;
  patient: Profile;
}

// Controlli comuni: chi chiede deve essere un medico, il paziente deve esistere.
async function parties(store: Store, req: Request, res: Response): Promise<Parties | null> {
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
    const documents = (await store.listDocuments(patient)).map((doc) => {
      try {
        return { id: doc.id, createdAt: doc.createdAt, ...openDocument(vault, doc) };
      } catch {
        // AES-GCM ha rilevato un'alterazione: il documento non viene consegnato.
        console.error(`Referto ${doc.id} alterato o non decifrabile`);
        return { id: doc.id, createdAt: doc.createdAt, error: "integrità non verificata" };
      }
    });
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
        await store.addAccessLog({ entryId: entryId.toString(), recordHash, details });
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
        await store.addAccessLog({ entryId: entryId.toString(), recordHash, details });
      } catch (err) {
        if (err instanceof LedgerRevert && err.errorName === "NotEmergencyStaff") {
          console.warn(`Accesso d'emergenza rifiutato: ${p.requester} non è abilitato`);
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
