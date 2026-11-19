import { randomBytes } from "node:crypto";
import type { Request, Response } from "express";
import { getAddress, isHexString } from "ethers";
import { config } from "../config.js";
import {
  consentAnchor,
  consentDomain,
  CONSENT_TYPES,
  openConsentReceipt,
  recoverSigner,
  sealConsentReceipt,
  type ConsentMessage,
  type ConsentReceipt,
} from "../crypto/consent.js";
import type { Vault } from "../crypto/vault.js";
import { LedgerRevert, type Ledger } from "../models/ledger.js";
import type { Profile, Store } from "../models/store.js";
import { NOTICE_HASH, NOTICE_VERSION } from "../privacy.js";
import { USERNAME } from "./registration.js";

// Finalità ammesse. Un Set, non un oggetto: "toString" o "__proto__" non devono passare.
export const PURPOSES = new Set(["care", "research", "administration"]);
export const MAX_DAYS = 365;

const nowSeconds = () => Math.floor(Date.now() / 1000);

// Un consenso vale solo se le due fonti concordano (fail-closed):
// - sulla catena l'ancora risulta valida (non revocata e non scaduta);
// - l'ultima ricevuta conservata per quell'ancora è una concessione, firmata dal paziente,
//   per lo stesso medico e la stessa finalità, e non è scaduta.
// Concessione e revoca scrivono prima sulla catena e poi la ricevuta: se una delle due
// scritture manca, le fonti non concordano e l'accesso è negato.
export async function consentStatus(
  store: Store,
  ledger: Ledger,
  vault: Vault,
  patientName: string,
  patient: Profile,
  doctorName: string,
  purpose: string,
): Promise<{ consentId: string; valid: boolean }> {
  if (!patient.secret) throw new Error(`Profilo di ${patientName} senza segreto delle ancore: rieseguire npm run profilo`);
  const consentId = consentAnchor(vault, patient.secret, doctorName, purpose);
  const onChain = await ledger.isConsentValid(consentId);
  if (!onChain) return { consentId, valid: false };
  const latest = await store.latestConsent(consentId);
  if (!latest) return { consentId, valid: false };
  let receipt: ConsentReceipt;
  try {
    receipt = openConsentReceipt(vault, latest);
  } catch {
    console.error(`Ricevuta del consenso ${latest.receiptHash} alterata o non decifrabile`);
    return { consentId, valid: false };
  }
  const m = receipt.message;
  const valid =
    m.action === "grant" &&
    m.patient === patientName &&
    m.doctor === doctorName &&
    m.purpose === purpose &&
    m.expiresAt > nowSeconds();
  return { consentId, valid };
}

// Gestione dei consensi da parte del paziente, in due passi come le passkey:
// 1. options: il server prepara il messaggio EIP-712 da firmare (con nonce e informativa);
// 2. verify: il paziente lo ha firmato nel wallet; il server verifica la firma, registra
//    l'ancora sulla catena e conserva la ricevuta cifrata.
export function consentsController(store: Store, ledger: Ledger, vault: Vault) {
  // Il richiedente deve essere un paziente con il profilo completo.
  async function patientOf(res: Response): Promise<{ username: string; profile: Required<Profile> } | null> {
    const username: string = res.locals.username;
    const profile = await store.getProfile(username);
    if (profile?.role !== "patient") {
      res.status(403).json({ error: "solo il paziente può gestire i propri consensi" });
      return null;
    }
    if (!profile.address || !profile.secret) {
      res.status(409).json({ error: "profilo incompleto: rivolgersi alla struttura" });
      return null;
    }
    return { username, profile: profile as Required<Profile> };
  }

  return {
    async options(req: Request, res: Response): Promise<void> {
      const p = await patientOf(res);
      if (!p) return;
      const { action, doctor, purpose, days } = req.body ?? {};
      if (action !== "grant" && action !== "revoke") {
        res.status(400).json({ error: "operazione non valida" });
        return;
      }
      if (typeof doctor !== "string" || !USERNAME.test(doctor) || (await store.getProfile(doctor))?.role !== "doctor") {
        res.status(400).json({ error: "medico non valido" });
        return;
      }
      if (typeof purpose !== "string" || !PURPOSES.has(purpose)) {
        res.status(400).json({ error: "finalità non valida" });
        return;
      }
      if (action === "grant" && (!Number.isInteger(days) || days < 1 || days > MAX_DAYS)) {
        res.status(400).json({ error: `durata non valida (da 1 a ${MAX_DAYS} giorni)` });
        return;
      }
      const issuedAt = nowSeconds();
      const message: ConsentMessage = {
        action,
        patient: p.username,
        doctor,
        purpose,
        expiresAt: action === "grant" ? issuedAt + days * 86_400 : 0,
        noticeVersion: NOTICE_VERSION,
        noticeHash: NOTICE_HASH,
        issuedAt,
        nonce: "0x" + randomBytes(32).toString("hex"),
      };
      await store.saveConsentRequest(message.nonce, { username: p.username, message }, config.challengeTtlMs);
      res.json({ domain: consentDomain(ledger.chain), types: CONSENT_TYPES, primaryType: "Consent", message });
    },

    async verify(req: Request, res: Response): Promise<void> {
      const p = await patientOf(res);
      if (!p) return;
      const { nonce, signature } = req.body ?? {};
      if (!isHexString(nonce, 32) || !isHexString(signature, 65)) {
        res.status(400).json({ error: "richiesta non valida" });
        return;
      }
      // La richiesta vale una volta sola e solo per il paziente che l'ha aperta.
      const request = await store.takeConsentRequest(nonce, p.username);
      if (!request) {
        res.status(400).json({ error: "richiesta di firma assente o scaduta" });
        return;
      }
      const { message } = request;
      let signer: string;
      try {
        signer = recoverSigner(ledger.chain, message, signature);
      } catch {
        signer = "";
      }
      // La firma deve venire dal wallet registrato per il paziente.
      if (signer !== getAddress(p.profile.address)) {
        res.status(401).json({ error: "firma non valida o di un altro wallet" });
        return;
      }

      const receipt: ConsentReceipt = { domain: consentDomain(ledger.chain), message, signature, signer };
      const consentId = consentAnchor(vault, p.profile.secret, message.doctor, message.purpose);
      const stored = sealConsentReceipt(vault, consentId, receipt);
      try {
        if (message.action === "grant") await ledger.grantConsent(consentId, message.expiresAt, stored.receiptHash);
        else await ledger.revokeConsent(consentId, stored.receiptHash);
      } catch (err) {
        if (err instanceof LedgerRevert && err.errorName === "InvalidExpiry") {
          res.status(400).json({ error: "scadenza non valida" });
          return;
        }
        if (err instanceof LedgerRevert && err.errorName === "EnforcedPause") {
          res.status(503).json({ error: "registro dei consensi sospeso: le nuove concessioni non sono accettate" });
          return;
        }
        console.error(`Registro dei consensi non disponibile: ${(err as Error).message}`);
        res.status(503).json({ error: "registro dei consensi non disponibile, riprova più tardi" });
        return;
      }
      await store.addConsent(stored);
      res.json({ action: message.action, doctor: message.doctor, purpose: message.purpose, expiresAt: message.expiresAt, receiptHash: stored.receiptHash });
    },

    // I consensi del paziente: per ogni medico e finalità, l'ultima operazione e se oggi vale.
    async mine(_req: Request, res: Response): Promise<void> {
      const p = await patientOf(res);
      if (!p) return;
      const latest = new Map<string, ConsentReceipt & { receiptHash: string }>();
      for (const stored of await store.listConsentsOf(vault.indexTag(p.username))) {
        try {
          const receipt = openConsentReceipt(vault, stored);
          if (receipt.message.patient !== p.username) continue;
          latest.set(stored.consentId, { ...receipt, receiptHash: stored.receiptHash });
        } catch {
          console.error(`Ricevuta del consenso ${stored.receiptHash} alterata o non decifrabile`);
        }
      }
      const consents = [];
      for (const r of latest.values()) {
        const { consentId, valid } = await consentStatus(store, ledger, vault, p.username, p.profile, r.message.doctor, r.message.purpose);
        consents.push({
          doctor: r.message.doctor,
          purpose: r.message.purpose,
          action: r.message.action,
          expiresAt: r.message.expiresAt,
          signedAt: r.message.issuedAt,
          noticeVersion: r.message.noticeVersion,
          receiptHash: r.receiptHash,
          consentId,
          valid,
        });
      }
      res.json(consents);
    },
  };
}
