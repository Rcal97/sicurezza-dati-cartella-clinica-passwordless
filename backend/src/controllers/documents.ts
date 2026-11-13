import type { Request, Response } from "express";
import { generateAuthenticationOptions, verifyAuthenticationResponse, type AuthenticationResponseJSON } from "@simplewebauthn/server";
import { isoBase64URL } from "@simplewebauthn/server/helpers";
import { config } from "../config.js";
import { sealAccessLog, sealDocument } from "../crypto/records.js";
import { challengeFor, newPayload, payloadDigest } from "../crypto/signature.js";
import type { Vault } from "../crypto/vault.js";
import { LedgerRevert, Outcome, Purpose, type Ledger } from "../models/ledger.js";
import type { Store } from "../models/store.js";
import { challengeOf } from "./authentication.js";
import { parties } from "./records.js";
import { randomBytes, randomUUID } from "node:crypto";

const MAX_TITLE = 200;
const MAX_BODY = 20_000;

// Controller dei referti scritti e firmati dal medico.
export function documentsController(store: Store, ledger: Ledger, vault: Vault) {
  return {
    // 1. Il medico invia il referto; il server prepara la richiesta di firma.
    async options(req: Request, res: Response): Promise<void> {
      const p = await parties(store, req, res);
      if (!p) return;
      const { title, body } = req.body ?? {};
      if (typeof title !== "string" || title.trim().length === 0 || title.length > MAX_TITLE) {
        res.status(400).json({ error: `titolo obbligatorio (al massimo ${MAX_TITLE} caratteri)` });
        return;
      }
      if (typeof body !== "string" || body.trim().length === 0 || body.length > MAX_BODY) {
        res.status(400).json({ error: `testo obbligatorio (al massimo ${MAX_BODY} caratteri)` });
        return;
      }
      // Scrive nella cartella solo chi ha in cura il paziente: serve il consenso per la cura.
      let consent: boolean;
      try {
        consent = await ledger.isConsentValid(p.patient.address, p.doctor.address, Purpose.Care);
      } catch {
        res.status(503).json({ error: "registro dei consensi non disponibile, riprova più tardi" });
        return;
      }
      if (!consent) {
        res.status(403).json({ error: "nessun consenso valido per la cura di questo paziente" });
        return;
      }

      const payload = newPayload(p.patientName, p.requester, title, body);
      const user = await store.getUser(p.requester);
      // La challenge è l'impronta del referto: firmandola, la passkey firma il referto.
      // Qui l'elenco delle credenziali non rivela nulla: il medico è già autenticato.
      const options = await generateAuthenticationOptions({
        rpID: config.rpID,
        challenge: payloadDigest(payload),
        allowCredentials: user?.credentials.map((c) => ({ id: c.id, transports: c.transports })) ?? [],
        userVerification: "required",
      });
      await store.saveSignatureRequest(options.challenge, { username: p.requester, payload }, config.challengeTtlMs);
      res.json(options);
    },

    // 2. Il medico ha firmato con la passkey: si verifica la firma, si registra e si salva.
    async verify(req: Request, res: Response): Promise<void> {
      const requester: string = res.locals.username;
      const response = req.body?.response;
      if (typeof response !== "object" || response === null || typeof response.id !== "string") {
        res.status(400).json({ error: "richiesta non valida" });
        return;
      }
      const challenge = challengeOf(response);
      // La richiesta di firma vale una volta sola e solo per il medico che l'ha aperta.
      const request = challenge ? await store.takeSignatureRequest(challenge, requester) : null;
      if (!request || challenge !== challengeFor(request.payload)) {
        res.status(400).json({ error: "richiesta di firma assente o scaduta" });
        return;
      }

      // La firma deve venire da una passkey del medico stesso.
      const credential = (await store.getUser(requester))?.credentials.find((c) => c.id === response.id);
      if (!credential) {
        res.status(401).json({ error: "firma non valida" });
        return;
      }
      const expectedCounter = credential.counter;
      try {
        const result = await verifyAuthenticationResponse({
          response: response as AuthenticationResponseJSON,
          expectedChallenge: challenge!,
          expectedOrigin: config.origin,
          expectedRPID: config.rpID,
          credential,
          requireUserVerification: true,
        });
        if (!result.verified) throw new Error("firma non verificata");
        // Anche la firma fa avanzare il contatore: un clone resta riconoscibile.
        if (!(await store.updateCounter(requester, credential.id, expectedCounter, result.authenticationInfo.newCounter))) {
          throw new Error("uso contemporaneo della stessa credenziale");
        }
      } catch (err) {
        console.warn(`Firma di un referto rifiutata: ${(err as Error).message}`);
        res.status(401).json({ error: "firma non valida" });
        return;
      }

      const { payload } = request;
      const doctor = await store.getProfile(requester);
      const patient = await store.getProfile(payload.patient);
      if (doctor?.role !== "doctor" || patient?.role !== "patient") {
        res.status(403).json({ error: "operazione non consentita" });
        return;
      }

      const documentId = randomUUID();
      const details = {
        kind: "document-signed" as const,
        requester,
        patient: payload.patient,
        documentId,
        at: new Date().toISOString(),
        nonce: randomBytes(16).toString("hex"),
      };
      // Come per la lettura, anche la scrittura passa dal registro di audit, che verifica
      // di nuovo il consenso. Se la catena non risponde, il referto non viene salvato.
      try {
        const sealedLog = sealAccessLog(vault, null, details);
        const entryId = await ledger.recordAccess({
          patient: patient.address,
          accessor: doctor.address,
          purpose: Purpose.Care,
          outcome: Outcome.Granted,
          recordHash: sealedLog.recordHash,
        });
        await store.addAccessLog({ ...sealedLog, entryId: entryId.toString() });
      } catch (err) {
        if (err instanceof LedgerRevert && err.errorName === "ConsentNotValid") {
          res.status(403).json({ error: "nessun consenso valido per la cura di questo paziente" });
          return;
        }
        console.error(`Registro di audit non disponibile: ${(err as Error).message}`);
        res.status(503).json({ error: "registro di audit non disponibile, riprova più tardi" });
        return;
      }

      const signature = {
        author: requester,
        signedAt: payload.signedAt,
        nonce: payload.nonce,
        credentialId: credential.id,
        publicKey: isoBase64URL.fromBuffer(credential.publicKey),
        response: response as AuthenticationResponseJSON,
      };
      await store.addDocument(sealDocument(vault, payload.patient, { title: payload.title, body: payload.body, signature }, documentId));
      res.json({ id: documentId, signedAt: payload.signedAt });
    },
  };
}
