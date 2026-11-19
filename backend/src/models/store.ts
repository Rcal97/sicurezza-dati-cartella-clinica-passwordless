import type { WebAuthnCredential } from "@simplewebauthn/server";
import type { ConsentMessage } from "../crypto/consent.js";
import type { SignedPayload } from "../crypto/signature.js";
import type { SealedDocument } from "../crypto/vault.js";

// Model dell'architettura MVC: l'unico punto di accesso ai dati off-chain.
// Le implementazioni sono due: in memoria (test) e su MongoDB (server).

export interface User {
  username: string;
  webauthnUserID: string;
  credentials: WebAuthnCredential[];
}

export interface PendingRegistration {
  challenge: string;
  webauthnUserID: string;
}

// Ruolo di un utente, assegnato dopo l'identificazione. Il paziente ha in più:
// - address: l'indirizzo del suo wallet, con cui firma i consensi (resta off-chain);
// - secret: 32 byte casuali da cui derivano le ancore dei suoi consensi sulla catena.
//   Cancellandolo (art. 17), quelle ancore non si ricollegano più a lui.
export type Role = "doctor" | "patient";
export interface Profile {
  role: Role;
  address?: string;
  secret?: string;
}

// Dettagli di un accesso, conservati off-chain: sulla catena va solo la loro impronta.
export type AccessDetails =
  | {
      kind: "ordinary";
      requester: string;
      patient: string;
      purpose: string;
      outcome: "granted" | "denied";
      at: string;
      nonce: string;
    }
  | {
      kind: "document-signed";
      requester: string;
      patient: string;
      documentId: string;
      at: string;
      nonce: string;
    }
  | {
      // "emergency-rejected": tentativo respinto dal contratto, che non lascia traccia
      // sulla catena; resta però nel registro off-chain.
      kind: "emergency" | "emergency-rejected";
      requester: string;
      patient: string;
      reason: string;
      at: string;
      nonce: string;
    };

// Voce del registro degli accessi off-chain. I dettagli contengono dati personali e,
// negli accessi d'emergenza, la motivazione clinica: sono conservati cifrati.
export interface AccessLogEntry {
  entryId: string | null; // voce sul registro di audit on-chain; null se non registrata
  patientTag: string; // etichetta HMAC del paziente, per trovarne le voci senza il nome in chiaro
  recordHash: string; // impronta dei dettagli in chiaro (la stessa scritta sulla catena)
  createdAt: string;
  sealed: SealedDocument;
}

// Referto conservato cifrato: in chiaro restano solo identificativo, paziente e data.
export interface StoredDocument {
  id: string;
  patient: string;
  createdAt: string;
  sealed: SealedDocument;
}

// Ricevuta di un consenso, cifrata. In chiaro restano l'ancora (già pubblica sulla catena),
// l'etichetta HMAC del paziente per cercarle e l'impronta scritta sulla catena.
export interface StoredConsent {
  consentId: string;
  patientTag: string;
  receiptHash: string;
  createdAt: string;
  sealed: SealedDocument;
}

// Richiesta di firma di un consenso, in attesa che il paziente firmi con il wallet.
export interface ConsentRequest {
  username: string;
  message: ConsentMessage;
}

export interface SignatureRequest {
  username: string; // il medico che ha chiesto di firmare
  payload: SignedPayload;
}

export interface Store {
  getUser(username: string): Promise<User | null>;
  // Aggiunge una credenziale all'utente (creandolo se serve).
  // Restituisce "duplicate" se l'ID della credenziale è già registrato.
  addCredential(username: string, webauthnUserID: string, credential: WebAuthnCredential): Promise<"ok" | "duplicate">;
  // Aggiorna il contatore solo se vale ancora "expected" (compare-and-set): due login
  // contemporanei con lo stesso valore, come quelli di una chiave clonata, non passano entrambi.
  updateCounter(username: string, credentialID: string, expected: number, counter: number): Promise<boolean>;

  // Challenge monouso: "take" le legge e le cancella in un'unica operazione.
  savePendingRegistration(username: string, pending: PendingRegistration, ttlMs: number): Promise<void>;
  takePendingRegistration(username: string): Promise<PendingRegistration | null>;
  // Le challenge di login sono indicizzate dal loro valore e non dallo username:
  // chi chiede opzioni per un altro utente non può invalidare la sua challenge.
  saveLoginChallenge(challenge: string, ttlMs: number): Promise<void>;
  takeLoginChallenge(challenge: string): Promise<boolean>;
  // Richieste di firma di un referto: la challenge è l'impronta del contenuto da firmare.
  saveSignatureRequest(challenge: string, request: SignatureRequest, ttlMs: number): Promise<void>;
  // Consumata solo dal medico che l'ha aperta: un altro utente non può invalidarla.
  takeSignatureRequest(challenge: string, username: string): Promise<SignatureRequest | null>;
  // Richieste di firma di un consenso, indicizzate dal nonce e consumate solo dal paziente che le ha aperte.
  saveConsentRequest(nonce: string, request: ConsentRequest, ttlMs: number): Promise<void>;
  takeConsentRequest(nonce: string, username: string): Promise<ConsentRequest | null>;

  // Inviti alla registrazione, rilasciati dopo l'identificazione dell'utente (identity proofing).
  // Sono legati a uno username, monouso e indicizzati dall'hash del codice.
  // "erased" se lo username appartiene a un utente cancellato: non si riassegna a un'altra persona.
  createInvitation(codeHash: string, username: string, ttlMs: number): Promise<"ok" | "erased">;
  hasInvitation(codeHash: string, username: string): Promise<boolean>;
  // Consuma l'invito in modo atomico: restituisce true una sola volta.
  takeInvitation(codeHash: string, username: string): Promise<boolean>;

  // Sessioni indicizzate dall'hash del token, mai dal token in chiaro.
  // Una sessione scade dopo idleMs di inattività e comunque dopo maxMs dalla creazione.
  createSession(tokenHash: string, username: string, idleMs: number, maxMs: number): Promise<void>;
  // Restituisce l'utente e rinnova la scadenza; null se la sessione non esiste o è scaduta.
  touchSession(tokenHash: string, idleMs: number): Promise<string | null>;
  deleteSession(tokenHash: string): Promise<void>;
  // Chiude tutte le sessioni di un utente (dispositivo perso, passkey revocata).
  deleteSessionsOf(username: string): Promise<void>;

  // Revoca di una passkey: "last" se è l'ultima rimasta (l'utente resterebbe chiuso fuori),
  // "missing" se l'utente non ha quella credenziale.
  removeCredential(username: string, credentialID: string): Promise<"ok" | "last" | "missing">;
  // Revoca di tutte le passkey (dispositivi persi): serve un nuovo invito per rientrare.
  removeAllCredentials(username: string): Promise<void>;

  // Profili: un indirizzo di wallet appartiene a un solo utente ("duplicate" altrimenti).
  setProfile(username: string, profile: Profile): Promise<"ok" | "duplicate">;
  getProfile(username: string): Promise<Profile | null>;
  // Elenco dei medici (solo nomi utente), per scegliere a chi dare il consenso.
  listDoctors(): Promise<string[]>;

  // Ricevute dei consensi, in ordine di registrazione.
  addConsent(entry: StoredConsent): Promise<void>;
  listConsentsOf(patientTag: string): Promise<StoredConsent[]>;
  // L'ultima ricevuta registrata per un'ancora (concessione o revoca), se c'è.
  latestConsent(consentId: string): Promise<StoredConsent | null>;

  // Copia off-chain dei dettagli degli accessi registrati sulla catena.
  addAccessLog(entry: AccessLogEntry): Promise<void>;
  listAccessLog(): Promise<AccessLogEntry[]>;
  listAccessLogOf(patientTag: string): Promise<AccessLogEntry[]>;

  // Referti cifrati di un paziente.
  addDocument(doc: StoredDocument): Promise<void>;
  listDocuments(patient: string): Promise<StoredDocument[]>;

  // Cancellazione su richiesta (art. 17 GDPR): identità digitale e profilo, con il segreto da
  // cui derivano le ancore sulla catena; i referti solo se richiesto, perché la documentazione
  // clinica ha obblighi di conservazione. Il registro degli accessi e le ricevute dei consensi
  // restano, cifrati, per dimostrare la liceità di quanto avvenuto (accountability, art. 5.2).
  eraseUser(username: string, options: { documents: boolean }): Promise<ErasureResult>;

  close(): Promise<void>;
}

export interface ErasureResult {
  account: boolean; // passkey e identificativo WebAuthn
  profile: boolean; // ruolo, wallet e segreto delle ancore
  sessions: number;
  invitations: number;
  documents: number; // referti cancellati (0 se conservati)
  documentsKept: number; // referti conservati
}
