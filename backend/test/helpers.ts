import { randomBytes } from "node:crypto";
import { Wallet } from "ethers";
import { config } from "../src/config.js";
import { consentAnchor, consentDomain, CONSENT_TYPES, sealConsentReceipt, type ConsentMessage } from "../src/crypto/consent.js";
import type { Vault } from "../src/crypto/vault.js";
import { hashToken } from "../src/middleware/session.js";
import type { Ledger } from "../src/models/ledger.js";
import type { Role, Store } from "../src/models/store.js";
import { NOTICE_HASH, NOTICE_VERSION } from "../src/privacy.js";

// Simula l'ufficio che, dopo aver identificato una persona, le rilascia un invito alla registrazione.
export async function invite(store: Store, username: string): Promise<string> {
  const code = randomBytes(16).toString("base64url");
  await store.createInvitation(hashToken(code), username, config.invitationTtlMs);
  return code;
}

// Profilo come lo crea "npm run profilo": il medico ha solo il ruolo; il paziente ha il wallet
// con cui firma i consensi e il segreto delle ancore.
export async function makeProfile(store: Store, username: string, role: Role): Promise<Wallet | null> {
  if (role === "doctor") {
    await store.setProfile(username, { role });
    return null;
  }
  const wallet = new Wallet("0x" + randomBytes(32).toString("hex"));
  await store.setProfile(username, { role, address: wallet.address, secret: randomBytes(32).toString("hex") });
  return wallet;
}

// Il paziente firma il consenso (o la revoca) con il wallet e il backend lo registra: stessa
// sequenza del controller dei consensi, senza passare dall'API (che ha i suoi test).
export async function signConsent(
  store: Store,
  ledger: Ledger,
  vault: Vault,
  patient: { username: string; wallet: Wallet | null },
  doctor: string,
  purpose: string,
  action: "grant" | "revoke" = "grant",
  seconds = 3600,
): Promise<string> {
  const profile = (await store.getProfile(patient.username))!;
  const issuedAt = Math.floor(Date.now() / 1000);
  const message: ConsentMessage = {
    action,
    patient: patient.username,
    doctor,
    purpose,
    expiresAt: action === "grant" ? issuedAt + seconds : 0,
    noticeVersion: NOTICE_VERSION,
    noticeHash: NOTICE_HASH,
    issuedAt,
    nonce: "0x" + randomBytes(32).toString("hex"),
  };
  const domain = consentDomain(ledger.chain);
  const signature = await patient.wallet!.signTypedData(domain, CONSENT_TYPES, message);
  const consentId = consentAnchor(vault, profile.secret!, doctor, purpose);
  const stored = sealConsentReceipt(vault, consentId, { domain, message, signature, signer: patient.wallet!.address });
  if (action === "grant") await ledger.grantConsent(consentId, message.expiresAt, stored.receiptHash);
  else await ledger.revokeConsent(consentId, stored.receiptHash);
  await store.addConsent(stored);
  return consentId;
}
