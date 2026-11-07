import { randomBytes } from "node:crypto";
import { config } from "../src/config.js";
import { hashToken } from "../src/middleware/session.js";
import type { Store } from "../src/models/store.js";

// Simula l'ufficio che, dopo aver identificato una persona, le rilascia un invito alla registrazione.
export async function invite(store: Store, username: string): Promise<string> {
  const code = randomBytes(16).toString("base64url");
  await store.createInvitation(hashToken(code), username, config.invitationTtlMs);
  return code;
}
