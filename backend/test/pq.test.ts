import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { app } from "../src/app.js";
import { config } from "../src/config.js";
import { SoftAuthenticator } from "./softAuthenticator.js";

let server: Server;
let baseUrl: string;

before(async () => {
  server = app.listen(0);
  await new Promise((resolve) => server.once("listening", resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}/webauthn`;
});

after(() => {
  server.close();
});

async function post(path: string, body: unknown) {
  const res = await fetch(baseUrl + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}

describe("FIDO2 post-quantistico (ML-DSA-44, FIPS 204)", () => {
  it("il server offre ML-DSA-44 come algoritmo preferito", async () => {
    const options = await post("/register/options", { username: "pq.preferito" });
    assert.equal(options.body.pubKeyCredParams[0].alg, -48);
  });

  it("registra una passkey ML-DSA-44 e poi effettua il login", async () => {
    const auth = new SoftAuthenticator("ML-DSA-44");
    const regOptions = await post("/register/options", { username: "pq.utente" });
    const reg = await post("/register/verify", { username: "pq.utente", response: auth.register(regOptions.body, config.origin) });
    assert.equal(reg.status, 200);

    const options = await post("/authenticate/options", { username: "pq.utente" });
    const login = await post("/authenticate/verify", { username: "pq.utente", response: auth.authenticate(options.body, config.origin) });
    assert.equal(login.status, 200);
  });

  it("una firma ML-DSA prodotta da un'altra chiave viene rifiutata", async () => {
    const auth = new SoftAuthenticator("ML-DSA-44");
    const regOptions = await post("/register/options", { username: "pq.vittima" });
    await post("/register/verify", { username: "pq.vittima", response: auth.register(regOptions.body, config.origin) });

    // L'attaccante conosce l'ID della credenziale ma non la chiave privata.
    const attacker = new SoftAuthenticator("ML-DSA-44");
    const options = await post("/authenticate/options", { username: "pq.vittima" });
    const forged = { ...attacker.authenticate(options.body, config.origin), id: auth.id, rawId: auth.id };
    const login = await post("/authenticate/verify", { username: "pq.vittima", response: forged });
    assert.equal(login.status, 401);
  });
});
