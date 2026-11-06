import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createApp } from "../src/app.js";
import { MemoryStore } from "../src/models/memoryStore.js";
import { config } from "../src/config.js";
import { FLAG_AT, FLAG_UP, SoftAuthenticator } from "./softAuthenticator.js";

let server: Server;
let baseUrl: string;

before(async () => {
  server = createApp(new MemoryStore()).listen(0);
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

async function register(username: string, auth: SoftAuthenticator, origin = config.origin, flags?: number) {
  const options = await post("/register/options", { username });
  return post("/register/verify", { username, response: auth.register(options.body, origin, flags) });
}

async function login(username: string, auth: SoftAuthenticator, origin = config.origin) {
  const options = await post("/authenticate/options", { username });
  return post("/authenticate/verify", { username, response: auth.authenticate(options.body, origin) });
}

describe("FIDO2: casi legittimi", () => {
  it("registra una passkey e poi effettua il login", async () => {
    const auth = new SoftAuthenticator();
    assert.equal((await register("anna.bianchi", auth)).status, 200);
    const res = await login("anna.bianchi", auth);
    assert.equal(res.status, 200);
    assert.equal(res.body.verified, true);
  });

  it("accetta login successivi con signCount crescente", async () => {
    const auth = new SoftAuthenticator();
    await register("carla.neri", auth);
    for (let i = 0; i < 3; i++) {
      assert.equal((await login("carla.neri", auth)).status, 200);
    }
  });
});

describe("FIDO2: attacchi", () => {
  it("replay: una risposta di login già usata viene rifiutata", async () => {
    const auth = new SoftAuthenticator();
    await register("dario.gallo", auth);
    const options = await post("/authenticate/options", { username: "dario.gallo" });
    const captured = auth.authenticate(options.body, config.origin);
    assert.equal((await post("/authenticate/verify", { username: "dario.gallo", response: captured })).status, 200);

    // L'attaccante ha intercettato la risposta e la rimanda su una nuova sessione.
    await post("/authenticate/options", { username: "dario.gallo" });
    const replay = await post("/authenticate/verify", { username: "dario.gallo", response: captured });
    assert.equal(replay.status, 401);
  });

  it("phishing: una registrazione da un origin diverso viene rifiutata", async () => {
    const res = await register("elena.costa", new SoftAuthenticator(), "https://cartella-clinica.evil.example");
    assert.equal(res.status, 400);
  });

  it("phishing: un login da un origin diverso viene rifiutato", async () => {
    const auth = new SoftAuthenticator();
    await register("fabio.ricci", auth);
    const res = await login("fabio.ricci", auth, "https://cartella-clinica.evil.example");
    assert.equal(res.status, 401);
  });

  it("clonazione: un signCount che torna indietro viene rifiutato", async () => {
    const auth = new SoftAuthenticator();
    await register("giulia.moro", auth);
    await login("giulia.moro", auth);
    await login("giulia.moro", auth);
    // Il clone parte da uno stato vecchio della chiave: il suo contatore è indietro.
    auth.counter = 0;
    assert.equal((await login("giulia.moro", auth)).status, 401);
  });

  it("credenziale sconosciuta: un altro dispositivo non può entrare", async () => {
    await register("luca.ferri", new SoftAuthenticator());
    const res = await login("luca.ferri", new SoftAuthenticator());
    assert.equal(res.status, 401);
  });

  it("senza verifica dell'utente (impronta o PIN) la registrazione è rifiutata", async () => {
    const res = await register("marta.villa", new SoftAuthenticator(), config.origin, FLAG_UP | FLAG_AT);
    assert.equal(res.status, 400);
  });

  it("la stessa credenziale non può essere registrata da due utenti", async () => {
    const auth = new SoftAuthenticator();
    assert.equal((await register("nino.sala", auth)).status, 200);
    assert.equal((await register("olga.riva", auth)).status, 409);
  });
});
