import { mkdirSync, writeFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { Wallet } from "ethers";

// Campagne d'attacco ripetute contro il backend vero (archivi in memoria).
// Per ogni scenario si misura, prova dopo prova, se l'attacco riesce e se l'operazione
// legittima corrispondente riesce ancora: la sicurezza non deve costare disponibilità.
//
// Uso: npm run bench:attacchi
// Confronto con una versione precedente del backend (solo scenari di autenticazione):
//   APP_DIR=<cartella backend della versione> VERSIONE=<nome> npm run bench:attacchi
const APP = pathToFileURL(resolve(process.env.APP_DIR ?? new URL("..", import.meta.url).pathname) + "/").href;
const VERSIONE = process.env.VERSIONE ?? "attuale";
const SOLO_AUTENTICAZIONE = process.env.APP_DIR !== undefined;
const PROVE = Number(process.env.PROVE ?? 30);

const { createApp } = await import(APP + "src/app.ts");
const { MemoryStore } = await import(APP + "src/models/memoryStore.ts");
const { MemoryLedger } = await import(APP + "src/models/memoryLedger.ts");
const { Vault } = await import(APP + "src/crypto/vault.ts");
const { invite } = await import(APP + "test/helpers.ts");
const { SoftAuthenticator } = await import(APP + "test/softAuthenticator.ts");
const { config } = await import(APP + "src/config.ts");

const EVIL = "https://cartella-clinica.evil.example";
const store = new MemoryStore();
const ledger = new MemoryLedger();
const vault = Vault.generate();
// La versione attuale accetta le opzioni (limite di frequenza alto per non falsare le misure).
const server = createApp(store, ledger, vault, { maxRequestsPerMinute: 1_000_000 }).listen(0);
await new Promise((r) => server.once("listening", r));
const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

type Res = { status: number; setCookie: string; body: any };
async function call(path: string, body: unknown, cookie?: string): Promise<Res> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (cookie) headers.Cookie = cookie;
  const r = await fetch(base + path, { method: "POST", headers, body: JSON.stringify(body) });
  return { status: r.status, setCookie: r.headers.get("set-cookie") ?? "", body: await r.json().catch(() => ({})) };
}

let counter = 0;
const nuovo = (prefisso: string) => `${prefisso}.${++counter}`;

async function registra(username: string, auth = new SoftAuthenticator()) {
  const invitation = await invite(store, username);
  const o = await call("/webauthn/register/options", { username, invitation });
  await call("/webauthn/register/verify", { username, invitation, response: auth.register(o.body, config.origin) });
  return auth;
}

async function login(username: string, auth: any, origin = config.origin) {
  const o = await call("/webauthn/authenticate/options", { username });
  const r = await call("/webauthn/authenticate/verify", { username, response: auth.authenticate(o.body, origin) });
  return { ok: r.status === 200, cookie: r.setCookie.split(";")[0] };
}

async function utente(role: "doctor" | "patient") {
  const username = nuovo(role === "doctor" ? "dr" : "paz");
  const address = Wallet.createRandom().address;
  await store.setProfile(username, { role, address });
  const auth = await registra(username);
  const { cookie } = await login(username, auth);
  return { username, address, auth, cookie };
}

const consenso = (p: { address: string }, d: { address: string }, finalita = 0) => ledger.grantConsent(p.address, d.address, finalita);
const apri = (d: { cookie: string }, p: { username: string }, purpose = "care") =>
  call("/records/access", { patient: p.username, purpose }, d.cookie);

async function firma(d: any, paziente: string, firmatario = d.auth, cookieVerifica = d.cookie) {
  const o = await call("/records/documents/options", { patient: paziente, title: "Visita", body: "Nessuna anomalia." }, d.cookie);
  if (o.status !== 200) return o;
  return call("/records/documents/verify", { response: firmatario.authenticate(o.body, config.origin) }, cookieVerifica);
}

// Ogni scenario restituisce [attacco riuscito, operazione legittima riuscita].
type Scenario = { nome: string; autenticazione: boolean; prova: () => Promise<[boolean, boolean]> };
const scenari: Scenario[] = [
  {
    nome: "Phishing: login da un sito clone",
    autenticazione: true,
    prova: async () => {
      const u = nuovo("u");
      const auth = await registra(u);
      return [(await login(u, auth, EVIL)).ok, (await login(u, auth)).ok];
    },
  },
  {
    nome: "Replay di una risposta di login",
    autenticazione: true,
    prova: async () => {
      const u = nuovo("u");
      const auth = await registra(u);
      const o = await call("/webauthn/authenticate/options", { username: u });
      const captured = auth.authenticate(o.body, config.origin);
      const legit = (await call("/webauthn/authenticate/verify", { username: u, response: captured })).status === 200;
      await call("/webauthn/authenticate/options", { username: u });
      const replay = (await call("/webauthn/authenticate/verify", { username: u, response: captured })).status === 200;
      return [replay, legit];
    },
  },
  {
    nome: "Clone usato in parallelo all'originale",
    autenticazione: true,
    prova: async () => {
      const u = nuovo("u");
      const auth = await registra(u);
      const clone = Object.assign(Object.create(Object.getPrototypeOf(auth)), auth);
      const o1 = await call("/webauthn/authenticate/options", { username: u });
      const o2 = await call("/webauthn/authenticate/options", { username: u });
      const [a, b] = await Promise.all([
        call("/webauthn/authenticate/verify", { username: u, response: auth.authenticate(o1.body, config.origin) }),
        call("/webauthn/authenticate/verify", { username: u, response: clone.authenticate(o2.body, config.origin) }),
      ]);
      const riusciti = [a, b].filter((r) => r.status === 200).length;
      return [riusciti === 2, (await login(u, auth)).ok];
    },
  },
  {
    nome: "Blocco del login altrui (DoS)",
    autenticazione: true,
    prova: async () => {
      const u = nuovo("u");
      const auth = await registra(u);
      const mine = await call("/webauthn/authenticate/options", { username: u });
      await call("/webauthn/authenticate/options", { username: u }); // l'attaccante
      const r = await call("/webauthn/authenticate/verify", { username: u, response: auth.authenticate(mine.body, config.origin) });
      return [r.status !== 200, (await login(u, auth)).ok];
    },
  },
  {
    nome: "Enumerazione degli utenti",
    autenticazione: true,
    prova: async () => {
      const u = nuovo("u");
      const auth = await registra(u);
      const a = await call("/webauthn/authenticate/options", { username: u });
      const b = await call("/webauthn/authenticate/options", { username: nuovo("inesistente") });
      const distinguibili = (a.body.allowCredentials ?? []).length !== (b.body.allowCredentials ?? []).length;
      return [distinguibili, (await login(u, auth)).ok];
    },
  },
  {
    nome: "Passkey aggiunta all'account di un altro",
    autenticazione: true,
    prova: async () => {
      const u = nuovo("u");
      await registra(u);
      const attacker = new SoftAuthenticator();
      const o = await call("/webauthn/register/options", { username: u });
      const r = o.status === 200 ? await call("/webauthn/register/verify", { username: u, response: attacker.register(o.body, config.origin) }) : o;
      // Operazione legittima: registrazione di un nuovo utente con un invito valido.
      const v = nuovo("u");
      const invitation = await invite(store, v);
      const ov = await call("/webauthn/register/options", { username: v, invitation });
      const rv = await call("/webauthn/register/verify", { username: v, invitation, response: new SoftAuthenticator().register(ov.body, config.origin) });
      return [r.status === 200, rv.status === 200];
    },
  },
  {
    nome: "Cartella aperta per una finalità senza consenso",
    autenticazione: false,
    prova: async () => {
      const d = await utente("doctor");
      const p = await utente("patient");
      consenso(p, d, 0);
      return [(await apri(d, p, "research")).status === 200, (await apri(d, p, "care")).status === 200];
    },
  },
  {
    nome: "Cartella aperta dopo la revoca del consenso",
    autenticazione: false,
    prova: async () => {
      const d = await utente("doctor");
      const p = await utente("patient");
      consenso(p, d, 0);
      const legit = (await apri(d, p)).status === 200;
      ledger.revokeConsent(p.address, d.address, 0);
      return [(await apri(d, p)).status === 200, legit];
    },
  },
  {
    nome: "Paziente che apre la cartella di un altro",
    autenticazione: false,
    prova: async () => {
      const d = await utente("doctor");
      const p1 = await utente("patient");
      const p2 = await utente("patient");
      consenso(p2, d, 0);
      return [(await apri(p1, p2)).status === 200, (await apri(d, p2)).status === 200];
    },
  },
  {
    nome: "Accesso d'emergenza senza abilitazione",
    autenticazione: false,
    prova: async () => {
      const d = await utente("doctor");
      const er = await utente("doctor");
      const p = await utente("patient");
      ledger.emergencyStaff.add(er.address.toLowerCase());
      const reason = "Paziente incosciente in pronto soccorso";
      const attack = (await call("/records/emergency", { patient: p.username, reason }, d.cookie)).status === 200;
      const legit = (await call("/records/emergency", { patient: p.username, reason }, er.cookie)).status === 200;
      return [attack, legit];
    },
  },
  {
    nome: "Referto firmato con la passkey di un altro",
    autenticazione: false,
    prova: async () => {
      const d = await utente("doctor");
      const other = await utente("doctor");
      const p = await utente("patient");
      consenso(p, d, 0);
      return [(await firma(d, p.username, other.auth)).status === 200, (await firma(d, p.username)).status === 200];
    },
  },
  {
    nome: "Firma intercettata riusata da un collega",
    autenticazione: false,
    prova: async () => {
      const d = await utente("doctor");
      const other = await utente("doctor");
      const p = await utente("patient");
      consenso(p, d, 0);
      const o = await call("/records/documents/options", { patient: p.username, title: "Visita", body: "Ok." }, d.cookie);
      const response = d.auth.authenticate(o.body, config.origin);
      const attack = (await call("/records/documents/verify", { response }, other.cookie)).status === 200;
      const legit = (await call("/records/documents/verify", { response }, d.cookie)).status === 200;
      return [attack, legit];
    },
  },
  {
    nome: "Referto scambiato nel database",
    autenticazione: false,
    prova: async () => {
      const d = await utente("doctor");
      const p = await utente("patient");
      consenso(p, d, 0);
      await firma(d, p.username);
      await firma(d, p.username);
      const docs = store.documents.filter((x: any) => x.patient === p.username);
      docs[1].sealed = { ...docs[1].sealed, ciphertext: docs[0].sealed.ciphertext };
      const r = await apri(d, p);
      const attack = r.body.documents?.some((x: any) => x.id === docs[1].id && !x.error) ?? false;
      const legit = r.body.documents?.some((x: any) => x.id === docs[0].id && x.signature?.valid) ?? false;
      return [attack, legit];
    },
  },
];

const OUT = new URL("../../analisi/dati/", import.meta.url);
mkdirSync(OUT, { recursive: true });
const rows: string[] = [];
for (const s of scenari) {
  if (SOLO_AUTENTICAZIONE && !s.autenticazione) continue;
  for (let i = 0; i < PROVE; i++) {
    const [attacco, legittimo] = await s.prova();
    rows.push([VERSIONE, JSON.stringify(s.nome), i, Number(attacco), Number(legittimo)].join(","));
  }
  console.log(`${s.nome}: fatto`);
}

// Intensità dell'attacco al login: la vittima chiede le opzioni, l'attaccante ne chiede k
// a nome suo prima che la vittima completi il login.
const dos: string[] = [];
for (const k of [0, 1, 2, 5, 10, 20]) {
  for (let i = 0; i < PROVE; i++) {
    const u = nuovo("dos");
    const auth = await registra(u);
    const mine = await call("/webauthn/authenticate/options", { username: u });
    for (let j = 0; j < k; j++) await call("/webauthn/authenticate/options", { username: u });
    const r = await call("/webauthn/authenticate/verify", { username: u, response: auth.authenticate(mine.body, config.origin) });
    dos.push([VERSIONE, k, i, Number(r.status === 200)].join(","));
  }
}

const suffisso = VERSIONE === "attuale" ? "" : `-${VERSIONE}`;
writeFileSync(new URL(`attacchi${suffisso}.csv`, OUT), ["versione,scenario,prova,attacco_riuscito,legittimo_riuscito", ...rows].join("\n") + "\n");
writeFileSync(new URL(`login_dos${suffisso}.csv`, OUT), ["versione,richieste_attaccante,prova,vittima_entra", ...dos].join("\n") + "\n");
console.log(`Scritti attacchi${suffisso}.csv (${rows.length} righe) e login_dos${suffisso}.csv (${dos.length} righe)`);
server.close();
