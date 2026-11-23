import { useEffect, useState, type KeyboardEvent } from "react";
import {
  browserSupportsWebAuthn,
  startAuthentication,
  startRegistration,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";
import { api } from "./api";
import PannelloCartella from "./Cartella";
import PannelloConsensi from "./Consensi";
import Informativa from "./Informativa";
import MieiReferti from "./MieiReferti";

type Messaggio = { tipo: "ok" | "errore"; testo: string } | null;
type Passkey = { id: string; transports: string[] };
type Profilo = { username: string; role: "doctor" | "patient" | null; address: string | null };
type Scheda = { id: string; nome: string };

// Le schede dipendono dal ruolo: il paziente gestisce la propria cartella, il medico consulta quelle altrui.
const SCHEDE: Record<"doctor" | "patient" | "nessuno", Scheda[]> = {
  patient: [
    { id: "referti", nome: "Referti" },
    { id: "consensi", nome: "Consensi" },
    { id: "accessi", nome: "Accessi" },
    { id: "account", nome: "Account" },
  ],
  doctor: [
    { id: "cartella", nome: "Cartelle" },
    { id: "account", nome: "Account" },
  ],
  nessuno: [{ id: "account", nome: "Account" }],
};

const RUOLO = { doctor: "Medico", patient: "Paziente" } as const;

// Marchio: una cartella con la croce sanitaria, disegnata a mano in SVG (nessuna immagine esterna).
function Marchio() {
  return (
    <svg className="marchio" viewBox="0 0 32 32" aria-hidden="true">
      <path d="M3 8.5A2.5 2.5 0 0 1 5.5 6h6.4l2.6 3h12A2.5 2.5 0 0 1 29 11.5v13a2.5 2.5 0 0 1-2.5 2.5h-21A2.5 2.5 0 0 1 3 24.5z" />
      <path className="croce" d="M14.2 13h3.6v3.2H21v3.6h-3.2V23h-3.6v-3.2H11v-3.6h3.2z" />
    </svg>
  );
}

// Traduce gli errori più comuni in messaggi comprensibili per l'utente.
function descrivi(err: unknown): string {
  if (err instanceof Error) {
    if (err.name === "NotAllowedError") return "Operazione annullata o scaduta.";
    if (err.name === "InvalidStateError") return "Questo dispositivo è già registrato per l'utente.";
    return err.message;
  }
  return "Errore imprevisto.";
}

export default function App() {
  const [username, setUsername] = useState("");
  const [invito, setInvito] = useState("");
  const [utente, setUtente] = useState<string | null>(null);
  const [messaggio, setMessaggio] = useState<Messaggio>(null);
  const [inCorso, setInCorso] = useState(false);
  const [passkeys, setPasskeys] = useState<Passkey[]>([]);
  const [profilo, setProfilo] = useState<Profilo | null>(null);
  const [scheda, setScheda] = useState<string | null>(null);

  // All'avvio controlla se esiste già una sessione valida.
  useEffect(() => {
    api.me().then(setUtente);
  }, []);

  // Da autenticato, carica l'elenco delle proprie passkey.
  useEffect(() => {
    if (!utente) return;
    api.get<Passkey[]>("/session/passkeys").then(setPasskeys).catch(() => setPasskeys([]));
    api.get<Profilo>("/directory/profile").then(setProfilo).catch(() => setProfilo(null));
  }, [utente]);

  // All'uscita si azzera tutto lo stato legato all'utente: il profilo di chi è uscito
  // non deve restare in memoria quando dallo stesso browser accede qualcun altro.
  function chiudiSessione() {
    setUtente(null);
    setProfilo(null);
    setPasskeys([]);
    setScheda(null);
  }

  async function esegui(azione: () => Promise<void>) {
    setInCorso(true);
    setMessaggio(null);
    try {
      await azione();
    } catch (err) {
      setMessaggio({ tipo: "errore", testo: descrivi(err) });
    } finally {
      setInCorso(false);
    }
  }

  // Registrazione di una passkey: con un codice d'invito (prima volta) oppure,
  // da utente autenticato, per aggiungere un altro dispositivo al proprio account.
  async function registraPasskey(nome: string, invitation?: string) {
    const optionsJSON = await api.post<PublicKeyCredentialCreationOptionsJSON>("/webauthn/register/options", {
      username: nome,
      invitation,
    });
    // Il browser chiede all'autenticatore di creare la passkey (impronta, volto o PIN).
    const response = await startRegistration({ optionsJSON });
    await api.post("/webauthn/register/verify", { username: nome, invitation, response });
  }

  const registra = () =>
    esegui(async () => {
      await registraPasskey(username, invito);
      setInvito("");
      setMessaggio({ tipo: "ok", testo: "Passkey registrata. Ora puoi accedere." });
    });

  const aggiungi = () =>
    esegui(async () => {
      await registraPasskey(utente!);
      setMessaggio({ tipo: "ok", testo: "Nuova passkey aggiunta al tuo account." });
    });

  const accedi = () =>
    esegui(async () => {
      const optionsJSON = await api.post<PublicKeyCredentialRequestOptionsJSON>("/webauthn/authenticate/options", { username });
      // L'autenticatore firma la challenge con la chiave privata, che non lascia il dispositivo.
      const response = await startAuthentication({ optionsJSON });
      await api.post("/webauthn/authenticate/verify", { username, response });
      setUtente(await api.me());
    });

  const esci = () =>
    esegui(async () => {
      await api.post("/session/logout");
      chiudiSessione();
      setMessaggio({ tipo: "ok", testo: "Sei uscito." });
    });

  const esciOvunque = () =>
    esegui(async () => {
      await api.post("/session/logout-all");
      chiudiSessione();
      setMessaggio({ tipo: "ok", testo: "Sei uscito da tutti i dispositivi." });
    });

  // Revoca di una passkey (per esempio di un dispositivo perso): per sicurezza
  // il backend chiude tutte le sessioni, quindi bisogna accedere di nuovo.
  const revoca = (id: string) =>
    esegui(async () => {
      await api.post("/session/passkeys/revoke", { id });
      chiudiSessione();
      setMessaggio({ tipo: "ok", testo: "Passkey revocata. Accedi di nuovo con un dispositivo rimasto." });
    });

  const intestazione = (
    <span className="testata-marchio">
      <Marchio />
      <span>
        <span className="testata-nome">Cartella clinica</span>
        <span className="testata-ente">Struttura sanitaria di esempio</span>
      </span>
    </span>
  );
  const avviso = messaggio && (
    <p className={messaggio.tipo} role="status">
      {messaggio.testo}
    </p>
  );
  const piede = (
    <footer className="piede">
      Questo servizio usa un solo cookie tecnico di sessione, nessun cookie di profilazione. Dati clinici sintetici, a scopo
      dimostrativo.
    </footer>
  );

  if (!browserSupportsWebAuthn()) {
    return (
      <main className="ingresso">
        <div className="foglio">
          {intestazione}
          <p className="errore">Questo browser non supporta le passkey: usa una versione recente di Chrome, Edge, Firefox o Safari.</p>
        </div>
      </main>
    );
  }

  // Pagina d'ingresso: accesso con passkey o prima registrazione con il codice d'invito.
  if (!utente) {
    return (
      <>
        <main className="ingresso">
          <div className="foglio">
            {intestazione}
            <h1>Accedi alla tua cartella</h1>
            <p className="nota">Niente password: usi la passkey del tuo dispositivo, con impronta, volto o PIN.</p>
            <label htmlFor="username">Nome utente</label>
            <input
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value.trim().toLowerCase())}
              autoComplete="username webauthn"
              placeholder="mario.bianchi"
            />
            <div className="azioni">
              <button onClick={accedi} disabled={inCorso || username.length < 3}>
                Accedi con la passkey
              </button>
            </div>
            <details className="prima-volta">
              <summary>È il tuo primo accesso?</summary>
              <p className="nota">Inserisci il codice d'invito che ti ha consegnato la struttura e registra la passkey di questo dispositivo.</p>
              <label htmlFor="invito">Codice d'invito</label>
              <input id="invito" value={invito} onChange={(e) => setInvito(e.target.value.trim())} autoComplete="off" />
              <div className="azioni">
                <button className="secondario" onClick={registra} disabled={inCorso || username.length < 3 || invito.length === 0}>
                  Registra la passkey
                </button>
              </div>
            </details>
            {avviso}
            <Informativa />
          </div>
        </main>
        {piede}
      </>
    );
  }

  const schede = SCHEDE[profilo?.role ?? "nessuno"];
  const attiva = scheda && schede.some((s) => s.id === scheda) ? scheda : schede[0]!.id;

  // Frecce sinistra e destra per spostarsi tra le schede, come previsto per le tablist (WAI-ARIA).
  function frecce(e: KeyboardEvent<HTMLDivElement>) {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
    const i = schede.findIndex((s) => s.id === attiva);
    const prossima = schede[(i + (e.key === "ArrowRight" ? 1 : schede.length - 1)) % schede.length]!;
    setScheda(prossima.id);
    document.getElementById(`scheda-${prossima.id}`)?.focus();
  }

  return (
    <>
      <header className="testata">
        {intestazione}
        <div className="testata-utente">
          <span>
            <strong>{utente}</strong>
            {profilo?.role && <span className="ruolo">{RUOLO[profilo.role]}</span>}
          </span>
          <button className="secondario" onClick={esci} disabled={inCorso}>
            Esci
          </button>
        </div>
      </header>
      <nav className="schede" role="tablist" aria-label="Sezioni" onKeyDown={frecce}>
        {schede.map((s) => (
          <button
            key={s.id}
            id={`scheda-${s.id}`}
            role="tab"
            aria-selected={s.id === attiva}
            aria-controls="pannello"
            tabIndex={s.id === attiva ? 0 : -1}
            onClick={() => setScheda(s.id)}
          >
            {s.nome}
          </button>
        ))}
      </nav>
      <main className="contenuto" id="pannello" role="tabpanel" aria-labelledby={`scheda-${attiva}`}>
        {avviso}
        <div hidden={attiva !== "cartella"}>{profilo?.role === "doctor" && <PannelloCartella />}</div>
        <div hidden={attiva !== "referti"}>{profilo?.role === "patient" && <MieiReferti />}</div>
        {profilo?.role === "patient" && profilo.address && <PannelloConsensi indirizzo={profilo.address} scheda={attiva} />}
        {profilo?.role === "patient" && !profilo.address && (attiva === "consensi" || attiva === "accessi") && (
          <p className="vuoto">Il tuo profilo non ha ancora un wallet associato: rivolgiti alla struttura.</p>
        )}
        <div hidden={attiva !== "account"}>
          <section aria-labelledby="titolo-passkey">
            <h2 id="titolo-passkey">Le tue passkey</h2>
            <p className="nota">Ogni dispositivo con cui accedi ha la sua passkey. Se ne perdi uno, revoca la sua.</p>
            <ul className="elenco-passkey">
              {passkeys.map((p) => (
                <li key={p.id}>
                  <span>
                    <code>{p.id.slice(0, 12)}…</code> <span className="nota">{p.transports.join(", ") || "dispositivo"}</span>
                  </span>
                  <button className="secondario" onClick={() => revoca(p.id)} disabled={inCorso || passkeys.length < 2}>
                    Revoca
                  </button>
                </li>
              ))}
            </ul>
            <div className="azioni">
              <button onClick={aggiungi} disabled={inCorso}>
                Aggiungi un'altra passkey
              </button>
              <button className="secondario" onClick={esciOvunque} disabled={inCorso}>
                Esci da tutti i dispositivi
              </button>
            </div>
          </section>
          {profilo && profilo.role === null && (
            <p className="vuoto">Il tuo profilo non ha ancora un ruolo: lo assegna la struttura dopo averti identificato.</p>
          )}
          <section aria-labelledby="titolo-privacy">
            <h2 id="titolo-privacy">Privacy</h2>
            <Informativa />
          </section>
        </div>
      </main>
      {piede}
    </>
  );
}
