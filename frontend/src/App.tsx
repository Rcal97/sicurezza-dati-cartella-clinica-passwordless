import { useEffect, useState } from "react";
import {
  browserSupportsWebAuthn,
  startAuthentication,
  startRegistration,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";
import { api } from "./api";
import PannelloCartella from "./Cartella";

type Messaggio = { tipo: "ok" | "errore"; testo: string } | null;
type Passkey = { id: string; transports: string[] };

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

  // All'avvio controlla se esiste già una sessione valida.
  useEffect(() => {
    api.me().then(setUtente);
  }, []);

  // Da autenticato, carica l'elenco delle proprie passkey.
  useEffect(() => {
    if (utente) api.get<Passkey[]>("/session/passkeys").then(setPasskeys).catch(() => setPasskeys([]));
  }, [utente]);

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
      setUtente(null);
      setMessaggio({ tipo: "ok", testo: "Sei uscito." });
    });

  const esciOvunque = () =>
    esegui(async () => {
      await api.post("/session/logout-all");
      setUtente(null);
      setMessaggio({ tipo: "ok", testo: "Sei uscito da tutti i dispositivi." });
    });

  // Revoca di una passkey (per esempio di un dispositivo perso): per sicurezza
  // il backend chiude tutte le sessioni, quindi bisogna accedere di nuovo.
  const revoca = (id: string) =>
    esegui(async () => {
      await api.post("/session/passkeys/revoke", { id });
      setUtente(null);
      setMessaggio({ tipo: "ok", testo: "Passkey revocata. Accedi di nuovo con un dispositivo rimasto." });
    });

  if (!browserSupportsWebAuthn()) {
    return (
      <main className="scheda">
        <h1>Cartella clinica</h1>
        <p className="errore">Questo browser non supporta le passkey.</p>
      </main>
    );
  }

  return (
    <main className={utente ? "scheda larga" : "scheda"}>
      <h1>Cartella clinica</h1>
      {utente ? (
        <>
          <p>
            Accesso effettuato come <strong>{utente}</strong>.
          </p>
          <div className="azioni">
            <button onClick={esci} disabled={inCorso}>
              Esci
            </button>
            <button className="secondario" onClick={aggiungi} disabled={inCorso}>
              Aggiungi un'altra passkey
            </button>
          </div>
          <h2>Le tue passkey</h2>
          <ul className="passkey">
            {passkeys.map((p) => (
              <li key={p.id}>
                <code>{p.id.slice(0, 12)}…</code> {p.transports.join(", ")}
                <button className="secondario" onClick={() => revoca(p.id)} disabled={inCorso || passkeys.length < 2}>
                  Revoca
                </button>
              </li>
            ))}
          </ul>
          <button className="secondario" onClick={esciOvunque} disabled={inCorso}>
            Esci da tutti i dispositivi
          </button>
          <PannelloCartella />
        </>
      ) : (
        <>
          <p className="nota">Accesso senza password con una passkey.</p>
          <label htmlFor="username">Nome utente</label>
          <input
            id="username"
            value={username}
            onChange={(e) => setUsername(e.target.value.trim().toLowerCase())}
            autoComplete="username webauthn"
            placeholder="mario.rossi"
          />
          <label htmlFor="invito">Codice d'invito</label>
          <input
            id="invito"
            value={invito}
            onChange={(e) => setInvito(e.target.value.trim())}
            autoComplete="off"
            placeholder="solo per la prima registrazione"
          />
          <div className="azioni">
            <button onClick={accedi} disabled={inCorso || username.length < 3}>
              Accedi
            </button>
            <button className="secondario" onClick={registra} disabled={inCorso || username.length < 3 || invito.length === 0}>
              Registra una passkey
            </button>
          </div>
        </>
      )}
      {messaggio && <p className={messaggio.tipo}>{messaggio.testo}</p>}
    </main>
  );
}
