import { useEffect, useState } from "react";
import {
  browserSupportsWebAuthn,
  startAuthentication,
  startRegistration,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";
import { api } from "./api";

type Messaggio = { tipo: "ok" | "errore"; testo: string } | null;

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
  const [utente, setUtente] = useState<string | null>(null);
  const [messaggio, setMessaggio] = useState<Messaggio>(null);
  const [inCorso, setInCorso] = useState(false);

  // All'avvio controlla se esiste già una sessione valida.
  useEffect(() => {
    api.me().then(setUtente);
  }, []);

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

  const registra = () =>
    esegui(async () => {
      const optionsJSON = await api.post<PublicKeyCredentialCreationOptionsJSON>("/webauthn/register/options", { username });
      // Il browser chiede all'autenticatore di creare la passkey (impronta, volto o PIN).
      const response = await startRegistration({ optionsJSON });
      await api.post("/webauthn/register/verify", { username, response });
      setMessaggio({ tipo: "ok", testo: "Passkey registrata. Ora puoi accedere." });
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

  if (!browserSupportsWebAuthn()) {
    return (
      <main className="scheda">
        <h1>Cartella clinica</h1>
        <p className="errore">Questo browser non supporta le passkey.</p>
      </main>
    );
  }

  return (
    <main className="scheda">
      <h1>Cartella clinica</h1>
      {utente ? (
        <>
          <p>
            Accesso effettuato come <strong>{utente}</strong>.
          </p>
          <button onClick={esci} disabled={inCorso}>
            Esci
          </button>
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
          <div className="azioni">
            <button onClick={accedi} disabled={inCorso || username.length < 3}>
              Accedi
            </button>
            <button className="secondario" onClick={registra} disabled={inCorso || username.length < 3}>
              Registra una passkey
            </button>
          </div>
        </>
      )}
      {messaggio && <p className={messaggio.tipo}>{messaggio.testo}</p>}
    </main>
  );
}
