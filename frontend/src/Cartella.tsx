import { useState } from "react";
import { startAuthentication, type PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/browser";
import { api } from "./api";
import { Documento, type Referto } from "./Documento";

type Cartella = { patient: string; auditEntry: string; documents: Referto[] };

const FINALITA = [
  ["care", "Cura"],
  ["research", "Ricerca"],
  ["administration", "Amministrazione"],
] as const;

// Pannello del medico: consultazione di una cartella e scrittura di un referto firmato.
// Ogni decisione (ruolo, consenso, audit) spetta al backend e ai contratti.
export default function PannelloCartella() {
  const [paziente, setPaziente] = useState("");
  const [finalita, setFinalita] = useState("care");
  const [cartella, setCartella] = useState<Cartella | null>(null);
  const [titolo, setTitolo] = useState("");
  const [testo, setTesto] = useState("");
  const [messaggio, setMessaggio] = useState<{ tipo: "ok" | "errore"; testo: string } | null>(null);
  const [inCorso, setInCorso] = useState(false);

  async function esegui(azione: () => Promise<void>) {
    setInCorso(true);
    setMessaggio(null);
    try {
      await azione();
    } catch (err) {
      const nome = err instanceof Error ? err.name : "";
      const testo = nome === "NotAllowedError" ? "Firma annullata o scaduta." : err instanceof Error ? err.message : "Errore imprevisto.";
      setMessaggio({ tipo: "errore", testo });
    } finally {
      setInCorso(false);
    }
  }

  const apri = () =>
    esegui(async () => {
      setCartella(null);
      setCartella(await api.post<Cartella>("/records/access", { patient: paziente, purpose: finalita }));
    });

  // Il server prepara la richiesta di firma (la challenge è l'impronta del referto),
  // la passkey firma dopo impronta o PIN, il server verifica, registra e salva.
  const firma = () =>
    esegui(async () => {
      const optionsJSON = await api.post<PublicKeyCredentialRequestOptionsJSON>("/records/documents/options", {
        patient: paziente,
        title: titolo,
        body: testo,
      });
      const response = await startAuthentication({ optionsJSON });
      await api.post("/records/documents/verify", { response });
      setTitolo("");
      setTesto("");
      setCartella(await api.post<Cartella>("/records/access", { patient: paziente, purpose: "care" }));
      setMessaggio({ tipo: "ok", testo: "Referto firmato e aggiunto alla cartella." });
    });

  return (
    <>
      <section aria-labelledby="titolo-consulta">
        <h2 id="titolo-consulta">Consulta una cartella</h2>
        <p className="nota">Ogni apertura è registrata sulla blockchain ed è visibile al paziente.</p>
        <div className="riga-modulo">
          <div className="campo">
            <label htmlFor="paziente">Paziente</label>
            <input
              id="paziente"
              value={paziente}
              onChange={(e) => setPaziente(e.target.value.trim().toLowerCase())}
              placeholder="mario.bianchi"
            />
          </div>
          <div className="campo">
            <label htmlFor="finalita">Finalità</label>
            <select id="finalita" value={finalita} onChange={(e) => setFinalita(e.target.value)}>
              {FINALITA.map(([valore, etichetta]) => (
                <option key={valore} value={valore}>
                  {etichetta}
                </option>
              ))}
            </select>
          </div>
          <button onClick={apri} disabled={inCorso || paziente.length < 3}>
            Apri cartella
          </button>
        </div>

        {cartella && (
          <>
            <p className="esito-accesso">
              Cartella di <strong>{cartella.patient}</strong>: accesso registrato nell'audit, voce n. {cartella.auditEntry}.
            </p>
            {cartella.documents.length === 0 && <p className="vuoto">La cartella non contiene ancora referti.</p>}
            <div className="pila-referti">
              {cartella.documents.map((d) => (
                <Documento key={d.id} referto={d} />
              ))}
            </div>
          </>
        )}
      </section>

      <section aria-labelledby="titolo-nuovo">
        <h2 id="titolo-nuovo">Nuovo referto</h2>
        <div className="foglio modulo">
          <p className="nota">
            Per <strong>{paziente || "il paziente indicato sopra"}</strong>. Serve un consenso valido per la cura; la passkey
            firma il contenuto esatto del referto.
          </p>
          <label htmlFor="titolo">Titolo</label>
          <input id="titolo" value={titolo} maxLength={200} onChange={(e) => setTitolo(e.target.value)} placeholder="Visita di controllo" />
          <label htmlFor="testo">Testo</label>
          <textarea id="testo" value={testo} maxLength={20000} rows={6} onChange={(e) => setTesto(e.target.value)} />
          <div className="azioni">
            <button onClick={firma} disabled={inCorso || paziente.length < 3 || !titolo.trim() || !testo.trim()}>
              Firma con la passkey e salva
            </button>
          </div>
        </div>
      </section>
      {messaggio && (
        <p className={messaggio.tipo} role="status">
          {messaggio.testo}
        </p>
      )}
    </>
  );
}
