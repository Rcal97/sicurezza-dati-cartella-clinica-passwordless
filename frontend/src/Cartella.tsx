import { useState } from "react";
import { startAuthentication, type PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/browser";
import { api } from "./api";

type Firma = { author: string; signedAt: string; valid: boolean } | null;
type Referto = { id: string; createdAt: string; title?: string; body?: string; signature?: Firma; error?: string };
type Cartella = { patient: string; auditEntry: string; documents: Referto[] };

const FINALITA = [
  ["care", "Cura"],
  ["research", "Ricerca"],
  ["administration", "Amministrazione"],
] as const;

const data = (iso: string) => new Date(iso).toLocaleString("it-IT");

// Stato della firma di un referto, come lo verifica il backend a ogni consegna.
function StatoFirma({ firma }: { firma?: Firma }) {
  if (!firma) return <span className="nota">Non firmato (caricato dal laboratorio)</span>;
  if (!firma.valid) return <span className="errore">FIRMA NON VALIDA: il contenuto non è quello firmato</span>;
  return (
    <span className="ok">
      Firmato da {firma.author} il {data(firma.signedAt)}
    </span>
  );
}

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
    <section>
      <h2>Cartella di un paziente</h2>
      <label htmlFor="paziente">Paziente</label>
      <input id="paziente" value={paziente} onChange={(e) => setPaziente(e.target.value.trim().toLowerCase())} placeholder="paz.bianchi" />
      <label htmlFor="finalita">Finalità dell'accesso</label>
      <select id="finalita" value={finalita} onChange={(e) => setFinalita(e.target.value)}>
        {FINALITA.map(([valore, etichetta]) => (
          <option key={valore} value={valore}>
            {etichetta}
          </option>
        ))}
      </select>
      <div className="azioni">
        <button onClick={apri} disabled={inCorso || paziente.length < 3}>
          Apri cartella
        </button>
      </div>

      {cartella && (
        <>
          <p className="nota">Accesso registrato nell'audit (voce n. {cartella.auditEntry}).</p>
          {cartella.documents.length === 0 && <p className="nota">Nessun referto.</p>}
          <ul className="referti">
            {cartella.documents.map((d) => (
              <li key={d.id}>
                {d.error ? (
                  <span className="errore">Referto del {data(d.createdAt)}: {d.error}</span>
                ) : (
                  <>
                    <strong>{d.title}</strong> <span className="nota">{data(d.createdAt)}</span>
                    <p>{d.body}</p>
                    <StatoFirma firma={d.signature} />
                  </>
                )}
              </li>
            ))}
          </ul>
        </>
      )}

      <h2>Nuovo referto</h2>
      <label htmlFor="titolo">Titolo</label>
      <input id="titolo" value={titolo} maxLength={200} onChange={(e) => setTitolo(e.target.value)} />
      <label htmlFor="testo">Testo</label>
      <textarea id="testo" value={testo} maxLength={20000} rows={5} onChange={(e) => setTesto(e.target.value)} />
      <div className="azioni">
        <button onClick={firma} disabled={inCorso || paziente.length < 3 || !titolo.trim() || !testo.trim()}>
          Firma con la passkey e salva
        </button>
      </div>
      {messaggio && <p className={messaggio.tipo}>{messaggio.testo}</p>}
    </section>
  );
}
