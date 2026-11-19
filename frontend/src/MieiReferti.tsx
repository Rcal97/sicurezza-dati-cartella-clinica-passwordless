import { useEffect, useState } from "react";
import { api } from "./api";

type Firma = { author: string; signedAt: string; valid: boolean } | null;
type Referto = { id: string; createdAt: string; title?: string; body?: string; signature?: Firma; error?: string };

const data = (iso: string) => new Date(iso).toLocaleString("it-IT");

// La propria cartella (art. 15 GDPR) e l'esportazione dei propri dati in JSON (art. 20).
// Le correzioni avvengono per integrazione: un nuovo referto firmato, senza cancellare i precedenti.
export default function MieiReferti() {
  const [referti, setReferti] = useState<Referto[] | null>(null);
  const [errore, setErrore] = useState<string | null>(null);

  useEffect(() => {
    api.get<Referto[]>("/records/mine").then(setReferti).catch((e: Error) => setErrore(e.message));
  }, []);

  async function esporta() {
    setErrore(null);
    try {
      const res = await fetch("/records/mine/export");
      if (!res.ok) throw new Error(`Errore ${res.status}`);
      const url = URL.createObjectURL(await res.blob());
      const a = document.createElement("a");
      a.href = url;
      a.download = "i-miei-dati.json";
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setErrore((e as Error).message);
    }
  }

  return (
    <section>
      <h2>I miei referti</h2>
      {referti === null && !errore && <p className="nota">Caricamento…</p>}
      {referti?.length === 0 && <p className="nota">Nessun referto.</p>}
      <ul className="referti">
        {referti?.map((d) => (
          <li key={d.id}>
            {d.error ? (
              <span className="errore">Referto del {data(d.createdAt)}: {d.error}</span>
            ) : (
              <>
                <strong>{d.title}</strong> <span className="nota">{data(d.createdAt)}</span>
                <p>{d.body}</p>
                {d.signature ? (
                  d.signature.valid ? (
                    <span className="ok">Firmato da {d.signature.author} il {data(d.signature.signedAt)}</span>
                  ) : (
                    <span className="errore">FIRMA NON VALIDA</span>
                  )
                ) : (
                  <span className="nota">Non firmato (caricato dal laboratorio)</span>
                )}
              </>
            )}
          </li>
        ))}
      </ul>
      <div className="azioni">
        <button className="secondario" onClick={esporta}>
          Scarica tutti i miei dati (JSON)
        </button>
      </div>
      <p className="nota">
        Il file contiene referti, ricevute firmate dei consensi e registro degli accessi. Per correggere un dato rivolgiti
        al medico: la rettifica avviene con un nuovo referto, senza cancellare quelli precedenti.
      </p>
      {errore && <p className="errore">{errore}</p>}
    </section>
  );
}
