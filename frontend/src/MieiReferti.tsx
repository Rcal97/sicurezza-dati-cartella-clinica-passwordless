import { useEffect, useState } from "react";
import { api } from "./api";
import { Documento, type Referto } from "./Documento";

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
      if (!res.ok) throw new Error(`Esportazione non riuscita (errore ${res.status}).`);
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
    <section aria-labelledby="titolo-referti">
      <div className="testata-sezione">
        <h2 id="titolo-referti">I miei referti</h2>
        <button className="secondario" onClick={esporta}>
          Scarica tutti i miei dati
        </button>
      </div>
      <p className="nota">
        Il file scaricato (JSON) contiene referti, ricevute firmate dei consensi e registro degli accessi. Per correggere un
        dato rivolgiti al medico: la rettifica si fa con un nuovo referto, senza cancellare i precedenti.
      </p>
      {referti === null && !errore && <p className="nota">Caricamento dei referti…</p>}
      {referti?.length === 0 && <p className="vuoto">La tua cartella non contiene ancora referti.</p>}
      <div className="pila-referti">
        {referti?.map((d) => (
          <Documento key={d.id} referto={d} />
        ))}
      </div>
      {errore && <p className="errore">{errore}</p>}
    </section>
  );
}
