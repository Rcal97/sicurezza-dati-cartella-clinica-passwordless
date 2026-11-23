import type { ReactNode } from "react";

export type Firma = { author: string; signedAt: string; valid: boolean } | null;
export type Referto = { id: string; createdAt: string; title?: string; body?: string; signature?: Firma; error?: string };

const data = (iso: string) => new Date(iso).toLocaleString("it-IT", { dateStyle: "short", timeStyle: "short" });

// Timbro: l'esito di una verifica crittografica, reso come il timbro su un documento cartaceo.
// "firma" = firma con passkey valida, "catena" = confermato sulla blockchain, "errore" = verifica fallita.
export function Timbro({ tipo, titolo, children }: { tipo: "firma" | "catena" | "errore"; titolo: string; children?: ReactNode }) {
  return (
    <span className={`timbro timbro-${tipo}`}>
      <span className="timbro-titolo">{titolo}</span>
      {children && <span className="timbro-dettaglio">{children}</span>}
    </span>
  );
}

// Un referto impaginato come un foglio: intestazione, testo e, in calce, il timbro della firma.
export function Documento({ referto }: { referto: Referto }) {
  if (referto.error) {
    return (
      <article className="foglio referto">
        <p className="errore">Referto del {data(referto.createdAt)}: {referto.error}.</p>
        <Timbro tipo="errore" titolo="Integrità non verificata" />
      </article>
    );
  }
  const firma = referto.signature;
  return (
    <article className="foglio referto">
      <header>
        <h3>{referto.title}</h3>
        <time dateTime={referto.createdAt}>{data(referto.createdAt)}</time>
      </header>
      <p className="referto-testo">{referto.body}</p>
      <footer>
        {!firma && <span className="nota">Non firmato: caricato dal laboratorio.</span>}
        {firma && !firma.valid && (
          <Timbro tipo="errore" titolo="Firma non valida">
            il contenuto non è quello firmato
          </Timbro>
        )}
        {firma?.valid && (
          <Timbro tipo="firma" titolo="Firmato con passkey">
            {firma.author}, {data(firma.signedAt)}
          </Timbro>
        )}
      </footer>
    </article>
  );
}
