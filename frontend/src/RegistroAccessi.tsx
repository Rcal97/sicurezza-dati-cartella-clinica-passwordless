import { useEffect, useState } from "react";
import { Contract, EventLog, type BrowserProvider } from "ethers";
import { api } from "./api";
import { Timbro } from "./Documento";

// Eventi del registro di audit con cui il paziente verifica le voci da sé, con il proprio wallet.
// Non contengono dati personali: numero della voce, ancora del consenso o del medico, impronte.
const ABI_AUDIT = [
  "event AccessRecorded(uint256 indexed entryId, bytes32 indexed consentId, uint8 outcome, bytes32 recordHash)",
  "event EmergencyAccess(uint256 indexed entryId, bytes32 indexed staffId, bytes32 reasonHash, bytes32 recordHash)",
];
const FINALITA: Record<string, string> = { care: "cura", research: "ricerca", administration: "amministrazione" };

type Voce = {
  at: string;
  entryId: string | null;
  recordHash: string;
  altered?: true;
  requester?: string;
  kind?: "ordinary" | "document-signed" | "emergency" | "emergency-rejected";
  outcome?: "granted" | "denied";
  purpose?: string;
  reason?: string;
};
type Esito = "ok" | "diversa" | "assente";

// Tipo di voce, per il colore del segno a margine del registro.
function gravita(v: Voce): "normale" | "negato" | "emergenza" {
  if (v.altered || (v.kind === "ordinary" && v.outcome === "denied") || v.kind === "emergency-rejected") return "negato";
  if (v.kind === "emergency") return "emergenza";
  return "normale";
}

function descrivi(v: Voce): string {
  if (v.altered) return "Voce alterata o non leggibile: segnalala alla struttura.";
  const finalita = v.purpose ? FINALITA[v.purpose] ?? v.purpose : "";
  switch (v.kind) {
    case "ordinary":
      return v.outcome === "granted"
        ? `ha aperto la cartella per ${finalita}`
        : `ha tentato di aprire la cartella per ${finalita}, senza consenso: accesso negato`;
    case "document-signed":
      return "ha aggiunto un referto firmato";
    case "emergency":
      return `accesso d'emergenza, motivazione: «${v.reason}»`;
    default:
      return `tentativo d'emergenza respinto, motivazione: «${v.reason}»`;
  }
}

// Chi ha consultato la cartella del paziente, quando, perché e con quale esito (art. 15 GDPR).
// Il backend fornisce le voci; il confronto con la catena lo fa il browser del paziente:
// - ogni voce deve avere sulla catena la stessa impronta (integrità);
// - per le ancore dei consensi del paziente, già verificate con le sue ricevute firmate, non
//   devono esserci sulla catena accessi che l'elenco non mostra (completezza).
export default function RegistroAccessi(props: {
  auditLog: string | null;
  provider: BrowserProvider | null;
  consentIds: string[];
  onVerificaConsensi: (() => void) | null;
}) {
  const [voci, setVoci] = useState<Voce[] | null>(null);
  // Esito per voce, indicizzato dall'impronta: due voci con lo stesso numero (per esempio una
  // registrata su una rete di prova poi azzerata) non devono condividere il risultato.
  const [esiti, setEsiti] = useState<Record<string, Esito>>({});
  // Voci presenti sulla catena ma non mostrate dal backend: un backend compromesso potrebbe nasconderle.
  const [mancanti, setMancanti] = useState<string[] | null>(null);
  const [errore, setErrore] = useState<string | null>(null);
  const [inCorso, setInCorso] = useState(false);

  useEffect(() => {
    api.get<Voce[]>("/records/access-log").then(setVoci).catch((e: Error) => setErrore(e.message));
  }, []);

  async function verifica() {
    if (!props.provider || !props.auditLog || !voci) return;
    setInCorso(true);
    setErrore(null);
    try {
      const audit = new Contract(props.auditLog, ABI_AUDIT, props.provider);
      const numeri = voci.filter((v) => v.entryId !== null).map((v) => BigInt(v.entryId!));
      // Più valori nello stesso argomento del filtro valgono come "oppure".
      const eventi =
        numeri.length === 0
          ? []
          : [
              ...(await audit.queryFilter(audit.filters.AccessRecorded(numeri))),
              ...(await audit.queryFilter(audit.filters.EmergencyAccess(numeri))),
            ];
      const sullaCatena = new Map<string, string>();
      for (const ev of eventi) {
        if (ev instanceof EventLog) sullaCatena.set(ev.args.entryId.toString(), String(ev.args.recordHash).toLowerCase());
      }
      const delPaziente =
        props.consentIds.length === 0 ? [] : await audit.queryFilter(audit.filters.AccessRecorded(null, props.consentIds));
      const registrati = delPaziente.filter((ev) => ev instanceof EventLog).map((ev) => (ev as EventLog).args.entryId.toString());
      const nuovi: Record<string, Esito> = {};
      for (const v of voci) {
        if (v.entryId === null) continue;
        const hash = sullaCatena.get(v.entryId);
        nuovi[v.recordHash] = hash === undefined ? "assente" : hash === v.recordHash.toLowerCase() ? "ok" : "diversa";
      }
      setEsiti(nuovi);
      const mostrate = new Set(voci.map((v) => v.entryId));
      setMancanti(props.consentIds.length === 0 ? null : registrati.filter((id) => !mostrate.has(id)).sort((a, b) => Number(a) - Number(b)));
    } catch (e) {
      setErrore((e as Error).message);
    } finally {
      setInCorso(false);
    }
  }

  const quando = (iso: string) =>
    new Date(iso).toLocaleString("it-IT", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });

  return (
    <section aria-labelledby="titolo-accessi">
      <div className="testata-sezione">
        <h2 id="titolo-accessi">Chi ha consultato la mia cartella</h2>
        {voci && voci.length > 0 && props.consentIds.length > 0 && (
          <button className="secondario" onClick={verifica} disabled={inCorso || !props.provider}>
            Verifica sulla blockchain
          </button>
        )}
        {voci && voci.length > 0 && props.consentIds.length === 0 && props.onVerificaConsensi && (
          <button className="secondario" onClick={props.onVerificaConsensi}>
            Verifica i consensi, poi gli accessi
          </button>
        )}
      </div>
      <p className="nota">
        Ogni voce ha un'impronta registrata sulla blockchain: la verifica confronta le due copie dal tuo browser, senza fidarsi del
        server.
      </p>
      {mancanti !== null && mancanti.length === 0 && (
        <p className="ok">Sulla blockchain non ci sono accessi ai tuoi consensi che questo registro non mostri.</p>
      )}
      {mancanti !== null && mancanti.length > 0 && (
        <p className="errore">
          Sulla blockchain ci sono accessi alla tua cartella che questo registro non mostra (voci n. {mancanti.join(", ")}):
          segnalalo alla struttura.
        </p>
      )}
      {voci === null && !errore && <p className="nota">Caricamento del registro…</p>}
      {voci?.length === 0 && <p className="vuoto">Nessuno ha ancora consultato la tua cartella.</p>}
      {voci && voci.length > 0 && (
        <table className="registro">
          <thead>
            <tr>
              <th scope="col">Data e ora</th>
              <th scope="col">Chi e che cosa</th>
              <th scope="col">Blockchain</th>
            </tr>
          </thead>
          <tbody>
            {voci.map((v) => (
              <tr key={v.recordHash} className={`voce-${gravita(v)}`}>
                <td className="registro-data">{quando(v.at)}</td>
                <td>
                  {v.requester && <strong>{v.requester}</strong>} {descrivi(v)}
                </td>
                <td className="registro-catena">
                  <span className="nota">{v.entryId === null ? "non registrata" : `voce n. ${v.entryId}`}</span>
                  {v.entryId !== null && esiti[v.recordHash] === "ok" && <Timbro tipo="catena" titolo="Confermata" />}
                  {v.entryId !== null && esiti[v.recordHash] === "diversa" && <Timbro tipo="errore" titolo="Non corrisponde" />}
                  {v.entryId !== null && esiti[v.recordHash] === "assente" && <Timbro tipo="errore" titolo="Non trovata" />}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {errore && <p className="errore">{errore}</p>}
    </section>
  );
}
