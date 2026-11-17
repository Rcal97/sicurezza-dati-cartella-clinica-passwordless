import { useEffect, useState } from "react";
import { Contract, EventLog, type BrowserProvider } from "ethers";
import { api } from "./api";

// Eventi del registro di audit con cui il paziente verifica le voci da sé, con il proprio wallet.
const ABI_AUDIT = [
  "event AccessRecorded(uint256 indexed entryId, address indexed patient, address indexed accessor, uint8 purpose, uint8 outcome, bytes32 recordHash)",
  "event EmergencyAccess(uint256 indexed entryId, address indexed patient, address indexed accessor, bytes32 reasonHash, bytes32 recordHash)",
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
// Il backend fornisce le voci; il confronto con la catena lo fa il browser del paziente,
// così un backend compromesso non può presentare una storia diversa da quella registrata.
export default function RegistroAccessi(props: {
  indirizzo: string;
  auditLog: string | null;
  provider: BrowserProvider | null;
}) {
  const [voci, setVoci] = useState<Voce[] | null>(null);
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
      const eventi = [
        ...(await audit.queryFilter(audit.filters.AccessRecorded(null, props.indirizzo))),
        ...(await audit.queryFilter(audit.filters.EmergencyAccess(null, props.indirizzo))),
      ];
      const sullaCatena = new Map<string, string>();
      for (const ev of eventi) {
        if (ev instanceof EventLog) sullaCatena.set(ev.args.entryId.toString(), String(ev.args.recordHash).toLowerCase());
      }
      const nuovi: Record<string, Esito> = {};
      for (const v of voci) {
        if (v.entryId === null) continue;
        const hash = sullaCatena.get(v.entryId);
        nuovi[v.entryId] = hash === undefined ? "assente" : hash === v.recordHash.toLowerCase() ? "ok" : "diversa";
      }
      setEsiti(nuovi);
      const mostrate = new Set(voci.map((v) => v.entryId));
      setMancanti([...sullaCatena.keys()].filter((id) => !mostrate.has(id)).sort((a, b) => Number(a) - Number(b)));
    } catch (e) {
      setErrore((e as Error).message);
    } finally {
      setInCorso(false);
    }
  }

  return (
    <>
      <h2>Chi ha consultato la mia cartella</h2>
      {voci === null && !errore && <p className="nota">Caricamento…</p>}
      {voci?.length === 0 && <p className="nota">Nessun accesso registrato.</p>}
      <ul className="referti">
        {voci?.map((v) => (
          <li key={v.recordHash} className="accesso">
            <span className="nota">{new Date(v.at).toLocaleString("it-IT")}</span>{" "}
            {v.requester && <strong>{v.requester}</strong>} {descrivi(v)}
            <br />
            <span className="nota">
              {v.entryId === null ? "non registrato sulla catena" : `voce on-chain n. ${v.entryId}`}
            </span>
            {v.entryId !== null && esiti[v.entryId] === "ok" && <span className="ok"> — verificata sulla blockchain</span>}
            {v.entryId !== null && esiti[v.entryId] === "diversa" && (
              <span className="errore"> — NON corrisponde a quanto registrato sulla blockchain</span>
            )}
            {v.entryId !== null && esiti[v.entryId] === "assente" && (
              <span className="errore"> — voce non trovata sulla blockchain</span>
            )}
          </li>
        ))}
      </ul>
      {voci && voci.length > 0 && (
        <div className="azioni">
          <button className="secondario" onClick={verifica} disabled={inCorso || !props.provider}>
            Verifica sulla blockchain
          </button>
          {!props.provider && <span className="nota">Collega il wallet per verificare.</span>}
        </div>
      )}
      {mancanti !== null && mancanti.length === 0 && (
        <p className="ok">Tutti gli accessi registrati sulla blockchain per il tuo indirizzo sono in questo elenco.</p>
      )}
      {mancanti !== null && mancanti.length > 0 && (
        <p className="errore">
          Sulla blockchain ci sono accessi alla tua cartella che questo elenco non mostra (voci n. {mancanti.join(", ")}):
          segnalalo alla struttura.
        </p>
      )}
      {errore && <p className="errore">{errore}</p>}
    </>
  );
}
