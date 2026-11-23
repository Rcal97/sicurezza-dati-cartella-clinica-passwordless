import { useCallback, useEffect, useState } from "react";
import { BrowserProvider, Contract, EventLog, type Eip1193Provider, type TypedDataDomain, type TypedDataField } from "ethers";
import { api } from "./api";
import { Timbro } from "./Documento";
import Informativa from "./Informativa";
import RegistroAccessi from "./RegistroAccessi";

// Il wallet segnala con questi eventi il cambio di rete o di account (EIP-1193).
type Wallet = Eip1193Provider & {
  on?: (evento: string, gestore: (dato: unknown) => void) => void;
  removeListener?: (evento: string, gestore: (dato: unknown) => void) => void;
};

declare global {
  interface Window {
    ethereum?: Wallet;
  }
}

const collega = (wallet: Wallet) => new BrowserProvider(wallet, undefined, { cacheTimeout: -1 });

// Eventi del registro dei consensi: contengono solo l'ancora, la scadenza e l'impronta della ricevuta.
const ABI_CONSENSI = [
  "event ConsentGranted(bytes32 indexed consentId, uint64 expiresAt, bytes32 receiptHash)",
  "event ConsentRevoked(bytes32 indexed consentId, bytes32 receiptHash)",
];
const FINALITA: Record<string, string> = { care: "Cura", research: "Ricerca", administration: "Amministrazione" };
const MAX_GIORNI = 365; // come MAX_DURATION nel contratto

type Rete = { chainId: number; consentRegistry: string; auditLog: string };
type Consenso = {
  doctor: string;
  purpose: string;
  action: "grant" | "revoke";
  expiresAt: number;
  signedAt: number;
  noticeVersion: string;
  receiptHash: string;
  consentId: string;
  valid: boolean;
};
type RichiestaFirma = {
  domain: TypedDataDomain;
  types: Record<string, TypedDataField[]>;
  message: { nonce: string; noticeVersion: string } & Record<string, unknown>;
};
type Verifica = "ok" | "diversa";

function descrivi(err: unknown): string {
  const e = err as { code?: string; shortMessage?: string; message?: string };
  if (e.code === "ACTION_REJECTED") return "Firma annullata nel wallet.";
  return e.shortMessage ?? e.message ?? "Errore imprevisto.";
}

// Pagina del paziente: concede e revoca i consensi firmandoli con il proprio wallet (EIP-712).
// La firma non è una transazione: non costa nulla e il wallet non compare sulla blockchain.
// Il wallet mostra in chiaro medico, finalità, scadenza e versione dell'informativa prima di firmare.
// Resta montata anche quando è visibile un'altra scheda: collegamento al wallet ed esiti delle
// verifiche non si perdono passando da "Consensi" ad "Accessi" e viceversa.
export default function PannelloConsensi({ indirizzo, scheda }: { indirizzo: string; scheda: string }) {
  const [rete, setRete] = useState<Rete | null>(null);
  const [medici, setMedici] = useState<string[]>([]);
  const [provider, setProvider] = useState<BrowserProvider | null>(null);
  const [consensi, setConsensi] = useState<Consenso[]>([]);
  const [verifiche, setVerifiche] = useState<Record<string, Verifica>>({});
  const [medico, setMedico] = useState("");
  const [finalita, setFinalita] = useState("care");
  const [giorni, setGiorni] = useState(30);
  const [letta, setLetta] = useState(false);
  const [messaggio, setMessaggio] = useState<{ tipo: "ok" | "errore"; testo: string } | null>(null);
  const [inCorso, setInCorso] = useState(false);

  const caricaConsensi = useCallback(async () => {
    setConsensi(await api.get<Consenso[]>("/consents"));
    setVerifiche({});
  }, []);

  useEffect(() => {
    api.get<Rete>("/directory/chain").then(setRete).catch(() => setRete(null));
    api.get<string[]>("/directory/doctors").then(setMedici).catch(() => setMedici([]));
    api.get<Consenso[]>("/consents").then(setConsensi).catch(() => setConsensi([]));
  }, []);

  // Se nel wallet cambiano rete o account, il collegamento va rifatto (e i controlli ripetuti).
  useEffect(() => {
    const wallet = window.ethereum;
    if (!wallet?.on || !rete) return;
    const scollega = () => {
      setProvider(null);
      setMessaggio({ tipo: "errore", testo: "Nel wallet sono cambiati la rete o l'account: collegalo di nuovo." });
    };
    const reteCambiata = (chainId: unknown) => {
      if (Number(chainId) !== rete.chainId) scollega();
    };
    const accountCambiato = (accounts: unknown) => {
      const primo = Array.isArray(accounts) ? String(accounts[0] ?? "") : "";
      if (primo.toLowerCase() !== indirizzo.toLowerCase()) scollega();
    };
    wallet.on("chainChanged", reteCambiata);
    wallet.on("accountsChanged", accountCambiato);
    return () => {
      wallet.removeListener?.("chainChanged", reteCambiata);
      wallet.removeListener?.("accountsChanged", accountCambiato);
    };
  }, [rete, indirizzo]);

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

  const connetti = () =>
    esegui(async () => {
      if (!window.ethereum) throw new Error("Serve un wallet nel browser (per esempio MetaMask).");
      if (!rete) throw new Error("Informazioni sulla rete non disponibili.");
      let p = collega(window.ethereum);
      await p.send("eth_requestAccounts", []);
      // La firma EIP-712 è legata alla rete del registro: il wallet deve essere su quella rete.
      if (Number((await p.getNetwork()).chainId) !== rete.chainId) {
        await p.send("wallet_switchEthereumChain", [{ chainId: "0x" + rete.chainId.toString(16) }]);
        p = collega(window.ethereum);
        if (Number((await p.getNetwork()).chainId) !== rete.chainId) {
          throw new Error("Il wallet non è passato alla rete del registro dei consensi.");
        }
      }
      const account = (await p.getSigner()).address;
      if (account !== indirizzo) {
        throw new Error(`Nel wallet è selezionato ${account}: scegli l'account ${indirizzo}, il tuo wallet registrato.`);
      }
      setProvider(p);
    });

  // Il server prepara il messaggio, il wallet lo mostra e lo firma, il server verifica e registra.
  async function firma(richiesta: { action: "grant" | "revoke"; doctor: string; purpose: string; days?: number }) {
    if (!provider) return;
    const r = await api.post<RichiestaFirma>("/consents/options", richiesta);
    const signature = await (await provider.getSigner()).signTypedData(r.domain, r.types, r.message);
    await api.post("/consents/verify", { nonce: r.message.nonce, signature });
    await caricaConsensi();
  }

  const concedi = () =>
    esegui(async () => {
      await firma({ action: "grant", doctor: medico, purpose: finalita, days: giorni });
      setLetta(false);
      setMessaggio({ tipo: "ok", testo: "Consenso firmato e registrato. Sulla blockchain ci sono solo un'ancora opaca e l'impronta della ricevuta." });
    });

  const revoca = (c: Consenso) =>
    esegui(async () => {
      await firma({ action: "revoke", doctor: c.doctor, purpose: c.purpose });
      setMessaggio({ tipo: "ok", testo: "Revoca firmata e registrata." });
    });

  // Il browser controlla da sé che sulla catena, per l'ancora del consenso, l'ultima operazione
  // registrata porti l'impronta della ricevuta che il paziente ha firmato.
  const verifica = () =>
    esegui(async () => {
      if (!provider || !rete) return;
      const registro = new Contract(rete.consentRegistry, ABI_CONSENSI, provider);
      const nuove: Record<string, Verifica> = {};
      for (const c of consensi) {
        const eventi = [
          ...(await registro.queryFilter(registro.filters.ConsentGranted(c.consentId))),
          ...(await registro.queryFilter(registro.filters.ConsentRevoked(c.consentId))),
        ]
          .filter((e): e is EventLog => e instanceof EventLog)
          .sort((a, b) => a.blockNumber - b.blockNumber || a.index - b.index);
        const ultimo = eventi.at(-1);
        nuove[c.consentId] = ultimo && String(ultimo.args.receiptHash).toLowerCase() === c.receiptHash.toLowerCase() ? "ok" : "diversa";
      }
      setVerifiche(nuove);
    });

  const attivi = consensi.filter((c) => c.valid);
  const storici = consensi.filter((c) => !c.valid);
  const breve = `${indirizzo.slice(0, 6)}…${indirizzo.slice(-4)}`;
  const quando = (s: number) => new Date(s * 1000).toLocaleDateString("it-IT", { day: "numeric", month: "long", year: "numeric" });
  const esito = (c: Consenso) =>
    verifiche[c.consentId] === "ok" ? (
      <Timbro tipo="catena" titolo="Confermato sulla blockchain" />
    ) : verifiche[c.consentId] === "diversa" ? (
      <Timbro tipo="errore" titolo="Non corrisponde alla blockchain" />
    ) : null;

  if (scheda !== "consensi" && scheda !== "accessi") return null;

  return (
    <>
      <div className={provider ? "wallet collegato" : "wallet"}>
        {provider ? (
          <p>
            Wallet collegato: <code title={indirizzo}>{breve}</code>. Firmi i consensi senza transazioni e senza costi; il tuo
            wallet non compare sulla blockchain.
          </p>
        ) : (
          <p>Per firmare i consensi e verificare i dati sulla blockchain collega il wallet {breve}.</p>
        )}
        {!provider && (
          <button onClick={connetti} disabled={inCorso || !rete}>
            Collega il wallet
          </button>
        )}
      </div>
      {messaggio && (
        <p className={messaggio.tipo} role="status">
          {messaggio.testo}
        </p>
      )}

      <div hidden={scheda !== "consensi"}>
        <section aria-labelledby="titolo-consensi">
          <div className="testata-sezione">
            <h2 id="titolo-consensi">Consensi attivi</h2>
            {consensi.length > 0 && (
              <button className="secondario" onClick={verifica} disabled={inCorso || !provider}>
                Verifica sulla blockchain
              </button>
            )}
          </div>
          {attivi.length === 0 && <p className="vuoto">Nessun medico può consultare la tua cartella. Puoi autorizzarne uno qui sotto.</p>}
          <ul className="elenco-consensi">
            {attivi.map((c) => (
              <li key={c.consentId}>
                <div>
                  <p className="consenso-chi">
                    <strong>{c.doctor}</strong>, per {(FINALITA[c.purpose] ?? c.purpose).toLowerCase()}
                  </p>
                  <p className="nota">
                    Valido fino al {quando(c.expiresAt)}. Firmato il {quando(c.signedAt)}, informativa {c.noticeVersion}.
                  </p>
                  {esito(c)}
                </div>
                <button className="secondario" onClick={() => revoca(c)} disabled={inCorso || !provider}>
                  Revoca
                </button>
              </li>
            ))}
          </ul>
          {storici.length > 0 && (
            <details className="storico">
              <summary>Consensi revocati o scaduti ({storici.length})</summary>
              <ul className="elenco-consensi">
                {storici.map((c) => (
                  <li key={c.consentId}>
                    <div>
                      <p className="consenso-chi">
                        <strong>{c.doctor}</strong>, per {(FINALITA[c.purpose] ?? c.purpose).toLowerCase()}:{" "}
                        {c.action === "revoke" ? "revocato" : "scaduto"}
                      </p>
                      {esito(c)}
                    </div>
                  </li>
                ))}
              </ul>
            </details>
          )}
        </section>

        <section aria-labelledby="titolo-nuovo-consenso">
          <h2 id="titolo-nuovo-consenso">Autorizza un medico</h2>
          <div className="foglio modulo">
            <div className="riga-modulo">
              <div className="campo">
                <label htmlFor="medico">Medico</label>
                <select id="medico" value={medico} onChange={(e) => setMedico(e.target.value)}>
                  <option value="">Scegli un medico</option>
                  {medici.map((m) => (
                    <option key={m} value={m}>
                      {m}
                    </option>
                  ))}
                </select>
              </div>
              <div className="campo">
                <label htmlFor="finalita-consenso">Finalità</label>
                <select id="finalita-consenso" value={finalita} onChange={(e) => setFinalita(e.target.value)}>
                  {Object.entries(FINALITA).map(([valore, etichetta]) => (
                    <option key={valore} value={valore}>
                      {etichetta}
                    </option>
                  ))}
                </select>
              </div>
              <div className="campo stretto">
                <label htmlFor="giorni">Giorni</label>
                <input
                  id="giorni"
                  type="number"
                  min={1}
                  max={MAX_GIORNI}
                  value={giorni}
                  onChange={(e) => setGiorni(Math.min(MAX_GIORNI, Math.max(1, Math.trunc(Number(e.target.value)) || 1)))}
                />
              </div>
            </div>
            <Informativa />
            <label className="spunta">
              <input type="checkbox" checked={letta} onChange={(e) => setLetta(e.target.checked)} />
              <span>Ho letto l'informativa. La sua versione sarà riportata nel consenso che firmo.</span>
            </label>
            <div className="azioni">
              <button onClick={concedi} disabled={inCorso || !provider || !medico || !letta}>
                Firma il consenso con il wallet
              </button>
            </div>
          </div>
        </section>
      </div>

      <div hidden={scheda !== "accessi"}>
        <RegistroAccessi
          auditLog={rete?.auditLog ?? null}
          provider={provider}
          consentIds={consensi.filter((c) => verifiche[c.consentId] === "ok").map((c) => c.consentId)}
          onVerificaConsensi={consensi.length > 0 && provider ? verifica : null}
        />
      </div>
    </>
  );
}
