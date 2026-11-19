import { useCallback, useEffect, useState } from "react";
import { BrowserProvider, Contract, EventLog, type Eip1193Provider, type TypedDataDomain, type TypedDataField } from "ethers";
import { api } from "./api";
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
export default function PannelloConsensi({ indirizzo }: { indirizzo: string }) {
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

  return (
    <section>
      <h2>I miei consensi</h2>
      <p className="nota">
        Firmi i consensi con il wallet <code>{indirizzo}</code>. Non sono transazioni: non servono ETH e il tuo wallet non
        compare sulla blockchain.
      </p>
      {!provider && (
        <button onClick={connetti} disabled={inCorso || !rete}>
          Collega il wallet
        </button>
      )}

      {attivi.length === 0 && <p className="nota">Nessun consenso attivo.</p>}
      <ul className="referti">
        {attivi.map((c) => (
          <li key={c.consentId} className="consenso">
            <span>
              <strong>{c.doctor}</strong> — {FINALITA[c.purpose] ?? c.purpose}, fino al {new Date(c.expiresAt * 1000).toLocaleString("it-IT")}
              <br />
              <span className="nota">
                firmato il {new Date(c.signedAt * 1000).toLocaleString("it-IT")}, informativa v{c.noticeVersion}
              </span>
              {verifiche[c.consentId] === "ok" && <span className="ok"> — verificato sulla blockchain</span>}
              {verifiche[c.consentId] === "diversa" && <span className="errore"> — NON corrisponde alla blockchain</span>}
            </span>
            <button className="secondario" onClick={() => revoca(c)} disabled={inCorso || !provider}>
              Revoca
            </button>
          </li>
        ))}
      </ul>
      {storici.length > 0 && (
        <details>
          <summary>Consensi revocati o scaduti ({storici.length})</summary>
          <ul className="referti">
            {storici.map((c) => (
              <li key={c.consentId}>
                <strong>{c.doctor}</strong> — {FINALITA[c.purpose] ?? c.purpose}: {c.action === "revoke" ? "revocato" : "scaduto"}{" "}
                {verifiche[c.consentId] === "ok" && <span className="ok"> — verificato sulla blockchain</span>}
                {verifiche[c.consentId] === "diversa" && <span className="errore"> — NON corrisponde alla blockchain</span>}
              </li>
            ))}
          </ul>
        </details>
      )}
      {consensi.length > 0 && (
        <div className="azioni">
          <button className="secondario" onClick={verifica} disabled={inCorso || !provider}>
            Verifica i consensi sulla blockchain
          </button>
        </div>
      )}

      <h2>Nuovo consenso</h2>
      <label htmlFor="medico">Medico</label>
      <select id="medico" value={medico} onChange={(e) => setMedico(e.target.value)}>
        <option value="">Scegli un medico</option>
        {medici.map((m) => (
          <option key={m} value={m}>
            {m}
          </option>
        ))}
      </select>
      <label htmlFor="finalita-consenso">Finalità</label>
      <select id="finalita-consenso" value={finalita} onChange={(e) => setFinalita(e.target.value)}>
        {Object.entries(FINALITA).map(([valore, etichetta]) => (
          <option key={valore} value={valore}>
            {etichetta}
          </option>
        ))}
      </select>
      <label htmlFor="giorni">Durata in giorni (al massimo {MAX_GIORNI})</label>
      <input
        id="giorni"
        type="number"
        min={1}
        max={MAX_GIORNI}
        value={giorni}
        onChange={(e) => setGiorni(Math.min(MAX_GIORNI, Math.max(1, Math.trunc(Number(e.target.value)) || 1)))}
      />
      <Informativa />
      <label className="spunta">
        <input type="checkbox" checked={letta} onChange={(e) => setLetta(e.target.checked)} /> Ho letto l'informativa; la sua
        versione sarà indicata nel consenso che firmo.
      </label>
      <div className="azioni">
        <button onClick={concedi} disabled={inCorso || !provider || !medico || !letta}>
          Firma il consenso con il wallet
        </button>
      </div>
      {messaggio && <p className={messaggio.tipo}>{messaggio.testo}</p>}

      <RegistroAccessi
        auditLog={rete?.auditLog ?? null}
        provider={provider}
        consentIds={consensi.filter((c) => verifiche[c.consentId] === "ok").map((c) => c.consentId)}
      />
    </section>
  );
}
