import { useCallback, useEffect, useState } from "react";
import { BrowserProvider, Contract, type Eip1193Provider } from "ethers";
import { api } from "./api";

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

// Senza cache: dopo una transazione l'elenco va riletto dalla catena, non da una risposta
// memorizzata qualche istante prima (ethers riusa per 250 ms le richieste identiche).
const collega = (wallet: Wallet) => new BrowserProvider(wallet, undefined, { cacheTimeout: -1 });

// Solo le funzioni e gli eventi del registro dei consensi che servono alla pagina.
const ABI = [
  "function grantConsent(address grantee, uint8 purpose, uint64 expiresAt)",
  "function revokeConsent(address grantee, uint8 purpose)",
  "function isConsentValid(address patient, address grantee, uint8 purpose) view returns (bool)",
  "event ConsentGranted(address indexed patient, address indexed grantee, uint8 indexed purpose, uint64 expiresAt)",
];
const FINALITA = ["Cura", "Ricerca", "Amministrazione"];
const MAX_GIORNI = 365; // come MAX_DURATION nel contratto

type Medico = { username: string; address: string };
type Rete = { chainId: number; consentRegistry: string };
type Consenso = { medico: string; address: string; purpose: number; expiresAt: number };

// Testo leggibile per gli errori più comuni del wallet.
function descrivi(err: unknown): string {
  const e = err as { code?: string; shortMessage?: string; message?: string };
  if (e.code === "ACTION_REJECTED") return "Operazione annullata nel wallet.";
  return e.shortMessage ?? e.message ?? "Errore imprevisto.";
}

// Pagina del paziente: concede e revoca i consensi firmando lui stesso le transazioni con il
// proprio wallet. Il backend fornisce solo informazioni pubbliche (medici e indirizzo del
// contratto) e non vede mai la chiave del paziente.
export default function PannelloConsensi({ indirizzo }: { indirizzo: string }) {
  const [rete, setRete] = useState<Rete | null>(null);
  const [medici, setMedici] = useState<Medico[]>([]);
  const [provider, setProvider] = useState<BrowserProvider | null>(null);
  const [consensi, setConsensi] = useState<Consenso[]>([]);
  const [medico, setMedico] = useState("");
  const [finalita, setFinalita] = useState(0);
  const [giorni, setGiorni] = useState(30);
  const [messaggio, setMessaggio] = useState<{ tipo: "ok" | "errore"; testo: string } | null>(null);
  const [inCorso, setInCorso] = useState(false);

  useEffect(() => {
    api.get<Rete>("/directory/chain").then(setRete).catch(() => setRete(null));
    api.get<Medico[]>("/directory/doctors").then(setMedici).catch(() => setMedici([]));
  }, []);

  // Se nel wallet si passa a un'altra rete o a un altro account, il collegamento non vale più:
  // va rifatto da capo, così che i controlli su rete e indirizzo vengano ripetuti. Il passaggio
  // alla rete giusta, chiesto dalla pagina stessa durante il collegamento, non conta.
  useEffect(() => {
    const wallet = window.ethereum;
    if (!wallet?.on || !rete) return;
    const scollega = () => {
      setProvider(null);
      setConsensi([]);
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

  // Consensi attivi, ricostruiti dagli eventi del contratto e confermati con isConsentValid.
  const carica = useCallback(
    async (p: BrowserProvider) => {
      if (!rete) return;
      const registro = new Contract(rete.consentRegistry, ABI, p);
      const eventi = await registro.queryFilter(registro.filters.ConsentGranted(indirizzo));
      const ultimi = new Map<string, Consenso>();
      for (const ev of eventi) {
        if (!("args" in ev)) continue;
        const address: string = ev.args.grantee;
        const purpose = Number(ev.args.purpose);
        const nome = medici.find((m) => m.address === address)?.username ?? address;
        ultimi.set(`${address}|${purpose}`, { medico: nome, address, purpose, expiresAt: Number(ev.args.expiresAt) });
      }
      const attivi = [];
      for (const c of ultimi.values()) {
        if (await registro.getFunction("isConsentValid")(indirizzo, c.address, c.purpose)) attivi.push(c);
      }
      setConsensi(attivi);
    },
    [rete, medici, indirizzo],
  );

  const connetti = () =>
    esegui(async () => {
      if (!window.ethereum) throw new Error("Serve un wallet nel browser (per esempio MetaMask).");
      if (!rete) throw new Error("Informazioni sulla rete non disponibili.");
      let p = collega(window.ethereum);
      await p.send("eth_requestAccounts", []);
      if (Number((await p.getNetwork()).chainId) !== rete.chainId) {
        await p.send("wallet_switchEthereumChain", [{ chainId: "0x" + rete.chainId.toString(16) }]);
        // Un provider di ethers resta legato alla rete su cui è nato: dopo il cambio se ne crea uno nuovo.
        p = collega(window.ethereum);
        if (Number((await p.getNetwork()).chainId) !== rete.chainId) {
          throw new Error("Il wallet non è passato alla rete del registro dei consensi.");
        }
      }
      const account = (await p.getSigner()).address;
      // Il consenso vale solo se firmato dall'indirizzo pseudonimo registrato per il paziente.
      if (account !== indirizzo) {
        throw new Error(`Nel wallet è selezionato ${account}: scegli l'account ${indirizzo}, il tuo indirizzo registrato.`);
      }
      setProvider(p);
      await carica(p);
    });

  const concedi = () =>
    esegui(async () => {
      if (!provider || !rete) return;
      const registro = new Contract(rete.consentRegistry, ABI, await provider.getSigner());
      const adesso = (await provider.getBlock("latest"))!.timestamp;
      const tx = await registro.getFunction("grantConsent")(medico, finalita, adesso + giorni * 86400);
      await tx.wait();
      await carica(provider);
      setMessaggio({ tipo: "ok", testo: "Consenso concesso e registrato sulla blockchain." });
    });

  const revoca = (c: Consenso) =>
    esegui(async () => {
      if (!provider || !rete) return;
      const registro = new Contract(rete.consentRegistry, ABI, await provider.getSigner());
      await (await registro.getFunction("revokeConsent")(c.address, c.purpose)).wait();
      await carica(provider);
      setMessaggio({ tipo: "ok", testo: "Consenso revocato." });
    });

  return (
    <section>
      <h2>I miei consensi</h2>
      <p className="nota">
        Il tuo indirizzo per i consensi: <code>{indirizzo}</code>. Le transazioni le firmi tu, con il tuo wallet.
      </p>
      {!provider ? (
        <button onClick={connetti} disabled={inCorso || !rete}>
          Collega il wallet
        </button>
      ) : (
        <>
          {consensi.length === 0 && <p className="nota">Nessun consenso attivo.</p>}
          <ul className="referti">
            {consensi.map((c) => (
              <li key={`${c.address}|${c.purpose}`} className="consenso">
                <span>
                  <strong>{c.medico}</strong> — {FINALITA[c.purpose]}, fino al{" "}
                  {new Date(c.expiresAt * 1000).toLocaleString("it-IT")}
                </span>
                <button className="secondario" onClick={() => revoca(c)} disabled={inCorso}>
                  Revoca
                </button>
              </li>
            ))}
          </ul>

          <h2>Nuovo consenso</h2>
          <label htmlFor="medico">Medico</label>
          <select id="medico" value={medico} onChange={(e) => setMedico(e.target.value)}>
            <option value="">Scegli un medico</option>
            {medici.map((m) => (
              <option key={m.address} value={m.address}>
                {m.username}
              </option>
            ))}
          </select>
          <label htmlFor="finalita-consenso">Finalità</label>
          <select id="finalita-consenso" value={finalita} onChange={(e) => setFinalita(Number(e.target.value))}>
            {FINALITA.map((f, i) => (
              <option key={f} value={i}>
                {f}
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
            onChange={(e) => setGiorni(Math.min(MAX_GIORNI, Math.max(1, Number(e.target.value) || 1)))}
          />
          <div className="azioni">
            <button onClick={concedi} disabled={inCorso || !medico}>
              Concedi il consenso
            </button>
          </div>
        </>
      )}
      {messaggio && <p className={messaggio.tipo}>{messaggio.testo}</p>}
    </section>
  );
}
