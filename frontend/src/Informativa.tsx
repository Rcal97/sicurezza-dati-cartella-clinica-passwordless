import { useEffect, useState } from "react";
import { api } from "./api";

type Testo = { version: string; hash: string; text: string };

// Informativa privacy e cookie (artt. 13-14 GDPR, art. 122 Codice privacy), letta dal backend:
// è la stessa di cui il consenso riporta versione e impronta.
export default function Informativa() {
  const [informativa, setInformativa] = useState<Testo | null>(null);

  useEffect(() => {
    api.get<Testo>("/privacy").then(setInformativa).catch(() => setInformativa(null));
  }, []);

  if (!informativa) return null;
  return (
    <details className="informativa">
      <summary>Informativa privacy e cookie (versione {informativa.version})</summary>
      <pre>{informativa.text}</pre>
      <p className="nota">
        Impronta SHA-256 del testo: <code>{informativa.hash}</code>
      </p>
    </details>
  );
}
