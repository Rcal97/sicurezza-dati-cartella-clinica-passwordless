import { createHash } from "node:crypto";

// Informativa sul trattamento dei dati (artt. 13-14 GDPR) e sui cookie (art. 122 del Codice
// privacy). Ogni consenso registra la versione e l'impronta del testo che il paziente ha letto:
// se il testo cambia, va cambiata anche la versione e i nuovi consensi faranno riferimento a quella.
// Il prototipo usa una struttura sanitaria fittizia e dati sintetici.
export const NOTICE_VERSION = "1.0";

export const NOTICE_TEXT = `INFORMATIVA SUL TRATTAMENTO DEI DATI PERSONALI E SUI COOKIE (versione ${NOTICE_VERSION})

1. Titolare e responsabile della protezione dei dati
Titolare del trattamento è la struttura sanitaria che gestisce il servizio (nel prototipo: "Struttura sanitaria di esempio"). Il responsabile della protezione dei dati (DPO) è contattabile all'indirizzo indicato dalla struttura.

2. Dati trattati
Dati identificativi dell'account (nome utente e chiave pubblica della passkey); dati relativi alla salute contenuti nei referti; consensi espressi e loro ricevute firmate; registro degli accessi alla cartella. I dati biometrici usati per sbloccare la passkey restano sul dispositivo dell'interessato e non sono mai trasmessi al servizio.

3. Finalità e basi giuridiche
a) Cura (diagnosi, assistenza, terapia): art. 9, par. 2, lett. h) GDPR. La consultazione della cartella da parte di un medico avviene solo con il consenso specifico del paziente per quel medico e per questa finalità, revocabile in ogni momento.
b) Ricerca: consenso esplicito, art. 9, par. 2, lett. a) GDPR, separato e facoltativo; il rifiuto non ha conseguenze sulle cure.
c) Amministrazione: adempimenti amministrativi connessi all'assistenza, art. 9, par. 2, lett. h) GDPR.
d) Accesso d'emergenza: per tutelare la vita o la salute dell'interessato quando non può esprimere il consenso (art. 9, par. 2, lett. c) GDPR), solo da personale abilitato, con motivazione obbligatoria e registrazione dell'accesso.

4. Modalità del trattamento e blockchain
I referti, le ricevute dei consensi e i dettagli degli accessi sono conservati cifrati (AES-256-GCM, con chiavi protette da cifratura post-quantistica ibrida). Sulla blockchain pubblica Ethereum non sono scritti dati personali in chiaro: solo identificativi opachi calcolati con una chiave segreta della struttura (HMAC-SHA256), scadenze e impronte crittografiche di dati conservati altrove. Cancellando il segreto associato all'interessato, quegli identificativi non sono più riconducibili a lui.

5. Destinatari
Personale sanitario autorizzato secondo i consensi espressi; personale d'emergenza abilitato; fornitori tecnici nominati responsabili del trattamento. I dati non sono diffusi.

6. Conservazione
Referti: per il tempo previsto dalla normativa sulla documentazione sanitaria. Registro degli accessi e ricevute dei consensi: per il tempo necessario a dimostrare la liceità dei trattamenti e a rispondere a richieste dell'interessato o delle autorità. Account e passkey: fino alla cancellazione richiesta dall'interessato.

7. Diritti dell'interessato
Accesso (art. 15), anche all'elenco di chi ha consultato la cartella; rettifica (art. 16), che per i referti avviene per integrazione, senza cancellare quanto già registrato; cancellazione (art. 17), nei limiti degli obblighi di conservazione; limitazione (art. 18); portabilità (art. 20) per i dati trattati sulla base del consenso; opposizione (art. 21); revoca del consenso in qualsiasi momento, senza pregiudicare la liceità del trattamento precedente (art. 7). Reclamo al Garante per la protezione dei dati personali.

8. Cookie
Il servizio usa un solo cookie tecnico di sessione ("sid"), necessario per mantenere l'accesso dopo l'autenticazione: HttpOnly, SameSite=Strict, Secure in produzione; scade dopo 15 minuti di inattività e comunque dopo 8 ore. Non sono usati cookie di profilazione né di terze parti: per questo non è richiesto un consenso ai cookie (art. 122 del Codice privacy).
`;

export const NOTICE_HASH = "0x" + createHash("sha256").update(NOTICE_TEXT).digest("hex");
