# Cartella clinica passwordless

**Consenso, accesso e audit con FIDO2 e blockchain**

Progetto d'esame di Sicurezza dei Dati, Università degli Studi di Salerno, Laurea magistrale in Informatica, curriculum Sicurezza Informatica.

Prototipo di cartella clinica elettronica in cui:

- pazienti e medici accedono **senza password**, con una passkey FIDO2/WebAuthn, resistente al phishing e al replay;
- il paziente **concede e revoca il consenso** firmandolo con il proprio wallet (EIP-712), per un medico, una finalità (cura, ricerca, amministrazione) e fino a una scadenza; la ricevuta firmata, con la versione dell'informativa accettata, è conservata cifrata e il suo stato è registrato su uno smart contract;
- ogni accesso, concesso o negato, è **registrato su blockchain** prima che i dati vengano consegnati;
- i referti sono **cifrati** con uno schema ibrido post-quantistico (ML-KEM-768 + X25519, AES-256-GCM) e **firmati** dal medico con la passkey.

Sulla blockchain pubblica **non va alcun dato personale**, nemmeno gli indirizzi di pazienti e medici: solo ancore opache (HMAC-SHA256 con una chiave della struttura e un segreto per ogni paziente), scadenze e impronte crittografiche. Tutti i dati clinici sono **sintetici**.

La relazione completa è nella cartella [`relazione/`](relazione/).

## Struttura

| Cartella | Contenuto |
| --- | --- |
| `backend/` | Server Node.js 24 + TypeScript + Express 5: autenticazione FIDO2, sessioni, controllo degli accessi, cifratura e firma dei referti, audit |
| `frontend/` | Interfaccia web React + Vite: passkey, cartelle, consensi con MetaMask, registro degli accessi verificabile sulla catena |
| `blockchain/` | Smart contract Solidity 0.8 (`ConsentRegistry`, `AuditLog`) con OpenZeppelin, test e pubblicazione con Hardhat |
| `analisi/` | Script di misura e notebook Jupyter che rigenera le figure della valutazione |
| `infra/` | Inizializzazione di MongoDB e script di supporto |
| `relazione/` | Sorgenti LaTeX della relazione |

## Requisiti

- Node.js 24 (versione in `.nvmrc`)
- Docker, per MongoDB 8.0
- Un browser con supporto alle passkey e l'estensione MetaMask

Su Linux, MongoDB 8.x non si avvia con i kernel dalla 6.19 alla 7.0.13: serve un kernel precedente al 6.19 o almeno il 7.0.14 (`uname -r`).

## Avvio in locale

1. **Configurazione.** Copia `.env.example` in `.env` e cambia le password di MongoDB. Il file `.env` è escluso da Git.
2. **Dipendenze.** Esegui `npm ci` nelle cartelle `backend`, `frontend` e `blockchain`.
3. **Database.** Dalla cartella principale: `docker compose up -d`.
4. **Blockchain locale.** Nella cartella `blockchain`, in un terminale dedicato: `npm run node`. In un altro terminale: `npm run deploy:local`.
5. **Chiavi dell'archivio**, solo la prima volta. Nella cartella `backend`: `npm run chiavi`. Scegli una passphrase di almeno 12 caratteri e non perderla: senza di essa i referti non si possono più leggere.
6. **Backend.** Nella cartella `backend`: `npm run dev`. Chiede la passphrase.
7. **Frontend.** Nella cartella `frontend`: `npm run dev`, poi apri <http://localhost:5173>.

Per spegnere tutto: Ctrl+C nei terminali di frontend, backend e nodo Hardhat, poi `docker compose stop`.

## Operazioni della struttura sanitaria

Si eseguono dalla cartella `backend` e simulano gli uffici che identificano le persone.

| Comando | A cosa serve |
| --- | --- |
| `npm run invito -- <username>` | Rilascia un invito monouso per registrare la prima passkey |
| `npm run profilo -- <username> medico` | Assegna il ruolo di medico |
| `npm run profilo -- <username> paziente <indirizzo>` | Assegna il ruolo di paziente e il wallet con cui firmerà i consensi |
| `npm run emergenza -- <medico> [--disabilita]` | Abilita un medico agli accessi d'emergenza (chiede la chiave dell'amministratore dei contratti) |
| `npm run referto -- <paziente> "<titolo>" <file>` | Carica un referto di laboratorio, cifrato |
| `npm run revoca -- <username>` | Revoca d'ufficio passkey e sessioni di un utente |
| `npm run registro-accessi -- [paziente]` | Consulta il registro cifrato degli accessi |
| `npm run cancella-utente -- <username> [--referti]` | Cancellazione su richiesta (art. 17 GDPR) |
| `npm run backup-chiavi -- <cartella>` | Backup delle chiavi diviso in 5 quote (soglia 3) |
| `npm run ripristino-chiavi -- <backup.json> <quota> <quota> <quota>` | Ripristino dalle quote |

## Test

| Gruppo | Comando | Test |
| --- | --- | --- |
| Backend, unitari | `npm test` in `backend` | 145 |
| Backend su MongoDB reale | `npm run test:mongo` in `backend` | 21 |
| Backend sulla blockchain locale | `npm run test:chain` in `backend` | 10 |
| Smart contract | `npm test` in `blockchain` | 40 |

`test:mongo` richiede MongoDB avviato; `test:chain` richiede il nodo Hardhat avviato e i contratti pubblicati.

## Sicurezza del repository

- Nessun segreto è nel repository: `.env`, la cartella `secrets/` e le quote di backup sono esclusi da Git.
- La chiave in `.env.example` è una delle chiavi di prova **pubbliche** di Hardhat, valida solo sulla rete locale; il backend rifiuta di usarla su qualunque altra rete.
- Versioni delle librerie fissate nei `package-lock.json`; immagine di MongoDB fissata con il digest.
- Su GitHub sono attivi Dependabot, la ricerca dei segreti con blocco dei push e l'analisi statica con CodeQL.
