# Cartella clinica passwordless

Progetto d'esame di Sicurezza dei Dati (Università di Salerno, Laurea magistrale in Informatica, curriculum Sicurezza Informatica).

Sistema per l'accesso a cartelle cliniche sintetiche con:

- accesso senza password tramite FIDO2/WebAuthn;
- consenso del paziente e audit degli accessi su blockchain (Ethereum, Solidity);
- referti cifrati con uno schema ibrido post-quantistico (ML-KEM-768 e X25519) e firmati dal medico con la passkey.

Sulla blockchain finiscono solo hash e indirizzi. I dati clinici restano cifrati off-chain e sono esclusivamente dati sintetici.

## Struttura

- `blockchain/` smart contract Solidity (Hardhat, OpenZeppelin)
- `backend/` server Node.js con TypeScript
- `frontend/` interfaccia web con WebAuthn
- `docs/` appunti e decisioni di progetto

La relazione è nella cartella `relazione/`.

## Stato

Bozza iniziale: struttura del repository.
