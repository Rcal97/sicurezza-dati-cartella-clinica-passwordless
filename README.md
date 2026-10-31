# Cartella clinica passwordless

Progetto d'esame di Sicurezza dei Dati (Università di Salerno, Laurea magistrale in Informatica, curriculum Sicurezza Informatica).

Sistema per l'accesso a cartelle cliniche sintetiche con:

- accesso senza password tramite FIDO2/WebAuthn;
- consenso del paziente e audit degli accessi su blockchain (Ethereum, Solidity);
- prova di abilitazione del medico con prove a conoscenza zero (circom, snarkjs).

Sulla blockchain finiscono solo hash, indirizzi e prove. I dati clinici restano cifrati off-chain e sono esclusivamente dati sintetici.

## Struttura

- `blockchain/` smart contract Solidity (Hardhat, OpenZeppelin)
- `backend/` server Node.js con TypeScript
- `frontend/` interfaccia web con WebAuthn
- `circuits/` circuiti circom per gli ZKP
- `docs/` appunti e decisioni di progetto

La relazione e la presentazione sono su Overleaf.

## Stato

Bozza iniziale: struttura del repository.
