#!/usr/bin/env bash
# Rigenera tutte le misure e le figure dell'analisi sperimentale.
# Uso, dalla cartella principale del progetto:  bash analisi/genera.sh
# Prerequisiti: dipendenze npm installate in blockchain/ e backend/, ambiente Python
# creato in analisi/.venv (vedi analisi/requirements.txt).
set -euo pipefail
cd "$(dirname "$0")/.."
RADICE="$PWD"

if [ ! -x analisi/.venv/bin/jupyter ]; then
  echo "Manca l'ambiente Python: crealo con"
  echo "  cd analisi && python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt"
  exit 1
fi

echo "== 1/5 Costi on-chain (gas)"
(cd blockchain && npx hardhat run scripts/gas.ts)

echo "== 2/5 Prestazioni crittografiche (qualche minuto)"
(cd backend && npm run bench:crypto)

echo "== 3/5 Campagne d'attacco sulla versione attuale"
(cd backend && npm run bench:attacchi > /dev/null)

echo "== 4/5 Campagne d'attacco sulla versione precedente alla revisione di sicurezza"
PRIMA="$(mktemp -d)/prima-revisione"
git worktree add --quiet --detach "$PRIMA" 1e078ed
ln -s "$RADICE/backend/node_modules" "$PRIMA/backend/node_modules"
(cd backend && APP_DIR="$PRIMA/backend" VERSIONE=prima-della-revisione npm run bench:attacchi > /dev/null)
git worktree remove --force "$PRIMA"

echo "== 5/5 Esecuzione del notebook e creazione delle figure"
(cd analisi && .venv/bin/jupyter nbconvert --to notebook --execute --inplace analisi.ipynb)

echo "Fatto: dati in analisi/dati, figure in analisi/figure."
