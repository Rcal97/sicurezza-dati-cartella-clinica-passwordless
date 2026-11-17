#!/usr/bin/env bash
# Copia i sorgenti della relazione dalla cartella in cui si compila (su Windows) alla
# cartella relazione/ del repository. Copia solo .tex, .bib e le figure in PDF: i file
# temporanei di LaTeX e il PDF finale non vengono versionati.
# Uso (da WSL, nella cartella del progetto):
#   bash infra/salva-relazione.sh /mnt/c/Users/<utente>/Relazione_Sicurezza
set -euo pipefail

origine="${1:-}"
if [[ -z "$origine" || ! -f "$origine/main.tex" ]]; then
  echo "Uso: bash infra/salva-relazione.sh <cartella che contiene main.tex>" >&2
  exit 1
fi

destinazione="$(cd "$(dirname "$0")/.." && pwd)/relazione"
mkdir -p "$destinazione"

# La copia sostituisce quella precedente: un file tolto dalla relazione sparisce anche qui.
rm -rf "$destinazione"
mkdir -p "$destinazione"
(
  cd "$origine"
  find . -type f \( -name '*.tex' -o \( -name '*.bib' ! -name '*-blx.bib' \) -o -path './figure/*.pdf' \) -print0 |
    xargs -0 cp --parents -t "$destinazione"
)

echo "Relazione copiata in $destinazione. File modificati:"
git -C "$destinazione" status --short --untracked-files=all -- .
