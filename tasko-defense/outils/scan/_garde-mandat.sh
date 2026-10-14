#!/usr/bin/env bash
# _garde-mandat.sh — garde d'autorisation partagé par les scripts de scan.
# À SOURCER, pas à exécuter. Fournit la fonction `exiger_mandat`.
#
# exiger_mandat <chemin-mandat> <cible> <type_test> [ip_source]
#   Appelle le moteur de mandat (tasko.cli). Si le test n'est PAS autorisé
#   (mandat non signé, hors périmètre, hors fenêtre, type interdit, mauvaise
#   IP source…), affiche la raison et STOPPE le script (exit 2).
#   Rien n'est scanné tant que cette fonction n'a pas renvoyé 0.

# Racine du paquet tasko (deux niveaux au-dessus de outils/scan/).
_GARDE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TASKO_ROOT="$(cd "$_GARDE_DIR/../.." && pwd)"

exiger_mandat() {
  local mandat="$1" cible="$2" type_test="$3" ip_source="${4:-}"

  if [ -z "$mandat" ] || [ -z "$cible" ] || [ -z "$type_test" ]; then
    echo "ERREUR interne : exiger_mandat <mandat> <cible> <type_test> [ip_source]" >&2
    exit 3
  fi
  if [ ! -f "$mandat" ]; then
    echo "ERREUR : mandat introuvable : $mandat" >&2
    echo "        Crée-le depuis mandats/exemple.mandat.yaml et fais-le SIGNER." >&2
    exit 3
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    echo "ERREUR : python3 requis pour vérifier le mandat." >&2
    exit 3
  fi

  local args=(verifier --mandat "$mandat" --cible "$cible" --type "$type_test")
  [ -n "$ip_source" ] && args+=(--ip-source "$ip_source")

  # On exécute le CLI depuis la racine du paquet pour que `import tasko` marche.
  if ( cd "$TASKO_ROOT" && python3 -m tasko.cli "${args[@]}" ); then
    return 0
  else
    local code=$?
    echo "" >&2
    echo ">>> SCAN BLOQUÉ par le garde de mandat (cible: $cible, test: $type_test)." >&2
    echo ">>> Aucune requête n'a été envoyée. Corrige le mandat et réessaie." >&2
    exit "$code"
  fi
}
