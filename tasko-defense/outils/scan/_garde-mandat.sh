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

# Enveloppe : exécute le CLI tasko depuis la racine du paquet (import tasko OK).
tasko_cli() { ( cd "$TASKO_ROOT" && python3 -m tasko.cli "$@" ); }

# journaliser_outil <journal> <reference> <cible> <type> <outil> <ip_source> <decision> [fichier_empreinte]
# Consigne un lancement d'outil au journal des tests (Article 8 / Annexe C).
journaliser_outil() {
  local journal="$1" ref="$2" cible="$3" type_test="$4" outil="$5" ip="$6" dec="$7" emp="${8:-}"
  [ -n "$journal" ] || return 0
  local args=(journaliser --fichier "$journal" --reference "$ref" --cible "$cible" \
              --outil "$outil" --decision "$dec")
  [ -n "$type_test" ] && args+=(--type "$type_test")
  [ -n "$ip" ] && args+=(--ip-source "$ip")
  [ -n "$emp" ] && [ -f "$emp" ] && args+=(--empreinte-de "$emp")
  tasko_cli "${args[@]}" >/dev/null 2>&1 || true
}

# reference_mandat <mandat> : imprime la référence du mandat (pour les journaux/rapports).
reference_mandat() { tasko_cli info --mandat "$1" 2>/dev/null | sed -n 's/^Référence *: //p' | head -1; }

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
