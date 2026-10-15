#!/usr/bin/env bash
# audit-parc.sh — Audit DÉFENSIF d'un PARC entier (lot d'hôtes), cadré par mandat.
#
# Pour un parc de milliers de machines : au lieu de lancer les scans un à un, on
# fournit un INVENTAIRE (une cible par ligne) ; CHAQUE cible est vérifiée contre
# le mandat AVANT d'être scannée. Une cible hors mandat est IGNORÉE (jamais
# scannée), le lot continue. On TROUVE les failles, on n'exploite rien.
#
# Astuce d'échelle : le mandat peut lui-même pointer un fichier d'inventaire
# (perimetre.ips_fichier / domaines_fichier) — tu déclares tes plages une fois.
#
# Prérequis : python3 + PyYAML, et les outils du scan choisi (nuclei/wpscan ou nmap).
#
# Usage :
#   export MANDAT=../../mandats/auto-audit.mandat.yaml   # mandat SIGNÉ
#   export AUDIT_IP=198.51.100.10                        # (optionnel) IP source
#   export WPSCAN_API_TOKEN=xxxx                         # pour un audit web
#   bash audit-parc.sh inventaire.txt web      # inventaire = une URL par ligne
#   bash audit-parc.sh parc.txt reseau         # inventaire = un hôte/IP par ligne

set -uo pipefail
cd "$(dirname "$0")"
source ./_garde-mandat.sh

die() { echo "ERREUR : $*" >&2; exit 1; }

MANDAT="${MANDAT:-}"
AUDIT_IP="${AUDIT_IP:-}"
PAUSE="${PAUSE:-2}"                 # pause (s) entre deux hôtes (ménage le réseau)
INVENTAIRE="${1:-}"
TYPE="${2:-}"

[ -n "$MANDAT" ] || die "variable MANDAT non définie (chemin d'un mandat signé)."
[ -f "$INVENTAIRE" ] || die "inventaire introuvable : ${INVENTAIRE:-<manquant>}"
case "$TYPE" in
  web)     TEST_TYPE="scan_web";    SCANNER="scan-web.sh" ;;
  reseau)  TEST_TYPE="scan_reseau"; SCANNER="scan-reseau.sh" ;;
  *) die "usage : bash audit-parc.sh <inventaire> <web|reseau>" ;;
esac

DATE=$(date +%Y%m%d-%H%M%S)
OUT="$PWD/audits-parc/$DATE"
mkdir -p "$OUT"
JOURNAL="$OUT/journal-tests.jsonl"
REF="$(reference_mandat "$MANDAT")"
RESUME="$OUT/resume.txt"

n=0; ok=0; ignore=0; echec=0
echo "=== Audit de parc ($TYPE) : $DATE ===" | tee "$RESUME"
echo "Mandat : $MANDAT ($REF)" | tee -a "$RESUME"
echo "" | tee -a "$RESUME"

while IFS= read -r CIBLE || [ -n "$CIBLE" ]; do
  CIBLE="${CIBLE%%#*}"                 # retire les commentaires
  CIBLE="$(echo "$CIBLE" | xargs 2>/dev/null)"  # trim espaces
  [ -z "$CIBLE" ] && continue
  n=$((n+1))

  # 1) Garde de mandat : la cible est-elle autorisée pour ce type de test ?
  gargs=(verifier --mandat "$MANDAT" --cible "$CIBLE" --type "$TEST_TYPE" \
         --journal "$JOURNAL" --outil "audit-parc")
  [ -n "$AUDIT_IP" ] && gargs+=(--ip-source "$AUDIT_IP")
  if ! tasko_cli "${gargs[@]}" >/dev/null 2>&1; then
    echo "  [IGNORÉ hors mandat] $CIBLE" | tee -a "$RESUME"
    ignore=$((ignore+1))
    continue
  fi

  # 2) Scan de la cible autorisée (échec isolé : on continue le lot).
  echo "  [SCAN] $CIBLE" | tee -a "$RESUME"
  if MANDAT="$MANDAT" AUDIT_IP="$AUDIT_IP" bash "./$SCANNER" "$CIBLE" \
        > "$OUT/scan_$(echo "$CIBLE" | sed 's|[^a-zA-Z0-9]|_|g').log" 2>&1; then
    ok=$((ok+1))
  else
    echo "    (échec du scan — voir le log)" | tee -a "$RESUME"
    echec=$((echec+1))
  fi
  sleep "$PAUSE"
done < "$INVENTAIRE"

echo "" | tee -a "$RESUME"
echo "=== Terminé : $n cible(s) | $ok scannée(s) | $ignore ignorée(s) hors mandat | $echec échec(s) ===" | tee -a "$RESUME"
echo "Résultats : $OUT" | tee -a "$RESUME"

# Annexe C agrégée du lot (preuve du caractère autorisé).
tasko_cli journal --fichier "$JOURNAL" --sortie "$OUT/annexe-C-journal.md" >/dev/null 2>&1 || true
echo "Journal (Annexe C) : $OUT/annexe-C-journal.md" | tee -a "$RESUME"
