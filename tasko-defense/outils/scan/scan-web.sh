#!/usr/bin/env bash
# scan-web.sh — Audit web DÉFENSIF, cadré par un MANDAT signé.
# Trouve les failles pour les CORRIGER. Aucun exploit.
#
# Chaque cible est vérifiée contre le mandat (périmètre, fenêtre horaire, type
# de test, IP source) AVANT le moindre envoi. Un site non couvert est ignoré,
# jamais scanné.
#
# Prérequis :
#   - python3 + PyYAML (pour le moteur de mandat)
#   - nuclei  : release officielle (voir GUIDE Étape 1) dans le PATH
#   - wpscan  : gem install wpscan  (token gratuit sur wpscan.com)
#
# Usage :
#   export MANDAT=../../mandats/tonsite.mandat.yaml   # mandat SIGNÉ
#   export WPSCAN_API_TOKEN=xxxx
#   export AUDIT_IP=198.51.100.10        # ton IP source déclarée (Article 3)
#   bash scan-web.sh                     # cibles lues dans sites.txt
#   bash scan-web.sh https://un-site/    # ou une cible unique en argument

set -euo pipefail
cd "$(dirname "$0")"
source ./_garde-mandat.sh

# --- Configuration ---
MANDAT="${MANDAT:-}"
SITES_FILE="${SITES_FILE:-sites.txt}"
WPSCAN_TOKEN="${WPSCAN_API_TOKEN:-}"
AUDIT_IP="${AUDIT_IP:-}"
DATE=$(date +%Y%m%d-%H%M)
# Chemin ABSOLU : les appels à tasko_cli changent de répertoire (cd TASKO_ROOT),
# donc un chemin relatif serait résolu au mauvais endroit.
OUT="$PWD/rapports/$DATE"
RATE_LIMIT="${RATE_LIMIT:-30}"     # requêtes/seconde max
THROTTLE_MS="${THROTTLE_MS:-500}"  # pause entre requêtes WPScan

die() { echo "ERREUR : $*" >&2; exit 1; }

[ -n "$MANDAT" ] || die "variable MANDAT non définie (chemin d'un mandat signé)."
[ -n "$WPSCAN_TOKEN" ] || die "WPSCAN_API_TOKEN non défini (token gratuit sur wpscan.com)."
command -v nuclei >/dev/null 2>&1 || die "nuclei introuvable dans le PATH (voir GUIDE Étape 1)."
command -v wpscan >/dev/null 2>&1 || die "wpscan introuvable (gem install wpscan)."

# --- Construire la liste des cibles (argument unique, ou sites.txt normalisé) ---
mkdir -p "$OUT"
CIBLES="$OUT/cibles.txt"
if [ "$#" -ge 1 ]; then
  printf '%s\n' "$@" > "$CIBLES"
else
  [ -f "$SITES_FILE" ] || die "ni argument, ni $SITES_FILE (une URL https:// par ligne)."
  # Normalise : enlève les CR (CRLF), les commentaires, les espaces, les lignes vides.
  sed -e 's/\r$//' -e 's/#.*//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$SITES_FILE" \
    | grep -v '^$' > "$CIBLES" || true
fi
[ -s "$CIBLES" ] || die "aucune cible à scanner."

JOURNAL="$OUT/journal-tests.jsonl"
REF="$(reference_mandat "$MANDAT")"

echo "=== Audit web défensif : $DATE ==="
echo "Mandat  : $MANDAT ($REF)"
echo "Cibles  : $(wc -l < "$CIBLES") | Rapports -> $OUT"
echo ""

# --- Garde de mandat : ne garder que les cibles AUTORISÉES pour scan_web ---
echo "--- Vérification du mandat (scan_web) ---"
AUTORISEES="$OUT/cibles-autorisees.txt"; : > "$AUTORISEES"
while IFS= read -r URL || [ -n "$URL" ]; do
  [ -z "$URL" ] && continue
  gargs=(verifier --mandat "$MANDAT" --cible "$URL" --type scan_web --journal "$JOURNAL" --outil tasko-gate)
  [ -n "$AUDIT_IP" ] && gargs+=(--ip-source "$AUDIT_IP")
  if ( cd "$TASKO_ROOT" && python3 -m tasko.cli "${gargs[@]}" ); then
    echo "$URL" >> "$AUTORISEES"
  else
    echo "  [IGNORÉ - hors mandat] $URL"
  fi
done < "$CIBLES"
echo ""
[ -s "$AUTORISEES" ] || die "aucune cible autorisée par le mandat — rien à scanner."

# --- Étape 0 : accessibilité (sur les cibles autorisées seulement) ---
echo "--- Étape 0 : accessibilité ---"
while IFS= read -r URL || [ -n "$URL" ]; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -L --max-time 15 "$URL" 2>/dev/null) || CODE="000"
  case "$CODE" in
    200)     echo "  [OK]  $URL ($CODE)" ;;
    301|302) echo "  [REDIR] $URL ($CODE)" ;;
    403)     echo "  [BLOQUÉ] $URL ($CODE) — WAF/Cloudflare ? liste blanche ton IP d'audit" ;;
    000)     echo "  [INJOIGNABLE] $URL — vérifie l'URL/DNS" ;;
    *)       echo "  [?]   $URL ($CODE)" ;;
  esac
done < "$AUTORISEES"
echo ""

# --- Étape 1 : Nuclei (templates dangereux explicitement exclus) ---
echo "--- Étape 1 : Nuclei ---"
nuclei -update-templates -silent 2>/dev/null || true
NRC=0
nuclei -l "$AUTORISEES" \
       -severity low,medium,high,critical \
       -exclude-tags dos,fuzz,intrusive,brute-force \
       -rate-limit "$RATE_LIMIT" \
       -timeout 20 \
       -jsonl -o "$OUT/nuclei.jsonl" \
       -stats > "$OUT/nuclei.log" 2>&1 || NRC=$?
if [ "$NRC" -eq 0 ]; then echo "  -> $OUT/nuclei.jsonl"; else echo "  [ÉCHEC nuclei code $NRC] voir $OUT/nuclei.log"; fi
journaliser_outil "$JOURNAL" "$REF" "(liste)" "scan_web" "nuclei" "$AUDIT_IP" "terminé (code $NRC)" "$OUT/nuclei.jsonl"
echo ""

# --- Étape 2 : WPScan (WordPress), avec interprétation du code de sortie ---
echo "--- Étape 2 : WPScan ---"
i=0
while IFS= read -r URL || [ -n "$URL" ]; do
  i=$((i+1))
  SLUG=$(printf '%s' "$URL" | sed 's|https\?://||; s|/.*||; s|[^a-zA-Z0-9]|_|g')
  OUTJSON="$OUT/wpscan_${i}_${SLUG}.json"   # index i -> pas d'écrasement entre URLs d'un même hôte
  echo "  Scan WordPress : $URL"
  WRC=0
  wpscan --url "$URL" \
         --enumerate vp,vt,u1-3 \
         --plugins-detection mixed \
         --api-token "$WPSCAN_TOKEN" \
         --throttle "$THROTTLE_MS" \
         --format json \
         --output "$OUTJSON" \
         --no-banner </dev/null 2>>"$OUT/wpscan.stderr" || WRC=$?
  case "$WRC" in
    0) echo "    OK — aucune vulnérabilité connue" ;;
    5) echo "    [VULNÉRABLE] findings dans $OUTJSON" ;;
    4) echo "    [ÉCHEC WPScan] token invalide ou cible injoignable — voir $OUT/wpscan.stderr" ;;
    *) echo "    [code $WRC] voir $OUTJSON / $OUT/wpscan.stderr (souvent : pas WordPress)" ;;
  esac
  journaliser_outil "$JOURNAL" "$REF" "$URL" "scan_web" "wpscan" "$AUDIT_IP" "terminé (code $WRC)" "$OUTJSON"
done < "$AUTORISEES"
echo ""

# --- Rapport client (Article 6) + Annexe C (Article 8) ---
echo "--- Génération du rapport ---"
tasko_cli rapport --dossier "$OUT" --mandat "$MANDAT" --date "$DATE" --sortie "$OUT/rapport.md" || true
tasko_cli journal --fichier "$JOURNAL" --sortie "$OUT/annexe-C-journal.md" >/dev/null 2>&1 || true
echo ""

echo "=== Audit terminé ==="
echo "Rapports   : $OUT"
echo "Rapport    : $OUT/rapport.md"
echo "Journal    : $OUT/annexe-C-journal.md (preuve Article 8)"
echo "Trie les findings par sévérité (critical/high d'abord), corrige, puis relance."
