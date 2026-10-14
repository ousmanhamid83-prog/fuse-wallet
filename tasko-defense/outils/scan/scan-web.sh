#!/usr/bin/env bash
# scan-web.sh — Audit DÉFENSIF des sites que TU contrôles.
# Objectif : TROUVER les failles pour les CORRIGER. Aucun exploit.
#
# Prérequis :
#   - nuclei  : go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
#   - wpscan  : gem install wpscan   (token gratuit sur wpscan.com)
#
# Usage :
#   1. Mets tes sites dans sites.txt (une URL https:// par ligne)
#   2. Mets ton token WPScan dans la variable ci-dessous (ou variable d'env)
#   3. bash scan-web.sh

set -euo pipefail

# --- Configuration ---
SITES_FILE="sites.txt"
WPSCAN_TOKEN="${WPSCAN_API_TOKEN:-METS_TON_TOKEN_ICI}"
DATE=$(date +%Y%m%d-%H%M)
OUT="rapports/$DATE"
RATE_LIMIT=30          # requêtes/seconde max (ménage l'hébergement mutualisé)
THROTTLE_MS=500        # pause entre requêtes WPScan

mkdir -p "$OUT"
echo "=== Audit défensif démarré : $DATE ==="
echo "Rapports -> $OUT"
echo ""

# --- Vérif préalable : chaque site répond-il vraiment ? (évite les scans vides) ---
echo "--- Étape 0 : vérification d'accessibilité ---"
while read -r URL; do
  [ -z "$URL" ] && continue
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -L --max-time 15 "$URL" || echo "000")
  case "$CODE" in
    200) echo "  [OK]  $URL ($CODE)" ;;
    301|302) echo "  [REDIR] $URL ($CODE) — le scan suivra la redirection" ;;
    403) echo "  [BLOQUÉ] $URL ($CODE) — ModSecurity/Cloudflare ? Mets ton IP en liste blanche" ;;
    000) echo "  [INJOIGNABLE] $URL — vérifie l'URL/DNS" ;;
    *)   echo "  [?]   $URL ($CODE)" ;;
  esac
done < "$SITES_FILE"
echo ""

# --- Étape 1 : Nuclei (vue d'ensemble rapide) ---
echo "--- Étape 1 : Nuclei ---"
nuclei -update-templates -silent 2>/dev/null || true
nuclei -l "$SITES_FILE" \
       -severity low,medium,high,critical \
       -rate-limit "$RATE_LIMIT" \
       -timeout 20 \
       -jsonl -o "$OUT/nuclei.jsonl" \
       -stats 2>&1 | tail -n 5 || true
echo "  -> $OUT/nuclei.jsonl"
echo ""

# --- Étape 2 : WPScan (sites WordPress uniquement) ---
echo "--- Étape 2 : WPScan (WordPress) ---"
while read -r URL; do
  [ -z "$URL" ] && continue
  SLUG=$(echo "$URL" | sed 's|https\?://||; s|/.*||; s|[^a-zA-Z0-9]|_|g')
  echo "  Scan WordPress : $URL"
  wpscan --url "$URL" \
         --enumerate vp,vt,u1-3 \
         --plugins-detection mixed \
         --api-token "$WPSCAN_TOKEN" \
         --throttle "$THROTTLE_MS" \
         --format json \
         --output "$OUT/wpscan_${SLUG}.json" \
         --no-banner 2>/dev/null || echo "    (pas WordPress ou inaccessible — ignoré)"
done < "$SITES_FILE"
echo ""

echo "=== Audit terminé ==="
echo "Rapports dans : $OUT"
echo ""
echo "Prochaine étape : trie les findings par sévérité (critical/high d'abord),"
echo "corrige, puis relance ce script pour vérifier que la faille a disparu."
