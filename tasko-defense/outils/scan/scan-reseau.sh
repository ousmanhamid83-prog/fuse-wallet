#!/usr/bin/env bash
# scan-reseau.sh — Audit réseau DÉFENSIF de TON serveur (VPS que tu contrôles).
# Trouve : ports ouverts, services obsolètes, mauvaises configs. Pour CORRIGER.
#
# ⚠️ À lancer UNIQUEMENT sur un serveur que tu possèdes/contrôles (ton VPS).
#    JAMAIS sur un hébergement mutualisé (tu scannerais l'infra d'autres clients).
#
# Prérequis : sudo apt install nmap

set -euo pipefail

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
  echo "Usage : bash scan-reseau.sh <ip-ou-domaine-de-TON-serveur>"
  echo "Exemple : bash scan-reseau.sh 198.51.100.10"
  exit 1
fi

DATE=$(date +%Y%m%d-%H%M)
OUT="rapports-reseau/$DATE"
mkdir -p "$OUT"

echo "=== Audit réseau défensif : $TARGET ($DATE) ==="
echo ""

# --- 1. Découverte des ports ouverts + version des services ---
# -sV : détecte la version (pour repérer un service obsolète/vulnérable)
echo "--- 1. Ports ouverts et services ---"
nmap -sV --top-ports 1000 "$TARGET" -oN "$OUT/ports.txt"
echo "  -> $OUT/ports.txt"
echo ""

# --- 2. Détection de vulnérabilités connues (scripts NSE défensifs) ---
# Ces scripts CHERCHENT des failles connues ; ils ne les exploitent pas.
echo "--- 2. Vulnérabilités connues (NSE 'vuln') ---"
nmap -sV --script=vuln "$TARGET" -oN "$OUT/vuln.txt"
echo "  -> $OUT/vuln.txt"
echo ""

# --- 3. Configuration TLS/SSL (certificat, chiffrements faibles) ---
echo "--- 3. Audit TLS/SSL ---"
nmap --script=ssl-enum-ciphers,ssl-cert -p 443 "$TARGET" -oN "$OUT/tls.txt"
echo "  -> $OUT/tls.txt"
echo ""

echo "=== Terminé ==="
echo "Rapports : $OUT"
echo ""
echo "À corriger en priorité :"
echo "  - tout port ouvert non nécessaire -> ferme-le (pare-feu ufw/iptables)"
echo "  - tout service en version obsolète -> mets à jour"
echo "  - chiffrements TLS faibles -> désactive-les dans ta config serveur"
