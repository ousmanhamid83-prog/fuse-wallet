#!/usr/bin/env bash
# scan-reseau.sh — Audit réseau DÉFENSIF, cadré par un MANDAT signé.
# À lancer UNIQUEMENT sur un serveur DÉDIÉ du Client (jamais du mutualisé :
# tu scannerais l'infra d'autres clients de l'hébergeur).
#
# La cible est vérifiée contre le mandat (type 'scan_reseau', qui exige en plus
# un hébergement déclaré dédié) AVANT tout envoi. Les scripts NSE dangereux
# (dos, intrusive, exploit, external) sont EXCLUS : on cherche les failles, on
# ne les exploite pas et on ne dégrade pas la disponibilité (mandat §2.4).
#
# Prérequis : python3 + PyYAML, et nmap.
#
# Usage :
#   export MANDAT=../../mandats/tonsite.mandat.yaml   # mandat SIGNÉ, scan_reseau autorisé
#   export AUDIT_IP=198.51.100.10                     # IP source déclarée (Article 3)
#   bash scan-reseau.sh <ip-ou-domaine-du-serveur-du-Client>

set -euo pipefail
cd "$(dirname "$0")"
source ./_garde-mandat.sh

die() { echo "ERREUR : $*" >&2; exit 1; }

MANDAT="${MANDAT:-}"
AUDIT_IP="${AUDIT_IP:-}"
TARGET="${1:-}"

[ -n "$MANDAT" ] || die "variable MANDAT non définie (chemin d'un mandat signé)."
[ -n "$TARGET" ] || die "usage : bash scan-reseau.sh <ip-ou-domaine-du-serveur-du-Client>"
command -v nmap >/dev/null 2>&1 || die "nmap introuvable (sudo apt install -y nmap)."

# Refuse une "cible" qui est en fait une option, une plage ou plusieurs cibles :
# on n'autorise qu'un seul hôte/IP, jamais une injection d'arguments nmap.
case "$TARGET" in
  -*|*" "*|*,*|*"*"*|*/*) die "cible invalide (un seul hôte/IP, pas d'option, plage ou liste) : $TARGET" ;;
esac

# --- Garde de mandat (scan_reseau) : stoppe le script si non autorisé ---
echo "--- Vérification du mandat (scan_reseau) ---"
exiger_mandat "$MANDAT" "$TARGET" "scan_reseau" "$AUDIT_IP"
echo ""

DATE=$(date +%Y%m%d-%H%M)
SLUG=$(printf '%s' "$TARGET" | sed 's|[^a-zA-Z0-9.]|_|g')
# Chemin ABSOLU (tasko_cli fait cd vers la racine du paquet).
OUT="$PWD/rapports-reseau/${SLUG}_${DATE}"
mkdir -p "$OUT"
chmod 700 "$OUT" 2>/dev/null || true
JOURNAL="$OUT/journal-tests.jsonl"
REF="$(reference_mandat "$MANDAT")"
journaliser_outil "$JOURNAL" "$REF" "$TARGET" "scan_reseau" "tasko-gate" "$AUDIT_IP" "autorisé"

echo "=== Audit réseau défensif : $TARGET ($DATE) ==="
echo ""

# 1. Ports ouverts + versions (repérer un service obsolète)
echo "--- 1. Ports ouverts et services ---"
nmap -sV --top-ports 1000 "$TARGET" -oN "$OUT/ports.txt"
echo "  -> $OUT/ports.txt"; echo ""

# 2. Vulnérabilités connues — SEULEMENT les scripts sûrs et non externes.
#    'vuln and safe' écarte les scripts dos/intrusive/exploit ; 'not external'
#    écarte ceux qui envoient des données à des tiers (ex. vulners.com),
#    pour respecter la confidentialité (Article 6).
echo "--- 2. Vulnérabilités connues (NSE 'vuln and safe and not external') ---"
nmap -sV --script "vuln and safe and not external" "$TARGET" -oN "$OUT/vuln.txt"
echo "  -> $OUT/vuln.txt"; echo ""

# 3. Configuration TLS/SSL
echo "--- 3. Audit TLS/SSL ---"
nmap --script "ssl-enum-ciphers,ssl-cert" -p 443 "$TARGET" -oN "$OUT/tls.txt"
echo "  -> $OUT/tls.txt"; echo ""

# Journalise les sorties nmap (empreintes, Article 8)
for F in ports vuln tls; do
  journaliser_outil "$JOURNAL" "$REF" "$TARGET" "scan_reseau" "nmap ($F)" "$AUDIT_IP" "terminé" "$OUT/$F.txt"
done

# --- Rapport client (Article 6) + Annexe C (Article 8) ---
echo "--- Génération du rapport ---"
tasko_cli rapport --dossier "$OUT" --mandat "$MANDAT" --date "$DATE" --sortie "$OUT/rapport.md" || true
tasko_cli journal --fichier "$JOURNAL" --sortie "$OUT/annexe-C-journal.md" >/dev/null 2>&1 || true
echo ""

echo "=== Terminé ==="
echo "Rapports : $OUT"
echo "Rapport  : $OUT/rapport.md    Journal : $OUT/annexe-C-journal.md"
echo "À corriger : ports inutiles -> fermer ; services obsolètes -> mettre à jour ;"
echo "chiffrements TLS faibles -> désactiver."
