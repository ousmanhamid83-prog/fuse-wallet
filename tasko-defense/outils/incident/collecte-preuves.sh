#!/usr/bin/env bash
# collecte-preuves.sh — Collecte de preuves DÉFENSIVE après une intrusion.
# But : figer l'état du serveur pour les AUTORITÉS, sans altérer les preuves.
#
# ⚠️ RÈGLES D'OR (sinon les preuves ne valent rien devant la justice) :
#   1. À lancer UNIQUEMENT sur TON serveur (ton VPS), en tant que root.
#   2. Ne MODIFIE rien sur le système : il ne fait que LIRE et COPIER.
#   3. AVANT de lancer ce script, prends un SNAPSHOT du VPS (hPanel Hostinger)
#      -> ça fige tout le disque sans y toucher. C'est ta preuve maîtresse.
#   4. Chaque fichier collecté est haché (SHA-256) : c'est la "chaîne de
#      possession" qui prouve que les preuves n'ont pas été modifiées après coup.
#   5. Copie ensuite le dossier de preuves sur un support EXTERNE en lecture seule.
#
# Ordre de volatilité : on capture d'abord le plus volatil (mémoire, réseau,
# processus) avant le disque, car ça disparaît au moindre redémarrage.
#
# Usage : sudo bash collecte-preuves.sh

set -uo pipefail   # pas de "set -e" : on veut continuer même si une commande échoue

# --- Répertoire de preuves horodaté (UTC) ---
TS=$(date -u +%Y%m%dT%H%M%SZ)
EVID="preuves_${TS}"
mkdir -p "$EVID"
MANIFEST="$EVID/MANIFEST.txt"

log() { echo "[$(date -u +%H:%M:%SZ)] $*" | tee -a "$EVID/journal-collecte.txt"; }
# Exécute une commande et range sa sortie dans un fichier du dossier de preuves
grab() {
  local out="$EVID/$1"; shift
  log "Collecte: $* -> $out"
  { echo "# Commande: $*"; echo "# Heure (UTC): $(date -u)"; echo "---"; "$@"; } \
    > "$out" 2>&1 || log "  (échec partiel: $*)"
}

log "=== Début de collecte : $TS ==="
log "Opérateur: $(whoami) | Hôte: $(hostname) | Fuseau: $(date +%Z)"

# === CONTEXTE TEMPS (crucial pour corréler avec les logs) ===
{
  echo "Heure système (UTC): $(date -u)"
  echo "Heure locale: $(date)"
  echo "Synchro NTP:"; timedatectl 2>/dev/null
} > "$EVID/00-temps.txt"

# === 1. ÉTAT VOLATIL (à capturer en premier) ===
grab "10-processus.txt"        ps auxww
grab "11-arbre-processus.txt"  ps -ejH
grab "12-connexions.txt"       ss -tunap
grab "13-ports-ecoute.txt"     ss -tlnp
grab "14-fichiers-ouverts.txt" lsof -n -P
grab "15-modules-noyau.txt"    lsmod          # détection rootkit (modules suspects)
grab "16-arp.txt"              arp -a
grab "17-routes.txt"           ip route
grab "18-pare-feu.txt"         iptables -L -n -v

# === 2. SESSIONS & COMPTES (qui s'est connecté ?) ===
grab "20-connectes-now.txt"    who -a
grab "21-w.txt"                w
grab "22-derniers-logins.txt"  last -F -n 100
grab "23-logins-echoues.txt"   lastb -F -n 100   # tentatives de connexion ratées
cp -p /etc/passwd "$EVID/24-passwd.copy" 2>/dev/null && log "Copie /etc/passwd"
grab "25-sudoers.txt"          cat /etc/sudoers

# === 3. PERSISTANCE (comment l'attaquant reste-t-il ?) ===
grab "30-crontab-root.txt"     crontab -l
grab "31-cron-system.txt"      ls -laR /etc/cron.d /etc/cron.daily /etc/cron.hourly /var/spool/cron
grab "32-services.txt"         systemctl list-units --type=service --all
grab "33-services-actifs.txt"  systemctl list-unit-files --state=enabled

# === 4. FICHIERS RÉCEMMENT MODIFIÉS (web shells, backdoors) ===
# Fichiers modifiés dans les 7 derniers jours sous les répertoires web et système
log "Recherche fichiers modifiés < 7 jours (peut prendre du temps)..."
find /var/www /tmp /dev/shm /etc 2>/dev/null -type f -mtime -7 \
  -printf "%TY-%Tm-%Td %TH:%TM  %p\n" 2>/dev/null \
  | sort > "$EVID/40-fichiers-recents.txt" || true
# Fichiers PHP suspects dans les uploads (vecteur classique de web shell)
find /var/www 2>/dev/null -path "*/uploads/*" -name "*.php" \
  > "$EVID/41-php-dans-uploads.txt" || true

# === 5. PRÉSERVATION DES LOGS (copie, ne pas déplacer) ===
log "Copie des journaux système et web..."
mkdir -p "$EVID/logs"
for L in /var/log/auth.log /var/log/syslog /var/log/secure /var/log/messages; do
  [ -f "$L" ] && cp -p "$L" "$EVID/logs/" 2>/dev/null && log "  $L"
done
# Logs web (Nginx / Apache) — souvent là que se voit l'attaque
for D in /var/log/nginx /var/log/apache2 /var/log/httpd; do
  [ -d "$D" ] && cp -rp "$D" "$EVID/logs/" 2>/dev/null && log "  $D"
done

# === 6. INTÉGRITÉ : hacher TOUTES les preuves (chaîne de possession) ===
log "Calcul des empreintes SHA-256 (intégrité)..."
( cd "$EVID" && find . -type f ! -name MANIFEST.txt -exec sha256sum {} \; ) \
  | sort > "$MANIFEST"

# Empreinte du manifest lui-même (scelle l'ensemble)
sha256sum "$MANIFEST" > "$EVID/MANIFEST.sha256"

log "=== Collecte terminée ==="
log "Dossier de preuves : $EVID"
echo ""
echo "PROCHAINES ÉTAPES :"
echo "  1. Copie '$EVID' sur un support EXTERNE en lecture seule (clé USB, stockage chiffré)."
echo "  2. Note QUI a collecté, QUAND (UTC), et où c'est stocké (voir journal-collecte.txt)."
echo "  3. NE TRAVAILLE PLUS sur ce serveur : reconstruis sur une instance propre,"
echo "     en gardant le snapshot + ce dossier comme preuves intactes."
echo "  4. Transmets aux autorités (ANTIC / ANSICE / police judiciaire)."
echo "  5. Le MANIFEST.txt prouve que les preuves n'ont pas été altérées après collecte."
