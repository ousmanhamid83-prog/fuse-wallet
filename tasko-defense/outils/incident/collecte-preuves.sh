#!/usr/bin/env bash
# collecte-preuves.sh — Collecte de preuves DÉFENSIVE après une intrusion.
# But : figer l'état du serveur pour les AUTORITÉS, sans altérer les preuves.
#
# ⚠️ RÈGLES D'OR (sinon les preuves ne valent rien devant la justice) :
#   1. À lancer UNIQUEMENT sur TON serveur (ton VPS), en tant que root.
#   2. Ne MODIFIE rien sur le système : il ne fait que LIRE et COPIER.
#      Les preuves sont écrites sur un SUPPORT EXTERNE (argument obligatoire),
#      jamais sur le disque compromis.
#   3. AVANT de lancer ce script, prends un SNAPSHOT du VPS (hPanel Hostinger)
#      -> ça fige tout le disque sans y toucher. C'est ta preuve maîtresse.
#   4. Chaque fichier collecté est haché (SHA-256) : c'est la "chaîne de
#      possession" qui prouve que les preuves n'ont pas été modifiées après coup.
#   5. Garde ensuite le support externe en lecture seule.
#
# Ordre de volatilité : on capture d'abord le plus volatil (mémoire, réseau,
# processus) avant le disque, car ça disparaît au moindre redémarrage.
#
# Usage : sudo bash collecte-preuves.sh /mnt/preuves-externe
#         (le dossier de destination doit être un support EXTERNE déjà monté)

set -uo pipefail   # pas de "set -e" : on veut continuer même si une commande échoue
umask 077          # CP-10 : tout ce qu'on crée est privé (lecture root uniquement)

# === CP-05 : contrôle root (sinon les artefacts privilégiés manquent) ===
if [ "$(id -u)" -ne 0 ]; then
  echo "ERREUR: lancer en root (sudo)" >&2
  exit 1
fi

# === CP-02 : destination EXTERNE obligatoire (ne rien écrire sur le disque compromis) ===
if [ "$#" -lt 1 ]; then
  echo "ERREUR: destination manquante." >&2
  echo "Usage: sudo bash collecte-preuves.sh /mnt/preuves-externe" >&2
  echo "  (fournis un support EXTERNE déjà monté ; les preuves y seront écrites)" >&2
  exit 1
fi

DEST_ARG="$1"
if [ ! -d "$DEST_ARG" ]; then
  echo "ERREUR: la destination '$DEST_ARG' n'existe pas ou n'est pas un dossier." >&2
  echo "  Monte d'abord ton support externe, puis relance avec son chemin." >&2
  exit 1
fi
# Résolution en chemin ABSOLU (physique, symlinks résolus)
DEST=$(cd "$DEST_ARG" 2>/dev/null && pwd -P)
if [ -z "${DEST:-}" ]; then
  echo "ERREUR: impossible de résoudre le chemin absolu de '$DEST_ARG'." >&2
  exit 1
fi

# --- Répertoire de preuves horodaté (UTC), SUR LE SUPPORT EXTERNE ---
TS=$(date -u +%Y%m%dT%H%M%SZ)
EVID="$DEST/preuves_${TS}"
MANIFEST="$EVID/MANIFEST.txt"

# CP-02/critic : échec de mkdir = fatal, on ne prétend pas avoir réussi
if ! mkdir -p "$EVID"; then
  echo "ERREUR: impossible de créer le dossier de preuves '$EVID'." >&2
  echo "  Vérifie que le support est monté, inscriptible et non plein." >&2
  exit 1
fi
chmod 700 "$EVID" 2>/dev/null || true   # CP-10

# Compteur d'échecs de copie (critic : pas de succès silencieux)
ERREURS=0

log() { echo "[$(date -u +%H:%M:%SZ)] $*" | tee -a "$EVID/journal-collecte.txt"; }

dispo() { command -v "$1" >/dev/null 2>&1; }

# Exécute une commande et range sa sortie dans un fichier du dossier de preuves.
grab() {
  local out="$EVID/$1"; shift
  log "Collecte: $* -> $out"
  { echo "# Commande: $*"; echo "# Heure (UTC): $(date -u)"; echo "---"; "$@"; } \
    > "$out" 2>&1 || log "  (échec partiel: $*)"
}

# Note explicite quand un outil est absent (CP-07) : on trace, on n'échoue pas en silence.
note() {
  local out="$EVID/$1"; shift
  { echo "# NOTE: $*"; echo "# Heure (UTC): $(date -u)"; } > "$out" 2>&1 || true
  log "  NOTE ($out) : $*"
}

# Copie vérifiée (critic : on détecte et on TRACE chaque échec, sans /dev/null aveugle).
#   copier <source> <dest>
copier() {
  local src="$1" dst="$2"
  if [ ! -e "$src" ]; then
    log "  absent (ignoré) : $src"
    return 0
  fi
  if cp -a "$src" "$dst" 2>>"$EVID/journal-collecte.txt"; then
    log "  copié : $src -> $dst"
  else
    log "  ÉCHEC copie : $src (voir erreur ci-dessus — disque plein ? dest en lecture seule ?)"
    ERREURS=$((ERREURS + 1))
  fi
}

# Copie en conservant l'arborescence (--parents) : utile pour la persistance (CP-03).
#   copier_parents <source>
copier_parents() {
  local src="$1"
  if [ ! -e "$src" ]; then
    log "  absent (ignoré) : $src"
    return 0
  fi
  if cp -a --parents "$src" "$EVID" 2>>"$EVID/journal-collecte.txt"; then
    log "  copié : $src"
  else
    log "  ÉCHEC copie : $src (voir erreur ci-dessus — disque plein ? dest en lecture seule ?)"
    ERREURS=$((ERREURS + 1))
  fi
}

# Espace libre destination (en Kio) pour le pré-contrôle
espace_libre_kb() { df -Pk "$DEST" 2>/dev/null | awk 'NR==2 {print $4}'; }
espace_libre_h()  { df -Ph "$DEST" 2>/dev/null | awk 'NR==2 {print $4}'; }

SEUIL_KB=102400   # 100 Mio : en dessous, on alerte fort

log "=== Début de collecte : $TS ==="
log "Opérateur: $(whoami) | Hôte: $(hostname) | Fuseau: $(date +%Z)"
log "Destination (externe) : $EVID"
LIBRE_DEBUT=$(espace_libre_kb)
log "Espace libre destination (début) : $(espace_libre_h)"
if [ -n "${LIBRE_DEBUT:-}" ] && [ "$LIBRE_DEBUT" -lt "$SEUIL_KB" ] 2>/dev/null; then
  log "ATTENTION: espace libre FAIBLE sur la destination (< 100 Mio)."
  log "  La collecte risque d'être incomplète. Libère de la place ou change de support."
  echo "ATTENTION: espace libre faible sur '$DEST' — collecte potentiellement incomplète." >&2
fi

# === CONTEXTE TEMPS (crucial pour corréler avec les logs) ===
{
  echo "Heure système (UTC): $(date -u)"
  echo "Heure locale: $(date)"
  echo "Synchro NTP:"; timedatectl 2>/dev/null
} > "$EVID/00-temps.txt" 2>&1

# === 1. ÉTAT VOLATIL (à capturer en premier) ===
grab "10-processus.txt"        ps auxww
grab "11-arbre-processus.txt"  ps -ejH

# CP-07 : connexions — ss de préférence, sinon netstat, sinon note
if dispo ss; then
  grab "12-connexions.txt"     ss -tunap
elif dispo netstat; then
  grab "12-connexions.txt"     netstat -tunap
else
  note "12-connexions.txt"     "ni 'ss' ni 'netstat' disponibles (connexions non collectées)"
fi

# CP-07 : ports en écoute — ss de préférence, sinon netstat, sinon note
if dispo ss; then
  grab "13-ports-ecoute.txt"   ss -tlnp
elif dispo netstat; then
  grab "13-ports-ecoute.txt"   netstat -tlnp
else
  note "13-ports-ecoute.txt"   "ni 'ss' ni 'netstat' disponibles (ports en écoute non collectés)"
fi

# lsof souvent absent sur un système minimal
if dispo lsof; then
  grab "14-fichiers-ouverts.txt" lsof -n -P
else
  note "14-fichiers-ouverts.txt" "'lsof' absent (fichiers ouverts non collectés)"
fi

grab "15-modules-noyau.txt"    lsmod          # détection rootkit (modules suspects)

# CP-07 : table ARP/voisins — 'ip neigh' de préférence (net-tools souvent absent), sinon arp
if dispo ip; then
  grab "16-voisins-arp.txt"    ip neigh
elif dispo arp; then
  grab "16-voisins-arp.txt"    arp -a
else
  note "16-voisins-arp.txt"    "ni 'ip' ni 'arp' disponibles (table ARP/voisins non collectée)"
fi

# Routes — 'ip route' de préférence
if dispo ip; then
  grab "17-routes.txt"         ip route
elif dispo route; then
  grab "17-routes.txt"         route -n
else
  note "17-routes.txt"         "ni 'ip' ni 'route' disponibles (routes non collectées)"
fi

# Pare-feu — iptables, sinon nft, sinon note
if dispo iptables; then
  grab "18-pare-feu.txt"       iptables -L -n -v
elif dispo nft; then
  grab "18-pare-feu.txt"       nft list ruleset
else
  note "18-pare-feu.txt"       "ni 'iptables' ni 'nft' disponibles (règles pare-feu non collectées)"
fi

# === 2. SESSIONS & COMPTES (qui s'est connecté ?) ===
grab "20-connectes-now.txt"    who -a
grab "21-w.txt"                w
grab "22-derniers-logins.txt"  last -F -n 100
grab "23-logins-echoues.txt"   lastb -F -n 100   # tentatives de connexion ratées
copier /etc/passwd "$EVID/24-passwd.copy"
grab "25-sudoers.txt"          cat /etc/sudoers

# === 3. PERSISTANCE (comment l'attaquant reste-t-il ?) ===
# CP-05 : crontab root explicitement ciblé
grab "30-crontab-root.txt"     crontab -l -u root
grab "31-cron-system.txt"      ls -laR /etc/cron.d /etc/cron.daily /etc/cron.hourly \
                                       /etc/cron.weekly /etc/cron.monthly /var/spool/cron
grab "32-services.txt"         systemctl list-units --type=service --all
grab "33-services-actifs.txt"  systemctl list-unit-files --state=enabled

# CP-03 : artefacts de persistance implicites dans le playbook (umask 077, arborescence conservée)
log "Copie des artefacts de persistance (comptes, cron, ssh, démarrage)..."
for P in /etc/shadow /etc/group /etc/gshadow /etc/sudoers.d \
         /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly \
         /etc/cron.weekly /etc/cron.monthly /etc/cron.allow /etc/cron.deny \
         /var/spool/cron \
         /etc/ld.so.preload /etc/rc.local \
         /etc/profile.d /etc/systemd/system \
         /etc/ssh/sshd_config /etc/ssh/sshd_config.d; do
  copier_parents "$P"
done

# CP-03/CP-05 : pour CHAQUE utilisateur, ses artefacts + le contenu de sa crontab
log "Collecte par utilisateur (crontab, ~/.ssh, historiques, rc)..."
CRON_USERS="$EVID/35-crontabs-utilisateurs.txt"
{
  echo "# Contenu des crontabs par utilisateur (crontab -l -u <user>)"
  echo "# Heure (UTC): $(date -u)"
  echo "---"
} > "$CRON_USERS" 2>&1
VUS=" "   # homes déjà traités (évite les doublons des comptes système)
while IFS=: read -r user _ uid _ _ home _; do
  [ -n "${user:-}" ] || continue
  # crontab de l'utilisateur (y compris "no crontab for X" tracé comme note)
  {
    echo "=== crontab de : $user ==="
    crontab -l -u "$user" 2>&1
    echo ""
  } >> "$CRON_USERS" 2>&1
  # Artefacts du home (une seule fois par chemin de home)
  if [ -n "${home:-}" ] && [ -d "$home" ] && [[ "$VUS" != *" $home "* ]]; then
    VUS="$VUS$home "
    copier_parents "$home/.ssh"            # authorized_keys, known_hosts, clés
    copier_parents "$home/.bash_history"
    copier_parents "$home/.bashrc"
    copier_parents "$home/.profile"
  fi
done < /etc/passwd

# === 4. FICHIERS RÉCEMMENT MODIFIÉS (web shells, backdoors) ===
# Fichiers modifiés dans les 7 derniers jours sous les répertoires web et système.
# CP-02 : on EXCLUT le dossier de preuves de la recherche (au cas où il serait sous un chemin scanné).
log "Recherche fichiers modifiés < 7 jours (peut prendre du temps)..."
find /var/www /tmp /dev/shm /etc -path "$EVID" -prune -o \
  -type f -mtime -7 \
  -printf "%TY-%Tm-%Td %TH:%TM  %p\n" -print 2>/dev/null \
  | sort > "$EVID/40-fichiers-recents.txt" 2>/dev/null || true
# Fichiers PHP suspects dans les uploads (vecteur classique de web shell)
find /var/www -path "$EVID" -prune -o \
  -path "*/uploads/*" -name "*.php" -print 2>/dev/null \
  > "$EVID/41-php-dans-uploads.txt" 2>/dev/null || true

# === 5. PRÉSERVATION DES LOGS (copie, ne pas déplacer) ===
# CP-08 : on préserve AUSSI les logs tournés (.1, *.gz), journald et les binaires wtmp/btmp.
log "Copie des journaux système et web (y compris rotations)..."
if ! mkdir -p "$EVID/logs"; then
  log "  ÉCHEC: impossible de créer $EVID/logs"
  ERREURS=$((ERREURS + 1))
fi
# Journaux texte + leurs rotations (.1, .2, *.gz...)
for base in auth.log syslog secure messages kern.log faillog mail.log ufw.log; do
  for f in "/var/log/$base" /var/log/"$base".*; do
    [ -f "$f" ] && copier "$f" "$EVID/logs/"
  done
done
# CP-08 : binaires de connexion bruts (wtmp/btmp/lastlog) — à copier tels quels
for b in /var/log/wtmp /var/log/btmp /var/log/lastlog; do
  copier "$b" "$EVID/logs/"
done
# Logs web (Nginx / Apache) — souvent là que se voit l'attaque (rotations incluses)
for D in /var/log/nginx /var/log/apache2 /var/log/httpd; do
  [ -d "$D" ] && copier "$D" "$EVID/logs/"
done
# CP-08 : export du journal systemd (journald) si disponible
if dispo journalctl; then
  log "Export du journal systemd (journalctl -o export)..."
  if journalctl -o export > "$EVID/logs/journal-systemd.txt" 2>>"$EVID/journal-collecte.txt"; then
    log "  journald exporté -> logs/journal-systemd.txt"
  else
    log "  ÉCHEC export journald (disque plein ? journald indisponible ?)"
    ERREURS=$((ERREURS + 1))
  fi
else
  note "logs/journal-systemd.absent.txt" "'journalctl' absent (journald non exporté)"
fi

# === BILAN avant hachage (critic : refléter les échecs DANS le journal) ===
LIBRE_FIN_H=$(espace_libre_h)
log "Bilan : $ERREURS échec(s) de copie détecté(s)."
log "Espace libre destination (fin) : ${LIBRE_FIN_H:-inconnu}"
if [ "$ERREURS" -ne 0 ]; then
  log "ATTENTION: collecte INCOMPLÈTE — chercher les lignes 'ÉCHEC' ci-dessus."
  log "  Cause probable : disque de destination plein ou en lecture seule."
fi

# CP-01 : la DERNIÈRE ligne du journal est écrite AVANT le hachage, sinon
#         sha256sum -c MANIFEST.txt échouerait toujours (journal modifié après coup).
log "=== Fin d'écriture du journal (avant hachage) ==="

# === 6. INTÉGRITÉ : hacher TOUTES les preuves (chaîne de possession) ===
# CP-01 : on exclut MANIFEST.txt ET MANIFEST.sha256 du manifeste.
# CP-06 : tout est calculé DEPUIS l'intérieur du dossier (chemins relatifs vérifiables).
( cd "$EVID" && find . -type f ! -name MANIFEST.txt ! -name MANIFEST.sha256 \
    -exec sha256sum {} \; ) | sort > "$MANIFEST" 2>/dev/null

# CP-06 : empreinte du manifeste calculée DEPUIS l'intérieur (pas de chemin parent)
( cd "$EVID" && sha256sum MANIFEST.txt > MANIFEST.sha256 ) 2>/dev/null

# ----- À PARTIR D'ICI : plus AUCUNE écriture dans le dossier de preuves (CP-01) -----
# On n'écrit plus que sur stdout/stderr.

# critic : ne JAMAIS prétendre au succès si le manifeste est vide ou si une étape a échoué.
if [ ! -s "$MANIFEST" ]; then
  echo "" >&2
  echo "########################################################################" >&2
  echo "ÉCHEC CRITIQUE : le manifeste est VIDE — aucune preuve exploitable." >&2
  echo "  Rien n'a pu être écrit (support plein, en lecture seule, ou démonté ?)." >&2
  echo "  NE PAS considérer cette collecte comme valide." >&2
  echo "  Dossier : $EVID" >&2
  echo "########################################################################" >&2
  exit 1
fi

MH=$(awk '{print $1}' "$EVID/MANIFEST.sha256" 2>/dev/null)

if [ "$ERREURS" -ne 0 ]; then
  echo ""
  echo "########################################################################"
  echo "ATTENTION : COLLECTE INCOMPLÈTE — $ERREURS échec(s) de copie."
  echo "  Cause probable : disque de destination plein ou en lecture seule."
  echo "  Le manifeste ne couvre QUE les fichiers réellement écrits."
  echo "  Consulte '$EVID/journal-collecte.txt' (lignes 'ÉCHEC')."
  echo "  NE communique PAS cette collecte comme complète aux autorités."
  echo "########################################################################"
  echo "Dossier (partiel) : $EVID"
  echo "Empreinte SHA-256 du MANIFEST (à noter hors-ligne) :"
  echo "  $MH"
  exit 3
fi

# === SUCCÈS : collecte complète et scellée ===
echo ""
echo "=== Collecte terminée ==="
echo "Dossier de preuves : $EVID"
echo ""
# CP-06 : on IMPRIME l'empreinte du MANIFEST pour la noter hors-hôte
echo "Empreinte SHA-256 du MANIFEST.txt (NOTE-LA HORS-LIGNE — c'est le sceau) :"
echo "  $MH"
echo ""
echo "VÉRIFICATION (depuis l'intérieur du dossier) :"
echo "  cd '$EVID' && sha256sum -c MANIFEST.txt && sha256sum -c MANIFEST.sha256"
echo ""
echo "PROCHAINES ÉTAPES :"
echo "  1. Garde '$EVID' sur son support EXTERNE en lecture seule (clé USB, stockage chiffré)."
echo "  2. Note QUI a collecté, QUAND (UTC), et où c'est stocké (voir journal-collecte.txt)."
echo "  3. NE TRAVAILLE PLUS sur ce serveur : reconstruis sur une instance propre,"
echo "     en gardant le snapshot + ce dossier comme preuves intactes."
echo "  4. Transmets aux autorités (ANTIC / ANSICE / police judiciaire)."
echo "  5. Le MANIFEST.txt + son empreinte prouvent que les preuves n'ont pas été altérées."
exit 0
