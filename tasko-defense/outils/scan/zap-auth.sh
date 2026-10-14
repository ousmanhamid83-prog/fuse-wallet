#!/usr/bin/env bash
# zap-auth.sh — Lanceur du scan ZAP AUTHENTIFIE, cadre par un MANDAT signe.
# Trouve les failles pour les CORRIGER. Aucun exploit, aucune donnee reelle modifiee.
#
# La cible est verifiee contre le mandat (type 'test_authentifie') AVANT que ZAP
# ne demarre : si le mandat n'autorise PAS ce test (non signe, hors perimetre,
# hors fenetre horaire, mauvaise IP source...), le garde STOPPE le script et
# ZAP n'est JAMAIS lance. Aucune requete n'est envoyee tant que le garde n'a
# pas renvoye 0.
#
# ATTENTION : ce scan AUTHENTIFIE attaque derriere le login. Vise une copie de
#   PRE-PRODUCTION / STAGING, jamais la production avec de vraies donnees
#   clients (mandat §2.4). Voir zap-auth.yaml pour la policy (XSS persistant et
#   regles d'ecriture desactives).
#
# Prerequis : python3 + PyYAML (moteur de mandat), docker.
#
# Usage :
#   export MANDAT=../../mandats/tonsite.mandat.yaml   # mandat SIGNE, test_authentifie autorise
#   export ZAP_USER="compte-de-test"                  # compte de test fourni par le Client
#   export ZAP_PWD="..."                              # mot de passe (jamais en dur)
#   export AUDIT_IP=198.51.100.10                     # IP source declaree (Article 3), optionnel
#   bash zap-auth.sh https://staging.ton-site.cm/     # cible en argument
#   # ou :  export TARGET=https://staging.ton-site.cm/ ; bash zap-auth.sh

set -euo pipefail
cd "$(dirname "$0")"
source ./_garde-mandat.sh

die() { echo "ERREUR : $*" >&2; exit 1; }

MANDAT="${MANDAT:-}"
ZAP_USER="${ZAP_USER:-}"
ZAP_PWD="${ZAP_PWD:-}"
AUDIT_IP="${AUDIT_IP:-}"
TARGET="${1:-${TARGET:-}}"

[ -n "$MANDAT" ]   || die "variable MANDAT non definie (chemin d'un mandat signe)."
[ -n "$TARGET" ]   || die "cible manquante : bash zap-auth.sh <url>  (ou export TARGET=...)."
[ -n "$ZAP_USER" ] || die "ZAP_USER non defini (compte de test fourni par le Client)."
[ -n "$ZAP_PWD" ]  || die "ZAP_PWD non defini (mot de passe du compte de test)."
command -v docker >/dev/null 2>&1 || die "docker introuvable (installe Docker)."

# Refuse une "cible" qui est en fait une option ou plusieurs cibles (pas d'injection
# d'arguments) : une seule URL, sans tiret initial, espace ni virgule.
case "$TARGET" in
  -*|*" "*|*,*) die "cible invalide (une seule URL, sans option, espace ni virgule) : $TARGET" ;;
esac

# --- Garde de mandat (test_authentifie) : STOPPE le script AVANT tout lancement ZAP ---
echo "--- Verification du mandat (test_authentifie) ---"
exiger_mandat "$MANDAT" "$TARGET" "test_authentifie" "$AUDIT_IP"
echo ""

# --- Coherence cible <-> plan ZAP ---
# Le mandat autorise TARGET, mais ZAP scanne l'URL ecrite dans zap-auth.yaml
# ('urls:'). Les deux DOIVENT designer le meme site, sinon l'autorisation ne
# couvre pas ce qui est reellement scanne. Verification best-effort (non bloquante).
HOTE=$(printf '%s' "$TARGET" | sed -E 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##; s#[/?:].*$##')
if [ -n "$HOTE" ] && ! grep -q -- "$HOTE" zap-auth.yaml; then
  echo "AVERTISSEMENT : l'hote « $HOTE » n'apparait pas dans zap-auth.yaml." >&2
  echo "   Verifie que 'urls:' (et les URLs de login) pointent bien vers $TARGET," >&2
  echo "   sinon le mandat autorise une cible differente de celle reellement scannee." >&2
  echo "" >&2
fi

# --- Rappel : droits du dossier (le conteneur ZAP tourne en uid 1000) ---
# Le volume /zap/wrk/ est monte en lecture-ecriture (:rw). S'il appartient a root,
# ZAP (uid 1000) ne pourra pas y ecrire les rapports (« permission denied »).
echo ">>> Si l'ecriture des rapports echoue (permission denied), donne les droits a l'uid 1000 :"
echo ">>>   sudo chown 1000:1000 \"\$PWD\""
echo ">>> (ou dedie un dossier de rapports possede par l'uid 1000)."
echo ""

# --- Lancement ZAP (autorise par le mandat) ---
# -e ZAP_USER -e ZAP_PWD : transmet les identifiants (deja dans l'environnement)
#   au conteneur. Sans eux, ZAP se connecterait avec le littéral « ${ZAP_USER} ».
# On (re)exporte pour garantir que `docker run -e` les voie.
export ZAP_USER ZAP_PWD
echo "--- Lancement du scan ZAP authentifie sur : $TARGET ---"
exec docker run --rm \
  -v "$(pwd)":/zap/wrk/:rw \
  -e ZAP_USER \
  -e ZAP_PWD \
  -t ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -cmd -autorun /zap/wrk/zap-auth.yaml
