#!/usr/bin/env python3
"""Mode « purple » — validation de la détection (défensif, non offensif).

Objectif : vérifier que la chaîne de détection de l'opérateur FONCTIONNE, c'est-à-
dire que lorsqu'un trafic « qui ressemble à une attaque » arrive sur le honeypot
(ou une pré-prod autorisée), ce honeypot le JOURNALISE et Wazuh ALERTE. Autrement
dit : on teste le défenseur, pas l'adversaire.

Ce module N'EST PAS une arme d'exploitation. Il envoie des SONDES INERTES et
MARQUÉES :
  - « inertes » : chaque sonde ne contient que des CHAÎNES qui *ressemblent* à des
    attaques (pour matcher les signatures de ``threat-intel.py`` / les règles
    Wazuh). Aucune charge fonctionnelle, aucun exploit, aucun C2, aucun DoS : la
    cible ne fait qu'enregistrer la requête puis répond banalement. Une seule
    requête par sonde, timeout court, aucune reprise, une pause entre sondes.
  - « marquées » : chaque sonde porte un canari unique (un UUID) dans l'en-tête
    ``X-Tasko-Purple`` et un User-Agent ``Tasko-Purple-DetectionTest/<version>``,
    pour qu'on retrouve SA trace précise dans les journaux, et qu'un honeypot ou
    un SOC ne confonde jamais ce test avec une vraie attaque.

Verrou éthique (identique au reste de Tasko Defense) :
  - TOUTE cible, y compris ton propre honeypot en boucle locale, exige un
    ``Mandat`` SIGNÉ autorisant ``validation_detection`` sur cette cible (via
    :func:`tasko.mandat.autoriser`). Pour ta propre infra, tu signes un mandat
    dont tu es à la fois Prestataire et Client (voir mandats/honeypot-local).
  - À défaut de mandat couvrant la cible : refus net, et AUCUNE sonde n'est émise
    (prouvable par :func:`compteur_envois`).
  - Garde de cohérence : l'hôte autorisé doit être exactement celui qui sera
    contacté, sinon refus (anti-URL forgée).

Bibliothèque standard uniquement (http.client / urllib / socket).
"""
from __future__ import annotations

import dataclasses
import http.client
import json
import socket
import time
import urllib.parse
import uuid
from datetime import datetime, timezone

# Réutilisation des moteurs du paquet (mandat + journal). Imports tolérants pour
# que le module fonctionne aussi bien importé comme ``tasko.purple`` que depuis
# un sys.path pointant sur la racine du dépôt.
try:  # exécuté comme membre du paquet
    from .mandat import autoriser, extraire_hote
    from . import journal as _J
    from . import __version__ as _VERSION
except ImportError:  # pragma: no cover - exécution hors paquet
    from tasko.mandat import autoriser, extraire_hote
    from tasko import journal as _J
    try:
        from tasko import __version__ as _VERSION
    except ImportError:
        _VERSION = "dev"

__all__ = [
    "Sonde",
    "SONDES",
    "rejouer",
    "sonder_ssh",
    "rendre_markdown",
    "compteur_envois",
    "reinitialiser_compteur",
    "USER_AGENT",
]

# ---------------------------------------------------------------------------
# Constantes de sûreté : jamais agressif.
# ---------------------------------------------------------------------------
USER_AGENT = f"Tasko-Purple-DetectionTest/{_VERSION}"
TIMEOUT_HTTP = 5.0          # timeout court par requête (s) : on n'insiste jamais
TIMEOUT_SSH = 5.0           # idem pour la sonde TCP/SSH
PORT_SSH_DEFAUT = 2222      # faux SSH du honeypot (voir outils/honeypot.py)
RAPPEL_WAZUH = (
    "Vérifie l'alerte correspondante dans Wazuh : chaque sonde DÉTECTÉE doit "
    "déclencher une règle (honeypot/web/ssh). Une sonde NON DÉTECTÉE révèle un "
    "trou de détection à corriger (règle manquante, log non ingéré…)."
)

# Compteur global des requêtes réseau RÉELLEMENT tentées. Il n'est incrémenté
# qu'à l'intérieur des primitives d'émission, juste avant le moindre octet
# réseau. Il sert de preuve de sûreté : un refus éthique le laisse à zéro.
COMPTEUR_ENVOIS = 0


def compteur_envois() -> int:
    """Nombre de requêtes réseau réellement tentées depuis la dernière remise à zéro.

    Preuve de sûreté : après un refus éthique, ce compteur vaut 0 — aucune sonde
    n'a touché le réseau.
    """
    return COMPTEUR_ENVOIS


def reinitialiser_compteur() -> None:
    """Remet à zéro le compteur d'envois réseau (utilisé par les tests)."""
    global COMPTEUR_ENVOIS
    COMPTEUR_ENVOIS = 0


# ---------------------------------------------------------------------------
# Catalogue des sondes inertes.
# ---------------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class Sonde:
    """Une sonde inerte de validation de détection.

    - ``id`` : identifiant court et unique de la sonde ;
    - ``methode`` : méthode HTTP (GET, POST…) ;
    - ``chemin`` : chemin « logique » (lisible) ; il est URL-encodé avant envoi
      pour former une requête VALIDE (jamais d'espace brut) — il ne contient que
      des chaînes qui ressemblent à des attaques, jamais de code exécutable ;
    - ``corps`` : corps optionnel (formulaire factice) pour les requêtes POST ;
    - ``signature_attendue`` : étiquette de la signature censée se déclencher
      (vocabulaire de ``threat-intel.py`` / règles Wazuh) ;
    - ``description`` : à quoi sert la sonde et ce qu'elle valide.
    """

    id: str
    methode: str
    chemin: str
    signature_attendue: str
    description: str
    corps: str | None = None


# Chaque sonde = une CHAÎNE inerte qui ressemble à une attaque connue. La cible
# ne l'exécute jamais : elle se contente de la journaliser. Les chaînes ci-dessous
# correspondent 1:1 aux signatures de outils/threat-intel.py (SUSPICIOUS_WEB).
SONDES: list[Sonde] = [
    Sonde(
        id="sql_injection",
        methode="GET",
        chemin="/?id=1 UNION SELECT 1,2,3",
        signature_attendue="sql_injection",
        description="Chaîne d'injection SQL inerte (UNION SELECT) — valide la "
                    "règle sql_injection. La cible ne fait que la journaliser.",
    ),
    Sonde(
        id="path_traversal",
        methode="GET",
        chemin="/../../etc/passwd",
        signature_attendue="path_traversal",
        description="Chaîne de traversée de chemin inerte (../ + /etc/passwd) — "
                    "valide la règle path_traversal. Aucun fichier n'est lu.",
    ),
    Sonde(
        id="wp_login_bruteforce",
        methode="POST",
        chemin="/wp-login.php",
        corps="log=admin&pwd=TASKO-PURPLE-INERTE",
        signature_attendue="wp_login_bruteforce",
        description="Accès POST à /wp-login.php avec un corps factice (identifiants "
                    "bidon) — valide la règle wp_login_bruteforce. Une seule tentative.",
    ),
    Sonde(
        id="xss_attempt",
        methode="GET",
        chemin="/?q=<script>alert(1)</script>",
        signature_attendue="xss_attempt",
        description="Chaîne XSS réfléchie inerte (<script>) — valide la règle "
                    "xss_attempt. La cible ne l'interprète pas.",
    ),
    Sonde(
        id="sensitive_file_probe",
        methode="GET",
        chemin="/.env",
        signature_attendue="sensitive_file_probe",
        description="Sonde de fichier sensible (/.env) — valide la règle "
                    "sensitive_file_probe. Aucun secret n'est transmis.",
    ),
]


# ---------------------------------------------------------------------------
# Verrou éthique.
# ---------------------------------------------------------------------------
def _autoriser_cible(cible, hote, mandat, ip_source, moment, reference):
    """Décide si la validation de détection peut viser ``cible``.

    TOUTE cible (y compris la boucle locale) exige un mandat signé autorisant
    ``validation_detection``. Retourne ``(autorise, raison, reference)``.
    """
    # Garde de cohérence : l'hôte AUTORISÉ (extraire_hote) doit être exactement
    # celui qu'on CONTACTERA (urlsplit). Sinon, une URL forgée pourrait faire
    # autoriser un hôte et en contacter un autre -> refus, aucune sonde émise.
    hote_contacte = (_construire_cible(cible)[1] or "").rstrip(".").lower()
    if hote_contacte != hote:
        return (False,
                f"incohérence d'analyse d'URL : hôte autorisé {hote!r} ≠ hôte "
                f"contacté {hote_contacte!r} — AUCUNE sonde émise",
                reference)

    # Plus d'exception « boucle locale » : tout passe par le mandat, y compris
    # ton propre honeypot (tu signes un mandat de ta propre infra).
    if mandat is None:
        return (False,
                "aucun mandat fourni : la validation de détection exige un mandat "
                "signé autorisant 'validation_detection' sur cette cible — y compris "
                "pour ton propre honeypot. AUCUNE sonde émise",
                reference)
    decision = autoriser(mandat, cible, "validation_detection",
                         moment=moment, ip_source=ip_source)
    return (bool(decision), decision.raison, decision.reference or reference)


# ---------------------------------------------------------------------------
# Primitives d'émission (http.client / socket). Inertes : une requête, un log.
# ---------------------------------------------------------------------------
def _maintenant() -> str:
    return datetime.now(timezone.utc).isoformat()


def _construire_cible(cible: str) -> tuple[str, str, int]:
    """Extrait (schéma, hôte, port) d'une URL de cible. http:// implicite."""
    brut = cible if "://" in cible else "http://" + cible
    parts = urllib.parse.urlsplit(brut)
    schema = parts.scheme or "http"
    hote = parts.hostname or ""
    port = parts.port or (443 if schema == "https" else 80)
    return schema, hote, port


def _decode_deux_fois(texte: str) -> str:
    """Double passe d'URL-décodage (comme threat-intel.py : gère %20, +, doubles)."""
    return urllib.parse.unquote_plus(urllib.parse.unquote_plus(texte))


def _chemin_transmis(chemin: str, canari: str) -> str:
    """Encode le chemin en cible-requête VALIDE et y ajoute le canari.

    Les espaces et caractères spéciaux sont percent-encodés (une requête HTTP ne
    peut pas contenir d'espace brut) : la chaîne d'attaque reste présente (sous
    forme encodée, exactement comme une vraie attaque) et donc détectable après
    décodage. Le canari est ajouté en paramètre ``tasko_canari`` pour qu'un
    honeypot qui ne journalise que le chemin capture tout de même le marqueur.
    """
    encode = urllib.parse.quote(chemin, safe="/?=&")
    sep = "&" if "?" in encode else "?"
    return f"{encode}{sep}tasko_canari={canari}"


def _envoyer_http(schema, hote, port, sonde: Sonde, canari: str, timeout: float) -> dict:
    """Émet UNE requête HTTP inerte et marquée pour une sonde. Aucune reprise.

    Retourne ``{"code_http", "longueur", "erreur"}``. Incrémente le compteur
    d'envois réseau AVANT toute connexion (preuve de sûreté).
    """
    global COMPTEUR_ENVOIS
    COMPTEUR_ENVOIS += 1  # une tentative réseau va avoir lieu, on la compte d'abord

    cible_req = _chemin_transmis(sonde.chemin, canari)
    corps = sonde.corps
    entetes = {
        "User-Agent": USER_AGENT,       # marqueur lisible par un humain / un SOC
        "X-Tasko-Purple": canari,       # marqueur unique (canari) de CETTE sonde
        "Accept": "*/*",
        "Connection": "close",          # pas de keep-alive : une requête, on ferme
    }
    if corps is not None:
        corps = corps + "&tasko_canari=" + canari
        entetes["Content-Type"] = "application/x-www-form-urlencoded"

    if schema == "https":
        conn = http.client.HTTPSConnection(hote, port, timeout=timeout)
    else:
        conn = http.client.HTTPConnection(hote, port, timeout=timeout)
    try:
        conn.request(sonde.methode, cible_req, body=corps, headers=entetes)
        reponse = conn.getresponse()
        donnees = reponse.read()
        return {"code_http": reponse.status, "longueur": len(donnees), "erreur": None}
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _blob_journal(chemin: str) -> str:
    """Concatène les champs utiles du journal honeypot (JSONL) en une chaîne.

    Le résultat contient la version brute ET la version URL-décodée, afin de
    retrouver aussi bien un canari (hexadécimal, inchangé) qu'une chaîne d'attaque
    encodée dans le chemin.
    """
    morceaux: list[str] = []
    try:
        with open(chemin, "r", encoding="utf-8", errors="ignore") as f:
            for ligne in f:
                ligne = ligne.strip()
                if not ligne:
                    continue
                try:
                    rec = json.loads(ligne)
                except json.JSONDecodeError:
                    continue
                for cle in ("path", "body", "user_agent", "client_banner",
                            "requestline", "note", "method", "source_ip", "srcip"):
                    val = rec.get(cle)
                    if val:
                        morceaux.append(str(val))
    except OSError:
        return ""
    brut = " ".join(morceaux)
    return brut + "\n" + _decode_deux_fois(brut)


def _evaluer_detection(details: list[dict], honeypot_log) -> dict:
    """Pour chaque sonde, marque DÉTECTÉ / NON DÉTECTÉ en relisant le journal.

    Une sonde est DÉTECTÉE si son canari OU sa chaîne de signature apparaît dans
    le journal du honeypot. Retourne le bilan agrégé (PASS si tout est détecté).
    """
    if not honeypot_log:
        for d in details:
            d["detection"] = "NON VÉRIFIÉ"
            d["detecte"] = None
            d["par_canari"] = None
            d["par_signature"] = None
        return {"detectees": 0, "total": len(details), "statut": "NON VÉRIFIÉ",
                "note": "journal honeypot non fourni : détection non évaluée"}

    blob = _blob_journal(honeypot_log)
    detectees = 0
    for d in details:
        par_canari = d["canari"] in blob
        # Repli « signature » : la chaîne d'attaque (chemin décodé) apparaît-elle ?
        par_signature = d["chemin"] in blob
        d["detecte"] = bool(par_canari or par_signature)
        d["par_canari"] = par_canari
        d["par_signature"] = par_signature
        d["detection"] = "DÉTECTÉ" if d["detecte"] else "NON DÉTECTÉ"
        if d["detecte"]:
            detectees += 1
    statut = "PASS" if (details and detectees == len(details)) else "FAIL"
    return {"detectees": detectees, "total": len(details), "statut": statut}


def _journaliser(journal, reference, cible, ip_source, decision, raison, details):
    """Consigne un événement au journal des tests si un chemin est fourni."""
    if not journal:
        return
    try:
        _J.enregistrer(journal, _J.Evenement(
            reference=reference or "",
            cible=cible,
            type_test="validation_detection",
            outil="purple",
            ip_source=ip_source or "",
            decision=decision,
            raison=raison,
            details=details or {},
        ))
    except OSError:
        pass


# ---------------------------------------------------------------------------
# API publique.
# ---------------------------------------------------------------------------
def rejouer(cible, *, mandat=None, ip_source=None, journal=None, reference="",
            honeypot_log=None, pause=0.2, moment=None) -> dict:
    """Rejoue le catalogue de sondes inertes contre ``cible`` pour tester la détection.

    Verrou éthique d'abord : une cible en boucle locale (le honeypot de
    l'opérateur) est autorisée sans mandat ; toute autre cible EXIGE un
    ``mandat`` autorisant ``validation_detection``, sinon la fonction refuse et
    n'émet AUCUNE sonde.

    :param cible: URL de la cible (ex. ``http://127.0.0.1:8080/``).
    :param mandat: objet :class:`tasko.mandat.Mandat` (requis hors boucle locale).
    :param ip_source: IP d'où part le test (vérifiée par le mandat si fournie).
    :param journal: chemin du journal des tests (JSONL) où consigner l'exécution.
    :param reference: référence du mandat/dossier (reportée dans le journal).
    :param honeypot_log: chemin du journal du honeypot ; s'il est fourni, chaque
        sonde est marquée DÉTECTÉ / NON DÉTECTÉ selon qu'on y retrouve sa trace.
    :param pause: pause (s) entre deux sondes, pour ne jamais ressembler à un DoS.
    :param moment: instant du test (transmis au mandat).
    :returns: un rapport (dict) : cible, autorisation, détails par sonde
        (id, canari, code HTTP, détection), bilan de détection, et rappel Wazuh.
    """
    hote = extraire_hote(cible)
    autorise, raison, ref = _autoriser_cible(cible, hote, mandat, ip_source,
                                              moment, reference)

    rapport: dict = {
        "outil": "purple",
        "type_test": "validation_detection",
        "cible": cible,
        "hote": hote,
        "reference": ref,
        "ip_source": ip_source,
        "horodatage_utc": _maintenant(),
        "autorise": autorise,
        "raison": raison,
        "nb_sondes": len(SONDES),
        "envoyees": 0,
        "honeypot_log": honeypot_log,
        "sondes": [],
        "bilan_detection": {},
        "rappel": RAPPEL_WAZUH,
    }

    # --- Refus : on consigne et on sort AVANT la moindre émission réseau. ---
    if not autorise:
        rapport["bilan_detection"] = {"detectees": 0, "total": 0,
                                      "statut": "NON EXÉCUTÉ",
                                      "note": "refus éthique : aucune sonde émise"}
        _journaliser(journal, ref, cible, ip_source, "refusé", raison, None)
        return rapport

    # --- Émission des sondes : une requête chacune, pause entre elles. ---
    schema, hote_reseau, port = _construire_cible(cible)
    details: list[dict] = []
    for i, sonde in enumerate(SONDES):
        canari = uuid.uuid4().hex
        entree = {
            "id": sonde.id,
            "methode": sonde.methode,
            "chemin": sonde.chemin,
            "signature_attendue": sonde.signature_attendue,
            "canari": canari,
            "code_http": None,
            "longueur": None,
            "erreur": None,
            "horodatage_utc": _maintenant(),
        }
        try:
            res = _envoyer_http(schema, hote_reseau, port, sonde, canari, TIMEOUT_HTTP)
            entree["code_http"] = res["code_http"]
            entree["longueur"] = res["longueur"]
        except (OSError, http.client.HTTPException) as e:
            entree["erreur"] = f"{type(e).__name__}: {e}"
        details.append(entree)
        if i != len(SONDES) - 1 and pause > 0:
            time.sleep(pause)  # rate-limit : jamais de rafale type DoS

    rapport["sondes"] = details
    rapport["envoyees"] = len(details)

    # --- Évaluation de la détection via le journal du honeypot. ---
    rapport["bilan_detection"] = _evaluer_detection(details, honeypot_log)

    _journaliser(journal, ref, cible, ip_source, "rejoué", raison, {
        "sondes": len(details),
        "detectees": rapport["bilan_detection"].get("detectees"),
        "statut": rapport["bilan_detection"].get("statut"),
    })
    return rapport


def sonder_ssh(cible, port=PORT_SSH_DEFAUT, *, mandat=None, ip_source=None,
               journal=None, reference="", timeout=TIMEOUT_SSH, moment=None) -> dict:
    """Sonde TCP inerte du faux SSH : ouvre une connexion, envoie une bannière marquée, ferme.

    But : vérifier que le honeypot capture bien une tentative SSH (il journalise
    la bannière cliente). On n'envoie qu'une bannière d'identification MARQUÉE
    (contenant le canari) — jamais d'authentification, jamais d'exploit. Même
    verrou éthique que :func:`rejouer`.

    :returns: dict avec cible, port, canari, bannières (envoyée/reçue), détection
        éventuelle (si ``honeypot_log`` relu par l'appelant), et le rappel Wazuh.
    """
    global COMPTEUR_ENVOIS
    hote = extraire_hote(cible)
    autorise, raison, ref = _autoriser_cible(cible, hote, mandat, ip_source,
                                              moment, reference)
    canari = uuid.uuid4().hex
    banniere = f"SSH-2.0-Tasko-Purple-DetectionTest_{canari}\r\n"

    rapport: dict = {
        "outil": "purple-ssh",
        "type_test": "validation_detection",
        "cible": cible,
        "hote": hote,
        "port": port,
        "reference": ref,
        "ip_source": ip_source,
        "horodatage_utc": _maintenant(),
        "autorise": autorise,
        "raison": raison,
        "canari": canari,
        "banniere_envoyee": banniere.strip(),
        "banniere_recue": None,
        "envoyees": 0,
        "erreur": None,
        "rappel": RAPPEL_WAZUH,
    }

    if not autorise:
        _journaliser(journal, ref, cible, ip_source, "refusé", raison, None)
        rapport["canari"] = None  # rien n'a été émis : pas de marqueur en jeu
        return rapport

    hote_reseau = _construire_cible(cible)[1] or hote
    try:
        COMPTEUR_ENVOIS += 1  # une tentative réseau va avoir lieu
        with socket.create_connection((hote_reseau, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                recu = s.recv(256)  # bannière du serveur (faux SSH), facultative
            except (socket.timeout, OSError):
                recu = b""
            s.sendall(banniere.encode("latin-1", "ignore"))
            rapport["banniere_recue"] = recu.decode("latin-1", "ignore").strip()[:200]
        rapport["envoyees"] = 1
    except OSError as e:
        rapport["erreur"] = f"{type(e).__name__}: {e}"

    _journaliser(journal, ref, cible, ip_source, "rejoué", raison,
                 {"port": port, "canari": canari})
    return rapport


def rendre_markdown(rapport: dict) -> str:
    """Restitue un rapport de :func:`rejouer` sous forme Markdown lisible."""
    L = ["# Validation de détection (mode purple) — Tasko Defense", ""]
    L.append(f"- **Cible :** {rapport.get('cible', '')}")
    L.append(f"- **Hôte :** {rapport.get('hote', '')}")
    L.append(f"- **Horodatage (UTC) :** {rapport.get('horodatage_utc', '')}")
    if rapport.get("reference"):
        L.append(f"- **Référence :** {rapport['reference']}")
    if rapport.get("ip_source"):
        L.append(f"- **IP source :** {rapport['ip_source']}")
    etat = "AUTORISÉ" if rapport.get("autorise") else "REFUSÉ"
    L.append(f"- **Autorisation :** {etat} — {rapport.get('raison', '')}")
    L.append(f"- **Sondes émises :** {rapport.get('envoyees', 0)} / "
             f"{rapport.get('nb_sondes', 0)}")
    L.append("")
    L.append("> Sondes INERTES et MARQUÉES : on teste la DÉTECTION, on n'attaque pas.")
    L.append("")

    if not rapport.get("autorise"):
        L.append("**Aucune sonde n'a été émise** (verrou éthique). "
                 "Fournis un mandat autorisant `validation_detection`, ou vise le "
                 "honeypot local de l'opérateur.")
        L.append("")
        return "\n".join(L) + "\n"

    L.append("## Sondes")
    L.append("")
    L.append("| # | id | méthode | chemin | canari | code | détection |")
    L.append("|---|---|---|---|---|---|---|")
    for i, d in enumerate(rapport.get("sondes", []), 1):
        canari = str(d.get("canari") or "")[:8]
        chemin = str(d.get("chemin", "")).replace("|", "\\|")
        code = d.get("code_http")
        code = "ERR" if code is None else str(code)
        L.append(f"| {i} | {d.get('id', '')} | {d.get('methode', '')} | "
                 f"`{chemin}` | `{canari}` | {code} | {d.get('detection', '?')} |")
    L.append("")

    bilan = rapport.get("bilan_detection", {})
    L.append("## Bilan de détection")
    L.append("")
    L.append(f"- **Détectées :** {bilan.get('detectees', 0)} / "
             f"{bilan.get('total', 0)} — **{bilan.get('statut', '?')}**")
    if bilan.get("note"):
        L.append(f"- *{bilan['note']}*")
    L.append("")
    L.append(f"> **Rappel :** {rapport.get('rappel', RAPPEL_WAZUH)}")
    L.append("")
    return "\n".join(L) + "\n"
