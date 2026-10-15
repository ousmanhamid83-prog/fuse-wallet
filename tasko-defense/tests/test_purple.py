#!/usr/bin/env python3
"""Tests du mode « purple » (validation de détection).

Deux volets :
  1. Verrou éthique (sans réseau) : une cible externe SANS mandat est refusée et
     AUCUNE sonde n'est émise (prouvé par le compteur d'envois réseau).
  2. Chemin nominal LOCAL : on démarre le VRAI honeypot du dépôt sur 127.0.0.1
     (ports hauts), on rejoue les sondes, on vérifie qu'elles apparaissent dans
     le journal du honeypot (détection PASS), puis on TUE le honeypot proprement.

Tout trafic reste strictement sur 127.0.0.1. Le honeypot est lancé en
sous-processus isolé et terminé dans un `finally` : aucun port ni processus ne
reste occupé.

Lancer : python3 tests/test_purple.py
"""
from __future__ import annotations

import datetime as dt
import os
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tasko import purple  # noqa: E402
from tasko import journal as J  # noqa: E402
from tasko.mandat import Mandat  # noqa: E402

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HONEYPOT = os.path.join(RACINE, "outils", "honeypot.py")

# Ports hauts locaux dédiés au test (imposés par la consigne).
PORT_HTTP = 18080
PORT_SSH = 12222

TZ = "Africa/Ndjamena"  # UTC+1, sans heure d'été (comme test_mandat.py)
# Un mardi 01:30 local (= 00:30 UTC) : dans la fenêtre 01:00–05:00.
DANS = dt.datetime(2026, 6, 2, 0, 30, tzinfo=dt.timezone.utc)


def check(cond, nom):
    print(f"  {'OK ' if cond else 'ÉCHEC'} {nom}")
    return bool(cond)


def mandat_validation(**over) -> Mandat:
    """Mandat SIGNÉ autorisant validation_detection sur exemple.cm (en mémoire)."""
    base = {
        "reference": "T-PURPLE",
        "signe": True,
        "valide_du": "2026-01-01",
        "valide_au": "2026-12-31",
        "fuseau": TZ,
        "fenetres": [{"jours": [1, 2, 3, 4, 5], "debut": "01:00", "fin": "05:00"}],
        "ip_source": ["198.51.100.10"],
        "perimetre": {"domaines": ["exemple.cm"], "ips": ["203.0.113.0/24"],
                      "heberge_dedie": True},
        "exclusions": {"domaines": [], "ips": []},
        "annexe_d_signee": False,
        "tests_autorises": {"validation_detection": True},
    }
    base.update(over)
    return Mandat.depuis_dict(base)


def attendre_port(host, port, timeout=15.0) -> bool:
    """Attend que `host:port` accepte une connexion (honeypot prêt)."""
    fin = time.time() + timeout
    while time.time() < fin:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


# ---------------------------------------------------------------------------
# 1. Verrou éthique — aucun réseau.
# ---------------------------------------------------------------------------
def test_refus_ethique() -> bool:
    ok = True
    print("[1] Verrou éthique (cible externe, sans mandat)")

    purple.reinitialiser_compteur()
    rap = purple.rejouer("https://exemple-externe.cm/")
    ok &= check(rap["autorise"] is False, "cible externe sans mandat : non autorisée")
    ok &= check(rap["envoyees"] == 0 and rap["sondes"] == [],
                "refus : 0 sonde dans le rapport")
    ok &= check(purple.compteur_envois() == 0,
                "refus : 0 requête réseau tentée (compteur = 0)")
    md = purple.rendre_markdown(rap)
    ok &= check("REFUSÉ" in md and "Aucune sonde" in md,
                "rendu Markdown d'un refus explicite")

    # La sonde SSH applique le même verrou, sans émettre non plus.
    purple.reinitialiser_compteur()
    rap_ssh = purple.sonder_ssh("exemple-externe.cm")
    ok &= check(rap_ssh["autorise"] is False and rap_ssh["envoyees"] == 0
                and purple.compteur_envois() == 0,
                "sonde SSH externe sans mandat : refusée, 0 envoi")

    # Branche « mandat » vérifiée SANS réseau (on n'appelle pas rejouer sur un
    # hôte externe, interdit) : la logique d'autorisation autorise bien avec un
    # mandat valide et refuse sans.
    m = mandat_validation()
    aut, _, ref = purple._autoriser_cible("https://exemple.cm/", "exemple.cm",
                                          m, "198.51.100.10", DANS, "")
    ok &= check(aut and ref == "T-PURPLE",
                "mandat valide : validation_detection autorisée (hors ligne)")
    refus, _, _ = purple._autoriser_cible("https://exemple.cm/", "exemple.cm",
                                          None, None, DANS, "")
    ok &= check(not refus, "pas de mandat : validation_detection refusée (hors ligne)")
    # Boucle locale : autorisée sans mandat.
    loc, _, _ = purple._autoriser_cible("http://127.0.0.1:18080/", "127.0.0.1",
                                        None, None, DANS, "")
    ok &= check(loc, "boucle locale : autorisée sans mandat")
    return ok


# ---------------------------------------------------------------------------
# 2. Chemin nominal LOCAL — vrai honeypot sur 127.0.0.1.
# ---------------------------------------------------------------------------
def test_nominal_local() -> bool:
    ok = True
    print("[2] Chemin nominal LOCAL (honeypot réel sur 127.0.0.1)")

    tmp = tempfile.mkdtemp(prefix="tasko-purple-")
    log_hp = os.path.join(tmp, "honeypot.log")
    journal_tests = os.path.join(tmp, "journal-tests.jsonl")

    env = dict(os.environ)
    env.update({
        "HONEYPOT_HTTP_PORT": str(PORT_HTTP),
        "HONEYPOT_SSH_PORT": str(PORT_SSH),
        "HONEYPOT_LOG": log_hp,
        "HONEYPOT_BIND": "127.0.0.1",   # strictement local
        "HONEYPOT_IPV6": "0",           # pas d'écoute IPv6
    })

    proc = subprocess.Popen(
        [sys.executable, "-I", HONEYPOT],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        if not check(attendre_port("127.0.0.1", PORT_HTTP),
                     f"honeypot HTTP en écoute sur 127.0.0.1:{PORT_HTTP}"):
            return False

        purple.reinitialiser_compteur()
        rap = purple.rejouer("http://127.0.0.1:18080/",
                             honeypot_log=log_hp, journal=journal_tests, pause=0.05)

        ok &= check(rap["autorise"] is True, "cible locale : autorisée sans mandat")
        ok &= check(rap["envoyees"] == len(purple.SONDES),
                    f"{len(purple.SONDES)} sondes émises")
        ok &= check(purple.compteur_envois() == len(purple.SONDES),
                    "compteur réseau == nombre de sondes")

        # Toutes les sondes HTTP doivent apparaître dans le journal du honeypot.
        with open(log_hp, "r", encoding="utf-8") as f:
            contenu = f.read()
        toutes_dans_log = all(d["canari"] in contenu for d in rap["sondes"])
        ok &= check(toutes_dans_log,
                    "chaque canari de sonde présent dans le journal honeypot")

        ok &= check(rap["bilan_detection"].get("statut") == "PASS",
                    "bilan de détection = PASS (toutes détectées)")
        ok &= check(all(d["detection"] == "DÉTECTÉ" for d in rap["sondes"]),
                    "chaque sonde marquée DÉTECTÉ")
        ok &= check({d["id"] for d in rap["sondes"]} ==
                    {s.id for s in purple.SONDES},
                    "le rapport liste toutes les sondes du catalogue")

        # Journal des tests : un événement 'rejoué' consigné.
        entrees = J.lire(journal_tests)
        ok &= check(any(e.get("outil") == "purple" and e.get("decision") == "rejoué"
                        and e.get("type_test") == "validation_detection"
                        for e in entrees),
                    "journal des tests : événement purple/rejoué consigné")

        # Rendu Markdown exploitable.
        md = purple.rendre_markdown(rap)
        ok &= check("Validation de détection" in md and "PASS" in md
                    and "Wazuh" in md,
                    "rendu Markdown : titre + bilan PASS + rappel Wazuh")

        # Bonus : la sonde SSH inerte est capturée par le faux SSH.
        if check(attendre_port("127.0.0.1", PORT_SSH),
                 f"honeypot SSH en écoute sur 127.0.0.1:{PORT_SSH}"):
            rap_ssh = purple.sonder_ssh("127.0.0.1", port=PORT_SSH,
                                        journal=journal_tests)
            ok &= check(rap_ssh["autorise"] and rap_ssh["envoyees"] == 1,
                        "sonde SSH locale émise (1 connexion inerte)")
            time.sleep(0.6)  # laisse le honeypot journaliser la bannière reçue
            with open(log_hp, "r", encoding="utf-8") as f:
                contenu = f.read()
            ok &= check(rap_ssh["canari"] in contenu,
                        "canari SSH présent dans le journal honeypot")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)

    # Les ports doivent être de nouveau libres (honeypot arrêté).
    libre_http = attendre_port("127.0.0.1", PORT_HTTP, timeout=0.5) is False
    ok &= check(libre_http, f"port {PORT_HTTP} libéré après arrêt du honeypot")
    return ok


def run() -> int:
    ok = True
    ok &= test_refus_ethique()
    ok &= test_nominal_local()
    print("\nRÉSULTAT :", "TOUS LES TESTS PASSENT" if ok else "DES TESTS ÉCHOUENT")
    return 0 if ok else 1


# Compat pytest.
def test_mode_purple():
    assert run() == 0


if __name__ == "__main__":
    raise SystemExit(run())
