#!/usr/bin/env python3
"""Tests du module de documentation de PoC (Annexe D). Aucun accès réseau.

Logique pure : les mandats sont construits en mémoire, les preuves sont des
fichiers temporaires locaux. On vérifie que :
  - sans Annexe D signée, documenter() REFUSE et n'écrit rien ;
  - avec exploitation=true et annexe_d_signee=true, documenter() produit un
    dossier scellé ;
  - les empreintes SHA-256 des preuves sont correctes (recalculées à la main) ;
  - une preuve manquante est signalée, pas fatale ;
  - le Markdown contient les limites de l'Annexe D ;
  - ecrire() refuse d'écrire un dossier non autorisé (le refus n'écrit rien).

Lancer : python3 tests/test_poc.py   (ou via pytest).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tasko.mandat import Mandat                      # noqa: E402
from tasko import journal as J                       # noqa: E402
from tasko import poc as P                           # noqa: E402

TZ = "Africa/Ndjamena"  # UTC+1, sans heure d'été
# Un mardi 01:30 locale (dans la fenêtre), soit 00:30 UTC.
DANS = dt.datetime(2026, 6, 2, 0, 30, tzinfo=dt.timezone.utc)


def mandat_base(**over) -> Mandat:
    """Mandat signé, cible exemple.cm, sans Annexe D par défaut."""
    base = {
        "reference": "T-POC",
        "signe": True,
        "valide_du": "2026-01-01",
        "valide_au": "2026-12-31",
        "fuseau": TZ,
        "fenetres": [{"jours": [1, 2, 3, 4, 5], "debut": "01:00", "fin": "05:00"}],
        "ip_source": ["198.51.100.10"],
        "perimetre": {"domaines": ["exemple.cm"], "ips": [], "heberge_dedie": False},
        "exclusions": {"domaines": [], "ips": []},
        "annexe_d_signee": False,
        "tests_autorises": {
            "decouverte": True, "scan_web": True, "scan_reseau": False,
            "test_authentifie": False, "validation_detection": True,
            "exploitation": False, "ingenierie_sociale": False,
        },
    }
    base.update(over)
    return Mandat.depuis_dict(base)


def mandat_annexe_d() -> Mandat:
    """Mandat autorisant l'exploitation avec Annexe D signée."""
    return mandat_base(
        annexe_d_signee=True,
        tests_autorises={
            "decouverte": True, "scan_web": True, "scan_reseau": False,
            "test_authentifie": False, "validation_detection": True,
            "exploitation": True, "ingenierie_sociale": False,
        },
    )


def check(cond, nom):
    print(f"  {'OK ' if cond else 'ÉCHEC'} {nom}")
    return bool(cond)


def run() -> int:
    ok = True
    tmp = tempfile.mkdtemp(prefix="tasko-poc-test-")
    finding = {"cible": "https://exemple.cm/panier",
               "titre": "IDOR sur /panier (accès commande d'autrui)",
               "reference": "CWE-639", "severite": "élevée"}

    # Preuves : deux fichiers réels + un chemin inexistant.
    p1 = os.path.join(tmp, "capture-idor.txt")
    p2 = os.path.join(tmp, "trace-http.txt")
    contenu1 = b"capture d'ecran (texte) : reponse 200 pour une commande d'un autre compte\n"
    contenu2 = b"GET /panier?id=1042 HTTP/1.1\nHost: exemple.cm\n\nHTTP/1.1 200 OK\n"
    with open(p1, "wb") as fh:
        fh.write(contenu1)
    with open(p2, "wb") as fh:
        fh.write(contenu2)
    absent = os.path.join(tmp, "n-existe-pas.png")
    etapes = "1) Connexion compte A. 2) Remplacement de l'id par celui du compte B. 3) Observation."
    resultat = "La commande du compte B s'affiche : contrôle d'accès absent (IDOR confirmé)."

    # --- 1. Refus sans Annexe D ---
    # Mandat où l'exploitation est cochée MAIS l'Annexe D n'est pas signée :
    # c'est exactement le verrou Annexe D que l'on veut éprouver ici.
    sans_annexe = mandat_base(tests_autorises={
        "decouverte": True, "scan_web": True, "scan_reseau": False,
        "test_authentifie": False, "validation_detection": True,
        "exploitation": True, "ingenierie_sociale": False,
    })  # annexe_d_signee reste False (défaut de mandat_base)
    jref = os.path.join(tmp, "journal-refus.jsonl")
    refus = P.documenter(sans_annexe, finding, [p1, p2], etapes, resultat,
                         operateur="auditrice", moment=DANS,
                         ip_source="198.51.100.10", journal=jref)
    ok &= check(refus.get("autorise") is False, "sans Annexe D : documenter() refuse")
    ok &= check("Annexe D" in refus.get("refus", ""), "refus : raison mentionne l'Annexe D")
    ok &= check("preuves" not in refus, "refus : aucun contenu de dossier (pas de preuves)")
    ok &= check(not os.path.exists(jref), "refus : aucun événement journalisé")

    # Le refus n'écrit rien : ecrire() doit lever et ne créer aucun fichier.
    rj = os.path.join(tmp, "refus.json")
    rm = os.path.join(tmp, "refus.md")
    leve = False
    try:
        P.ecrire(refus, rj, rm)
    except ValueError:
        leve = True
    ok &= check(leve, "refus : ecrire() lève ValueError")
    ok &= check(not os.path.exists(rj) and not os.path.exists(rm),
                "refus : aucun fichier de dossier créé")

    # --- 2. Hors périmètre refusé même avec Annexe D ---
    hors = P.documenter(mandat_annexe_d(),
                        {**finding, "cible": "https://autre-site.net/"},
                        [p1], etapes, resultat, moment=DANS)
    ok &= check(hors.get("autorise") is False, "hors périmètre : documenter() refuse (malgré Annexe D)")

    # --- 3. Dossier produit avec Annexe D ---
    jok = os.path.join(tmp, "journal-tests.jsonl")
    dossier = P.documenter(mandat_annexe_d(), finding, [p1, p2, absent],
                           etapes, resultat, operateur="auditrice",
                           moment=DANS, ip_source="198.51.100.10", journal=jok)
    ok &= check(dossier.get("autorise") is True, "avec Annexe D : documenter() produit un dossier")
    ok &= check(dossier["reference_mandat"] == "T-POC", "dossier : référence mandat")
    ok &= check(dossier["operateur"] == "auditrice", "dossier : opérateur")
    ok &= check(dossier["finding"]["titre"] == finding["titre"], "dossier : finding repris")
    ok &= check(bool(dossier.get("horodatage_utc")), "dossier : horodatage UTC présent")

    # --- 4. Empreintes SHA-256 des preuves correctes ---
    attendu1 = hashlib.sha256(contenu1).hexdigest()
    attendu2 = hashlib.sha256(contenu2).hexdigest()
    par_nom = {p["nom"]: p for p in dossier["preuves"]}
    ok &= check(par_nom["capture-idor.txt"]["sha256"] == attendu1,
                "preuve 1 : SHA-256 correct")
    ok &= check(par_nom["capture-idor.txt"]["taille"] == len(contenu1),
                "preuve 1 : taille correcte")
    ok &= check(par_nom["trace-http.txt"]["sha256"] == attendu2,
                "preuve 2 : SHA-256 correct")
    ok &= check(par_nom["n-existe-pas.png"]["present"] is False
                and par_nom["n-existe-pas.png"]["sha256"] == "",
                "preuve absente : signalée, non fatale")
    ok &= check(dossier["preuves_manquantes"] == ["n-existe-pas.png"],
                "dossier : preuve manquante listée")

    # --- 5. Sceau cohérent et sensible à la falsification ---
    ok &= check(len(dossier["sceau"]) == 64, "dossier : sceau SHA-256 (64 hex)")
    ok &= check(P._sceller(dossier) == dossier["sceau"], "dossier : sceau recalculé identique")
    falsifie = json.loads(json.dumps(dossier))
    falsifie["resultat"] = "resultat modifie apres coup"
    ok &= check(P._sceller(falsifie) != dossier["sceau"],
                "dossier : toute modification casse le sceau")

    # --- 6. Journal : un événement 'documenté' ---
    entrees = J.lire(jok)
    ok &= check(len(entrees) == 1 and entrees[0]["decision"] == "documenté"
                and entrees[0]["outil"] == "poc-annexe-d",
                "journal : événement 'documenté' consigné (outil poc-annexe-d)")
    ok &= check(entrees[0]["empreinte"] == dossier["sceau"],
                "journal : empreinte = sceau du dossier")

    # --- 7. Markdown : limites Annexe D + tableau des preuves ---
    md = P.rendre_markdown(dossier)
    ok &= check("Annexe D" in md, "markdown : mentionne l'Annexe D")
    ok &= check(all(lim in md for lim in P.LIMITES_ANNEXE_D),
                "markdown : contient toutes les limites de l'Annexe D")
    ok &= check(attendu1 in md and attendu2 in md, "markdown : empreintes des preuves présentes")
    ok &= check("MANQUANTE" in md, "markdown : preuve manquante signalée")
    ok &= check(finding["titre"] in md, "markdown : titre du finding présent")

    # --- 8. ecrire() produit bien les deux fichiers ---
    cj = os.path.join(tmp, "dossier.json")
    cm = os.path.join(tmp, "dossier.md")
    P.ecrire(dossier, cj, cm)
    ok &= check(os.path.exists(cj) and os.path.exists(cm), "ecrire : JSON + Markdown créés")
    with open(cj, encoding="utf-8") as fh:
        relu = json.load(fh)
    ok &= check(relu["sceau"] == dossier["sceau"], "ecrire : JSON relu, sceau identique")

    print("\nRÉSULTAT :", "TOUS LES TESTS PASSENT" if ok else "DES TESTS ÉCHOUENT")
    return 0 if ok else 1


def test_poc_annexe_d():
    assert run() == 0


if __name__ == "__main__":
    raise SystemExit(run())
