#!/usr/bin/env python3
"""Tests du brouillon de PoC pré-rempli (gain de temps de saisie). Aucun réseau.

Vérifie que :
  - un brouillon est pré-rempli depuis un finding (métadonnées recopiées) ;
  - un brouillon rempli se recharge correctement (placeholders ignorés) ;
  - sceller via un brouillon donne le MÊME dossier que la saisie manuelle ;
  - le verrou Annexe D s'applique toujours (refus sans Annexe D signée).

Lancer : python3 tests/test_poc_brouillon.py
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tasko import poc as P          # noqa: E402
from tasko.mandat import Mandat     # noqa: E402


def check(cond, nom):
    print(f"  {'OK ' if cond else 'ÉCHEC'} {nom}")
    return bool(cond)


def mandat(annexe_d=True, **over) -> Mandat:
    base = {
        "reference": "T-POC", "signe": True,
        "valide_du": "2020-01-01", "valide_au": "2099-12-31",
        "fuseau": "UTC", "fenetres": [], "ip_source": [],
        "perimetre": {"domaines": ["demo.local"], "ips": [], "heberge_dedie": True},
        "exclusions": {"domaines": [], "ips": []},
        "annexe_d_signee": annexe_d,
        "tests_autorises": {"exploitation": True},
    }
    base.update(over)
    return Mandat.depuis_dict(base)


def run() -> int:
    ok = True
    tmp = tempfile.mkdtemp(prefix="tasko-brouillon-")

    finding = {"cible": "https://demo.local/login", "titre": "SQLi /login",
               "reference": "CVE-2024-0001", "severite": "élevée"}

    # 1) Brouillon pré-rempli : les métadonnées du finding sont présentes.
    texte = P.modele_brouillon(finding)
    ok &= check(all(v in texte for v in finding.values()),
                "brouillon : cible/titre/CVE/sévérité pré-remplis depuis le finding")
    ok &= check("À REMPLIR" in texte, "brouillon : champs manuels marqués « À REMPLIR »")

    # 2) On simule l'opérateur qui remplit la partie manuelle.
    rempli = (texte
              .replace("(décris ici, étape par étape, la PoC que TU as réalisée à la main)",
                       "Paramètre id: 1' OR '1'='1 (PoC manuelle)")
              .replace("(observation : en quoi la faille est démontrée — en lecture seule)",
                       "Accès admin démontré, aucune donnée extraite")
              .replace("(chemin d'une capture d'écran ou d'une trace requête/réponse)",
                       os.path.join(tmp, "capture.png")))
    with open(os.path.join(tmp, "capture.png"), "w") as f:
        f.write("preuve")
    chemin_brouillon = os.path.join(tmp, "brouillon.yaml")
    with open(chemin_brouillon, "w", encoding="utf-8") as f:
        f.write(rempli)

    # 3) Rechargement : finding reconstruit, placeholders ignorés.
    br = P.charger_brouillon(chemin_brouillon)
    ok &= check(br["finding"] == finding, "rechargement : finding identique au finding source")
    ok &= check("OR '1'='1" in br["etapes"] and "admin" in br["resultat"],
                "rechargement : étapes et résultat récupérés")
    ok &= check(br["preuves"] == [os.path.join(tmp, "capture.png")],
                "rechargement : preuve récupérée (placeholder ignoré)")

    # 4) Un brouillon NON rempli n'inclut aucune preuve placeholder.
    br_vide = P.charger_brouillon(os.path.join(tmp, "vide.yaml")) if False else None
    with open(os.path.join(tmp, "vide.yaml"), "w", encoding="utf-8") as f:
        f.write(P.modele_brouillon(finding))
    brv = P.charger_brouillon(os.path.join(tmp, "vide.yaml"))
    ok &= check(brv["preuves"] == [], "brouillon non rempli : aucune preuve placeholder retenue")

    # 5) Sceller via brouillon == sceller en manuel (même contenu de dossier).
    m = mandat()
    d_manuel = P.documenter(m, finding, br["preuves"], br["etapes"], br["resultat"],
                            operateur="analyste1")
    d_brouillon = P.documenter(m, br["finding"], br["preuves"], br["etapes"], br["resultat"],
                               operateur="analyste1")
    ok &= check(d_manuel.get("autorise") and d_brouillon.get("autorise"),
                "scellement autorisé (Annexe D signée)")
    ok &= check(d_manuel.get("finding") == d_brouillon.get("finding"),
                "brouillon vs manuel : même finding scellé")

    # 6) Verrou Annexe D : sans Annexe D signée, le scellement via brouillon refuse.
    d_refus = P.documenter(mandat(annexe_d=False), br["finding"], br["preuves"],
                           br["etapes"], br["resultat"])
    ok &= check(d_refus.get("autorise") is False, "sans Annexe D : brouillon refusé (verrou intact)")

    print("\nRÉSULTAT :", "TOUS LES TESTS PASSENT" if ok else "DES TESTS ÉCHOUENT")
    return 0 if ok else 1


def test_poc_brouillon():
    assert run() == 0


if __name__ == "__main__":
    raise SystemExit(run())
