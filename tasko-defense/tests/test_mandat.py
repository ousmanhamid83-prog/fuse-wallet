#!/usr/bin/env python3
"""Tests du moteur de mandat. Lancer : python3 -I -m pytest -q  (ou ce fichier directement).

Aucun accès réseau. Les mandats sont construits en mémoire.
"""
from __future__ import annotations

import datetime as dt
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tasko.mandat import (  # noqa: E402
    Mandat,
    MandatError,
    autoriser,
    etat_validite,
    extraire_hote,
)

TZ = "Africa/Ndjamena"  # UTC+1, sans heure d'été


def mandat_base(**over) -> Mandat:
    base = {
        "reference": "T-TEST",
        "signe": True,
        "valide_du": "2026-01-01",
        "valide_au": "2026-12-31",
        "fuseau": TZ,
        "fenetres": [{"jours": [1, 2, 3, 4, 5], "debut": "01:00", "fin": "05:00"}],
        "ip_source": ["198.51.100.10"],
        "perimetre": {"domaines": ["exemple.cm"], "ips": ["203.0.113.0/24"], "heberge_dedie": True},
        "exclusions": {"domaines": ["secret.exemple.cm"], "ips": ["203.0.113.5"]},
        "annexe_d_signee": False,
        "tests_autorises": {
            "decouverte": True,
            "scan_web": True,
            "scan_reseau": True,
            "test_authentifie": True,
            "validation_detection": True,
            "exploitation": False,
            "ingenierie_sociale": False,
        },
    }
    base.update(over)
    return Mandat.depuis_dict(base)


# Un mardi 01:30 (dans la fenêtre), UTC = 00:30.
DANS = dt.datetime(2026, 6, 2, 0, 30, tzinfo=dt.timezone.utc)
# Un mardi 12:00 (hors fenêtre).
HORS = dt.datetime(2026, 6, 2, 11, 0, tzinfo=dt.timezone.utc)


def check(cond, nom):
    print(f"  {'OK ' if cond else 'ÉCHEC'} {nom}")
    return cond


def run() -> int:
    ok = True

    # --- Signature ---
    m = mandat_base(signe=False)
    d = autoriser(m, "https://exemple.cm/", "scan_web", moment=DANS)
    ok &= check(not d.autorise and "signé" in d.raison, "mandat non signé refusé")

    m = mandat_base()
    d = autoriser(m, "https://exemple.cm/", "scan_web", moment=DANS, ip_source="198.51.100.10")
    ok &= check(d.autorise, "cas nominal autorisé")

    # --- Périmètre : hôte vs sous-chaîne (le piège evil) ---
    d = autoriser(m, "https://exemple.cm.evil.net/", "scan_web", moment=DANS)
    ok &= check(not d.autorise, "exemple.cm.evil.net hors périmètre (pas de piège sous-chaîne)")
    d = autoriser(m, "https://api.exemple.cm/", "scan_web", moment=DANS)
    ok &= check(d.autorise, "sous-domaine api.exemple.cm dans le périmètre")

    # --- Exclusions ---
    d = autoriser(m, "https://secret.exemple.cm/", "scan_web", moment=DANS)
    ok &= check(not d.autorise and "exclu" in d.raison, "domaine exclu refusé")

    # --- Fenêtre horaire ---
    d = autoriser(m, "https://exemple.cm/", "scan_web", moment=HORS)
    ok &= check(not d.autorise and "fenêtre" in d.raison, "hors fenêtre refusé")

    # --- Dates ---
    tot = dt.datetime(2025, 6, 3, 0, 30, tzinfo=dt.timezone.utc)
    d = autoriser(m, "https://exemple.cm/", "scan_web", moment=tot)
    ok &= check(not d.autorise and "valide" in d.raison, "avant début de validité refusé")

    # --- Type non autorisé ---
    d = autoriser(m, "https://exemple.cm/", "ingenierie_sociale", moment=DANS)
    ok &= check(not d.autorise, "type non coché refusé")

    # --- scan_reseau exige hébergement dédié ---
    m2 = mandat_base(perimetre={"domaines": ["exemple.cm"], "ips": ["203.0.113.0/24"], "heberge_dedie": False})
    d = autoriser(m2, "203.0.113.10", "scan_reseau", moment=DANS)
    ok &= check(not d.autorise and "dédié" in d.raison, "scan_reseau bloqué sans hébergement dédié")

    # --- exploitation exige Annexe D ---
    m3 = mandat_base(tests_autorises={**mandat_base().tests_autorises, "exploitation": True})
    d = autoriser(m3, "https://exemple.cm/", "exploitation", moment=DANS)
    ok &= check(not d.autorise and "Annexe D" in d.raison, "exploitation bloquée sans Annexe D")

    # --- IP source ---
    d = autoriser(m, "https://exemple.cm/", "scan_web", moment=DANS, ip_source="8.8.8.8")
    ok &= check(not d.autorise and "source" in d.raison, "IP source non déclarée refusée")

    # --- validation_detection (mode purple) autorisée dans le périmètre ---
    d = autoriser(m, "https://exemple.cm/", "validation_detection", moment=DANS, ip_source="198.51.100.10")
    ok &= check(d.autorise, "validation_detection autorisée (purple)")

    # --- Périmètre IP + exclusion IP ---
    d = autoriser(m, "203.0.113.10", "scan_reseau", moment=DANS)
    ok &= check(d.autorise, "IP dans la plage autorisée")
    d = autoriser(m, "203.0.113.5", "scan_reseau", moment=DANS)
    ok &= check(not d.autorise and "exclu" in d.raison, "IP exclue refusée")
    d = autoriser(m, "192.0.2.1", "scan_reseau", moment=DANS)
    ok &= check(not d.autorise, "IP hors plage refusée")

    # --- extraire_hote ---
    cas = {
        "https://x.cm/a/b?z=1": "x.cm",
        "x.cm:443": "x.cm",
        "user@x.cm": "x.cm",
        "HTTP://X.CM.": "x.cm",
        "203.0.113.0/24": "203.0.113.0",
        "[2001:db8::1]:8080": "2001:db8::1",
    }
    for entree, attendu in cas.items():
        ok &= check(extraire_hote(entree) == attendu, f"extraire_hote({entree!r}) == {attendu}")

    # --- Mandat incohérent : dates inversées ---
    try:
        mandat_base(valide_du="2026-12-31", valide_au="2026-01-01")
        ok &= check(False, "dates inversées détectées")
    except MandatError:
        ok &= check(True, "dates inversées détectées")

    # --- Fenêtre qui franchit minuit ---
    m4 = mandat_base(fenetres=[{"jours": [1, 2, 3, 4, 5, 6, 7], "debut": "22:00", "fin": "05:00"}])
    minuit = dt.datetime(2026, 6, 1, 23, 30, tzinfo=dt.timezone.utc)  # 00:30 local mardi
    d = autoriser(m4, "https://exemple.cm/", "scan_web", moment=minuit)
    ok &= check(d.autorise, "fenêtre franchissant minuit : 00:30 local autorisé")

    # --- Inventaire à l'échelle : perimetre.ips_fichier (parc de milliers d'IP) ---
    import tempfile
    tmp = tempfile.mkdtemp(prefix="tasko-inv-")
    with open(os.path.join(tmp, "parc.txt"), "w", encoding="utf-8") as f:
        f.write("# parc interne\n10.0.0.0/8\n192.168.0.0/16\n")
    with open(os.path.join(tmp, "m.yaml"), "w", encoding="utf-8") as f:
        f.write('mandat:\n  reference: "T-INV"\n  signe: true\n'
                '  valide_du: "2020-01-01"\n  valide_au: "2099-12-31"\n'
                '  fuseau: "UTC"\n  fenetres: []\n  ip_source: []\n'
                '  perimetre: {domaines: [], ips: ["127.0.0.0/8"], '
                'ips_fichier: "parc.txt", heberge_dedie: true}\n'
                '  exclusions: {domaines: [], ips: []}\n  annexe_d_signee: false\n'
                '  tests_autorises: {scan_reseau: true}\n')
    minv = Mandat.charger(os.path.join(tmp, "m.yaml"))
    ok &= check("10.0.0.0/8" in minv.ips and "192.168.0.0/16" in minv.ips,
                "inventaire : plages du fichier chargées dans le périmètre")
    d = autoriser(minv, "10.1.2.3", "scan_reseau", moment=DANS)
    ok &= check(d.autorise, "inventaire : IP du parc (10.1.2.3) autorisée")
    d = autoriser(minv, "8.8.8.8", "scan_reseau", moment=DANS)
    ok &= check(not d.autorise, "inventaire : IP hors parc (8.8.8.8) refusée")

    # --- état de validité (alertes d'expiration) ---
    ajd = dt.date(2026, 6, 15)
    mm = mandat_base(valide_du="2026-01-01", valide_au="2026-12-31")
    ok &= check(etat_validite(mm, ajd)["etat"] == "actif", "validité : mandat actif")
    mm = mandat_base(valide_du="2026-01-01", valide_au="2026-06-20")
    ok &= check(etat_validite(mm, ajd)["etat"] == "expire_bientot", "validité : expire bientôt (≤14j)")
    mm = mandat_base(valide_du="2026-01-01", valide_au="2026-05-01")
    ev = etat_validite(mm, ajd)
    ok &= check(ev["etat"] == "expire" and ev["jours_restants"] < 0, "validité : expiré")
    ok &= check(etat_validite(mandat_base(signe=False), ajd)["etat"] == "non_signe",
                "validité : non signé")

    print("\nRÉSULTAT :", "TOUS LES TESTS PASSENT" if ok else "DES TESTS ÉCHOUENT")
    return 0 if ok else 1


# Compat pytest : expose chaque assertion comme un test unique agrégé.
def test_moteur_mandat():
    assert run() == 0


if __name__ == "__main__":
    raise SystemExit(run())
