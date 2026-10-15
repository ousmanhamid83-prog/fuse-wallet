#!/usr/bin/env python3
"""Test du branchement de `preuve` dans threat-intel (décodage défensif des payloads).

Aucun réseau (pas de clé AbuseIPDB). Charge threat-intel.py par chemin (son nom
contient un tiret, non importable directement).

Lancer : python3 tests/test_threat_intel_preuve.py
"""
from __future__ import annotations

import base64
import importlib.util
import os
import sys
import tempfile

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RACINE)


def charger_module():
    chemin = os.path.join(RACINE, "outils", "threat-intel.py")
    spec = importlib.util.spec_from_file_location("ti_mod", chemin)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def check(cond, nom):
    print(f"  {'OK ' if cond else 'ÉCHEC'} {nom}")
    return bool(cond)


def run() -> int:
    ok = True
    ti = charger_module()

    ok &= check(ti._preuve is not None, "preuve est bien branché dans threat-intel")

    # 1) Décodage d'un payload URL-encodé repéré dans une ligne web.
    echantillons = {
        "sql_injection": [{
            "line_no": 7,
            "raw_line_excerpt":
                '45.9.20.7 - - [x] "GET /p?id=1%20UNION%20SELECT%201,2,3 HTTP/1.1" 200 1 "-" "curl/8"',
        }],
    }
    dec = ti.decoder_echantillons(echantillons)
    ok &= check(any("union select" in e["revele"].lower() for e in dec),
                "payload URL-encodé décodé (UNION SELECT révélé)")

    # 2) Décodage d'un jeton base64 embarqué dans un paramètre.
    charge = "<?php system($_GET['c']); ?>"
    b64 = base64.b64encode(charge.encode()).decode()
    echantillons2 = {
        "code_injection_probe": [{
            "line_no": 9,
            "raw_line_excerpt": f'8.8.8.8 - - [x] "GET /x?p={b64} HTTP/1.1" 200 1 "-" "-"',
        }],
    }
    dec2 = ti.decoder_echantillons(echantillons2)
    ok &= check(any("system" in e["comportement_apparent"] for e in dec2),
                "jeton base64 embarqué décodé (system repéré)")

    # 3) Une ligne sans encodage ni mot-clé ne produit AUCUN décodage (pas de bruit).
    echantillons3 = {"xxx": [{"line_no": 1, "raw_line_excerpt": "1.2.3.4 - - GET /accueil 200"}]}
    ok &= check(ti.decoder_echantillons(echantillons3) == [],
                "ligne banale : aucun décodage inventé")

    # 4) Chaîne complète : analyze_log -> le dossier contient preuves_decodees.
    tmp = tempfile.mkdtemp(prefix="ti-preuve-")
    log = os.path.join(tmp, "access.log")
    with open(log, "w", encoding="utf-8") as f:
        for i in range(6):  # au-dessus du seuil --min-hits par défaut (traité via API)
            f.write('45.9.20.7 - - [10/Oct/2026:11:00:0%d +0000] '
                    '"GET /p?id=1%%20UNION%%20SELECT%%201 HTTP/1.1" 200 1 "-" "curl/8"\n' % i)
    res = ti.analyze_log(log, "web", max_samples=3)
    samples = {lab: res["samples"].get("45.9.20.7", {}).get(lab, [])
               for lab in res["signatures"].get("45.9.20.7", [])}
    dec4 = ti.decoder_echantillons(samples)
    ok &= check(len(dec4) >= 1 and any("union select" in e["revele"].lower() for e in dec4),
                "chaîne analyze_log -> décodage du payload de l'IP suspecte")

    # 5) Verrou « en ligne sous mandat » : mandat_actif (aucun réseau).
    def mandat(nom, signe, du, au):
        p = os.path.join(tmp, nom)
        with open(p, "w", encoding="utf-8") as f:
            f.write(f'''mandat:
  reference: "T-TI"
  signe: {str(signe).lower()}
  valide_du: "{du}"
  valide_au: "{au}"
  fuseau: "UTC"
  fenetres: []
  ip_source: []
  perimetre: {{domaines: ["x.cm"], ips: [], heberge_dedie: false}}
  exclusions: {{domaines: [], ips: []}}
  annexe_d_signee: false
  tests_autorises: {{}}
''')
        return p

    ok &= check(ti.mandat_actif(mandat("ok.yaml", True, "2020-01-01", "2099-12-31"))[0] is True,
                "en ligne : mandat signé et valide => autorisé")
    ok &= check(ti.mandat_actif(mandat("ns.yaml", False, "2020-01-01", "2099-12-31"))[0] is False,
                "en ligne : mandat non signé => refusé (reste local)")
    ok &= check(ti.mandat_actif(mandat("exp.yaml", True, "2020-01-01", "2020-12-31"))[0] is False,
                "en ligne : mandat expiré => refusé (reste local)")

    print("\nRÉSULTAT :", "TOUS LES TESTS PASSENT" if ok else "DES TESTS ÉCHOUENT")
    return 0 if ok else 1


def test_threat_intel_preuve():
    assert run() == 0


if __name__ == "__main__":
    raise SystemExit(run())
