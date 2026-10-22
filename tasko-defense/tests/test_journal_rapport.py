#!/usr/bin/env python3
"""Tests du journal des tests et du générateur de rapport. Aucun réseau.

Lancer : python3 tests/test_journal_rapport.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tasko import journal as J      # noqa: E402
from tasko import rapport as R      # noqa: E402


def check(cond, nom):
    print(f"  {'OK ' if cond else 'ÉCHEC'} {nom}")
    return cond


def run() -> int:
    ok = True
    tmp = tempfile.mkdtemp(prefix="tasko-test-")

    # ---------------- journal ----------------
    jpath = os.path.join(tmp, "journal-tests.jsonl")
    J.enregistrer(jpath, J.Evenement(reference="T-1", cible="https://x.cm/",
                  type_test="scan_web", outil="tasko-gate", decision="autorisé"))
    J.enregistrer(jpath, J.Evenement(reference="T-1", cible="https://x.cm/",
                  type_test="scan_web", outil="nuclei", decision="terminé",
                  empreinte="abcdef0123456789"))
    entrees = J.lire(jpath)
    ok &= check(len(entrees) == 2, "journal : 2 entrées relues")
    ok &= check(all("horodatage_utc" in e for e in entrees), "journal : horodatage UTC présent")
    annexe = J.rendre_annexe_c(jpath)
    ok &= check("Annexe C" in annexe and "nuclei" in annexe and "abcdef012345" in annexe,
                "journal : Annexe C rendue avec empreinte tronquée")

    # empreinte_fichier
    f = os.path.join(tmp, "preuve.txt")
    with open(f, "w") as fh:
        fh.write("contenu")
    emp = J.empreinte_fichier(f)
    ok &= check(len(emp) == 64, "journal : empreinte SHA-256 (64 hex)")
    ok &= check(J.empreinte_fichier(os.path.join(tmp, "absent")) == "",
                "journal : fichier absent -> empreinte vide")

    # ---------------- rapport ----------------
    rep = os.path.join(tmp, "rapports")
    os.makedirs(rep)
    # nuclei JSONL
    with open(os.path.join(rep, "nuclei.jsonl"), "w") as fh:
        fh.write(json.dumps({"template-id": "tls-version", "host": "https://x.cm",
                 "info": {"name": "TLS 1.0", "severity": "medium",
                          "description": "Vieux TLS"}}) + "\n")
        fh.write(json.dumps({"template-id": "rce", "host": "https://x.cm",
                 "info": {"name": "RCE", "severity": "critical"}}) + "\n")
        fh.write("ligne cassée {non json\n")  # doit être ignorée
    # wpscan JSON
    with open(os.path.join(rep, "wpscan_1_x.json"), "w") as fh:
        json.dump({"target_url": "https://x.cm/",
                   "version": {"vulnerabilities": [
                       {"title": "WP XSS", "fixed_in": "6.5",
                        "references": {"cve": ["2024-1234"]}}]},
                   "plugins": {"contact": {"vulnerabilities": [
                       {"title": "SQLi plugin", "references": {"url": ["http://ex/1"]}}]}}}, fh)
    # ZAP JSON
    with open(os.path.join(rep, "rapport-zap.json"), "w") as fh:
        json.dump({"site": [{"@name": "https://x.cm", "alerts": [
            {"alert": "SQL Injection", "riskcode": "3", "cweid": "89",
             "desc": "<p>desc</p>", "solution": "<p>paramétrer</p>"},
            {"alert": "Info leak", "riskcode": "1", "cweid": "200"}]}]}, fh)
    # Nmap -oN
    with open(os.path.join(rep, "vuln.txt"), "w") as fh:
        fh.write("Nmap scan report for x.cm\n443/tcp open https\n"
                 "| ssl-heartbleed:\n|   VULNERABLE:\n|   CVE-2014-0160\n")

    findings = R.collecter_dossier(rep)
    par_outil = {}
    for f2 in findings:
        par_outil.setdefault(f2.outil, 0)
        par_outil[f2.outil] += 1
    ok &= check(par_outil.get("nuclei") == 2, "rapport : 2 findings nuclei (ligne cassée ignorée)")
    ok &= check(par_outil.get("wpscan") == 2, "rapport : 2 findings wpscan (version + plugin)")
    ok &= check(par_outil.get("zap") == 2, "rapport : 2 findings zap")
    ok &= check(par_outil.get("nmap") == 1, "rapport : 1 finding nmap (heartbleed)")

    tri = R.trier(findings)
    ok &= check(tri[0].severite == "critique", "rapport : le plus grave (critique) en tête")

    md = R.rendre_markdown(findings, reference_mandat="T-1", date="2026-10-15")
    ok &= check("## Synthèse" in md and "## Findings" in md and "T-1" in md,
                "rapport : Markdown avec synthèse + findings + référence")
    ok &= check("CVE-2024-1234" in md and "CWE-89" in md and "CVE-2014-0160" in md,
                "rapport : références CVE/CWE présentes")
    # dédup : relancer sur la même liste ne double pas
    ok &= check(len(R.dedupliquer(findings + findings)) == len(findings),
                "rapport : déduplication stable")
    # dossier vide
    vide = os.path.join(tmp, "vide")
    os.makedirs(vide)
    ok &= check("Aucune vulnérabilité" in R.rendre_markdown(R.collecter_dossier(vide)),
                "rapport : dossier vide -> message explicite")

    # export structuré (JSON) pour le tableau de bord
    st = R.vers_structure(findings, reference_mandat="T-1", date="2026-10-22")
    ok &= check(st["total"] == len(findings) and st["comptes"].get("critique") == 1
                and st["severites"][0] == "critique" and "findings" in st,
                "rapport : vers_structure (comptes + total + findings)")
    ok &= check(all({"cible", "severite", "titre"} <= set(f) for f in st["findings"]),
                "rapport : chaque finding JSON a cible/severite/titre")

    print("\nRÉSULTAT :", "TOUS LES TESTS PASSENT" if ok else "DES TESTS ÉCHOUENT")
    return 0 if ok else 1


def test_journal_rapport():
    assert run() == 0


if __name__ == "__main__":
    raise SystemExit(run())
