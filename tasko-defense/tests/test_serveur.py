#!/usr/bin/env python3
"""Tests du serveur web LOCAL : garde-fous de sécurité + exécution cadrée.

Aucune cible réelle : les scanners sont remplacés par des stubs sur 127.0.0.1.
Lancer : python3 tests/test_serveur.py
"""
from __future__ import annotations

import json
import os
import sys
import threading
import urllib.request
from http.server import ThreadingHTTPServer

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RACINE)

from tasko import serveur as S  # noqa: E402


def check(cond, nom):
    print(f"  {'OK ' if cond else 'ÉCHEC'} {nom}")
    return bool(cond)


def http(méthode, url, token=None, body=None, host=None):
    req = urllib.request.Request(url, method=méthode)
    if token:
        req.add_header("X-Tasko-Token", token)
    if host:
        req.add_header("Host", host)
    if body is not None:
        req.add_header("Content-Type", "application/json")
        req.data = json.dumps(body).encode()
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}


def run() -> int:
    ok = True

    # --- garde-fous unitaires (chemins) ---
    ok &= check(S._mandat_path("exemple.mandat.yaml") is not None, "mandat valide accepté")
    ok &= check(S._mandat_path("../../etc/passwd") is None, "traversée de chemin refusée")
    ok &= check(S._mandat_path("/etc/passwd") is None, "chemin absolu refusé")
    ok &= check(S._mandat_path("exemple.txt") is None, "extension non-yaml refusée")
    ok &= check(S._confiner("outils/scan", RACINE) is not None, "confinement : sous le projet OK")
    ok &= check(S._confiner("../..", RACINE) is None, "confinement : échappement refusé")

    # --- action verifier (sans HTTP) : tchadone non signé => refusé ---
    r = S.action_verifier({"mandat": "tchadone.mandat.yaml",
                           "cible": "https://tchadone.com/", "type": "scan_web"})
    ok &= check(r.get("autorise") is False, "verifier : mandat non signé => refusé")
    r = S.action_verifier({"mandat": "inexistant.yaml", "cible": "x", "type": "scan_web"})
    ok &= check("erreur" in r, "verifier : mandat inexistant => erreur")

    # --- serveur HTTP sur un port éphémère, 127.0.0.1 ---
    srv = ThreadingHTTPServer(("127.0.0.1", 0), S.Handler)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    base = f"http://127.0.0.1:{port}"
    try:
        # jeton exigé
        code, _ = http("GET", base + "/api/mandats")
        ok &= check(code == 403, "API sans jeton => 403")
        code, _ = http("GET", base + "/api/mandats?t=mauvais")
        ok &= check(code == 403, "API mauvais jeton => 403")
        # jeton correct
        code, d = http("GET", base + f"/api/mandats?t={S.TOKEN}")
        noms = [m.get("fichier") for m in d.get("mandats", [])]
        ok &= check(code == 200 and "exemple.mandat.yaml" in noms, "API mandats listés")
        # hôte non local refusé
        code, _ = http("GET", base + f"/api/mandats?t={S.TOKEN}", host="evil.example")
        ok &= check(code == 403, "hôte non local => 403")
        # action inconnue
        code, _ = http("POST", base + f"/api/inconnue?t={S.TOKEN}", token=S.TOKEN, body={})
        ok &= check(code == 404, "action inconnue => 404")
        # verifier via HTTP
        code, d = http("POST", base + f"/api/verifier?t={S.TOKEN}", token=S.TOKEN,
                       body={"mandat": "tchadone.mandat.yaml",
                             "cible": "https://tchadone.com/", "type": "scan_web"})
        ok &= check(code == 200 and d.get("autorise") is False, "HTTP verifier : refusé (non signé)")

        # --- audit réel via stubs (mandat signé local + inventaire sous le projet) ---
        stubs = os.path.join(RACINE, "_stubs_test")
        os.makedirs(stubs, exist_ok=True)
        for t in ("nmap",):
            p = os.path.join(stubs, t)
            with open(p, "w") as f:
                f.write("#!/usr/bin/env bash\nexit 0\n")
            os.chmod(p, 0o755)
        os.environ["PATH"] = stubs + os.pathsep + os.environ["PATH"]

        mloc = os.path.join(S.MANDATS_DIR, "_demo-serveur.mandat.yaml")
        with open(mloc, "w") as f:
            f.write('mandat:\n  reference: "DEMO-SRV"\n  signe: true\n'
                    '  valide_du: "2020-01-01"\n  valide_au: "2099-12-31"\n  fuseau: "UTC"\n'
                    '  fenetres: []\n  ip_source: []\n'
                    '  perimetre: {domaines: [], ips: ["127.0.0.0/8"], heberge_dedie: true}\n'
                    '  exclusions: {domaines: [], ips: []}\n  annexe_d_signee: false\n'
                    '  tests_autorises: {scan_reseau: true}\n')
        inv = os.path.join(RACINE, "outils", "scan", "_demo-parc.txt")
        with open(inv, "w") as f:
            f.write("127.0.0.1\n8.8.8.8\n")
        audits_dir = os.path.join(RACINE, "outils", "scan", "audits-parc")
        try:
            code, d = http("POST", base + f"/api/audit?t={S.TOKEN}", token=S.TOKEN,
                           body={"mandat": "_demo-serveur.mandat.yaml",
                                 "inventaire": inv, "type": "reseau", "pause": "0"})
            sortie = d.get("sortie", "")
            ok &= check(code == 200 and d.get("code") == 0, "HTTP audit : exécuté (code 0)")
            ok &= check("127.0.0.1" in sortie and "8.8.8.8" in sortie, "audit : les 2 cibles traitées")
            ok &= check("IGNORÉ hors mandat] 8.8.8.8" in sortie, "audit : 8.8.8.8 ignoré (hors mandat)")
            # chemin hors projet refusé
            code, d = http("POST", base + f"/api/audit?t={S.TOKEN}", token=S.TOKEN,
                           body={"mandat": "_demo-serveur.mandat.yaml",
                                 "inventaire": "/etc/hosts", "type": "reseau"})
            ok &= check("erreur" in d, "audit : inventaire hors projet refusé")
        finally:
            for pth in (mloc, inv):
                try: os.remove(pth)
                except OSError: pass
            import shutil
            shutil.rmtree(stubs, ignore_errors=True)
            shutil.rmtree(audits_dir, ignore_errors=True)
    finally:
        srv.shutdown(); srv.server_close()

    print("\nRÉSULTAT :", "TOUS LES TESTS PASSENT" if ok else "DES TESTS ÉCHOUENT")
    return 0 if ok else 1


def test_serveur():
    assert run() == 0


if __name__ == "__main__":
    raise SystemExit(run())
