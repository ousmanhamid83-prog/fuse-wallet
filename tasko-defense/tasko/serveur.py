#!/usr/bin/env python3
"""Serveur web LOCAL de Tasko Defense — agilité, sans surface d'attaque.

Donne au tableau de bord la possibilité de LANCER les audits (au lieu de copier
la commande), tout en gardant les garde-fous :

  - écoute UNIQUEMENT sur la boucle locale (127.0.0.1) — jamais exposé au réseau ;
  - un JETON aléatoire, généré au démarrage, est exigé pour toute action ;
  - seules des ACTIONS FIGÉES sont possibles (liste blanche) : lister les mandats,
    prévisualiser le verrou, lancer `audit-parc.sh`, charger un rapport. Aucune
    commande arbitraire, aucune exploitation ;
  - chaque scan reste cadré par le mandat (le script vérifie chaque cible) ;
  - les chemins sont confinés au dossier du projet (pas de traversée de chemin),
    les outils sont invoqués par liste d'arguments (jamais via un shell).

Lancement :  python3 -m tasko.serveur            (ou : tasko serveur)
Puis ouvre l'URL affichée (elle contient le jeton). Ctrl-C pour arrêter.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import socket
import subprocess
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    from .mandat import Mandat, MandatError, autoriser, TYPES_TEST
except ImportError:  # exécution directe
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tasko.mandat import Mandat, MandatError, autoriser, TYPES_TEST

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # .../tasko-defense
MANDATS_DIR = os.path.join(BASE, "mandats")
UI = os.path.join(BASE, "ui", "tableau-de-bord.html")
TOKEN = secrets.token_urlsafe(18)
TIMEOUT_SCAN = 1800          # 30 min max pour un audit de parc
_CIBLE_OK = re.compile(r"^[A-Za-z0-9._:\-/?=&%]+$")   # pas d'espace, pas d'option


# --------------------------------------------------------------------- utils
def _confiner(chemin: str, base: str) -> str | None:
    """Résout `chemin` et garantit qu'il reste SOUS `base`. None sinon."""
    reel = os.path.realpath(os.path.join(base, chemin))
    base_reel = os.path.realpath(base)
    if reel == base_reel or reel.startswith(base_reel + os.sep):
        return reel
    return None


def _mandat_path(nom: str) -> str | None:
    """Un mandat doit être un simple nom de fichier présent dans mandats/."""
    if not nom or "/" in nom or "\\" in nom or not nom.endswith((".yaml", ".yml")):
        return None
    p = _confiner(nom, MANDATS_DIR)
    return p if p and os.path.isfile(p) else None


# ------------------------------------------------------------------- actions
def action_mandats() -> dict:
    """Liste les mandats disponibles (fichier, référence, signé, périmètre)."""
    out = []
    for nom in sorted(os.listdir(MANDATS_DIR)) if os.path.isdir(MANDATS_DIR) else []:
        if not nom.endswith((".yaml", ".yml")):
            continue
        try:
            m = Mandat.charger(os.path.join(MANDATS_DIR, nom))
            out.append({
                "fichier": nom, "reference": m.reference, "signe": m.signe,
                "domaines": m.domaines, "ips": m.ips, "heberge_dedie": m.heberge_dedie,
                "tests": [t for t in TYPES_TEST if m.tests_autorises.get(t)],
            })
        except MandatError as e:
            out.append({"fichier": nom, "erreur": str(e)})
    return {"mandats": out}


def action_verifier(corps: dict) -> dict:
    """Prévisualise le verrou pour une cible (aucun scan émis)."""
    p = _mandat_path(corps.get("mandat", ""))
    if not p:
        return {"erreur": "mandat introuvable dans mandats/"}
    cible = str(corps.get("cible", "")).strip()
    type_test = str(corps.get("type", ""))
    if type_test not in TYPES_TEST:
        return {"erreur": f"type inconnu (attendu : {', '.join(TYPES_TEST)})"}
    if not _CIBLE_OK.match(cible or ""):
        return {"erreur": "cible invalide"}
    try:
        d = autoriser(Mandat.charger(p), cible, type_test,
                      ip_source=corps.get("ip_source") or None)
    except MandatError as e:
        return {"erreur": str(e)}
    return {"autorise": d.autorise, "raison": d.raison, "reference": d.reference}


def action_audit(corps: dict) -> dict:
    """Lance outils/scan/audit-parc.sh sur un inventaire, cadré par le mandat."""
    p = _mandat_path(corps.get("mandat", ""))
    if not p:
        return {"erreur": "mandat introuvable dans mandats/"}
    type_scan = str(corps.get("type", ""))
    if type_scan not in ("web", "reseau"):
        return {"erreur": "type doit être 'web' ou 'reseau'"}
    inv = _confiner(str(corps.get("inventaire", "")), BASE)
    if not inv or not os.path.isfile(inv):
        return {"erreur": "inventaire introuvable (doit être un fichier sous le projet)"}
    ip = str(corps.get("ip_source", "") or "")
    if ip and not _CIBLE_OK.match(ip):
        return {"erreur": "ip_source invalide"}

    env = dict(os.environ)
    env["MANDAT"] = p
    env["PAUSE"] = str(corps.get("pause", "2"))
    if ip:
        env["AUDIT_IP"] = ip
    if type_scan == "web" and corps.get("wpscan_token"):
        tok = str(corps["wpscan_token"])
        if _CIBLE_OK.match(tok):
            env["WPSCAN_API_TOKEN"] = tok
    try:
        proc = subprocess.run(
            ["bash", "audit-parc.sh", inv, type_scan],
            cwd=os.path.join(BASE, "outils", "scan"), env=env,
            capture_output=True, text=True, timeout=TIMEOUT_SCAN)
        return {"code": proc.returncode,
                "sortie": (proc.stdout or "") + (proc.stderr or "")}
    except subprocess.TimeoutExpired:
        return {"erreur": f"délai dépassé ({TIMEOUT_SCAN}s) — audit interrompu"}
    except OSError as e:
        return {"erreur": f"échec du lancement : {e}"}


def action_rapport(corps: dict) -> dict:
    """Agrège un dossier de scans en findings structurés (JSON) pour l'affichage."""
    dossier = _confiner(str(corps.get("dossier", "")), BASE)
    if not dossier or not os.path.isdir(dossier):
        return {"erreur": "dossier introuvable (doit être sous le projet)"}
    try:
        from . import rapport as _rapport
    except ImportError:
        import tasko.rapport as _rapport
    findings = _rapport.collecter_dossier(dossier)
    return _rapport.vers_structure(findings)


ACTIONS = {
    "mandats": lambda corps: action_mandats(),
    "verifier": action_verifier,
    "audit": action_audit,
    "rapport": action_rapport,
}


# ---------------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "TaskoLocal/1.0"

    def _json(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _hote_local(self) -> bool:
        hote = (self.headers.get("Host", "") or "").split(":")[0]
        return hote in ("127.0.0.1", "localhost", "::1", "")

    def _token_ok(self) -> bool:
        q = urllib.parse.urlparse(self.path).query
        t = urllib.parse.parse_qs(q).get("t", [""])[0]
        t = self.headers.get("X-Tasko-Token", t)
        return secrets.compare_digest(t, TOKEN)

    def do_GET(self):
        if not self._hote_local():
            return self._json({"erreur": "hôte non local refusé"}, 403)
        chemin = urllib.parse.urlparse(self.path).path
        if chemin in ("/", "/index.html", "/tableau-de-bord.html"):
            try:
                with open(UI, "rb") as f:
                    body = f.read()
            except OSError:
                return self._json({"erreur": "interface introuvable"}, 500)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
            return
        if chemin == "/api/mandats":
            if not self._token_ok():
                return self._json({"erreur": "jeton invalide"}, 403)
            return self._json(action_mandats())
        self._json({"erreur": "introuvable"}, 404)

    def do_POST(self):
        if not self._hote_local():
            return self._json({"erreur": "hôte non local refusé"}, 403)
        if not self._token_ok():
            return self._json({"erreur": "jeton invalide"}, 403)
        chemin = urllib.parse.urlparse(self.path).path
        action = chemin[len("/api/"):] if chemin.startswith("/api/") else ""
        fn = ACTIONS.get(action)
        if not fn:
            return self._json({"erreur": f"action inconnue : {action}"}, 404)
        try:
            n = int(self.headers.get("Content-Length", 0))
            corps = json.loads(self.rfile.read(n) or b"{}") if n else {}
            if not isinstance(corps, dict):
                raise ValueError("corps JSON invalide")
        except (ValueError, json.JSONDecodeError) as e:
            return self._json({"erreur": f"requête invalide : {e}"}, 400)
        self._json(fn(corps))

    def log_message(self, *a):
        pass  # silencieux


def servir(port: int = 8787) -> int:
    try:
        srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    except OSError as e:
        print(f"[ERREUR] impossible d'écouter sur 127.0.0.1:{port} ({e})", file=sys.stderr)
        return 1
    url = f"http://127.0.0.1:{port}/?t={TOKEN}"
    print("=== Tasko Defense — serveur LOCAL ===")
    print(f"Écoute sur 127.0.0.1:{port} (boucle locale uniquement).")
    print(f"Ouvre : {url}")
    print("Actions permises : lister les mandats, prévisualiser le verrou, lancer un")
    print("audit de parc (cadré par le mandat), charger un rapport. Aucune exploitation.")
    print("Ctrl-C pour arrêter.\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nArrêt.")
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Serveur web local de Tasko Defense")
    ap.add_argument("--port", type=int, default=8787)
    servir(ap.parse_args().port)
