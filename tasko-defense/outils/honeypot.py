#!/usr/bin/env python3
"""
honeypot.py — Pot de miel DÉFENSIF (observation passive des attaquants).
========================================================================
Un honeypot est un faux service exposé volontairement. Les attaquants viennent
à TOI : tu observes leurs méthodes, captures leurs IP et leurs payloads, sans
jamais toucher à leur machine ni causer de dommage. 100 % légal et passif.

Ce honeypot léger simule :
  - un faux SSH (port 2222) qui logue les tentatives de connexion
  - un faux panneau d'admin HTTP (port 8080) qui logue les requêtes

Il ne donne JAMAIS d'accès réel : il enregistre, répond de façon crédible, et
n'exécute rien de ce que l'attaquant envoie.

⚠️ À déployer sur TON infra (ton VPS), idéalement isolée du reste. Ne jamais
exposer tes vrais services sur ces ports. Sur Hostinger VPS, ouvre les ports
2222 et 8080 dans ton pare-feu pour ce honeypot uniquement.

Usage :
  python3 honeypot.py
  (puis surveille honeypot.log — chaque ligne = une tentative)

Pour le lancer en continu : utilise systemd ou tmux.
"""
from __future__ import annotations

import json
import socket
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

LOGFILE = "honeypot.log"
SSH_PORT = 2222
HTTP_PORT = 8080


def log_event(service: str, ip: str, data: dict) -> None:
    """Enregistre un événement en JSON (une ligne) — ingérable par Wazuh."""
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "honeypot": service,
        "source_ip": ip,
        **data,
    }
    line = json.dumps(record, ensure_ascii=False)
    with open(LOGFILE, "a") as f:
        f.write(line + "\n")
    print(f"[{service}] {ip} -> {data}")


# ----------------------------------------------------------------------------
# Faux SSH : on présente une bannière SSH crédible et on logue ce qui arrive.
# On ne traite JAMAIS l'authentification : aucun accès n'est possible.
# ----------------------------------------------------------------------------
def fake_ssh() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", SSH_PORT))
    srv.listen(5)
    print(f"[SSH-honeypot] en écoute sur le port {SSH_PORT}")
    while True:
        try:
            conn, addr = srv.accept()
            ip = addr[0]
            # Bannière SSH crédible (l'attaquant croit toucher un vrai serveur)
            conn.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n")
            conn.settimeout(5)
            try:
                data = conn.recv(1024)
                log_event("ssh", ip, {
                    "client_banner": data.decode(errors="ignore").strip()[:200],
                    "note": "tentative de connexion SSH",
                })
            except socket.timeout:
                log_event("ssh", ip, {"note": "connexion SSH sans données"})
            conn.close()
        except Exception as e:  # pragma: no cover
            print(f"[SSH-honeypot] erreur: {e}")


# ----------------------------------------------------------------------------
# Faux panneau d'admin HTTP : logue chaque requête (chemin, méthode, payload).
# Répond toujours par une fausse page de login : aucun accès réel.
# ----------------------------------------------------------------------------
class HoneyHTTP(BaseHTTPRequestHandler):
    def _log(self, body: str = "") -> None:
        log_event("http", self.client_address[0], {
            "method": self.command,
            "path": self.path[:300],
            "user_agent": self.headers.get("User-Agent", "")[:200],
            "body": body[:500],
        })

    def _fake_login_page(self) -> None:
        # Page crédible mais inerte : aucune logique d'authentification réelle.
        html = (b"<html><head><title>Admin Login</title></head><body>"
                b"<h2>Administration</h2><form method='post'>"
                b"<input name='user' placeholder='Utilisateur'>"
                b"<input name='pass' type='password' placeholder='Mot de passe'>"
                b"<button>Connexion</button></form></body></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "Apache/2.4.52 (Ubuntu)")
        self.end_headers()
        self.wfile.write(html)

    def do_GET(self) -> None:
        self._log()
        self._fake_login_page()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode(errors="ignore") if length else ""
        self._log(body)            # capture les identifiants tentés / payloads
        self._fake_login_page()    # répond toujours "login" : jamais d'accès

    def log_message(self, *args) -> None:
        pass  # on désactive le log par défaut (on utilise le nôtre)


def fake_http() -> None:
    srv = HTTPServer(("0.0.0.0", HTTP_PORT), HoneyHTTP)
    print(f"[HTTP-honeypot] en écoute sur le port {HTTP_PORT}")
    srv.serve_forever()


def main() -> None:
    print("=== Honeypot défensif démarré ===")
    print(f"Journal : {LOGFILE} (format JSON, ingérable par Wazuh)")
    print("Observation passive uniquement — aucune action vers les attaquants.\n")
    threading.Thread(target=fake_ssh, daemon=True).start()
    fake_http()  # bloquant (thread principal)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nHoneypot arrêté.")
