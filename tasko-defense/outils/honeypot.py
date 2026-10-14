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
n'exécute rien de ce que l'attaquant envoie. Aucune action n'est émise vers
l'attaquant : observation strictement passive.

⚠️ À déployer sur TON infra (ton VPS), idéalement isolée du reste. Ne jamais
exposer tes vrais services sur ces ports. Sur Hostinger VPS, ouvre les ports
2222 et 8080 dans ton pare-feu pour ce honeypot uniquement.

Configuration (variables d'environnement, toutes optionnelles) :
  HONEYPOT_LOG        chemin du journal JSON (défaut : <dossier du script>/honeypot.log)
  HONEYPOT_BIND       interface IPv4 d'écoute        (défaut : 0.0.0.0)
  HONEYPOT_BIND6      interface IPv6 d'écoute        (défaut : ::)
  HONEYPOT_IPV6       0 pour désactiver l'IPv6       (défaut : 1)
  HONEYPOT_SSH_PORT   port du faux SSH               (défaut : 2222)
  HONEYPOT_HTTP_PORT  port du faux panneau HTTP      (défaut : 8080)

Usage :
  python3 honeypot.py
  (puis surveille le journal — chaque ligne = un objet JSON = une tentative)

Pour le lancer en continu : utilise systemd (voir le guide) ou tmux.
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import os
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
# Chemin du journal : absolu, basé sur le dossier du script (pas le CWD), pour
# qu'un service systemd avec un autre WorkingDirectory logue toujours au bon
# endroit. Surchargé par HONEYPOT_LOG si défini.
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOGFILE = os.environ.get("HONEYPOT_LOG") or os.path.join(_SCRIPT_DIR, "honeypot.log")

BIND4 = os.environ.get("HONEYPOT_BIND", "0.0.0.0")
BIND6 = os.environ.get("HONEYPOT_BIND6", "::")
ENABLE_IPV6 = os.environ.get("HONEYPOT_IPV6", "1").lower() not in ("0", "false", "no", "")

SSH_PORT = int(os.environ.get("HONEYPOT_SSH_PORT", "2222"))
HTTP_PORT = int(os.environ.get("HONEYPOT_HTTP_PORT", "8080"))

# Limites de sécurité : on ne fait jamais confiance à l'attaquant.
MAX_BODY = 64 * 1024          # corps HTTP lu au maximum (anti-épuisement mémoire)
HANDLER_TIMEOUT = 10          # timeout socket HTTP par connexion (secondes)
SSH_TIMEOUT = 10              # timeout socket SSH par connexion (secondes)
LOG_MAX_BYTES = 10 * 1024 * 1024   # rotation à 10 Mio
LOG_BACKUPS = 5                    # on garde 5 fichiers (honeypot.log.1 .. .5)

# Journal JSON (une ligne = un objet), rotatif : ne peut pas remplir le disque.
# Initialisé dans setup_logging() une fois le chemin validé.
_event_logger: logging.Logger | None = None


# ----------------------------------------------------------------------------
# Journalisation
# ----------------------------------------------------------------------------
def console(msg: str) -> None:
    """Ligne concise pour la console/journald, toujours vidée (indépendant de
    PYTHONUNBUFFERED). Ne contient JAMAIS le corps capturé (mots de passe)."""
    print(msg, flush=True)


def setup_logging() -> None:
    """Configure le logger rotatif qui écrit le JSON ligne-par-ligne sur disque.
    Format Wazuh-ingestible : chaque ligne est un objet JSON autonome."""
    global _event_logger
    logger = logging.getLogger("honeypot.events")
    logger.setLevel(logging.INFO)
    logger.propagate = False  # n'écrit que dans le fichier, pas vers la racine
    handler = logging.handlers.RotatingFileHandler(
        LOGFILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(message)s"))  # le message EST le JSON
    logger.addHandler(handler)
    _event_logger = logger


def log_event(service: str, ip: str, data: dict) -> None:
    """Enregistre un événement en JSON (une ligne) — ingérable par Wazuh.

    On émet `srcip` EN PLUS de `source_ip` pour que la GeoIP / l'active-response
    de Wazuh puisse l'exploiter directement. La console ne reçoit qu'un résumé
    SANS le corps, afin que les identifiants capturés ne fuient pas dans journald.
    """
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "honeypot": service,
        "source_ip": ip,
        "srcip": ip,  # alias attendu par Wazuh (GeoIP / active-response)
        **data,
    }
    try:
        line = json.dumps(record, ensure_ascii=False)
        if _event_logger is not None:
            _event_logger.info(line)
        else:  # garde-fou : journalisation non initialisée
            with open(LOGFILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
    except Exception as e:  # ne jamais laisser une erreur de log tuer un thread
        console(f"[LOG-ERREUR] impossible d'écrire l'événement : {e}")
    # Résumé console SANS le corps (pas de fuite d'identifiants dans journald).
    preview = {k: v for k, v in data.items() if k != "body"}
    console(f"[{service}] {ip} -> {preview}")


# ----------------------------------------------------------------------------
# Faux SSH : on présente une bannière SSH crédible et on logue ce qui arrive.
# On ne traite JAMAIS l'authentification : aucun accès n'est possible.
# Chaque connexion est traitée dans son propre thread : un client lent ne peut
# pas bloquer les autres.
# ----------------------------------------------------------------------------
def handle_ssh(conn: socket.socket, addr) -> None:
    ip = addr[0]
    try:
        conn.settimeout(SSH_TIMEOUT)
        # Bannière SSH crédible (l'attaquant croit toucher un vrai serveur).
        conn.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n")
        try:
            data = conn.recv(1024)
        except (socket.timeout, OSError):
            data = b""
        if data:
            log_event("ssh", ip, {
                "client_banner": data.decode(errors="ignore").strip()[:200],
                "note": "tentative de connexion SSH",
            })
        else:
            log_event("ssh", ip, {"note": "connexion SSH sans données"})
    except OSError as e:
        # Connexion coupée par l'attaquant, etc. — on logue sans détail sensible.
        log_event("ssh", ip, {"note": f"erreur socket: {e.__class__.__name__}"})
    finally:
        try:
            conn.close()
        except OSError:
            pass


def ssh_accept_loop(srv: socket.socket) -> None:
    """Boucle d'acceptation sur une socket DÉJÀ liée (passée par main())."""
    host, port = srv.getsockname()[:2]
    console(f"[SSH-honeypot] en écoute sur {host}:{port}")
    while True:
        try:
            conn, addr = srv.accept()
        except OSError as e:  # pragma: no cover
            console(f"[SSH-honeypot] erreur accept: {e}")
            continue
        threading.Thread(target=handle_ssh, args=(conn, addr), daemon=True).start()


# ----------------------------------------------------------------------------
# Faux panneau d'admin HTTP : logue chaque requête (méthode, chemin, payload).
# Répond toujours par une fausse page de login : aucun accès réel.
#   - ThreadingHTTPServer + timeout par connexion : un client lent/mort ne
#     bloque jamais les autres (threads démons).
#   - Content-Length validé et plafonné : pas de crash, pas d'épuisement mémoire.
#   - Toutes les méthodes (y compris HEAD/OPTIONS/PUT/DELETE/PROPFIND) et les
#     requêtes malformées sont loguées.
# ----------------------------------------------------------------------------
class HoneyHTTP(BaseHTTPRequestHandler):
    # Timeout socket par connexion : un demi-ouvert ne bloque personne (HP-02).
    timeout = HANDLER_TIMEOUT
    # HTTP/1.0 : chaque requête = une connexion fermée ensuite (pas de keep-alive
    # qui garderait un socket ouvert).
    protocol_version = "HTTP/1.0"

    # Une SEULE bannière Server, crédible. En surchargeant version_string(),
    # send_response() émet cet unique en-tête Server (pas de doublon).
    def version_string(self) -> str:
        return "Apache/2.4.52 (Ubuntu)"

    # -- journalisation --------------------------------------------------------
    def _headers_get(self, name: str, default: str = "") -> str:
        hdrs = getattr(self, "headers", None)
        if hdrs is None:
            return default
        return hdrs.get(name, default)

    def _log(self, body: str = "", declared_len: int = 0, read_len: int = 0) -> None:
        log_event("http", self.client_address[0], {
            "method": self.command or "",
            "path": (self.path or "")[:300],
            "user_agent": (self._headers_get("User-Agent") or "")[:200],
            "content_length_declared": declared_len,
            "content_length_read": read_len,
            "body": body[:4096],  # payload/identifiants (fichier uniquement)
        })

    # -- lecture sûre du corps -------------------------------------------------
    def _read_body(self) -> tuple[int, bytes]:
        """Content-Length validé (jamais un int() brut qui plante), lecture
        plafonnée à MAX_BODY. Retourne (longueur déclarée, octets lus)."""
        raw_cl = self._headers_get("Content-Length", "")
        declared = 0
        if raw_cl:
            try:
                declared = int(raw_cl.strip())
            except (ValueError, TypeError):
                declared = 0  # valeur non numérique -> traitée comme 0
            if declared < 0:
                declared = 0
        to_read = min(declared, MAX_BODY)  # plafonne (anti-épuisement mémoire)
        body = b""
        if to_read > 0:
            try:
                body = self.rfile.read(to_read)
            except (socket.timeout, OSError):
                body = b""  # client lent/coupé : on logue quand même la tentative
        return declared, body

    # -- réponse crédible et inerte -------------------------------------------
    def _fake_login_page(self, head_only: bool = False) -> None:
        # Page crédible mais inerte : aucune logique d'authentification réelle.
        html = (b"<html><head><title>Admin Login</title></head><body>"
                b"<h2>Administration</h2><form method='post'>"
                b"<input name='user' placeholder='Utilisateur'>"
                b"<input name='pass' type='password' placeholder='Mot de passe'>"
                b"<button>Connexion</button></form></body></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        if not head_only:  # HEAD : en-têtes seulement, jamais de corps
            self.wfile.write(html)

    def _handle(self, read_body: bool = False, head_only: bool = False) -> None:
        declared = read = 0
        body = ""
        if read_body:
            declared, raw = self._read_body()
            read = len(raw)
            body = raw.decode("utf-8", errors="replace")
        self._log(body=body, declared_len=declared, read_len=read)  # logue TOUJOURS
        self._fake_login_page(head_only=head_only)                  # jamais d'accès

    # -- toutes les méthodes courantes sont loguées puis répondues (HP-05) -----
    def do_GET(self) -> None:
        self._handle()

    def do_HEAD(self) -> None:
        self._handle(head_only=True)

    def do_POST(self) -> None:
        self._handle(read_body=True)

    def do_PUT(self) -> None:
        self._handle(read_body=True)

    def do_PATCH(self) -> None:
        self._handle(read_body=True)

    def do_DELETE(self) -> None:
        self._handle(read_body=True)

    def do_OPTIONS(self) -> None:
        self._handle()

    def do_PROPFIND(self) -> None:
        self._handle(read_body=True)

    def do_TRACE(self) -> None:
        self._handle()

    # -- méthodes inconnues + requêtes malformées : loguées aussi (HP-05) ------
    def send_error(self, code, message=None, explain=None) -> None:
        # send_error() est appelé par la stdlib pour les méthodes non gérées
        # (501), les requêtes malformées (400) ou trop longues (414). On logue
        # la tentative AVANT de répondre, pour ne rien manquer.
        try:
            try:
                http_code = int(code)
            except (TypeError, ValueError):
                http_code = 0
            log_event("http", self.client_address[0], {
                "method": getattr(self, "command", "") or "",
                "path": (getattr(self, "path", "") or "")[:300],
                "user_agent": (self._headers_get("User-Agent") or "")[:200],
                "note": "requête rejetée/malformée",
                "http_code": http_code,
                "requestline": (getattr(self, "requestline", "") or "")[:200],
            })
        except Exception:  # ne jamais empêcher la réponse d'erreur
            pass
        super().send_error(code, message, explain)

    def log_message(self, format, *args) -> None:
        pass  # on désactive le log par défaut (stderr) : on utilise le nôtre

    def log_error(self, format, *args) -> None:
        pass  # idem : pas de bruit stderr (les timeouts sont gérés proprement)


class HoneyHTTPServer(ThreadingHTTPServer):
    daemon_threads = True        # un handler lent ne bloque pas l'arrêt
    allow_reuse_address = True   # SO_REUSEADDR (redémarrage rapide)

    def handle_error(self, request, client_address) -> None:
        # Connexion interrompue par l'attaquant (reset, etc.) : on évite la
        # trace complète sur stderr, on garde une ligne concise.
        ip = client_address[0] if client_address else "?"
        console(f"[HTTP-honeypot] connexion interrompue depuis {ip}")


class HoneyHTTPServer6(HoneyHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self) -> None:
        # IPV6_V6ONLY=1 : la socket IPv6 ne gère QUE l'IPv6, donc pas de conflit
        # avec la socket IPv4 liée séparément sur le même port.
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        except (AttributeError, OSError):
            pass
        super().server_bind()


# ----------------------------------------------------------------------------
# Liaison des sockets
# ----------------------------------------------------------------------------
def bind_tcp(family: int, host: str, port: int) -> socket.socket:
    """Crée et lie une socket TCP en écoute (utilisée pour le faux SSH)."""
    s = socket.socket(family, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        try:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        except (AttributeError, OSError):
            pass
    s.bind((host, port))
    s.listen(50)
    return s


def main() -> None:
    setup_logging()
    console("=== Honeypot défensif démarré ===")
    console(f"Journal : {LOGFILE} (JSON/ligne, rotatif {LOG_MAX_BYTES // (1024*1024)} Mio x {LOG_BACKUPS}, ingérable par Wazuh)")
    console("Observation passive uniquement — aucune action vers les attaquants.")

    ssh_sockets: list[socket.socket] = []
    http_servers: list[HoneyHTTPServer] = []

    # --- IMPORTANT : on lie TOUT avant de démarrer le moindre thread. Si une
    # liaison IPv4 (obligatoire) échoue, on sort en code non nul pour que
    # systemd (Restart=) / l'alerting le voient. (HP-06) ---

    # IPv4 SSH (obligatoire)
    try:
        ssh_sockets.append(bind_tcp(socket.AF_INET, BIND4, SSH_PORT))
    except OSError as e:
        console(f"[FATAL] liaison SSH impossible sur {BIND4}:{SSH_PORT} : {e}")
        sys.exit(1)

    # IPv4 HTTP (obligatoire)
    try:
        http_servers.append(HoneyHTTPServer((BIND4, HTTP_PORT), HoneyHTTP))
    except OSError as e:
        console(f"[FATAL] liaison HTTP impossible sur {BIND4}:{HTTP_PORT} : {e}")
        for s in ssh_sockets:
            s.close()
        sys.exit(1)

    # IPv6 (optionnel : on ne tombe jamais si l'IPv6 est indisponible) — HP-13
    if ENABLE_IPV6 and socket.has_ipv6:
        try:
            ssh_sockets.append(bind_tcp(socket.AF_INET6, BIND6, SSH_PORT))
        except OSError as e:
            console(f"[WARN] IPv6 SSH indisponible ({BIND6}:{SSH_PORT}) : {e}")
        try:
            http_servers.append(HoneyHTTPServer6((BIND6, HTTP_PORT), HoneyHTTP))
        except OSError as e:
            console(f"[WARN] IPv6 HTTP indisponible ({BIND6}:{HTTP_PORT}) : {e}")

    # --- toutes les sockets sont liées : on démarre les threads maintenant ---
    for s in ssh_sockets:
        threading.Thread(target=ssh_accept_loop, args=(s,), daemon=True).start()
    for srv in http_servers:
        host, port = srv.server_address[:2]
        console(f"[HTTP-honeypot] en écoute sur {host}:{port}")
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    # Thread principal bloquant : on attend juste (tout le travail est en threads).
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        console("\nHoneypot arrêté.")
        for srv in http_servers:
            try:
                srv.shutdown()
            except Exception:
                pass


if __name__ == "__main__":
    main()
