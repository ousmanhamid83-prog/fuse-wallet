#!/usr/bin/env python3
"""
threat-intel.py — Renseignement sur les menaces DÉFENSIF.
=========================================================
Documente un attaquant SANS jamais toucher à sa machine : on analyse les traces
qu'il a laissées sur les systèmes DU CLIENT (logs), on extrait les indicateurs
de compromission (IOC), et on les enrichit via des bases PUBLIQUES de réputation.

Le résultat est un dossier exploitable par les autorités pour l'attribution.

⚠️ Légal et défensif :
  - On lit UNIQUEMENT les logs des systèmes que tu es autorisé à auditer (mandat).
  - On interroge la base PUBLIQUE AbuseIPDB — on ne sonde JAMAIS l'attaquant.
  - Aucune connexion n'est JAMAIS établie vers les IP analysées (voir plus bas).

⚠️ IP cliente vraie (anti-usurpation) :
  L'IP d'un attaquant est extraite UNIQUEMENT du champ fiable de chaque ligne
  ($remote_addr pour nginx/apache, `from`/`rhost=` pour sshd, `source_ip` pour le
  honeypot). On ne « ramasse » plus une IP apparaissant dans l'URL, le Referer ou
  le User-Agent : un attaquant pouvait y glisser l'IP d'un tiers pour l'incriminer.
  Derrière un CDN / reverse-proxy (Cloudflare, etc.), $remote_addr est l'IP du
  proxy : configure nginx `real_ip` pour obtenir la vraie IP cliente, p.ex.
      set_real_ip_from 173.245.48.0/20;         # plages du CDN
      real_ip_header   CF-Connecting-IP;        # ou X-Forwarded-For
  sans cela, le premier champ reste l'IP du proxy, pas celle de l'attaquant.

Local vs en ligne :
  - Le DÉCODAGE des payloads (preuve) est TOUJOURS local : aucun réseau.
  - L'enrichissement RÉPUTATION (AbuseIPDB, base PUBLIQUE ; jamais la machine de
    l'attaquant) n'est activé que si `--mandat <mandat signé et valide>` est fourni
    ET qu'une clé est présente. Sans mandat : analyse 100 % locale. C'est
    l'exécution « semi-automatique » : une commande décode en local et, sous
    mandat, enrichit en ligne.

Prérequis :
  - `requests` est FACULTATIF : il n'est importé que si ABUSEIPDB_KEY est défini
    ET qu'un mandat autorise l'enrichissement. Sinon, 100 % hors-ligne.
  - Ubuntu 24.04 (pip bloqué par PEP 668) :  sudo apt install python3-requests
  - Clé AbuseIPDB gratuite : https://www.abuseipdb.com (1000 requêtes/jour)
      export ABUSEIPDB_KEY="ta_cle"

Usage :
  python3 threat-intel.py /var/log/nginx/access.log                 # local seul
  python3 threat-intel.py /var/log/auth.log --type auth
  # Enrichissement en ligne (sous mandat) + journalisation Annexe C :
  python3 threat-intel.py honeypot.log --type honeypot --exclude admins.txt \
          --mandat ../mandats/client.mandat.yaml --journal journal-tests.jsonl
"""
from __future__ import annotations

import argparse
import collections
import gzip
import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
import urllib.parse
import uuid
from datetime import datetime, timezone

# Branche l'analyseur de preuves (décodage/désobfuscation DÉFENSIF, hors ligne).
# Optionnel : si le paquet tasko n'est pas sur le PATH, on continue sans décodage.
try:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tasko import preuve as _preuve
except Exception:  # noqa: BLE001 - l'absence du module ne doit jamais casser l'analyse
    _preuve = None

TOOL_VERSION = "2.1.0"

# Jetons longs (base64/base64url/hex) potentiellement encodés, embarqués dans une
# ligne. Le '=' n'est accepté qu'en padding final (sinon on happe le '=' de 'p=...').
_RE_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")

# Clé lue au démarrage : si vide => mode hors-ligne, `requests` n'est jamais importé.
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")

# CGNAT (RFC 6598) : plage partagée par l'opérateur, pas une IP publique attribuable.
_CGNAT4 = ipaddress.ip_network("100.64.0.0/10")

# Seuil (conservateur) de promotion de l'indicateur « brute-force par clé » :
# il faut BEAUCOUP de connexions avortées en phase d'auth pour le retenir.
SSH_KEYPROBE_MIN = 10

# ---------------------------------------------------------------------------
# Signatures WEB. On matche sur un espace combinant la ligne BRUTE et sa version
# URL-décodée (deux passes d'unquote_plus) : %20UNION%20SELECT, UNION/**/SELECT,
# UNION+SELECT et les doubles-encodages (%252f) sont ainsi tous détectés.
# Les bornes de mots (\b) évitent les faux positifs (p.ex. « eval » dans un mot).
# ---------------------------------------------------------------------------
SUSPICIOUS_WEB = [
    (re.compile(r"\.\.[\/\\]"), "path_traversal"),                       # ../ ou ..\ (après décodage)
    (re.compile(r"(?i)/etc/passwd\b"), "path_traversal"),
    (re.compile(r"(?i)\bunion\b[\s/*+]+\bselect\b"), "sql_injection"),   # UNION/**/SELECT, UNION+SELECT, %20
    (re.compile(r"(?i)\b(?:or|and)\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+"), "sql_injection"),  # ' or 1=1
    (re.compile(r"(?i)<script\b"), "xss_attempt"),
    (re.compile(r"(?i)\bon(?:error|load|mouseover|click|focus)\s*="), "xss_attempt"),
    (re.compile(r"(?i)/wp-login\.php"), "wp_login_bruteforce"),
    (re.compile(r"(?i)/xmlrpc\.php"), "xmlrpc_abuse"),
    (re.compile(r"(?i)\.(?:env|git|sql|bak|htpasswd|aws)\b"), "sensitive_file_probe"),
    (re.compile(r"(?i)\b(?:eval|base64_decode|shell_exec|system|passthru|popen|proc_open)\s*\("),
     "code_injection_probe"),
]

# Signatures AUTH (sshd). On NE flague PAS « Accepted publickey » (admin légitime).
SUSPICIOUS_AUTH = [
    (re.compile(r"\bFailed password\b"), "ssh_failed_login"),
    (re.compile(r"\bInvalid user\b"), "ssh_invalid_user"),
    (re.compile(r"\bauthentication failure\b"), "auth_failure"),
    (re.compile(r"(?i)\bnot allowed because\b"), "ssh_access_denied"),
    (re.compile(r"\bPOSSIBLE BREAK-IN ATTEMPT\b"), "reverse_dns_mismatch"),
]

# Signal faible « brute-force par clé » : connexions avortées en phase d'auth.
# On ne le promeut en signature que si l'IP dépasse SSH_KEYPROBE_MIN occurrences.
RE_KEYPROBE = re.compile(r"(?:Connection closed by|Disconnected from) authenticating user ")

# ---------------------------------------------------------------------------
# Extraction d'IP cliente (jamais prise dans l'URL / Referer / User-Agent).
# ---------------------------------------------------------------------------
# sshd : IP après `rhost=`, `from <ip> port`, ou `authenticating user <u> <ip> port`.
_RE_AUTH_IP = [
    re.compile(r"rhost=([0-9A-Fa-f:.]+)"),
    re.compile(r"\bfrom ([0-9A-Fa-f:.]+) port \d+"),
    re.compile(r"authenticating user \S+ ([0-9A-Fa-f:.]+) port \d+"),
    re.compile(r"(?:closed|reset) by ([0-9A-Fa-f:.]+) port \d+"),
]

# Horodatage nginx/apache : [10/Oct/2026:13:55:36 +0000]
_RE_TS_WEB = re.compile(r"\[([^\]]+)\]")
# Horodatage auth : ISO (journald) ou syslog traditionnel « Oct 10 13:55:36 ».
_RE_TS_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)")
_RE_TS_SYSLOG = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")


def normalise_ip(raw: str) -> str | None:
    """Renvoie l'IP normalisée (str) si c'est une IP valide, sinon None."""
    if not raw:
        return None
    raw = raw.strip().strip("[]")
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return None


def is_public_ip(ip: str) -> bool:
    """IP publique routable uniquement (ni privée, ni CGNAT, ni multicast…).

    Exclut explicitement : privé, loopback, réservé, non-spécifié, lien-local,
    multicast (TI-15) et CGNAT 100.64.0.0/10 (TI-15) — ces plages ne désignent
    jamais un attaquant externe attribuable.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if (addr.is_private or addr.is_loopback or addr.is_reserved
            or addr.is_unspecified or addr.is_link_local or addr.is_multicast):
        return False
    if addr.version == 4 and addr in _CGNAT4:
        return False
    return True


def _decode_twice(text: str) -> str:
    """Double passe d'URL-décodage (gère %20, +, /**/ et les doubles encodages)."""
    return urllib.parse.unquote_plus(urllib.parse.unquote_plus(text))


# ---------------------------------------------------------------------------
# Extraction de l'IP cliente selon le type de log.
# ---------------------------------------------------------------------------
def extract_client_ip_web(line: str) -> str | None:
    """nginx/apache « combined » : le 1er champ est $remote_addr (l'IP cliente)."""
    stripped = line.strip()
    if not stripped:
        return None
    first = stripped.split(maxsplit=1)[0]
    return normalise_ip(first)


def extract_client_ip_auth(line: str) -> str | None:
    """sshd : IP après `rhost=` / `from … port` / `authenticating user … port`."""
    for rx in _RE_AUTH_IP:
        m = rx.search(line)
        if m:
            ip = normalise_ip(m.group(1))
            if ip:
                return ip
    return None


# ---------------------------------------------------------------------------
# Horodatage (first_seen / last_seen).
# ---------------------------------------------------------------------------
def timestamp_web(line: str) -> str | None:
    m = _RE_TS_WEB.search(line)
    if not m:
        return None
    tok = m.group(1)
    try:
        dt = datetime.strptime(tok, "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(timezone.utc).isoformat()
    except ValueError:
        return tok  # présent mais non normalisable : on garde le brut


def timestamp_auth(line: str) -> str | None:
    m = _RE_TS_ISO.match(line.strip())
    if m:
        return m.group(1)
    m = _RE_TS_SYSLOG.match(line.strip())
    if m:
        return m.group(1)  # syslog sans année : présent mais ambigu, gardé brut
    return None


# ---------------------------------------------------------------------------
# Détection des signatures sur une ligne.
# ---------------------------------------------------------------------------
def signatures_web(haystack_raw: str) -> list[str]:
    haystack = haystack_raw + "\n" + _decode_twice(haystack_raw)
    return [label for rx, label in SUSPICIOUS_WEB if rx.search(haystack)]


def signatures_auth(line: str) -> list[str]:
    return [label for rx, label in SUSPICIOUS_AUTH if rx.search(line)]


def _open_log(path: str):
    """Ouvre le log, en décompressant .gz de façon transparente (TI-13)."""
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="ignore")
    return open(path, "rt", errors="ignore")


def analyze_log(path: str, log_type: str, max_samples: int) -> dict:
    """Extrait l'IP cliente et l'activité suspecte, une ligne = un décompte."""
    hits: collections.Counter = collections.Counter()
    signatures: dict[str, set] = collections.defaultdict(set)
    samples: dict[str, dict[str, list]] = collections.defaultdict(
        lambda: collections.defaultdict(list))
    first_seen: dict[str, str] = {}
    last_seen: dict[str, str] = {}
    keyprobe: collections.Counter = collections.Counter()

    lines_total = 0
    lines_with_ip = 0
    lines_malformed = 0

    def add_sample(ip: str, label: str, line_no: int, line: str) -> None:
        bucket = samples[ip][label]
        if len(bucket) < max_samples:
            bucket.append({"line_no": line_no,
                           "raw_line_excerpt": line.rstrip("\n")[:280]})

    with _open_log(path) as f:
        for line_no, line in enumerate(f, start=1):
            lines_total += 1
            ip = None
            matched: list[str] = []
            ts = None

            if log_type == "honeypot":
                line_stripped = line.strip()
                if not line_stripped:
                    continue
                try:
                    rec = json.loads(line_stripped)
                except json.JSONDecodeError:
                    lines_malformed += 1
                    continue
                ip = normalise_ip(str(rec.get("source_ip", "")))
                ts = rec.get("ts")
                # Dans un honeypot, TOUTE interaction est un indicateur en soi.
                blob = " ".join(str(rec.get(k, "")) for k in
                                ("path", "body", "user_agent", "client_banner", "note"))
                matched = ["honeypot_interaction"] + signatures_web(blob)
            elif log_type == "auth":
                ip = extract_client_ip_auth(line)
                ts = timestamp_auth(line)
                matched = signatures_auth(line)
                if RE_KEYPROBE.search(line) and ip and is_public_ip(ip):
                    keyprobe[ip] += 1
                    add_sample(ip, "ssh_bruteforce_keyprobe", line_no, line)
            else:  # web
                ip = extract_client_ip_web(line)
                ts = timestamp_web(line)
                matched = signatures_web(line)

            if not ip or not is_public_ip(ip):
                continue

            lines_with_ip += 1
            hits[ip] += 1
            if ip not in first_seen:
                first_seen[ip] = ts or "inconnu"
            last_seen[ip] = ts or "inconnu"
            for label in matched:
                signatures[ip].add(label)
                add_sample(ip, label, line_no, line)

    # Promotion conservatrice du brute-force par clé (TI-14).
    for ip, n in keyprobe.items():
        if n >= SSH_KEYPROBE_MIN:
            signatures[ip].add("ssh_bruteforce_keyprobe")

    return {
        "lines_total": lines_total,
        "lines_with_ip": lines_with_ip,
        "lines_skipped": lines_total - lines_with_ip,
        "lines_malformed": lines_malformed,
        "hits": hits,
        "signatures": {k: sorted(v) for k, v in signatures.items()},
        "samples": samples,
        "first_seen": first_seen,
        "last_seen": last_seen,
    }


# ---------------------------------------------------------------------------
# Allowlist (--exclude) : IP / CIDR connus (admin, supervision).
# ---------------------------------------------------------------------------
def load_exclusions(path: str | None) -> list:
    nets = []
    if not path:
        return nets
    try:
        with open(path, "r", errors="ignore") as f:
            for raw in f:
                entry = raw.split("#", 1)[0].strip()
                if not entry:
                    continue
                try:
                    nets.append(ipaddress.ip_network(entry, strict=False))
                except ValueError:
                    print(f"[avertissement] entrée --exclude ignorée : {entry!r}",
                          file=sys.stderr)
    except OSError as e:
        print(f"[avertissement] --exclude illisible ({e}) — ignoré", file=sys.stderr)
    return nets


def is_excluded(ip: str, nets: list) -> bool:
    if not nets:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in nets)


# ---------------------------------------------------------------------------
# Enrichissement AbuseIPDB (PUBLIC). `requests` importé PARESSEUSEMENT (TI-11).
# ---------------------------------------------------------------------------
def enrich_abuseipdb(ip: str) -> tuple[dict, bool]:
    """Interroge la base PUBLIQUE AbuseIPDB. Ne contacte JAMAIS l'IP analysée.

    Renvoie (resultat, halt) ; halt=True sur 401/429 pour stopper les requêtes
    suivantes (clé invalide ou quota épuisé) — TI-07.
    """
    if not ABUSEIPDB_KEY:
        return ({"status": "non_enrichi",
                 "note": "ABUSEIPDB_KEY non définie — mode hors-ligne"}, False)
    try:
        import requests  # import PARESSEUX : seulement si une clé est présente
    except ImportError:
        return ({"status": "error",
                 "error": "module 'requests' absent "
                          "(apt install python3-requests ou venv)"}, False)
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            timeout=15,
        )
    except Exception as e:  # pragma: no cover - réseau
        return ({"status": "error", "error": f"requête échouée : {e}"}, False)

    if r.status_code != 200:
        detail = ""
        try:
            body = r.json()
            errs = body.get("errors") if isinstance(body, dict) else None
            if errs:
                detail = errs[0].get("detail", "")
        except Exception:
            detail = (r.text or "")[:200]
        halt = r.status_code in (401, 429)
        return ({"status": "error",
                 "error": f"HTTP {r.status_code}: {detail or 'réponse non-200'}"}, halt)

    try:
        d = r.json().get("data", {})
    except Exception as e:
        return ({"status": "error", "error": f"JSON invalide : {e}"}, False)
    return ({
        "status": "ok",
        "abuse_score": d.get("abuseConfidenceScore"),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "domain": d.get("domain"),
        "total_reports": d.get("totalReports"),
        "last_reported": d.get("lastReportedAt"),
    }, False)


def _risk_flag(rep: dict) -> tuple[str, str]:
    """(pictogramme, score affiché). '?' quand le score est INCONNU (pas faible)."""
    score = rep.get("abuse_score") if rep.get("status") == "ok" else None
    if score is None:
        return "❓", "?"
    if score >= 75:
        return "🔴", str(score)
    if score >= 25:
        return "🟠", str(score)
    return "🟢", str(score)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def decoder_echantillons(ip_samples: dict) -> list:
    """Décode (défensivement) les payloads obscurcis des extraits de preuve d'une IP.

    Pour chaque extrait : on tente de désobfusquer la ligne entière (gère
    l'URL-encodage) ET chaque jeton long (base64/hex embarqué). On ne retient que
    les décodages qui RÉVÈLENT quelque chose (au moins une couche, ou un
    comportement repéré). Purement local, aucune exécution, aucun réseau.
    """
    if _preuve is None:
        return []
    out, vus = [], set()
    for label, bucket in ip_samples.items():
        for s in bucket:
            raw = s.get("raw_line_excerpt", "")
            if not raw:
                continue
            for cand in [raw] + _RE_TOKEN.findall(raw):
                deob = _preuve.deobfusquer(cand)
                final = deob["final"]
                comp = _preuve.comportement_apparent(cand + "\n" + final)
                if deob["profondeur"] < 1 and not comp:
                    continue
                cle = final[:280]
                if cle in vus:
                    continue
                vus.add(cle)
                entree = {
                    "signature": label,
                    "line_no": s.get("line_no"),
                    "couches": [c["methode"] for c in deob["couches"]],
                    "revele": final[:280],
                    "comportement_apparent": comp,
                }
                iocs = _preuve.extraire_iocs(final)
                if any(iocs.values()):
                    entree["iocs_revele"] = iocs
                out.append(entree)
    return out


def mandat_actif(path: str) -> tuple[bool, str, str]:
    """Le mandat autorise-t-il l'enrichissement EN LIGNE (réputation publique) ?

    Exige un mandat SIGNÉ et dans sa période de validité. N'autorise JAMAIS de
    contact avec l'attaquant : seule la base de réputation publique est interrogée.
    Renvoie (ok, raison, reference).
    """
    try:
        from tasko.mandat import Mandat
    except Exception as e:  # noqa: BLE001 - absence du moteur => pas d'enrichissement
        return False, f"moteur de mandat indisponible ({e})", ""
    try:
        m = Mandat.charger(path)
    except Exception as e:  # noqa: BLE001
        return False, f"mandat illisible ({e})", ""
    if not m.signe:
        return False, "mandat non signé", m.reference
    jour = datetime.now(timezone.utc).date()
    if jour < m.valide_du or jour > m.valide_au:
        return False, f"mandat hors période de validité ({m.valide_du}..{m.valide_au})", m.reference
    return True, f"mandat {m.reference} actif", m.reference


def main() -> int:
    ap = argparse.ArgumentParser(description="Threat intelligence défensif")
    ap.add_argument("logfile", help="Chemin du fichier de log à analyser (.gz accepté)")
    ap.add_argument("--type", choices=["web", "auth", "honeypot"], default="web",
                    help="Type de log (web=Nginx/Apache, auth=SSH, honeypot=JSON)")
    ap.add_argument("--top", type=int, default=20, help="Nombre max d'IP à retenir")
    ap.add_argument("--min-hits", type=int, default=1,
                    help="Seuil d'occurrences, appliqué APRÈS le filtre par signature")
    ap.add_argument("--samples", type=int, default=3,
                    help="Nombre max d'extraits de preuve par signature et par IP")
    ap.add_argument("--exclude", metavar="FICHIER",
                    help="Allowlist d'IP/CIDR de confiance (admin, supervision)")
    ap.add_argument("--mandat-ref", metavar="REF",
                    help="Référence du mandat ayant autorisé l'analyse")
    ap.add_argument("--mandat", metavar="FICHIER",
                    help="Mandat signé : REQUIS pour l'enrichissement EN LIGNE "
                         "(réputation publique). Sans lui, analyse 100%% locale.")
    ap.add_argument("--journal", metavar="FICHIER",
                    help="Journal des tests (JSONL) où consigner l'analyse (Annexe C)")
    ap.add_argument("--out", metavar="FICHIER",
                    help="Chemin du dossier de sortie (refuse d'écraser un fichier existant)")
    args = ap.parse_args()

    if not os.path.isfile(args.logfile):
        print(f"Fichier introuvable : {args.logfile}", file=sys.stderr)
        return 1

    print(f"=== Analyse de {args.logfile} (type: {args.type}) ===\n")
    res = analyze_log(args.logfile, args.type, max_samples=args.samples)

    if res["lines_total"] == 0:
        print(f"[avertissement] {args.logfile} ne contient aucune ligne "
              f"(log vide ou rotation .gz corrompue ?) — dossier vide.",
              file=sys.stderr)

    print(f"Lignes analysées        : {res['lines_total']}")
    print(f"Lignes avec IP cliente  : {res['lines_with_ip']}")
    print(f"Lignes ignorées         : {res['lines_skipped']}")
    if res["lines_malformed"]:
        print(f"Lignes JSON malformées  : {res['lines_malformed']}")
    print(f"IP publiques distinctes : {len(res['hits'])}\n")

    excl = load_exclusions(args.exclude)
    hits = res["hits"]
    sigs = res["signatures"]

    excluded_ips = sorted(ip for ip in hits if is_excluded(ip, excl))

    # TI-04 : seules les IP avec >=1 signature deviennent des indicateurs.
    indicator_ips = [ip for ip in hits
                     if sigs.get(ip) and not is_excluded(ip, excl)]
    # Classement : d'abord nb de signatures DISTINCTES, puis nb de requêtes.
    indicator_ips.sort(key=lambda ip: (len(sigs[ip]), hits[ip]), reverse=True)
    # --min-hits appliqué APRÈS le filtre par signature.
    indicator_ips = [ip for ip in indicator_ips if hits[ip] >= args.min_hits]
    indicator_ips = indicator_ips[: args.top]

    # Contexte : IP volumineuses SANS signature (visiteurs normaux). NON enrichi.
    benign_ips = [ip for ip in hits
                  if not sigs.get(ip) and not is_excluded(ip, excl)]
    benign_ips.sort(key=lambda ip: hits[ip], reverse=True)
    benign_ips = benign_ips[: args.top]

    # --- Verrou « en ligne sous mandat » ---------------------------------------
    # Le DÉCODAGE des preuves reste 100 % local (aucun réseau). L'enrichissement
    # RÉPUTATION (AbuseIPDB, base PUBLIQUE ; jamais la machine de l'attaquant) n'est
    # activé que si un mandat SIGNÉ et VALIDE est fourni. Sans mandat : analyse locale.
    mandat_ref = args.mandat_ref or ""
    if not ABUSEIPDB_KEY:
        online_allowed, gate_note = False, "ABUSEIPDB_KEY absente : analyse hors ligne"
    elif not args.mandat:
        online_allowed, gate_note = False, "aucun --mandat : enrichissement en ligne désactivé (analyse locale)"
    else:
        online_allowed, gate_note, ref_m = mandat_actif(args.mandat)
        mandat_ref = mandat_ref or ref_m
    offline = not online_allowed

    report = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "tool_version": TOOL_VERSION,
        "host": socket.gethostname(),
        "mandat_ref": mandat_ref,
        "enrichissement": {"en_ligne": online_allowed, "raison": gate_note},
        "params": {
            "logfile": args.logfile,
            "type": args.type,
            "top": args.top,
            "min_hits": args.min_hits,
            "samples": args.samples,
            "exclude": args.exclude,
        },
        "source": {
            "abspath": os.path.abspath(args.logfile),
            "sha256": sha256_file(args.logfile),
            "size": os.path.getsize(args.logfile),
            "mtime_utc": datetime.fromtimestamp(
                os.path.getmtime(args.logfile), timezone.utc).isoformat(),
            "log_type": args.type,
        },
        "stats": {
            "lines_total": res["lines_total"],
            "lines_with_ip": res["lines_with_ip"],
            "lines_skipped": res["lines_skipped"],
            "lines_malformed": res["lines_malformed"],
            "distinct_public_ips": len(hits),
            "suspects": len(indicator_ips),
            "benign_context": len(benign_ips),
            "excluded_ips": len(excluded_ips),
        },
        "excluded_ips": excluded_ips,
        "indicators": [],
        "contexte": [],
    }

    mode = ("enrichissement réputation EN LIGNE (sous mandat)" if online_allowed
            else f"HORS LIGNE — {gate_note}")
    print(f"--- {len(indicator_ips)} IP suspecte(s) ({mode}) ---\n")

    enrichment_stopped = False
    for ip in indicator_ips:
        ip_sigs = sigs.get(ip, [])
        if enrichment_stopped:
            rep = {"status": "non_interroge",
                   "note": "enrichissement interrompu (HTTP 401/429 précédent)"}
        else:
            rep, halt = enrich_abuseipdb(ip)
            if halt:
                enrichment_stopped = True
                print(f"[AVERTISSEMENT] AbuseIPDB a renvoyé {rep.get('error')} — "
                      f"arrêt de l'enrichissement des IP suivantes.", file=sys.stderr)

        flag, score_disp = _risk_flag(rep)
        print(f"{flag} {ip}  | {hits[ip]} req | {len(ip_sigs)} sig | "
              f"score abus: {score_disp} | {rep.get('country', '?')} | {rep.get('isp', '?')}")
        if ip_sigs:
            print(f"     signatures: {', '.join(ip_sigs)}")

        # Extraits de preuve, limités aux signatures réellement retenues pour l'IP.
        ip_samples = {label: res["samples"].get(ip, {}).get(label, [])
                      for label in ip_sigs if res["samples"].get(ip, {}).get(label)}

        # Décodage défensif des payloads obscurcis (preuve branché).
        preuves_dec = decoder_echantillons(ip_samples)
        if preuves_dec:
            comps = sorted({c for e in preuves_dec for c in e["comportement_apparent"]})
            if comps:
                print(f"     payload décodé -> {', '.join(comps[:6])}")

        indic = {
            "ip": ip,
            "request_count": hits[ip],
            "signature_count": len(ip_sigs),
            "attack_signatures": ip_sigs,
            "first_seen": res["first_seen"].get(ip, "inconnu"),
            "last_seen": res["last_seen"].get(ip, "inconnu"),
            "samples": ip_samples,
            "reputation": rep,
        }
        if preuves_dec:
            indic["preuves_decodees"] = preuves_dec
        report["indicators"].append(indic)

    for ip in benign_ips:
        report["contexte"].append({
            "ip": ip,
            "request_count": hits[ip],
            "first_seen": res["first_seen"].get(ip, "inconnu"),
            "last_seen": res["last_seen"].get(ip, "inconnu"),
            "note": "aucune signature d'attaque — contexte uniquement, non enrichi",
        })

    # ---- Écriture du dossier : nom unique, refus d'écrasement (TI-09) ----
    if args.out:
        out = args.out
    else:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%f")
        out = f"dossier-threat-intel_{ts}_{uuid.uuid4().hex[:8]}.json"
    try:
        # mode 'x' : échoue si le fichier existe déjà (jamais d'écrasement).
        with open(out, "x", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    except FileExistsError:
        print(f"[erreur] le dossier existe déjà, écrasement refusé : {out}",
              file=sys.stderr)
        return 1

    # Empreinte d'intégrité du dossier (format sha256sum).
    digest = sha256_file(out)
    sha_path = out + ".sha256"
    try:
        with open(sha_path, "x", encoding="utf-8") as f:
            f.write(f"{digest}  {os.path.basename(out)}\n")
    except FileExistsError:
        print(f"[avertissement] {sha_path} existe déjà — empreinte non réécrite.",
              file=sys.stderr)

    print(f"\n=== Dossier enregistré : {out} ===")
    print(f"    SHA-256 : {digest}")
    print(f"    Empreinte : {sha_path}")
    n_dec = sum(1 for i in report["indicators"] if i.get("preuves_decodees"))
    if n_dec:
        print(f"    Payloads décodés (hors ligne) pour {n_dec} IP — voir 'preuves_decodees'.")

    # Journalise l'analyse (Annexe C) si demandé — scelle l'empreinte du dossier.
    if args.journal:
        try:
            from tasko import journal as _j
            _j.enregistrer(args.journal, _j.Evenement(
                reference=mandat_ref, cible=os.path.abspath(args.logfile),
                outil="threat-intel", decision="analysé",
                raison=f"{len(report['indicators'])} IOC, enrichissement en ligne={online_allowed}",
                empreinte=digest))
            print(f"    Journalisé (Annexe C) : {args.journal}")
        except Exception as e:  # noqa: BLE001
            print(f"    [avertissement] journalisation ignorée ({e})", file=sys.stderr)
    print("Ce dossier (IOC + réputation + payloads décodés) est transmissible aux")
    print("autorités pour l'attribution. Aucune machine attaquante n'a été contactée.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
