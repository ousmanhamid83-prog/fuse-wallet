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
  - On interroge des bases PUBLIQUES (AbuseIPDB) — on ne sonde PAS l'attaquant.
  - Aucune connexion n'est établie vers les IP analysées.

Prérequis :
  pip install requests
  Clé AbuseIPDB gratuite : https://www.abuseipdb.com (1000 requêtes/jour)
  export ABUSEIPDB_KEY="ta_cle"

Usage :
  python3 threat-intel.py /var/log/nginx/access.log
  python3 threat-intel.py /var/log/auth.log --type auth
"""
from __future__ import annotations

import argparse
import collections
import ipaddress
import json
import os
import re
import sys
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("Installe d'abord : pip install requests", file=sys.stderr)
    sys.exit(1)

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")

# Extraction d'IPv4 (on ignore les IP privées : ce ne sont pas des attaquants externes)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Motifs d'activité suspecte dans les logs web (tentatives classiques)
SUSPICIOUS_WEB = [
    (r"\.\./\.\.", "path_traversal"),
    (r"(?i)union\s+select", "sql_injection"),
    (r"(?i)<script", "xss_attempt"),
    (r"(?i)/wp-login\.php", "wp_login_bruteforce"),
    (r"(?i)/xmlrpc\.php", "xmlrpc_abuse"),
    (r"(?i)\.(env|git|sql|bak)\b", "sensitive_file_probe"),
    (r"(?i)(eval|base64_decode|shell_exec)", "code_injection_probe"),
]
# Motifs dans les logs d'authentification SSH
SUSPICIOUS_AUTH = [
    (r"Failed password", "ssh_failed_login"),
    (r"Invalid user", "ssh_invalid_user"),
    (r"authentication failure", "auth_failure"),
]


def is_public_ip(ip: str) -> bool:
    """Garde uniquement les IP publiques (les privées ne sont pas des attaquants externes)."""
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_reserved)
    except ValueError:
        return False


def analyze_log(path: str, log_type: str) -> dict:
    """Extrait les IP et l'activité suspecte d'un fichier de log."""
    patterns = SUSPICIOUS_AUTH if log_type == "auth" else SUSPICIOUS_WEB
    ip_hits: collections.Counter = collections.Counter()
    ip_signatures: dict[str, set] = collections.defaultdict(set)
    total_lines = 0

    with open(path, "r", errors="ignore") as f:
        for line in f:
            total_lines += 1
            ips = [ip for ip in IP_RE.findall(line) if is_public_ip(ip)]
            if not ips:
                continue
            matched = [label for rx, label in patterns if re.search(rx, line)]
            for ip in ips:
                ip_hits[ip] += 1
                for label in matched:
                    ip_signatures[ip].add(label)

    return {
        "total_lines": total_lines,
        "ip_hits": ip_hits,
        "ip_signatures": {k: sorted(v) for k, v in ip_signatures.items()},
    }


def enrich_abuseipdb(ip: str) -> dict:
    """Interroge la base PUBLIQUE AbuseIPDB (réputation de l'IP). Ne touche pas l'IP."""
    if not ABUSEIPDB_KEY:
        return {"error": "ABUSEIPDB_KEY non définie — enrichissement ignoré"}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            timeout=15,
        )
        d = r.json().get("data", {})
        return {
            "abuse_score": d.get("abuseConfidenceScore"),
            "country": d.get("countryCode"),
            "isp": d.get("isp"),
            "domain": d.get("domain"),
            "total_reports": d.get("totalReports"),
            "last_reported": d.get("lastReportedAt"),
        }
    except Exception as e:  # pragma: no cover
        return {"error": str(e)}


def main() -> int:
    ap = argparse.ArgumentParser(description="Threat intelligence défensif")
    ap.add_argument("logfile", help="Chemin du fichier de log à analyser")
    ap.add_argument("--type", choices=["web", "auth"], default="web",
                    help="Type de log (web=Nginx/Apache, auth=SSH)")
    ap.add_argument("--top", type=int, default=20, help="Nombre d'IP à enrichir")
    ap.add_argument("--min-hits", type=int, default=5,
                    help="Seuil minimal d'occurrences pour retenir une IP")
    args = ap.parse_args()

    if not os.path.isfile(args.logfile):
        print(f"Fichier introuvable : {args.logfile}", file=sys.stderr)
        return 1

    print(f"=== Analyse de {args.logfile} (type: {args.type}) ===\n")
    res = analyze_log(args.logfile, args.type)
    print(f"Lignes analysées : {res['total_lines']}")
    print(f"IP publiques distinctes : {len(res['ip_hits'])}\n")

    # Top des IP les plus actives au-dessus du seuil
    top_ips = [(ip, n) for ip, n in res["ip_hits"].most_common() if n >= args.min_hits]
    top_ips = top_ips[: args.top]

    report = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "source_log": args.logfile,
        "log_type": args.type,
        "indicators": [],
    }

    print(f"--- Top {len(top_ips)} IP suspectes (enrichissement réputation) ---\n")
    for ip, hits in top_ips:
        sigs = res["ip_signatures"].get(ip, [])
        intel = enrich_abuseipdb(ip)
        score = intel.get("abuse_score")
        flag = "🔴" if (score or 0) >= 75 else ("🟠" if (score or 0) >= 25 else "⚪")
        print(f"{flag} {ip}  | {hits} req | score abus: {score} "
              f"| {intel.get('country')} | {intel.get('isp')}")
        if sigs:
            print(f"     signatures: {', '.join(sigs)}")
        report["indicators"].append({
            "ip": ip,
            "request_count": hits,
            "attack_signatures": sigs,
            "reputation": intel,
        })

    # Sauvegarde du dossier (pour les autorités)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = f"dossier-threat-intel_{ts}.json"
    with open(out, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n=== Dossier enregistré : {out} ===")
    print("Ce dossier (IOC + réputation) est transmissible aux autorités pour")
    print("l'attribution. Aucune machine attaquante n'a été contactée.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
