#!/usr/bin/env python3
"""Analyseur de preuves — DÉCODAGE/DÉSOBFUSCATION défensif d'un artefact détenu.

Quand on trouve, dans un log ou un web shell, un payload obscurci (base64, hex,
URL-encodé, char-codes, gzip…), cet outil déroule ses couches pour en révéler le
texte et aider à COMPRENDRE l'attaque, afin de la documenter aux autorités.

Ce qu'il fait (100 % défensif, hors ligne) :
  - décode/désobfusque des REPRÉSENTATIONS que tu détiens déjà (encodages) ;
  - IDENTIFIE le *type* d'un hash par sa forme (MD5, SHA-256, bcrypt…) ;
  - extrait les IOC (IP, domaines, URL, emails) du contenu révélé ;
  - signale par heuristique ce que le payload SEMBLE faire (eval, téléchargement…).

Ce qu'il ne fait PAS, par conception :
  - AUCUN cassage de hash / mot de passe (pas de dictionnaire, pas de brute force) ;
  - AUCUN déchiffrement d'un chiffré nécessitant une clé qu'on ne possède pas ;
  - AUCUNE exécution du payload, AUCUN accès réseau.

Il transforme des octets déjà en main : il n'attaque rien.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import html
import re
import urllib.parse
import zlib

VERSION = "1.0"
_MAX_PROFONDEUR = 12
_MAX_APERCU = 400

# Mots-clés révélateurs : servent (a) à valider qu'un décodage a « ouvert » quelque
# chose d'utile, (b) à résumer le comportement apparent du payload.
MOTS_CLES = (
    "eval", "exec", "system", "shell_exec", "passthru", "popen", "assert",
    "base64_decode", "gzinflate", "str_rot13", "preg_replace", "create_function",
    "powershell", "-enc", "-encodedcommand", "frombase64string", "iex",
    "invoke-expression", "downloadstring", "downloadfile", "wget", "curl",
    "certutil", "bitsadmin", "mshta", "rundll32", "regsvr32", "/bin/sh",
    "bash -i", "nc ", "ncat", "socat", "cmd.exe", "document.cookie",
    "fromcharcode", "unescape", "atob", "<script", "union select", "etc/passwd",
    "wp-config", ".env", "authorized_keys", "/dev/tcp",
)

# Signatures de hash (type seulement — jamais de cassage).
_HASHS = (
    ("bcrypt", re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}")),
    ("md5crypt", re.compile(r"\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}")),
    ("sha256crypt", re.compile(r"\$5\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}")),
    ("sha512crypt", re.compile(r"\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("SHA-512 (128 hex)", re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{128}(?![0-9a-fA-F])")),
    ("SHA-256 (64 hex)", re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")),
    ("SHA-1 (40 hex)", re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])")),
    ("MD5 ou NTLM (32 hex)", re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])")),
)

_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_URL = re.compile(r"https?://[^\s\"'<>\\]+", re.I)
_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_RE_DOMAINE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)


def _taux_imprimable(b: bytes) -> float:
    if not b:
        return 0.0
    ok = sum(1 for x in b if 9 <= x <= 13 or 32 <= x <= 126 or x >= 128)
    return ok / len(b)


def _en_texte(b: bytes) -> str:
    return b.decode("utf-8", "replace")


def _utile(texte: str) -> int:
    """Nombre de mots-clés révélateurs présents (sert à valider un décodage)."""
    bas = texte.lower()
    return sum(1 for m in MOTS_CLES if m in bas)


# --------------------------------------------------------------- décodeurs
def _d_base64(s: str):
    compact = re.sub(r"\s+", "", s)
    if len(compact) < 16 or len(compact) % 4 != 0:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
        return None
    try:
        brut = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(brut) >= 2 and brut[:2] == b"\x1f\x8b":          # gzip
        try:
            brut = gzip.decompress(brut)
        except OSError:
            return None
    elif len(brut) >= 2 and brut[0] == 0x78:                 # zlib
        try:
            brut = zlib.decompress(brut)
        except zlib.error:
            pass
    if _taux_imprimable(brut) < 0.85:
        return None
    return _en_texte(brut)


def _d_base64url(s: str):
    compact = re.sub(r"\s+", "", s)
    if len(compact) < 16 or not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", compact):
        return None
    if "-" not in compact and "_" not in compact:
        return None  # sinon c'est du base64 standard, déjà traité
    pad = compact + "=" * (-len(compact) % 4)
    try:
        brut = base64.urlsafe_b64decode(pad)
    except (binascii.Error, ValueError):
        return None
    if _taux_imprimable(brut) < 0.85:
        return None
    return _en_texte(brut)


def _d_hex(s: str):
    compact = re.sub(r"(?:0x|\\x|%)|\s+", "", s)
    if len(compact) < 16 or len(compact) % 2 != 0:
        return None
    if not re.fullmatch(r"[0-9a-fA-F]+", compact):
        return None
    try:
        brut = bytes.fromhex(compact)
    except ValueError:
        return None
    if _taux_imprimable(brut) < 0.85:
        return None
    return _en_texte(brut)


def _d_url(s: str):
    if "%" not in s:
        return None
    out = urllib.parse.unquote_plus(s)
    return out if out != s else None


def _d_html(s: str):
    if "&#" not in s and "&" not in s:
        return None
    out = html.unescape(s)
    return out if out != s else None


def _d_charcode_js(s: str):
    m = re.search(r"fromCharCode\s*\(([^)]*)\)", s, re.I)
    if not m:
        return None
    nums = re.findall(r"\d+", m.group(1))
    if len(nums) < 4:
        return None
    try:
        return "".join(chr(int(n)) for n in nums)
    except (ValueError, OverflowError):
        return None


def _d_echappement(s: str):
    """Séquences \\xNN et \\uNNNN -> caractères."""
    if "\\x" not in s and "\\u" not in s:
        return None
    try:
        out = codecs.decode(s, "unicode_escape")
    except (UnicodeDecodeError, ValueError):
        return None
    return out if out != s else None


def _d_rot13(s: str):
    """ROT13 — accepté UNIQUEMENT s'il révèle plus de mots-clés (sinon trop bruyant)."""
    if not re.search(r"[A-Za-z]", s):
        return None
    out = codecs.encode(s, "rot_13")
    return out if _utile(out) > _utile(s) else None


# Ordre de priorité. hex AVANT base64 : une chaîne 100 % hexadécimale est aussi
# du base64 valide, mais c'est presque toujours de l'hex (le base64 réel contient
# des lettres hors [0-9a-f]). base64url exige '-'/'_', donc ne capte pas l'hex.
_DECODEURS = (
    ("String.fromCharCode", _d_charcode_js),
    ("échappement \\x/\\u", _d_echappement),
    ("base64url", _d_base64url),
    ("hex", _d_hex),
    ("gzip+base64 / base64", _d_base64),
    ("url", _d_url),
    ("entités HTML", _d_html),
    ("rot13", _d_rot13),
)


def deobfusquer(texte: str, max_profondeur: int = _MAX_PROFONDEUR) -> dict:
    """Déroule les couches d'encodage jusqu'au point fixe. Renvoie couches + final."""
    couches = []
    courant = texte
    vus = {courant}
    for _ in range(max_profondeur):
        progres = False
        for nom, dec in _DECODEURS:
            try:
                res = dec(courant)
            except Exception:  # noqa: BLE001 - un décodeur ne doit jamais planter l'analyse
                res = None
            if res and res != courant and res not in vus:
                couches.append({"methode": nom, "apercu": res[:_MAX_APERCU]})
                courant = res
                vus.add(courant)
                progres = True
                break
        if not progres:
            break
    return {"couches": couches, "final": courant, "profondeur": len(couches)}


def identifier_hashs(texte: str) -> list[dict]:
    """Repère le *type* des hashs présents (jamais de cassage)."""
    trouves, vus = [], set()
    for type_, rx in _HASHS:
        for m in rx.findall(texte):
            if m in vus:
                continue
            vus.add(m)
            trouves.append({"type": type_, "valeur": m})
    return trouves


def extraire_iocs(texte: str) -> dict:
    """Extrait les IOC du contenu révélé (données, pas instructions)."""
    def uniques(it):
        return sorted(set(it))
    urls = uniques(_RE_URL.findall(texte))
    emails = uniques(_RE_EMAIL.findall(texte))
    # On évite de reclasser comme « domaine » ce qui est déjà une URL/un email.
    deja = " ".join(urls + emails)
    domaines = uniques(d for d in _RE_DOMAINE.findall(texte)
                       if d.lower() not in deja.lower())
    return {
        "ips": uniques(_RE_IPV4.findall(texte)),
        "urls": urls,
        "domaines": domaines,
        "emails": emails,
    }


def comportement_apparent(texte: str) -> list[str]:
    """Mots-clés révélateurs présents (ce que le payload SEMBLE faire)."""
    bas = texte.lower()
    return [m.strip() for m in MOTS_CLES if m in bas]


def analyser(source: str, *, est_fichier: bool = False) -> dict:
    """Analyse un artefact (texte brut ou chemin de fichier si est_fichier)."""
    origine = "<texte>"
    if est_fichier:
        origine = source
        with open(source, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()

    deob = deobfusquer(source)
    final = deob["final"]
    # On cherche les hashs/IOC/comportements dans l'entrée ET le contenu révélé.
    corpus = source + "\n" + final
    return {
        "outil": "preuve",
        "version": VERSION,
        "origine": origine,
        "taille_entree": len(source),
        "deobfuscation": deob,
        "hashs": identifier_hashs(corpus),
        "iocs": extraire_iocs(corpus),
        "comportement_apparent": comportement_apparent(corpus),
    }


def rendre_markdown(analyse: dict) -> str:
    deob = analyse["deobfuscation"]
    L = ["# Analyse de preuve — décodage défensif", "",
         f"**Origine :** {analyse['origine']}  ",
         f"**Taille entrée :** {analyse['taille_entree']} octets  ",
         f"**Couches décodées :** {deob['profondeur']}  ", "",
         "> Décodage/désobfuscation d'un artefact détenu, pour COMPRENDRE l'attaque.",
         "> Aucun cassage de secret, aucun déchiffrement par clé, aucune exécution.", ""]

    if deob["couches"]:
        L += ["## Couches décodées", ""]
        for i, c in enumerate(deob["couches"], 1):
            L.append(f"{i}. **{c['methode']}** → `{c['apercu'][:160]}`")
        L += ["", "## Contenu final révélé", "", "```", deob["final"][:1200], "```", ""]
    else:
        L += ["## Contenu", "", "Aucune couche d'encodage détectée (texte déjà en clair).", ""]

    comp = analyse["comportement_apparent"]
    L += ["## Comportement apparent", "",
          ("- " + "\n- ".join(comp)) if comp else "Aucun mot-clé révélateur repéré.", ""]

    if analyse["hashs"]:
        L += ["## Hashs identifiés (type seulement — non cassés)", "",
              "| Type | Valeur |", "|---|---|"]
        for h in analyse["hashs"]:
            L.append(f"| {h['type']} | `{h['valeur']}` |")
        L.append("")

    io = analyse["iocs"]
    if any(io.values()):
        L += ["## IOC extraits", ""]
        for cle, lib in (("ips", "IP"), ("domaines", "Domaines"),
                         ("urls", "URL"), ("emails", "Emails")):
            if io[cle]:
                L.append(f"- **{lib} :** " + ", ".join(io[cle]))
        L.append("")
    return "\n".join(L) + "\n"
