#!/usr/bin/env python3
"""Générateur de rapport d'audit (Article 6 du mandat).

Agrège les sorties des outils de scan (Nuclei, WPScan, ZAP, Nmap) en une liste de
findings normalisés, triés par sévérité, et produit un rapport Markdown lisible par
le client. But : **corriger**, jamais exploiter. Aucun réseau n'est contacté : on
ne lit que des fichiers de rapport déjà produits localement.
"""
from __future__ import annotations

import dataclasses
import json
import os
import re

# Sévérités normalisées, de la plus grave à la plus faible.
SEVERITES = ("critique", "élevée", "moyenne", "faible", "info")
_ORDRE = {s: i for i, s in enumerate(SEVERITES)}

# Correspondances depuis les vocabulaires des outils.
_MAP_SEV = {
    "critical": "critique", "high": "élevée", "medium": "moyenne",
    "low": "faible", "info": "info", "information": "info", "informational": "info",
    "unknown": "info",
}
# ZAP riskcode -> sévérité
_MAP_ZAP = {"3": "élevée", "2": "moyenne", "1": "faible", "0": "info"}


@dataclasses.dataclass
class Finding:
    cible: str
    outil: str
    titre: str
    severite: str
    reference: str = ""     # CVE / URL / template-id
    description: str = ""
    recommandation: str = ""

    def cle(self) -> tuple:
        return (self.cible, self.outil, self.titre, self.reference)


def _sev(v: str) -> str:
    return _MAP_SEV.get(str(v).strip().lower(), "info")


def _tronque(s: str, n: int = 500) -> str:
    s = " ".join(str(s or "").split())
    return s if len(s) <= n else s[: n - 1] + "…"


# ---------------------------------------------------------------- parseurs
def charger_nuclei(chemin: str) -> list[Finding]:
    """Nuclei JSONL : une ligne JSON par finding."""
    out: list[Finding] = []
    try:
        with open(chemin, "r", encoding="utf-8") as f:
            for ligne in f:
                ligne = ligne.strip()
                if not ligne:
                    continue
                try:
                    d = json.loads(ligne)
                except json.JSONDecodeError:
                    continue
                info = d.get("info", {}) or {}
                refs = info.get("reference") or []
                if isinstance(refs, str):
                    refs = [refs]
                ref = (d.get("template-id", "") + (" | " + refs[0] if refs else "")).strip(" |")
                out.append(Finding(
                    cible=d.get("host") or d.get("matched-at") or d.get("url", ""),
                    outil="nuclei",
                    titre=info.get("name", d.get("template-id", "finding")),
                    severite=_sev(info.get("severity", "info")),
                    reference=ref,
                    description=_tronque(info.get("description", "")),
                    recommandation=_tronque(info.get("remediation", "")),
                ))
    except FileNotFoundError:
        pass
    return out


def charger_wpscan(chemin: str) -> list[Finding]:
    """WPScan JSON : vulnérabilités de la version, des plugins et des thèmes."""
    out: list[Finding] = []
    try:
        with open(chemin, "r", encoding="utf-8") as f:
            d = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return out
    cible = d.get("target_url") or d.get("target_ip") or ""

    def vulns(obj, origine):
        for v in (obj or []):
            refs = v.get("references", {}) or {}
            cve = refs.get("cve") or []
            url = refs.get("url") or []
            ref = ""
            if cve:
                ref = "CVE-" + cve[0] if not str(cve[0]).startswith("CVE") else cve[0]
            elif url:
                ref = url[0]
            fixed = v.get("fixed_in")
            reco = f"Mettre à jour vers {fixed} ou plus récent." if fixed else \
                "Appliquer le correctif de l'éditeur / désactiver le composant si non utilisé."
            out.append(Finding(
                cible=cible, outil="wpscan",
                titre=f"[{origine}] {v.get('title', 'vulnérabilité')}",
                severite="élevée",  # WPScan ne liste que des vulnérabilités connues
                reference=ref, description="", recommandation=reco,
            ))

    ver = d.get("version") or {}
    vulns(ver.get("vulnerabilities"), "WordPress")
    for section, label in (("plugins", "plugin"), ("themes", "thème")):
        for nom, obj in (d.get(section) or {}).items():
            vulns((obj or {}).get("vulnerabilities"), f"{label} {nom}")
    return out


def charger_zap(chemin: str) -> list[Finding]:
    """Rapport ZAP (traditional-json) : site[].alerts[]."""
    out: list[Finding] = []
    try:
        with open(chemin, "r", encoding="utf-8") as f:
            d = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return out
    for site in d.get("site", []) or []:
        cible = site.get("@name", "")
        for a in site.get("alerts", []) or []:
            ref = a.get("cweid", "")
            ref = f"CWE-{ref}" if ref and str(ref) not in ("", "-1") else ""
            out.append(Finding(
                cible=cible, outil="zap",
                titre=a.get("alert") or a.get("name", "alerte"),
                severite=_MAP_ZAP.get(str(a.get("riskcode", "0")), "info"),
                reference=ref,
                description=_tronque(re.sub("<[^>]+>", "", a.get("desc", ""))),
                recommandation=_tronque(re.sub("<[^>]+>", "", a.get("solution", ""))),
            ))
    return out


def charger_nmap(chemin: str) -> list[Finding]:
    """Nmap -oN (texte) : extraction best-effort des lignes VULNERABLE / CVE."""
    out: list[Finding] = []
    try:
        with open(chemin, "r", encoding="utf-8", errors="ignore") as f:
            texte = f.read()
    except FileNotFoundError:
        return out
    cible = ""
    m = re.search(r"Nmap scan report for (\S+)", texte)
    if m:
        cible = m.group(1)

    def emettre(lignes: list[str]) -> None:
        bloc = "\n".join(lignes)
        if "VULNERABLE" not in bloc and not re.search(r"CVE-\d{4}-\d+", bloc):
            return
        # Titre = nom du script NSE (1re ligne, après '|', avant ':').
        premiere = lignes[0].lstrip("|_ ").strip()
        titre = premiere.split(":")[0][:120] or "service potentiellement vulnérable"
        cves = ", ".join(sorted(set(re.findall(r"CVE-\d{4}-\d+", bloc))))
        out.append(Finding(
            cible=cible, outil="nmap", titre=titre, severite="moyenne",
            reference=cves, description=_tronque(bloc, 400),
            recommandation="Mettre à jour le service concerné ; vérifier le correctif éditeur.",
        ))

    # Regroupe chaque suite de lignes de sortie NSE ('|' / '|_') en un seul bloc.
    courant: list[str] = []
    for ligne in texte.splitlines():
        if ligne.startswith("|"):
            courant.append(ligne)
        else:
            if courant:
                emettre(courant)
                courant = []
    if courant:
        emettre(courant)
    return out


# ---------------------------------------------------------------- collecte
_PARSEURS = (
    ("nuclei.jsonl", charger_nuclei),
    ("wpscan", charger_wpscan),   # wpscan_*.json
    ("zap", charger_zap),         # *zap*.json
    ("vuln.txt", charger_nmap),
    ("ports.txt", charger_nmap),
)


def collecter_dossier(dossier: str) -> list[Finding]:
    """Parcourt un dossier de rapports et agrège tous les findings reconnus."""
    findings: list[Finding] = []
    for racine, _dirs, fichiers in os.walk(dossier):
        for nom in fichiers:
            chemin = os.path.join(racine, nom)
            bas = nom.lower()
            if bas == "nuclei.jsonl":
                findings += charger_nuclei(chemin)
            elif bas.startswith("wpscan") and bas.endswith(".json"):
                findings += charger_wpscan(chemin)
            elif "zap" in bas and bas.endswith(".json"):
                findings += charger_zap(chemin)
            elif bas in ("vuln.txt", "ports.txt"):
                findings += charger_nmap(chemin)
    return dedupliquer(findings)


def dedupliquer(findings: list[Finding]) -> list[Finding]:
    vus = {}
    for f in findings:
        vus[f.cle()] = f
    return list(vus.values())


def trier(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (_ORDRE.get(f.severite, 99), f.cible, f.titre))


# ---------------------------------------------------------------- rendu
def rendre_markdown(findings: list[Finding], *, reference_mandat: str = "",
                    date: str = "", operateur: str = "") -> str:
    findings = trier(findings)
    comptes = {s: 0 for s in SEVERITES}
    for f in findings:
        comptes[f.severite] = comptes.get(f.severite, 0) + 1

    L = ["# Rapport d'audit de sécurité — Tasko Defense", ""]
    if reference_mandat:
        L.append(f"**Mandat :** {reference_mandat}  ")
    if date:
        L.append(f"**Date :** {date}  ")
    if operateur:
        L.append(f"**Opérateur :** {operateur}  ")
    L += ["", "> But de ce rapport : **corriger** les vulnérabilités, jamais les exploiter.",
          "", "## Synthèse", "",
          "| Sévérité | Nombre |", "|---|---|"]
    for s in SEVERITES:
        L.append(f"| {s.capitalize()} | {comptes[s]} |")
    L += [f"| **Total** | **{len(findings)}** |", ""]

    if not findings:
        L += ["Aucune vulnérabilité détectée par les outils configurés.", ""]
        return "\n".join(L)

    L += ["## Findings (du plus grave au plus faible)", ""]
    for i, f in enumerate(findings, 1):
        L.append(f"### {i}. [{f.severite.upper()}] {f.titre}")
        L.append("")
        L.append(f"- **Cible :** {f.cible}")
        L.append(f"- **Outil :** {f.outil}")
        if f.reference:
            L.append(f"- **Référence :** {f.reference}")
        if f.description:
            L.append(f"- **Description :** {f.description}")
        reco = f.recommandation or "Corriger selon les bonnes pratiques de l'éditeur."
        L.append(f"- **Recommandation :** {reco}")
        L.append("")
    L += ["---", "",
          "*Un audit reflète l'état de sécurité au moment du test, dans les limites du mandat.*"]
    return "\n".join(L) + "\n"
