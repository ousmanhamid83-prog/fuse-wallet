#!/usr/bin/env python3
"""Journal des tests — preuve du caractère autorisé (Article 8 + Annexe C du mandat).

Le mandat juridique exige que le Prestataire conserve « les journaux de ses tests
(IP, dates, outils, empreintes) » comme preuve que son intervention était autorisée
et défensive. Ce module tient ce journal : un fichier JSONL append-only, une ligne
par événement (décision d'autorisation, lancement d'un outil), horodaté en UTC.

Il ne décide rien et ne contacte aucun réseau : il enregistre et restitue.
"""
from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import json
import os
import socket

CHAMPS_ANNEXE_C = ("horodatage_utc", "reference", "cible", "type_test", "outil",
                   "ip_source", "decision", "empreinte")


def _maintenant_utc() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def empreinte_fichier(chemin: str) -> str:
    """SHA-256 d'un fichier (empreinte d'une preuve/sortie d'outil). '' si absent."""
    try:
        h = hashlib.sha256()
        with open(chemin, "rb") as f:
            for bloc in iter(lambda: f.read(65536), b""):
                h.update(bloc)
        return h.hexdigest()
    except OSError:
        return ""


@dataclasses.dataclass
class Evenement:
    reference: str = ""          # référence du mandat
    cible: str = ""
    type_test: str = ""
    outil: str = ""              # tasko-gate, nuclei, wpscan, nmap, zap…
    ip_source: str = ""
    decision: str = ""           # autorisé | refusé | lancé | terminé
    raison: str = ""
    empreinte: str = ""          # SHA-256 d'une sortie, le cas échéant
    details: dict = dataclasses.field(default_factory=dict)

    def vers_dict(self) -> dict:
        d = {
            "horodatage_utc": _maintenant_utc(),
            "hote_operateur": socket.gethostname(),
            "operateur": os.environ.get("SUDO_USER") or os.environ.get("USER", ""),
            "reference": self.reference,
            "cible": self.cible,
            "type_test": self.type_test,
            "outil": self.outil,
            "ip_source": self.ip_source,
            "decision": self.decision,
            "raison": self.raison,
            "empreinte": self.empreinte,
        }
        if self.details:
            d["details"] = self.details
        return d


def enregistrer(chemin_journal: str, evenement: Evenement) -> dict:
    """Ajoute un événement au journal (JSONL, append-only). Renvoie la ligne écrite."""
    ligne = evenement.vers_dict()
    os.makedirs(os.path.dirname(os.path.abspath(chemin_journal)) or ".", exist_ok=True)
    with open(chemin_journal, "a", encoding="utf-8") as f:
        f.write(json.dumps(ligne, ensure_ascii=False) + "\n")
    return ligne


def lire(chemin_journal: str) -> list[dict]:
    """Charge toutes les entrées valides du journal (ignore les lignes illisibles)."""
    out: list[dict] = []
    try:
        with open(chemin_journal, "r", encoding="utf-8") as f:
            for ligne in f:
                ligne = ligne.strip()
                if not ligne:
                    continue
                try:
                    out.append(json.loads(ligne))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        pass
    return out


def rendre_annexe_c(chemin_journal: str) -> str:
    """Restitue le journal sous la forme du tableau de l'Annexe C (Markdown)."""
    entrees = lire(chemin_journal)
    entetes = ["Horodatage (UTC)", "Référence", "Cible", "Type", "Outil",
               "IP source", "Décision", "Empreinte"]
    lignes = ["# Annexe C — Journal des tests",
              "",
              f"Source : `{chemin_journal}` — {len(entrees)} entrée(s).",
              "",
              "| " + " | ".join(entetes) + " |",
              "|" + "|".join(["---"] * len(entetes)) + "|"]
    for e in entrees:
        emp = (e.get("empreinte") or "")[:12]
        lignes.append("| " + " | ".join([
            str(e.get("horodatage_utc", "")),
            str(e.get("reference", "")),
            str(e.get("cible", "")),
            str(e.get("type_test", "")),
            str(e.get("outil", "")),
            str(e.get("ip_source", "")),
            str(e.get("decision", "")),
            emp,
        ]) + " |")
    return "\n".join(lignes) + "\n"
