#!/usr/bin/env python3
"""Documentation de preuve de concept (PoC) — Annexe D.

Ce module N'EXÉCUTE AUCUNE exploitation. Il n'ouvre aucune connexion, n'envoie
aucune requête, ne contient aucun payload. C'est un outil de **preuve et
d'intégrité** : l'opérateur a réalisé la PoC à la main, dans le cadre légal de
l'Annexe D signée, et a enregistré ses preuves (captures d'écran, traces
requête/réponse). Ce module se contente de :

  1. vérifier, via le moteur de mandat, que l'exploitation était bien autorisée
     (Annexe D signée, cible dans le périmètre, fenêtre, IP source…) — sinon il
     REFUSE et ne produit aucun dossier ;
  2. sceller les preuves fournies (SHA-256, taille, nom) ;
  3. assembler un dossier horodaté, avec chaîne de possession et rappel explicite
     des limites de l'Annexe D, exportable en JSON et en Markdown.

Le but d'une PoC d'audit est de PROUVER une faille pour la faire corriger, jamais
de nuire : aucune donnée réelle extraite/modifiée/supprimée, aucune persistance
laissée, artefacts de test retirés et listés.

Dépend uniquement de la bibliothèque standard + des modules internes
``tasko.mandat`` (verrou d'autorisation) et ``tasko.journal`` (empreintes et
journal des tests). Aucun accès réseau.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os

from . import journal as _journal          # module : empreinte_fichier, Evenement…
from .mandat import Mandat, autoriser, extraire_hote

# Rappel, affiché dans chaque dossier, des limites non négociables de l'Annexe D.
# Une PoC d'audit reste défensive : elle démontre, elle ne cause pas de dommage.
LIMITES_ANNEXE_D = (
    "Aucune donnée réelle n'a été extraite, copiée, modifiée ou supprimée.",
    "Aucune persistance n'a été laissée (compte, tâche planifiée, implant, "
    "porte dérobée, règle, clé).",
    "Les artefacts de test créés pour la PoC ont été retirés ; ils sont listés "
    "dans ce dossier.",
    "La PoC sert à PROUVER la faille afin de la CORRIGER, jamais à nuire ni à "
    "exfiltrer.",
    "Exploitation menée strictement dans le périmètre, la fenêtre et l'IP source "
    "du mandat (Annexe D signée).",
    "Aucun déni de service, aucun pivot hors périmètre, aucun « hack back ».",
)

# Étiquette d'outil utilisée dans le journal des tests (Annexe C).
OUTIL = "poc-annexe-d"


def _maintenant_utc_iso() -> str:
    """Horodatage courant en UTC, format ISO 8601 (instant du scellement)."""
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _moment_utc_iso(moment: _dt.datetime | None) -> str:
    """Convertit un ``moment`` (aware ou naïf=UTC) en ISO UTC. '' si absent."""
    if moment is None:
        return ""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=_dt.timezone.utc)
    return moment.astimezone(_dt.timezone.utc).isoformat()


def _sceller(dossier: dict) -> str:
    """SHA-256 du dossier (hors champ ``sceau``), canonicalisé en JSON trié.

    Donne une empreinte globale de scellement : toute modification ultérieure du
    dossier (preuve, étape, résultat…) change ce sceau. C'est le maillon de tête
    de la chaîne de possession, au-dessus des empreintes par preuve.
    """
    sans_sceau = {c: v for c, v in dossier.items() if c != "sceau"}
    canon = json.dumps(sans_sceau, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canon).hexdigest()


def _normaliser_finding(finding: dict) -> dict:
    """Garde les champs attendus d'un finding : cible, titre, reference?, severite?."""
    f = finding or {}
    return {
        "cible": str(f.get("cible", "")),
        "titre": str(f.get("titre", "")),
        "reference": str(f.get("reference", "")),
        "severite": str(f.get("severite", "")),
    }


def _sceller_preuve(chemin: str) -> dict:
    """Scelle une preuve : nom, chemin, SHA-256, taille, présence.

    Une preuve introuvable n'est pas fatale : elle est signalée (present=False,
    sha256='', taille=0) pour que le dossier reste honnête sur ce qui manque.
    """
    chemin = str(chemin)
    nom = os.path.basename(chemin) or chemin
    empreinte = _journal.empreinte_fichier(chemin)   # '' si le fichier est absent
    present = bool(empreinte)
    try:
        taille = os.path.getsize(chemin) if present else 0
    except OSError:
        taille = 0
    return {
        "nom": nom,
        "chemin": chemin,
        "sha256": empreinte,
        "taille": taille,
        "present": present,
    }


def documenter(
    mandat: Mandat,
    finding: dict,
    preuves,
    etapes: str,
    resultat: str,
    *,
    operateur: str | None = None,
    moment: _dt.datetime | None = None,
    ip_source: str | None = None,
    journal: str | None = None,
) -> dict:
    """Documente et scelle une PoC déjà réalisée à la main (Annexe D). N'exploite rien.

    :param mandat: mandat déjà chargé (:class:`tasko.mandat.Mandat`).
    :param finding: dict ``{cible, titre, reference?, severite?}`` — la faille prouvée.
    :param preuves: liste de chemins de fichiers de preuve (captures, traces) que
        l'opérateur a enregistrés. Chaque preuve est scellée par SHA-256 ; une
        preuve introuvable est signalée, pas fatale.
    :param etapes: descriptif des étapes de la PoC (texte).
    :param resultat: observation / résultat de la PoC (texte).
    :param operateur: nom de l'opérateur ; par défaut l'utilisateur système.
    :param moment: instant de la PoC (pour la vérification d'autorisation) ; None => maintenant.
    :param ip_source: IP d'où la PoC a été menée (vérifiée contre le mandat si fournie).
    :param journal: chemin d'un journal des tests ; si fourni, un événement
        ``outil='poc-annexe-d', decision='documenté'`` y est consigné (succès seulement).

    Vérifie d'abord l'autorisation via ``autoriser(mandat, cible, 'exploitation', …)``.
    Le type ``exploitation`` exige ``annexe_d_signee=true`` dans le mandat. **En cas
    de refus (Annexe D non signée, hors périmètre, hors fenêtre…), renvoie un dict
    de refus clair (``{'autorise': False, …}``) et N'ÉCRIT RIEN** : ni dossier, ni
    journal. On ne scelle une PoC d'exploitation que si elle était autorisée.

    :returns: en cas de succès, le dossier (dict) prêt pour :func:`rendre_markdown`
        et :func:`ecrire` ; en cas de refus, un dict ``{'autorise': False,
        'refus': raison, 'reference': …, 'finding': …}``.
    """
    f = _normaliser_finding(finding)
    cible = f["cible"]

    # 1. Verrou d'autorisation : AUCUN dossier d'exploitation sans Annexe D signée.
    decision = autoriser(mandat, cible, "exploitation", moment=moment, ip_source=ip_source)
    if not decision:
        # Refus : on ne produit aucun artefact (ni dossier, ni entrée de journal).
        return {
            "autorise": False,
            "type": OUTIL,
            "refus": decision.raison,
            "reference": decision.reference,
            "finding": f,
            "horodatage_utc": _maintenant_utc_iso(),
        }

    # 2. Scellement des preuves fournies par l'opérateur.
    preuves_scellees = [_sceller_preuve(p) for p in (preuves or [])]
    manquantes = [p["nom"] for p in preuves_scellees if not p["present"]]

    # 3. Assemblage du dossier horodaté (chaîne de possession).
    operateur = (operateur or os.environ.get("SUDO_USER")
                 or os.environ.get("USER", "") or "inconnu")
    dossier: dict = {
        "autorise": True,
        "type": OUTIL,
        "reference_mandat": mandat.reference,
        "decision": decision.raison,
        "hote": extraire_hote(cible),
        "finding": f,
        "operateur": operateur,
        "horodatage_utc": _maintenant_utc_iso(),   # instant du scellement
        "moment_poc": _moment_utc_iso(moment),     # instant déclaré de la PoC
        "ip_source": ip_source or "",
        "etapes": str(etapes or ""),
        "resultat": str(resultat or ""),
        "preuves": preuves_scellees,
        "preuves_manquantes": manquantes,
        "limites_annexe_d": list(LIMITES_ANNEXE_D),
    }
    # Sceau global, calculé en dernier (couvre tout le reste du dossier).
    dossier["sceau"] = _sceller(dossier)

    # 4. Journalisation (Annexe C), uniquement en cas de succès.
    if journal:
        _journal.enregistrer(journal, _journal.Evenement(
            reference=mandat.reference,
            cible=cible,
            type_test="exploitation",
            outil=OUTIL,
            ip_source=ip_source or "",
            decision="documenté",
            raison=decision.raison,
            empreinte=dossier["sceau"],
            details={
                "finding": f["titre"],
                "preuves": len(preuves_scellees),
                "preuves_manquantes": manquantes,
            },
        ))

    return dossier


def rendre_markdown(dossier: dict) -> str:
    """Rend un dossier de PoC lisible en Markdown (titre, finding, limites, preuves).

    Si ``dossier`` est un refus (``autorise=False``), rend une note de refus courte,
    sans aucune preuve : il n'y a pas de dossier à présenter.
    """
    if not dossier.get("autorise"):
        return (
            "# PoC Annexe D — REFUSÉE\n\n"
            f"Documentation refusée : {dossier.get('refus', 'non autorisé')}\n\n"
            f"Référence mandat : {dossier.get('reference', '')}\n\n"
            "> Aucune PoC d'exploitation n'est documentée sans autorisation "
            "(Annexe D signée et cible dans le périmètre).\n"
        )

    f = dossier.get("finding", {})
    L = ["# Dossier de preuve de concept — Annexe D", ""]
    L.append(f"**Mandat :** {dossier.get('reference_mandat', '')}  ")
    L.append(f"**Finding :** {f.get('titre', '')}  ")
    L.append(f"**Cible :** {f.get('cible', '')}  ")
    if f.get("reference"):
        L.append(f"**Référence :** {f.get('reference')}  ")
    if f.get("severite"):
        L.append(f"**Sévérité :** {f.get('severite')}  ")
    L.append(f"**Opérateur :** {dossier.get('operateur', '')}  ")
    L.append(f"**Scellé le (UTC) :** {dossier.get('horodatage_utc', '')}  ")
    if dossier.get("moment_poc"):
        L.append(f"**PoC réalisée le (UTC) :** {dossier.get('moment_poc')}  ")
    if dossier.get("ip_source"):
        L.append(f"**IP source :** {dossier.get('ip_source')}  ")
    L.append(f"**Sceau (SHA-256) :** `{dossier.get('sceau', '')}`  ")
    L += ["", "> But de cette PoC : **prouver** la faille pour la **corriger**, "
          "jamais l'exploiter pour nuire.", ""]

    # Limites et engagements de l'Annexe D.
    L += ["## Limites et engagements (Annexe D)", ""]
    for lim in dossier.get("limites_annexe_d", LIMITES_ANNEXE_D):
        L.append(f"- {lim}")
    L.append("")

    # Étapes et résultat.
    L += ["## Étapes de la PoC", "", (dossier.get("etapes") or "_(non renseigné)_"), ""]
    L += ["## Résultat observé", "", (dossier.get("resultat") or "_(non renseigné)_"), ""]

    # Tableau des preuves avec empreintes.
    preuves = dossier.get("preuves", [])
    L += ["## Preuves (scellées par SHA-256)", ""]
    if not preuves:
        L += ["_Aucune preuve fournie._", ""]
    else:
        L += ["| Nom | Taille (o) | Présent | SHA-256 |", "|---|---|---|---|"]
        for p in preuves:
            present = "oui" if p.get("present") else "**MANQUANTE**"
            emp = p.get("sha256") or "—"
            L.append(f"| {p.get('nom', '')} | {p.get('taille', 0)} | {present} | `{emp}` |")
        L.append("")
        manquantes = dossier.get("preuves_manquantes") or []
        if manquantes:
            L.append("> Preuves introuvables au scellement : "
                     + ", ".join(manquantes) + ".")
            L.append("")

    L += ["---", "",
          "*Dossier produit par un outil de preuve/intégrité : aucune exploitation "
          "n'a été exécutée par cet outil.*"]
    return "\n".join(L) + "\n"


def ecrire(dossier: dict, chemin_json: str, chemin_md: str) -> tuple[str, str]:
    """Écrit le dossier en JSON et en Markdown. Renvoie ``(chemin_json, chemin_md)``.

    Refuse d'écrire un dossier non autorisé (``autorise=False``) : un refus ne
    produit aucun fichier. Lève :class:`ValueError` dans ce cas.
    """
    if not isinstance(dossier, dict) or not dossier.get("autorise"):
        raise ValueError("refus d'écrire : dossier non autorisé (aucune PoC à sceller)")

    for chemin, contenu in (
        (chemin_json, json.dumps(dossier, ensure_ascii=False, indent=2)),
        (chemin_md, rendre_markdown(dossier)),
    ):
        os.makedirs(os.path.dirname(os.path.abspath(chemin)) or ".", exist_ok=True)
        with open(chemin, "w", encoding="utf-8") as fh:
            fh.write(contenu)
    return chemin_json, chemin_md


# ---------------------------------------------------------------------------
# Brouillon pré-rempli — gain de temps de SAISIE (pas d'exploitation ici).
# Les métadonnées du finding (cible, titre, CVE, sévérité) sont recopiées
# automatiquement ; l'opérateur ne remplit QUE la partie manuelle (étapes,
# résultat, preuves). Le scellement reste soumis au verrou Annexe D.
# ---------------------------------------------------------------------------
def modele_brouillon(finding: dict | None = None) -> str:
    """Rend un brouillon YAML de PoC, métadonnées pré-remplies depuis un finding.

    ``finding`` : dict {cible, titre, reference, severite} (p.ex. issu d'un scan).
    Si ``None``, rend un gabarit vierge. Les champs « À REMPLIR » sont la PoC
    elle-même, que l'opérateur réalise et décrit à la main.
    """
    f = finding or {}

    def q(v):  # échappe pour une valeur YAML entre guillemets doubles
        return str(v or "").replace("\\", "\\\\").replace('"', '\\"')

    return (
        "# Brouillon de PoC (Annexe D) — métadonnées PRÉ-REMPLIES depuis le finding.\n"
        "# Ne remplis QUE les champs marqués « À REMPLIR » (la PoC, faite à la main),\n"
        "# puis scelle :  tasko poc --depuis-brouillon <ce fichier> --mandat <mandat signé>\n"
        "poc:\n"
        '  reference_mandat: ""          # (optionnel) référence du mandat qui autorise\n'
        f'  cible: "{q(f.get("cible"))}"\n'
        f'  titre: "{q(f.get("titre"))}"\n'
        f'  reference: "{q(f.get("reference"))}"\n'
        f'  severite: "{q(f.get("severite"))}"\n'
        '  operateur: ""                 # ton nom\n'
        "  # --- À REMPLIR À LA MAIN (la PoC elle-même) ---\n"
        "  etapes: |\n"
        "    (décris ici, étape par étape, la PoC que TU as réalisée à la main)\n"
        "  resultat: |\n"
        "    (observation : en quoi la faille est démontrée — en lecture seule)\n"
        "  preuves:\n"
        "    - (chemin d'une capture d'écran ou d'une trace requête/réponse)\n"
    )


def charger_brouillon(chemin: str) -> dict:
    """Charge un brouillon YAML rempli. Renvoie {finding, etapes, resultat, preuves, operateur}.

    Les lignes de preuve laissées sur le gabarit (entre parenthèses) sont ignorées.
    """
    import yaml  # dépendance déjà requise par le moteur de mandat

    with open(chemin, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    p = data.get("poc", data) if isinstance(data, dict) else {}
    if not isinstance(p, dict):
        raise ValueError(f"{chemin} : brouillon illisible (clé 'poc' attendue)")

    def propre(v):
        s = str(v or "").strip()
        # ignore les placeholders du gabarit (texte entre parenthèses)
        return "" if (s.startswith("(") and s.endswith(")")) else s

    preuves = []
    for item in (p.get("preuves") or []):
        s = propre(item)
        if s:
            preuves.append(s)
    return {
        "finding": {
            "cible": propre(p.get("cible")),
            "titre": propre(p.get("titre")),
            "reference": propre(p.get("reference")),
            "severite": propre(p.get("severite")),
        },
        "reference_mandat": propre(p.get("reference_mandat")),
        "operateur": propre(p.get("operateur")) or None,
        "etapes": propre(p.get("etapes")),
        "resultat": propre(p.get("resultat")),
        "preuves": preuves,
    }
