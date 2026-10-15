#!/usr/bin/env python3
"""tasko — point d'entrée en ligne de commande (défensif, cadré par mandat).

Sous-commandes :
  verifier       Autorise (ou non) un test sur une cible, MAINTENANT. Exit 0/2/3.
                 Journalise la décision si --journal est fourni.
  info           Résumé lisible d'un mandat.
  nouveau-mandat Crée un mandat machine (non signé) depuis le gabarit, puis le valide.
  journaliser    Ajoute une entrée au journal des tests (Article 8 / Annexe C).
  journal        Restitue le journal des tests sous forme d'Annexe C (Markdown).
  rapport        Agrège les sorties de scan d'un dossier en un rapport client (Art. 6).
"""
from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .mandat import TYPES_TEST, Mandat, MandatError, autoriser
from . import journal as _journal
from . import rapport as _rapport
from . import poc as _poc
from . import purple as _purple
from . import preuve as _preuve

CODE_OK = 0
CODE_REFUSE = 2
CODE_ERREUR = 3

_RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _cmd_verifier(args: argparse.Namespace) -> int:
    try:
        mandat = Mandat.charger(args.mandat)
    except MandatError as e:
        print(f"ERREUR mandat : {e}", file=sys.stderr)
        return CODE_ERREUR

    decision = autoriser(mandat, args.cible, args.type, ip_source=args.ip_source)
    etiquette = "AUTORISÉ" if decision.autorise else "REFUSÉ"
    flux = sys.stdout if decision.autorise else sys.stderr
    print(f"[{etiquette}] {decision.reference} :: {decision.raison}", file=flux)

    if args.journal:
        _journal.enregistrer(args.journal, _journal.Evenement(
            reference=decision.reference, cible=args.cible, type_test=args.type,
            outil=args.outil or "tasko-gate", ip_source=args.ip_source or "",
            decision="autorisé" if decision.autorise else "refusé",
            raison=decision.raison,
        ))
    return CODE_OK if decision.autorise else CODE_REFUSE


def _cmd_info(args: argparse.Namespace) -> int:
    try:
        m = Mandat.charger(args.mandat)
    except MandatError as e:
        print(f"ERREUR mandat : {e}", file=sys.stderr)
        return CODE_ERREUR
    actifs = [t for t in TYPES_TEST if m.tests_autorises.get(t)]
    print(f"Référence     : {m.reference}")
    print(f"Signé         : {'OUI' if m.signe else 'NON (aucun test autorisé)'}")
    print(f"Validité      : {m.valide_du} → {m.valide_au}  ({m.fuseau})")
    print(f"Fenêtres      : {len(m.fenetres)} définie(s)")
    print(f"IP source     : {', '.join(m.ip_source) or '(aucune déclarée)'}")
    print(f"Domaines      : {', '.join(m.domaines) or '(aucun)'}")
    print(f"IPs/plages    : {', '.join(m.ips) or '(aucune)'}")
    print(f"Hébergt dédié : {'oui' if m.heberge_dedie else 'non'}")
    print(f"Tests actifs  : {', '.join(actifs) or '(aucun)'}")
    print(f"Annexe D      : {'signée' if m.annexe_d_signee else 'non signée'}")
    if m.problemes:
        print(f"À compléter   : {len(m.problemes)} champ(s) à remplir avant signature :")
        for p in m.problemes:
            print(f"                - {p}")
    return CODE_OK


def _cmd_nouveau_mandat(args: argparse.Namespace) -> int:
    gabarit = os.path.join(_RACINE, "mandats", "exemple.mandat.yaml")
    if not os.path.isfile(gabarit):
        print(f"ERREUR : gabarit introuvable : {gabarit}", file=sys.stderr)
        return CODE_ERREUR
    if os.path.exists(args.sortie) and not args.force:
        print(f"ERREUR : {args.sortie} existe déjà (utilise --force pour écraser).", file=sys.stderr)
        return CODE_ERREUR
    with open(gabarit, "r", encoding="utf-8") as f:
        contenu = f.read()
    contenu = contenu.replace("TASKO-2026-exemple-001", args.reference)
    if args.domaine:
        contenu = contenu.replace('- "exemple.cm"', f'- "{args.domaine}"')
    if args.valide_du:
        contenu = contenu.replace('valide_du: "2026-01-01"', f'valide_du: "{args.valide_du}"')
    if args.valide_au:
        contenu = contenu.replace('valide_au: "2026-12-31"', f'valide_au: "{args.valide_au}"')
    os.makedirs(os.path.dirname(os.path.abspath(args.sortie)) or ".", exist_ok=True)
    with open(args.sortie, "w", encoding="utf-8") as f:
        f.write(contenu)
    print(f"Mandat créé (NON signé) : {args.sortie}")
    print("Prochaines étapes : remplir le périmètre/les dates, faire SIGNER le mandat")
    print("papier, puis passer `signe: true`. Tant que c'est non signé, aucun test n'est autorisé.")
    try:
        m = Mandat.charger(args.sortie)
        if m.problemes:
            print(f"\nChamps restant à compléter ({len(m.problemes)}) :")
            for p in m.problemes:
                print(f"  - {p}")
    except MandatError as e:
        print(f"AVERTISSEMENT validation : {e}", file=sys.stderr)
    return CODE_OK


def _cmd_journaliser(args: argparse.Namespace) -> int:
    empreinte = _journal.empreinte_fichier(args.empreinte_de) if args.empreinte_de else ""
    ligne = _journal.enregistrer(args.fichier, _journal.Evenement(
        reference=args.reference, cible=args.cible, type_test=args.type or "",
        outil=args.outil, ip_source=args.ip_source or "", decision=args.decision,
        raison=args.raison or "", empreinte=empreinte,
    ))
    print(f"Journalisé : {ligne['horodatage_utc']} {ligne['outil']} {ligne['cible']} "
          f"[{ligne['decision']}]" + (f" empreinte={empreinte[:12]}" if empreinte else ""))
    return CODE_OK


def _cmd_journal(args: argparse.Namespace) -> int:
    sortie = _journal.rendre_annexe_c(args.fichier)
    if args.sortie:
        with open(args.sortie, "w", encoding="utf-8") as f:
            f.write(sortie)
        print(f"Annexe C écrite : {args.sortie}")
    else:
        sys.stdout.write(sortie)
    return CODE_OK


def _cmd_rapport(args: argparse.Namespace) -> int:
    if not os.path.isdir(args.dossier):
        print(f"ERREUR : dossier introuvable : {args.dossier}", file=sys.stderr)
        return CODE_ERREUR
    reference = ""
    if args.mandat:
        try:
            reference = Mandat.charger(args.mandat).reference
        except MandatError:
            reference = ""
    findings = _rapport.collecter_dossier(args.dossier)
    md = _rapport.rendre_markdown(findings, reference_mandat=reference,
                                  date=args.date or "", operateur=args.operateur or "")
    if args.sortie:
        with open(args.sortie, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"Rapport écrit : {args.sortie} ({len(findings)} finding(s))")
    else:
        sys.stdout.write(md)
    return CODE_OK


def _cmd_poc(args: argparse.Namespace) -> int:
    try:
        mandat = Mandat.charger(args.mandat)
    except MandatError as e:
        print(f"ERREUR mandat : {e}", file=sys.stderr)
        return CODE_ERREUR

    if args.depuis_brouillon:
        try:
            br = _poc.charger_brouillon(args.depuis_brouillon)
        except (OSError, ValueError) as e:
            print(f"ERREUR brouillon : {e}", file=sys.stderr)
            return CODE_ERREUR
        finding = br["finding"]
        etapes, resultat = br["etapes"], br["resultat"]
        preuves = br["preuves"]
        operateur = args.operateur or br["operateur"]
    else:
        manquants = [n for n, v in (("--cible", args.cible), ("--titre", args.titre),
                                    ("--etapes", args.etapes), ("--resultat", args.resultat))
                     if not v]
        if manquants:
            print("ERREUR : champ(s) requis manquant(s) (ou utilise --depuis-brouillon) : "
                  + ", ".join(manquants), file=sys.stderr)
            return CODE_ERREUR
        finding = {"cible": args.cible, "titre": args.titre,
                   "reference": args.reference or "", "severite": args.severite or ""}
        etapes, resultat = args.etapes, args.resultat
        preuves = args.preuve or []
        operateur = args.operateur

    dossier = _poc.documenter(
        mandat, finding, preuves, etapes, resultat,
        operateur=operateur, ip_source=args.ip_source, journal=args.journal)
    if not dossier.get("autorise"):
        print(f"[REFUSÉ] {dossier.get('refus', 'non autorisé')}", file=sys.stderr)
        print(">>> Aucune PoC scellée. L'exploitation exige un mandat couvrant la cible "
              "avec l'Annexe D signée.", file=sys.stderr)
        return CODE_REFUSE
    if args.sortie:
        cj, cm = _poc.ecrire(dossier, args.sortie + ".json", args.sortie + ".md")
        print(f"PoC documentée et scellée : {cj} / {cm}")
    else:
        sys.stdout.write(_poc.rendre_markdown(dossier))
    return CODE_OK


def _cmd_poc_brouillon(args: argparse.Namespace) -> int:
    if not args.dossier:
        sortie_texte = _poc.modele_brouillon(None)   # gabarit vierge
    else:
        if not os.path.isdir(args.dossier):
            print(f"ERREUR : dossier introuvable : {args.dossier}", file=sys.stderr)
            return CODE_ERREUR
        findings = _rapport.trier(_rapport.collecter_dossier(args.dossier))
        if not findings:
            print("Aucun finding exploitable dans ce dossier.", file=sys.stderr)
            return CODE_ERREUR
        if args.finding is None:
            print(f"{len(findings)} finding(s) — relance avec --finding <N> pour pré-remplir :")
            for i, f in enumerate(findings, 1):
                ref = f" [{f.reference}]" if f.reference else ""
                print(f"  {i}. [{f.severite}] {f.titre} — {f.cible}{ref}")
            return CODE_OK
        if args.finding < 1 or args.finding > len(findings):
            print(f"ERREUR : --finding doit être entre 1 et {len(findings)}", file=sys.stderr)
            return CODE_ERREUR
        f = findings[args.finding - 1]
        sortie_texte = _poc.modele_brouillon({
            "cible": f.cible, "titre": f.titre,
            "reference": f.reference, "severite": f.severite})

    if args.sortie:
        with open(args.sortie, "w", encoding="utf-8") as fh:
            fh.write(sortie_texte)
        print(f"Brouillon écrit : {args.sortie}")
        print("Remplis les champs « À REMPLIR », puis scelle :")
        print(f"  tasko poc --depuis-brouillon {args.sortie} --mandat <mandat signé>")
    else:
        sys.stdout.write(sortie_texte)
    return CODE_OK


def _cmd_purple(args: argparse.Namespace) -> int:
    mandat = None
    if args.mandat:
        try:
            mandat = Mandat.charger(args.mandat)
        except MandatError as e:
            print(f"ERREUR mandat : {e}", file=sys.stderr)
            return CODE_ERREUR
    rapport = _purple.rejouer(
        args.cible, mandat=mandat, ip_source=args.ip_source, journal=args.journal,
        reference=args.reference or "", honeypot_log=args.honeypot_log, pause=args.pause)
    md = _purple.rendre_markdown(rapport)
    if args.ssh and rapport.get("autorise"):
        rssh = _purple.sonder_ssh(args.cible, port=args.ssh_port, mandat=mandat,
                                  ip_source=args.ip_source, journal=args.journal,
                                  reference=args.reference or "")
        md += (f"\n## Sonde SSH (port {rssh.get('port')})\n\n"
               f"- Canari : {rssh.get('canari')}\n"
               f"- Bannière reçue : {rssh.get('banniere_recue')}\n"
               f"- Envoyée : {rssh.get('envoyees')} | Erreur : {rssh.get('erreur')}\n")
    if args.sortie:
        with open(args.sortie, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"Rapport purple écrit : {args.sortie}")
    else:
        sys.stdout.write(md)
    return CODE_OK if rapport.get("autorise") else CODE_REFUSE


def _cmd_preuve(args: argparse.Namespace) -> int:
    if args.fichier:
        if not os.path.isfile(args.fichier):
            print(f"ERREUR : fichier introuvable : {args.fichier}", file=sys.stderr)
            return CODE_ERREUR
        analyse = _preuve.analyser(args.fichier, est_fichier=True)
    elif args.texte is not None:
        analyse = _preuve.analyser(args.texte)
    else:
        print("ERREUR : fournir --fichier ou --texte", file=sys.stderr)
        return CODE_ERREUR
    md = _preuve.rendre_markdown(analyse)
    if args.sortie:
        with open(args.sortie, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"Analyse écrite : {args.sortie} "
              f"({analyse['deobfuscation']['profondeur']} couche(s) décodée(s))")
    else:
        sys.stdout.write(md)
    return CODE_OK


def construire_parseur() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tasko", description="Tasko Defense — outils cadrés par mandat")
    p.add_argument("--version", action="version", version=f"tasko {__version__}")
    sous = p.add_subparsers(dest="commande", required=True)

    v = sous.add_parser("verifier", help="autorise (ou non) un test sur une cible")
    v.add_argument("--mandat", required=True)
    v.add_argument("--cible", required=True)
    v.add_argument("--type", required=True, choices=TYPES_TEST)
    v.add_argument("--ip-source", default=None)
    v.add_argument("--journal", default=None, help="fichier journal où consigner la décision")
    v.add_argument("--outil", default=None, help="nom de l'outil à consigner (déf. tasko-gate)")
    v.set_defaults(func=_cmd_verifier)

    i = sous.add_parser("info", help="résume un mandat")
    i.add_argument("--mandat", required=True)
    i.set_defaults(func=_cmd_info)

    nm = sous.add_parser("nouveau-mandat", help="crée un mandat machine (non signé) depuis le gabarit")
    nm.add_argument("--reference", required=True, help="référence du mandat, ex. TASKO-2026-client-001")
    nm.add_argument("--sortie", required=True, help="chemin du fichier .mandat.yaml à créer")
    nm.add_argument("--domaine", default=None, help="domaine principal du périmètre")
    nm.add_argument("--valide-du", default=None, help="date de début de validité (AAAA-MM-JJ)")
    nm.add_argument("--valide-au", default=None, help="date de fin de validité (AAAA-MM-JJ)")
    nm.add_argument("--force", action="store_true", help="écrase un fichier existant")
    nm.set_defaults(func=_cmd_nouveau_mandat)

    j = sous.add_parser("journaliser", help="ajoute une entrée au journal des tests")
    j.add_argument("--fichier", required=True)
    j.add_argument("--reference", default="")
    j.add_argument("--cible", default="")
    j.add_argument("--type", default=None, choices=[*TYPES_TEST, None])
    j.add_argument("--outil", required=True)
    j.add_argument("--ip-source", default=None)
    j.add_argument("--decision", default="lancé", help="autorisé|refusé|lancé|terminé")
    j.add_argument("--raison", default=None)
    j.add_argument("--empreinte-de", default=None, help="fichier dont on consigne le SHA-256")
    j.set_defaults(func=_cmd_journaliser)

    jr = sous.add_parser("journal", help="restitue le journal en Annexe C (Markdown)")
    jr.add_argument("--fichier", required=True)
    jr.add_argument("--sortie", default=None, help="fichier de sortie (sinon stdout)")
    jr.set_defaults(func=_cmd_journal)

    r = sous.add_parser("rapport", help="agrège un dossier de scans en rapport client")
    r.add_argument("--dossier", required=True, help="dossier de rapports (nuclei/wpscan/zap/nmap)")
    r.add_argument("--mandat", default=None, help="mandat pour renseigner la référence")
    r.add_argument("--date", default=None)
    r.add_argument("--operateur", default=None)
    r.add_argument("--sortie", default=None, help="fichier .md de sortie (sinon stdout)")
    r.set_defaults(func=_cmd_rapport)

    pc = sous.add_parser("poc", help="documente et scelle une PoC sous Annexe D (n'exécute rien)")
    pc.add_argument("--mandat", required=True)
    pc.add_argument("--depuis-brouillon", default=None,
                    help="brouillon YAML rempli (voir 'poc-brouillon') : remplit tout sauf le mandat")
    pc.add_argument("--cible", default=None)
    pc.add_argument("--titre", default=None, help="intitulé du finding / de la faille")
    pc.add_argument("--reference", default=None, help="CVE/CWE/ref template")
    pc.add_argument("--severite", default=None)
    pc.add_argument("--etapes", default=None, help="étapes de la PoC réalisées à la main")
    pc.add_argument("--resultat", default=None, help="observation / preuve d'exploitabilité")
    pc.add_argument("--preuve", action="append", help="fichier de preuve (répétable)")
    pc.add_argument("--operateur", default=None)
    pc.add_argument("--ip-source", default=None)
    pc.add_argument("--journal", default=None)
    pc.add_argument("--sortie", default=None, help="base du chemin (.json/.md seront créés)")
    pc.set_defaults(func=_cmd_poc)

    pb = sous.add_parser("poc-brouillon",
                         help="génère un brouillon de PoC pré-rempli depuis un finding de scan")
    pb.add_argument("--dossier", default=None, help="dossier de rapports (nuclei/wpscan/zap/nmap)")
    pb.add_argument("--finding", type=int, default=None,
                    help="n° du finding (1-based) ; sans lui, liste les findings")
    pb.add_argument("--sortie", default=None, help="fichier brouillon .yaml (sinon stdout)")
    pb.set_defaults(func=_cmd_poc_brouillon)

    pu = sous.add_parser("purple", help="rejoue des sondes inertes pour valider la détection")
    pu.add_argument("--cible", required=True, help="URL du honeypot/pré-prod (http://127.0.0.1:8080/)")
    pu.add_argument("--mandat", required=True, help="mandat signé autorisant validation_detection (requis pour TOUTE cible, honeypot local inclus)")
    pu.add_argument("--ip-source", default=None)
    pu.add_argument("--journal", default=None)
    pu.add_argument("--reference", default=None)
    pu.add_argument("--honeypot-log", default=None, help="journal honeypot à relire pour mesurer la détection")
    pu.add_argument("--pause", type=float, default=0.2, help="pause (s) entre sondes")
    pu.add_argument("--ssh", action="store_true", help="ajoute une sonde SSH inerte")
    pu.add_argument("--ssh-port", type=int, default=2222)
    pu.add_argument("--sortie", default=None)
    pu.set_defaults(func=_cmd_purple)

    pe = sous.add_parser("preuve", help="décode/désobfusque un artefact détenu (défensif, hors ligne)")
    pe.add_argument("--fichier", default=None, help="chemin d'un artefact (payload, extrait de log)")
    pe.add_argument("--texte", default=None, help="artefact fourni directement en argument")
    pe.add_argument("--sortie", default=None, help="fichier .md de sortie (sinon stdout)")
    pe.set_defaults(func=_cmd_preuve)
    return p


def main(argv: list[str] | None = None) -> int:
    args = construire_parseur().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
