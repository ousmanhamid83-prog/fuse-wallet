#!/usr/bin/env python3
"""tasko — point d'entrée en ligne de commande.

Sous-commandes :
  verifier   Vérifie qu'un mandat autorise un test sur une cible, MAINTENANT.
             Sort 0 si autorisé, 2 si refusé, 3 si erreur de mandat.
             C'est le garde appelé par les scripts de scan avant toute action.
  info       Affiche un résumé lisible d'un mandat.

Exemples :
  python3 -m tasko.cli verifier --mandat mandats/tchadone.mandat.yaml \\
      --cible https://tchadone.com/ --type scan_web --ip-source 198.51.100.10
  python3 -m tasko.cli info --mandat mandats/exemple.mandat.yaml
"""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .mandat import TYPES_TEST, Mandat, MandatError, autoriser

CODE_OK = 0
CODE_REFUSE = 2
CODE_ERREUR = 3


def _cmd_verifier(args: argparse.Namespace) -> int:
    try:
        mandat = Mandat.charger(args.mandat)
    except MandatError as e:
        print(f"ERREUR mandat : {e}", file=sys.stderr)
        return CODE_ERREUR

    decision = autoriser(
        mandat,
        args.cible,
        args.type,
        ip_source=args.ip_source,
    )
    etiquette = "AUTORISÉ" if decision.autorise else "REFUSÉ"
    flux = sys.stdout if decision.autorise else sys.stderr
    print(f"[{etiquette}] {decision.reference} :: {decision.raison}", file=flux)
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


def construire_parseur() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tasko", description="Tasko Defense — outils cadrés par mandat")
    p.add_argument("--version", action="version", version=f"tasko {__version__}")
    sous = p.add_subparsers(dest="commande", required=True)

    v = sous.add_parser("verifier", help="autorise (ou non) un test sur une cible")
    v.add_argument("--mandat", required=True, help="chemin du fichier .mandat.yaml")
    v.add_argument("--cible", required=True, help="URL, domaine ou IP visée")
    v.add_argument("--type", required=True, choices=TYPES_TEST, help="type de test")
    v.add_argument("--ip-source", default=None, help="IP d'où part le test (vérifiée si fournie)")
    v.set_defaults(func=_cmd_verifier)

    i = sous.add_parser("info", help="résume un mandat")
    i.add_argument("--mandat", required=True)
    i.set_defaults(func=_cmd_info)
    return p


def main(argv: list[str] | None = None) -> int:
    args = construire_parseur().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
