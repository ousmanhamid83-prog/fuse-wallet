"""Tasko Defense — socle logiciel défensif, cadré par un mandat.

Ce paquet fournit le « moteur de mandat » (module :mod:`tasko.mandat`) qui
sert de verrou d'autorisation : aucun outil de test ne doit viser une cible
sans qu'un mandat SIGNÉ couvre cette cible, à ce moment, pour ce type de test,
depuis l'IP source déclarée.

Principe : on trouve, on documente, on préserve, on notifie. Jamais
d'intrusion hors périmètre, jamais de DoS, jamais de hack back.
"""

__version__ = "3.0.0-dev"
