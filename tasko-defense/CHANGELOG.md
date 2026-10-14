# Changelog — Tasko Defense

## [3.0.0] — en cours (2026-10-14)

Réécriture autour du **mandat comme verrou logiciel**, et correction des défauts
relevés par l'audit de la v2 (73 constats). Développement tracé dans `JOURNAL-DEV.md`.

### Ajouté
- **Moteur de mandat** `tasko/mandat.py` + CLI `tasko/cli.py` : un mandat lisible
  par machine autorise ou refuse chaque test (signature, dates, fenêtres horaires,
  périmètre par labels, exclusions, type de test, IP source ; `scan_reseau` exige
  un hébergement dédié ; `exploitation` exige l'Annexe D). 22 tests unitaires.
- `mandats/` : gabarits `exemple` et `tchadone` (non signés par défaut).
- `outils/scan/_garde-mandat.sh` : garde partagé appelé par les scripts de scan.
- `README.md`, `JOURNAL-DEV.md`, `requirements.txt`, `.gitignore`, `sites.txt.exemple`.

### Corrigé (scans)
- `scan-web.sh` : vérifie chaque cible contre le mandat avant tout envoi ; interprète
  le code de sortie WPScan (0/5/4) ; exige le token ; vérifie la présence de nuclei
  et wpscan ; normalise `sites.txt` (CRLF, commentaires, dernière ligne) ; noms de
  rapports indexés (plus d'écrasement) ; `nuclei -exclude-tags dos,fuzz,intrusive,brute-force`.
- `scan-reseau.sh` : vérifie le mandat (type `scan_reseau`, hébergement dédié) ;
  refuse les cibles de type option/plage/liste (anti-injection) ; NSE
  `vuln and safe and not external` (plus de scripts dos/intrusive/exploit, ni d'envoi
  de versions à des tiers) ; rapports en permissions 700.

### Corrigé (durcissement des composants — en cours)
- `outils/honeypot.py` : voir commit dédié.
- `outils/threat-intel.py` : voir commit dédié.
- `outils/incident/collecte-preuves.sh` : voir commit dédié.
- `outils/scan/zap-auth.yaml` + `zap-auth.sh` : voir commit dédié.

### Retiré
- Dossier parasite `{outils,mandat,docs}` présent dans l'archive v2.

## [2.0.0] — 2026-06 (archive d'origine)
Version auditée : mandat et playbook (bon fond), honeypot, threat-intel, collecte
de preuves, scans web/réseau, plan ZAP. Le mandat n'était qu'un document ; plusieurs
outils produisaient des résultats faux sans le signaler.
