# Changelog — Tasko Defense

## [3.0.0] — en cours (2026-10-14)

Réécriture autour du **mandat comme verrou logiciel**, et correction des défauts
relevés par l'audit de la v2 (73 constats). Développement tracé dans `JOURNAL-DEV.md`.

### Ajouté
- **Brouillon de PoC pré-rempli** (gain de temps de saisie, sans automatiser
  l'exploitation) : `tasko poc-brouillon --dossier <rapports> --finding N` génère
  un brouillon YAML dont les métadonnées (cible, titre, CVE/CWE, sévérité) sont
  recopiées depuis le finding de scan ; l'opérateur ne remplit que la partie
  manuelle (étapes, résultat, preuves), puis `tasko poc --depuis-brouillon <f>`
  scelle (toujours soumis au verrou Annexe D). `nouveau-mandat` accepte
  `--valide-du/--valide-au`. 9 assertions supplémentaires.
- **Moteur de mandat** `tasko/mandat.py` + CLI `tasko/cli.py` : un mandat lisible
  par machine autorise ou refuse chaque test (signature, dates, fenêtres horaires,
  périmètre par labels, exclusions, type de test, IP source ; `scan_reseau` exige
  un hébergement dédié ; `exploitation` exige l'Annexe D). 22 tests unitaires.
- **Journal des tests** `tasko/journal.py` (Article 8 / Annexe C) : chaque décision
  et chaque lancement d'outil consignés en JSONL (horodatage UTC, opérateur, cible,
  outil, IP source, décision, empreinte SHA-256), restituables en Annexe C Markdown.
- **Générateur de rapport** `tasko/rapport.py` (Article 6) : agrège Nuclei, WPScan,
  ZAP et Nmap en findings normalisés, dédupliqués, triés par sévérité, avec CVE/CWE
  et recommandations, en rapport client Markdown. 14 tests unitaires.
- **Documentation de PoC** `tasko/poc.py` (Annexe D) : scelle les preuves d'une PoC
  réalisée à la main (SHA-256 par preuve + sceau global du dossier, rappel des limites
  Annexe D). N'exécute AUCUNE exploitation ; refuse sans Annexe D signée. 29 assertions.
- **Mode purple** `tasko/purple.py` (type `validation_detection`) : rejoue des sondes
  INERTES et marquées d'un canari contre le honeypot/une pré-prod pour vérifier que la
  détection se déclenche ; mesure DÉTECTÉ/NON DÉTECTÉ via le log honeypot et renvoie
  vers Wazuh. Boucle locale autorisée sans mandat ; toute autre cible exige un mandat.
  Garde de cohérence hôte autorisé == hôte contacté. Aucun exploit, pas de DoS.
- **CLI étendu** : `verifier` (+ `--journal`), `info`, `nouveau-mandat`, `journaliser`,
  `journal`, `rapport`, `poc`, `purple`.
- Scans câblés : journalisation automatique (empreintes) + génération du rapport et
  de l'Annexe C en fin d'exécution.
- `mandats/` : gabarits `exemple` et `tchadone` (non signés par défaut).
- `outils/scan/_garde-mandat.sh` : garde partagé + helpers journal/rapport.
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

### Corrigé (durcissement des composants)
- `outils/honeypot.py` : ThreadingHTTPServer + timeout, Content-Length plafonné,
  toutes les méthodes journalisées, bind avant threads, journal configurable +
  rotation, pas de secrets dans journald, champ `srcip`.
- `outils/threat-intel.py` : IP cliente extraite du bon champ, payloads encodés
  détectés, seules les IP à signature retenues (+ allowlist), IPv6, erreurs
  AbuseIPDB gérées, dossier enrichi + `.sha256`, `requests` en différé.
- `outils/incident/collecte-preuves.sh` : intégrité réparée, destination externe
  obligatoire, plus de faux succès disque plein, contrôle root, persistances
  collectées, replis sans net-tools.
- `outils/scan/zap-auth.yaml` + `zap-auth.sh` : regex de session corrigée,
  périmètre resserré, scan actif non destructeur, rapports horodatés, lanceur
  cadré par le mandat (type `test_authentifie`).

### Retiré
- Dossier parasite `{outils,mandat,docs}` présent dans l'archive v2.

## [2.0.0] — 2026-06 (archive d'origine)
Version auditée : mandat et playbook (bon fond), honeypot, threat-intel, collecte
de preuves, scans web/réseau, plan ZAP. Le mandat n'était qu'un document ; plusieurs
outils produisaient des résultats faux sans le signaler.
