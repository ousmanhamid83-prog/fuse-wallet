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
  vers Wazuh. **Mandat exigé pour TOUTE cible** (honeypot local inclus ; gabarit
  `mandats/honeypot-local.mandat.yaml`). Garde de cohérence hôte autorisé == hôte
  contacté. Aucun exploit, pas de DoS.
- **`preuve` branché dans `threat-intel`** : pour chaque IP suspecte, les payloads
  des extraits de preuve sont automatiquement décodés/désobfusqués (URL, base64/hex
  embarqués, gzip, fromCharCode…) et ajoutés au dossier sous `preuves_decodees`
  (couches, comportement apparent, IOC révélés). Local, hors ligne, n'exécute rien.
  `threat-intel` 2.1.0. Test d'intégration `tests/test_threat_intel_preuve.py`.
- **Verrou « en ligne sous mandat » dans `threat-intel`** : le décodage reste 100 %
  local ; l'enrichissement RÉPUTATION (AbuseIPDB, base publique — jamais la machine
  de l'attaquant) n'est activé qu'avec `--mandat <signé et valide>`. Sans mandat, même
  avec une clé, l'outil reste hors ligne (aucune requête). `--journal` consigne
  l'analyse (Annexe C) et scelle l'empreinte du dossier. Exécution « semi-auto » :
  une commande = décodage local + enrichissement en ligne si mandat.
- **Analyseur de preuves** `tasko/preuve.py` : décode/désobfusque un artefact détenu
  (base64/base64url, hex, URL, entités HTML, gzip/zlib, String.fromCharCode, \x/\u,
  rot13), identifie le *type* des hashs (MD5/SHA/bcrypt/JWT, SANS cassage), extrait les
  IOC, résume le comportement apparent. Hors ligne, n'exécute rien, ne casse/déchiffre
  aucun secret. 9 assertions.
- **CLI étendu** : `verifier` (+ `--journal`), `info`, `nouveau-mandat`
  (+ `--valide-du/--valide-au`), `journaliser`, `journal`, `rapport`, `poc`
  (+ `--depuis-brouillon`), `poc-brouillon`, `purple`, `preuve`.

- **Auto-audit** : `mandats/auto-audit.mandat.yaml` (tester ton propre parc) +
  `docs/auditer-ses-machines.md` (runbook : audit de tes machines, PoC Annexe D,
  récupération de tes fichiers perdus via sauvegardes/testdisk/photorec/ddrescue).
- **Audit de parc à l'échelle** (milliers de machines, sans les lister une par une) :
  - le mandat accepte un **fichier d'inventaire** (`perimetre.ips_fichier` /
    `domaines_fichier`) et des **plages CIDR** ; des milliers d'actifs se déclarent
    en quelques lignes.
  - `outils/scan/audit-parc.sh` : lance les scans sur tout un inventaire ; CHAQUE
    hôte est vérifié contre le mandat avant scan (hôte hors mandat = ignoré, jamais
    scanné), avec pause/rate-limit, rapports agrégés + Annexe C. Audit (on TROUVE)
    automatisé à l'échelle — jamais d'exploitation.

- **Tableau de bord — filtres, tendance, options de scan** : filtre des findings par
  **outil** (en plus de la sévérité et de la recherche) ; panneau **tendance des
  sévérités dans le temps** (charge plusieurs `findings.json` datés → graphe SVG
  accessible, légende + table) ; **options de scan sûres** dans le panneau
  d'exécution (débit req/s, pause, sévérités Nuclei en cases à cocher). Les options
  sont validées côté serveur et ne peuvent pas réactiver les tags dangereux
  (`dos/intrusive` restent exclus en dur ; `NUCLEI_SEVERITES` filtré par liste blanche).
- **Comparaison de deux audits** : `tasko diff --avant a.json --apres b.json`
  (corrigés / nouveaux / persistants) + `rapport.diff_findings` ; panneau
  « Comparer deux audits » dans le tableau de bord (client).
- **Alertes d'expiration des mandats** : `mandat.etat_validite` (non_signe / futur /
  actif / expire_bientot / expire) ; commande `tasko mandats` (liste + expiration) ;
  état affiché dans le tableau de bord (serveur).
- **Historique** (serveur) : `/api/historique` liste en lecture seule les audits et
  rapports déjà produits ; panneau dédié dans le tableau de bord.
- **Export PDF** : bouton « ⎙ PDF » (impression) + feuille de style `@media print`.
- **Accès distant sûr documenté** : tunnel SSH (le serveur reste `127.0.0.1`).
- **Serveur web LOCAL** `tasko/serveur.py` (`tasko serveur`) : donne au tableau de
  bord la capacité de **lancer** les audits (agilité), avec garde-fous stricts —
  écoute **127.0.0.1 uniquement**, **jeton** exigé, **liste d'actions figée**
  (lister les mandats, prévisualiser le verrou, lancer `audit-parc`, charger un
  rapport), chemins **confinés** au projet (anti-traversée), outils invoqués par
  liste d'arguments (jamais via un shell), hôte non local refusé. Chaque scan reste
  cadré par le mandat ; **aucune exploitation, aucune commande arbitraire**. Le
  tableau de bord active un panneau « Exécution » quand le jeton est présent.
  18 assertions de test (sécurité + audit via stubs).
- **Tableau de bord web** `ui/tableau-de-bord.html` : interface de **lecture**
  (100 % navigateur, aucun serveur, aucune exécution) pour visualiser les findings
  (synthèse par sévérité, table filtrable/triable — statut ordonné et toujours
  étiqueté), les IOC + payloads décodés du threat-intel, le journal (Annexe C) et
  l'état des mandats. Un panneau **compose** la commande d'audit de parc (sous
  mandat) à copier dans le terminal — il ne la lance pas. Données chargées via
  `tasko rapport --json findings.json` (+ dossier threat-intel + journal JSONL).
  Clair/sombre, sans dépendance externe. Palette de sévérité validée (dataviz).
- `tasko rapport --json <fichier>` : export structuré des findings pour le tableau de bord.
- **Aperçu des interfaces** : `docs/apercu-interfaces.html` — captures RÉELLES du
  terminal (aide, verrou, décodage de preuve, brouillon de PoC, rapport, purple,
  audit de parc). Tasko est un outil en ligne de commande, sans interface graphique.

### Refusé par conception (hors périmètre, non négociable)
- Pas de moteur d'exploitation automatisée NI semi-automatisée, pas de « red team
  engine », pas de cassage de hash/mot de passe, pas de déchiffrement de secret par
  clé non détenue — quel que soit le motif (y compris « ses propres machines » ou
  « récupérer ses fichiers »). L'exploitation reste un acte humain, autorisé
  (Annexe D) et documenté (`poc`). La récupération de données se fait via des outils
  dédiés (sauvegardes, récupération de système de fichiers), jamais par exploitation.
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
