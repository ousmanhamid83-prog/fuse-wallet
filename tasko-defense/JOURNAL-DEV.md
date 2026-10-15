# Journal de développement — Tasko Defense

Trace chronologique du développement, capturée au fil de l'eau (demandé par le
commanditaire). Chaque entrée = une étape, avec la décision et sa justification.
L'historique Git (une entrée par commit) complète ce journal.

---

## 2026-10-14 — Audit de l'existant (v2, archive de juin 2026)

Avant de développer, analyse technique de l'aptitude au lancement de l'archive
`tasko-defense.zip`. Méthode : 5 testeurs (un par composant) + 5 vérificateurs
indépendants (réfutation adverse) + 1 critique de complétude. 73 constats, 63
confirmés, 10 partiellement, 0 réfuté. Sévérités : 5 bloquants, 10 graves, 30
moyens, 28 mineurs. Tests en bac à sable : scanners remplacés par des stubs,
réseau simulé, seul 127.0.0.1 contacté, aucune cible réelle scannée.

Constats structurants qui orientent la v3 :
- L'autorisation (mandat) n'était qu'un document : rien, dans le logiciel, n'empêchait
  de scanner un site non couvert. → **Décision n°1 : faire du mandat un verrou logiciel.**
- Plusieurs outils tournaient en produisant des résultats faux sans le signaler
  (dossier threat-intel accusant des IP innocentes, contrôle d'intégrité des preuves
  toujours en échec, scan NSE `vuln` lançant des scripts DoS, regex ZAP jamais vraie,
  plan ZAP modifiant des données réelles). → **Décision n°2 : corriger la correction
  silencieuse et bloquer les comportements contraires au mandat (DoS, hors périmètre,
  modification de données).**
- L'installation échouait sur Ubuntu 24.04 (pip PEP 668, Go/Ruby/Docker jamais
  installés, service systemd du honeypot non démarrable). → **Décision n°3 : réparer
  l'installation et le service.**

Rapport complet : `RAPPORT-tasko-defense.md` (hors dépôt, livré au commanditaire).

## 2026-10-14 — v3 : socle logiciel

- **Import baseline** (commit « import baseline toolkit ») : l'archive est versionnée
  comme point de départ, sans le dossier parasite `{outils,mandat,docs}`.
- **Moteur de mandat** (`tasko/mandat.py`, commit dédié) : cœur de la v3. Un mandat
  lisible par machine (`mandats/*.mandat.yaml`) reflète le mandat juridique signé.
  `autoriser(mandat, cible, type_test, moment, ip_source)` refuse tout test non
  couvert. Verrous : signature obligatoire, dates de validité, fenêtres horaires
  (fuseau du mandat, gère le passage de minuit), périmètre par **labels** de domaine
  (évite le piège `exemple.cm` vs `exemple.cm.evil.net`), exclusions, type de test
  autorisé, IP source déclarée. Règles renforcées : `scan_reseau` exige un hébergement
  dédié ; `exploitation` exige l'Annexe D. 22 tests unitaires, tous verts.
  Choix : gabarit non signé = tolérant (se charge, liste les champs à remplir) ;
  mandat signé = strict (un champ invalide est une erreur, pas un test lancé par erreur).
- **Scans cadrés** (commit « scans web & réseau cadrés par le mandat ») :
  `_garde-mandat.sh` + `scan-web.sh`/`scan-reseau.sh` appellent le moteur AVANT tout
  envoi. Testé avec stubs sur 127.0.0.1 : mandat non signé → 0 appel d'outil ; mandat
  signé → scan autorisé. Corrections d'audit intégrées (code de sortie WPScan, token
  exigé, normalisation de sites.txt, `nuclei -exclude-tags dos,fuzz,intrusive,brute-force`,
  NSE `vuln and safe and not external`, anti-injection d'arguments).

## 2026-10-14 — v3 : durcissement des composants (en parallèle)

Durcissement de `honeypot.py`, `threat-intel.py`, `collecte-preuves.sh` et du plan
ZAP (`zap-auth.yaml` + lanceur `zap-auth.sh` cadré par le mandat), chacun contre la
liste précise de défauts de l'audit et du critique. Tests locaux uniquement (127.0.0.1,
réseau simulé, stubs), aucun scan réel. Détails dans le CHANGELOG et les commits.

Composants livrés (tous testés) :
- **honeypot.py** : ThreadingHTTPServer + timeout (plus de blocage), Content-Length
  plafonné, toutes les méthodes journalisées, bind avant threads (échec visible),
  journal configurable + rotation, pas de secrets dans journald.
- **threat-intel.py** : IP extraite du bon champ (fin des fausses IP manipulables),
  payloads encodés détectés, seules les IP à signature retenues, IPv6, erreurs
  AbuseIPDB gérées, dossier horodaté/haché + sidecar .sha256, requests en différé.
- **collecte-preuves.sh** : intégrité réparée (MANIFEST vérifiable), destination
  externe obligatoire, plus de faux succès disque plein, contrôle root, artefacts
  de persistance collectés, replis sans net-tools.
- **zap-auth.yaml + zap-auth.sh** : regex de session corrigée, périmètre resserré,
  scan actif non destructeur (XSS persistant OFF), rapports horodatés, lanceur
  qui exige le mandat (test_authentifie) avant docker.

### Vérification finale
`python3 -m py_compile` sur tout le Python, `bash -n` sur tous les scripts, parsing
YAML des mandats et du plan ZAP, 22/22 tests du moteur, verrou qui refuse le mandat
non signé (exit 2). Arbre propre. Prêt à pousser.

## 2026-10-15 — Volet « rouge » éthique : PoC Annexe D + mode purple

Deux fonctionnalités demandées, en restant strictement défensif et éthique.

- **`tasko/poc.py` (Annexe D)** : documente et **scelle** une PoC que l'opérateur
  a réalisée à la main (autorisé). SHA-256 par preuve + sceau global du dossier,
  rappel des limites Annexe D. **N'exécute aucune exploitation**, aucun réseau.
  Refuse sans Annexe D signée / hors périmètre. 29 assertions.
- **`tasko/purple.py` (`validation_detection`)** : rejoue des sondes **inertes
  marquées** (canari) contre le honeypot/pré-prod pour vérifier la détection,
  mesure DÉTECTÉ/NON DÉTECTÉ via le log honeypot, renvoie vers Wazuh. Boucle
  locale autorisée sans mandat ; toute autre cible exige un mandat. **Garde de
  cohérence** : hôte autorisé == hôte réellement contacté (sinon refus, 0 sonde).
  Pas d'exploit, pas de DoS (1 requête/sonde, pause entre elles).
- CLI : sous-commandes `poc` et `purple` câblées ; type `validation_detection`
  ajouté au moteur. Suite complète : 4 fichiers de tests, tous verts. Chaîne
  purple vérifiée contre le vrai honeypot local (5/5 sondes détectées).

> Décision éthique maintenue : Tasko **n'automatise pas** l'exploitation. La ligne
> « exploitation contrôlée » est active via le verrou (Annexe D) + le scellement
> de preuve ; l'acte d'exploitation reste humain, autorisé et documenté.

## 2026-10-15 — Automatiser le REMPLISSAGE de la PoC (pas l'exploitation)

Demande : gagner du temps de saisie « au niveau de l'exploitation ». Automatisé
le **clérical**, jamais l'acte offensif.

- `poc-brouillon` : lit les findings d'un dossier de scan (rapport.collecter_dossier),
  les liste, et génère un brouillon YAML dont les métadonnées (cible, titre, CVE/CWE,
  sévérité) sont recopiées depuis le finding choisi. L'opérateur ne remplit que la
  PoC (étapes/résultat/preuves) faite à la main.
- `poc --depuis-brouillon` : recharge le brouillon rempli et scelle, toujours soumis
  au verrou Annexe D (refus sans Annexe D signée — vérifié).
- `nouveau-mandat --valide-du/--valide-au` : pré-remplit les dates de validité.
- Tests : `tests/test_poc_brouillon.py` (9 assertions, dont « sceller via brouillon
  == sceller en manuel » et « verrou Annexe D intact »). Démo bout-en-bout OK :
  scan → brouillon pré-rempli → remplissage manuel → dossier scellé.

> Ligne tenue : le brouillon ne touche QUE la paperasse. L'exploitation reste
> humaine, autorisée, documentée. Aucun moteur d'exploitation, aucun cassage de
> secret n'a été ajouté.

## 2026-10-15 — Réintégration (annulation précédente = erreur de saisie)

L'annulation d'un tour précédent était une erreur de saisie de l'utilisateur.
Réintégration, par-dessus le travail ajouté depuis (`poc-brouillon`), sans rien
casser, des 3 éléments **défensifs** :

- `tasko/preuve.py` + `tests/test_preuve.py` : analyseur de décodage/désobfuscation
  d'un artefact détenu (aucun cassage, aucun réseau). Sous-commande `preuve`.
- `mandats/honeypot-local.mandat.yaml` : mandat de l'opérateur pour sa propre infra.
- `tasko/purple.py` + `tests/test_purple.py` en version **durcie** : plus d'exception
  « boucle locale » — TOUTE cible exige un mandat `validation_detection`. CLI :
  `--mandat` obligatoire pour `purple`.

Fusion ciblée de `cli.py` (ajout de l'import + `_cmd_preuve` + sous-commande
`preuve` + `purple --mandat` requis) en conservant `poc-brouillon`. Suite complète :
6 fichiers de tests, tous verts. Rien d'offensif ajouté ; le refus du moteur
d'exploitation/red-team reste entier.

## 2026-10-15 — `preuve` branché dans `threat-intel` (décodage auto des payloads)

Sur demande : brancher l'analyseur de preuves dans le threat-intel pour décoder
automatiquement les payloads repérés dans les logs — gain de temps, purement
défensif.

- Import tolérant de `tasko.preuve` dans `outils/threat-intel.py` (si absent, on
  continue sans décodage). `decoder_echantillons()` désobfusque la ligne entière
  (URL-encodage) et chaque jeton long (base64/hex embarqué) des extraits de preuve
  d'une IP, ne retient que ce qui révèle quelque chose, et ajoute `preuves_decodees`
  à l'indicateur (couches, comportement apparent, IOC révélés).
- Local, hors ligne, aucune exécution. Regex de jeton corrigée (`=` seulement en
  padding final) pour décoder un base64 embarqué après `p=`.
- `threat-intel` 2.1.0. Test `tests/test_threat_intel_preuve.py` (chaîne complète
  analyze_log → décodage). Suite complète : 7 fichiers, tous verts.

### Reste à faire (itérations futures)
- Corriger le rapport d'audit `RAPPORT-tasko-defense.md` selon les remarques du
  critique (quelques formulations à nuancer).
- Faire relire les modèles juridiques (mandat, Annexe D) par un juriste Tchad/CEMAC.
- Déployer et régler Wazuh (règle locale fournie) sur une vraie infrastructure.
- Tests d'intégration bout-en-bout sur un banc d'essai dédié (jamais en production).

> Note de méthode (capture du développement) : je ne peux pas enregistrer l'écran,
> mais ce journal + l'historique Git (commits atomiques, messages détaillés) + les
> preuves de test dans chaque message de commit constituent la trace complète et
> rejouable du développement.
