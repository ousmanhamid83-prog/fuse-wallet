# Tasko Defense

Boîte à outils de sécurité **défensive** pour audit et surveillance multi-sites,
cadrée par un **mandat** qui sert de verrou technique : aucun outil ne vise une
cible sans qu'un mandat **signé** la couvre, à ce moment, pour ce type de test,
depuis l'IP source déclarée.

> Principe : on **trouve** les failles, on **documente** les attaquants, on
> **préserve** les preuves, on **notifie** les autorités. Jamais d'intrusion hors
> périmètre, jamais de DoS, jamais de « hack back ».

## Le mandat comme verrou (nouveauté v3)

Le mandat juridique (`mandat/mandat-audit-v2.md`) se double d'un mandat **lisible
par machine** (`mandats/*.mandat.yaml`). Le moteur `tasko/mandat.py` l'applique :

```bash
# Résumer un mandat
python3 -m tasko.cli info --mandat mandats/tchadone.mandat.yaml

# Vérifier qu'un test est autorisé (exit 0 = oui, 2 = refusé, 3 = erreur)
python3 -m tasko.cli verifier \
    --mandat mandats/tonsite.mandat.yaml \
    --cible https://tonsite.cm/ --type scan_web --ip-source 198.51.100.10
```

Les scripts de scan appellent ce verrou automatiquement : une cible non couverte
est ignorée (scan web) ou bloque le scan (scan réseau). Tant que `signe: false`,
**rien** n'est autorisé.

En fin de scan, le logiciel produit deux livrables automatiquement :

```bash
# Rapport client trié par sévérité (Nuclei + WPScan + ZAP + Nmap agrégés)
python3 -m tasko.cli rapport --dossier rapports/<date> --mandat mandats/x.yaml -o rapport.md

# Journal des tests → Annexe C (preuve du caractère autorisé, Article 8)
python3 -m tasko.cli journal --fichier rapports/<date>/journal-tests.jsonl -o annexe-C.md

# Créer un nouveau mandat (non signé) depuis le gabarit
python3 -m tasko.cli nouveau-mandat --reference TASKO-2026-client-001 \
    --domaine client.cm --sortie mandats/client.mandat.yaml

# Documenter une PoC sous Annexe D (refuse sans Annexe D signée ; n'exécute RIEN)
python3 -m tasko.cli poc --mandat mandats/client.mandat.yaml \
    --cible https://client.cm/login --titre "SQLi /login" --reference CVE-... \
    --etapes "..." --resultat "..." --preuve capture.png --sortie poc-client

# Mode purple : rejouer des sondes INERTES contre TON honeypot et vérifier la détection
python3 -m tasko.cli purple --cible http://127.0.0.1:8080/ \
    --honeypot-log /var/log/tasko-honeypot/honeypot.log
```

Portée éthique : `poc` ne fait que **sceller** des preuves que l'opérateur a
produites à la main (autorisé par l'Annexe D) — aucune exploitation automatisée.
`purple` n'émet que des sondes **inertes et marquées** (canari) contre ton propre
honeypot ou une pré-prod sous mandat `validation_detection` ; toute cible externe
non autorisée est refusée sans qu'aucune sonde ne parte.

Pour un nouveau site : copier `mandats/exemple.mandat.yaml`, remplir le périmètre,
faire **signer** le mandat papier par le propriétaire, puis passer `signe: true`.

## Composants

| Chemin | Rôle |
|--------|------|
| `tasko/mandat.py`, `tasko/cli.py` | Moteur de mandat + CLI (le verrou) |
| `tasko/journal.py` | Journal des tests (Article 8 / Annexe C : preuve + empreintes) |
| `tasko/rapport.py` | Générateur de rapport client (Article 6 : vulnérabilités + CVSS) |
| `tasko/poc.py` | Documentation/scellement d'une PoC sous Annexe D (n'exécute rien) |
| `tasko/purple.py` | Mode purple : sondes inertes pour valider la détection (honeypot/Wazuh) |
| `mandats/` | Mandats lisibles par machine (gabarits non signés fournis) |
| `mandat/mandat-audit-v2.md` | Mandat juridique (règles d'engagement) |
| `outils/scan/scan-web.sh` | Audit web (Nuclei + WPScan), cadré par le mandat |
| `outils/scan/scan-reseau.sh` | Audit réseau (Nmap, scripts sûrs), serveur dédié |
| `outils/scan/zap-auth.yaml` + `zap-auth.sh` | Scan ZAP authentifié, cadré par le mandat |
| `outils/honeypot.py` | Pot de miel passif (faux SSH + faux admin HTTP) |
| `outils/threat-intel.py` | Analyse des logs → dossier IOC pour les autorités |
| `outils/incident/collecte-preuves.sh` | Collecte de preuves forensiquement saine |
| `docs/playbook-incident.md` | Playbook de réponse à incident |
| `GUIDE-DEPLOIEMENT.md` | Guide d'installation et chaîne d'utilisation |

## Prérequis

- Python 3.11+ et PyYAML (`sudo apt install -y python3-yaml`) pour le moteur de mandat.
- Selon les outils : `nmap`, `nuclei`, `wpscan`, Docker (ZAP). Voir `GUIDE-DEPLOIEMENT.md`.

## Tests

```bash
python3 tests/test_mandat.py      # 22 cas, sans réseau
```

## Avertissement

N'utiliser que sur des systèmes couverts par un mandat signé. L'attribution d'une
attaque et les poursuites relèvent des autorités, jamais de l'outil.
