# Tasko Defense — Guide de déploiement
## Plateforme de sécurité défensive pour audit et surveillance multi-sites

Ce guide relie tous les outils en **une chaîne cohérente** : du cadre légal
(mandat) jusqu'à la surveillance continue, en passant par l'audit, le
renseignement sur les menaces et la réponse à incident.

> **Principe fondateur de Tasko.** On **trouve** les failles, on **documente** les
> attaquants, on **préserve** les preuves, on **notifie** les autorités. On ne
> franchit jamais la ligne : pas d'intrusion sur un système tiers, pas de hack
> back, pas de DoS. C'est exactement ce qui fait une boîte de sécurité respectée.

---

## Vue d'ensemble — comment tout s'articule

```
                    ┌─────────────────────────────────────┐
                    │   ÉTAPE 0 — CADRE LÉGAL (obligatoire) │
                    │   mandat/ : signé AVANT tout test    │
                    └──────────────────┬──────────────────┘
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        ▼                               ▼                              ▼
┌───────────────┐            ┌───────────────────┐         ┌──────────────────┐
│ AUDIT (trouver)│            │ SURVEILLANCE       │         │ RÉPONSE INCIDENT  │
│ outils/scan/   │            │ (observer)         │         │ outils/incident/  │
│ - scan-web.sh  │            │ - honeypot.py      │         │ - collecte-       │
│ - zap-auth.yaml│            │ - Wazuh (SIEM)     │         │   preuves.sh      │
│ - scan-reseau  │            └─────────┬─────────┘         │ docs/playbook     │
└───────┬────────┘                      │                   └────────┬─────────┘
        │                               │                            │
        │         ┌─────────────────────▼─────────────────────┐      │
        │         │  THREAT INTELLIGENCE (documenter)          │      │
        └────────►│  outils/threat-intel.py                    │◄─────┘
                  │  Analyse les logs (audit + honeypot +      │
                  │  incident) → IOC + réputation → dossier    │
                  │  pour les AUTORITÉS                         │
                  └────────────────────────────────────────────┘
                                       │
                                       ▼
                        ┌──────────────────────────────┐
                        │  WAZUH centralise TOUS les logs│
                        │  (scan, honeypot, incident)   │
                        │  hors des serveurs surveillés  │
                        └──────────────────────────────┘
```

**La logique du flux** : le mandat autorise → l'audit trouve les failles → le
honeypot et Wazuh observent les attaques → le threat-intel transforme les logs
(de l'audit, du honeypot, des incidents) en dossier d'attribution → la réponse à
incident préserve les preuves → tout remonte dans Wazuh, hors d'atteinte d'un
attaquant qui nettoierait un serveur compromis.

---

## Architecture matérielle recommandée

| Élément | Où | Pourquoi |
|---------|-----|----------|
| **Nœud d'audit** | VPS Hostinger KVM (4 Go RAM) | Lance scans + threat-intel ; séparé des sites |
| **Serveur Wazuh** | Même VPS ou un second (8 Go RAM) | Centralise les logs ; OpenSearch est gourmand |
| **Honeypot** | VPS isolé OU conteneur dédié | Doit être isolé : c'est une cible volontaire |
| **Sites clients** | Leur hébergement (Hostinger, etc.) | Audités à distance, sous mandat |

> Pour un petit portefeuille, audit + Wazuh peuvent cohabiter sur un VPS correct.
> Le honeypot, lui, **doit** être isolé du reste : par définition on l'expose aux
> attaquants.

---

## Déploiement pas à pas

### Étape 0 — Cadre légal (jamais sauter)

1. Pour **chaque** client, remplir `mandat/mandat-audit-v2.md`.
2. Vérifier la cohérence des dates (période qui part de la signature).
3. Faire signer **avant** tout test. Conserver l'original + copie horodatée.
4. **Faire valider le modèle par un juriste** (Tchad / CEMAC) avant usage commercial.

> Sans mandat signé, aucun scan ne doit partir. C'est ce qui distingue l'audit
> légitime de l'accès non autorisé — et ce qui protège Tasko juridiquement.

### Étape 0 bis — Charger le mandat dans le logiciel

Le mandat juridique signé (Étape 0) se double d'un mandat **lisible par machine**
qui sert de verrou : les outils refusent toute cible non couverte.

```bash
cd tasko-defense
cp mandats/exemple.mandat.yaml mandats/monclient.mandat.yaml
# Remplis le périmètre (domaines/IP), les dates, la fenêtre horaire, l'IP source,
# puis — UNIQUEMENT après signature du mandat papier — passe `signe: true`.

python3 -m tasko.cli info --mandat mandats/monclient.mandat.yaml      # résumé
python3 -m tasko.cli verifier --mandat mandats/monclient.mandat.yaml \
    --cible https://monclient.cm/ --type scan_web --ip-source <IP d'audit>
# exit 0 = autorisé, 2 = refusé, 3 = erreur de mandat
```

> Tant que `signe: false`, **aucun** test n'est autorisé. On peut gérer plusieurs
> clients : un fichier `mandats/<client>.mandat.yaml` par mandat signé.

### Étape 1 — Préparer le nœud d'audit (VPS Ubuntu 24.04)

```bash
# Dépendances via apt (sur Ubuntu 24.04, `pip install` est refusé par PEP 668).
sudo apt update
sudo apt install -y python3-yaml python3-requests nmap \
     ruby-full build-essential libcurl4-openssl-dev zlib1g-dev docker.io
sudo gem install wpscan
sudo usermod -aG docker "$USER"   # puis se reconnecter (ZAP via docker)

# Nuclei : binaire officiel (évite une compilation Go longue sur un petit VPS).
NUCLEI_VER=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
  | grep -oP '"tag_name":\s*"v\K[0-9.]+')
curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_amd64.zip" -o /tmp/nuclei.zip
sudo unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin/

# Récupère ce dépôt sur le VPS (scp, git, ou upload via hPanel).
```

### Étape 2 — Lancer un audit (cadré par le mandat)

Les scripts interrogent le mandat avant tout envoi : une cible non couverte est
ignorée (scan web) ou bloque le scan (scan réseau). Déclare le mandat et ton IP.

```bash
cd tasko-defense/outils/scan
export MANDAT=../../mandats/monclient.mandat.yaml   # mandat SIGNÉ
export AUDIT_IP=198.51.100.10                        # ton IP source (Article 3)

# 2a. Scan web — cibles dans sites.txt (copie sites.txt.exemple), ou en argument.
export WPSCAN_API_TOKEN="ton_token"
bash scan-web.sh                       # ou : bash scan-web.sh https://monclient.cm/

# 2b. Scan authentifié ZAP — le lanceur vérifie le mandat (test_authentifie) d'abord.
#     À réserver de préférence à une copie de PRÉ-PROD (le scan actif écrit des données).
export ZAP_USER="compte_test" ZAP_PWD="motdepasse"
TARGET="https://monclient.cm/" bash zap-auth.sh

# 2c. Scan réseau — UNIQUEMENT un serveur DÉDIÉ du client (jamais du mutualisé).
#     Exige `heberge_dedie: true` et `scan_reseau: true` dans le mandat.
bash scan-reseau.sh ip-du-serveur-client
```

Trie les findings par sévérité (**critical/high** d'abord), livre le rapport
chiffré, et relance après correction pour vérifier.

### Étape 3 — Déployer le honeypot (sur infra isolée)

```bash
# 1) Crée l'utilisateur de service et installe le code sous /opt.
sudo useradd --system --no-create-home --shell /usr/sbin/nologin honeypot
sudo cp -r tasko-defense /opt/

# 2) Ouvre les ports honeypot, et ACTIVE le pare-feu.
# ⚠️ AVANT d'activer ufw : autorise ton VRAI SSH d'admin, sinon tu te verrouilles dehors.
sudo ufw allow OpenSSH    # ou : sudo ufw allow 22/tcp (ton port SSH réel)
sudo ufw allow 2222/tcp   # faux SSH (honeypot)
sudo ufw allow 8080/tcp   # faux panneau admin (honeypot)
sudo ufw enable           # sans ça, les règles ne s'appliquent pas
```

Service systemd (`/etc/systemd/system/honeypot.service`) :
```ini
[Unit]
Description=Tasko Honeypot
After=network.target
[Service]
User=honeypot
Group=honeypot
# LogsDirectory crée /var/log/tasko-honeypot/ APPARTENANT à l'utilisateur honeypot.
LogsDirectory=tasko-honeypot
Environment=HONEYPOT_LOG=/var/log/tasko-honeypot/honeypot.log PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 /opt/tasko-defense/outils/honeypot.py
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl daemon-reload && sudo systemctl enable --now honeypot
```

> Pourquoi ces correctifs : sans l'utilisateur `honeypot` créé et sans un
> répertoire de log inscriptible (`LogsDirectory` + `HONEYPOT_LOG`), le service
> démarrait « active (running) » mais n'enregistrait rien.

### Étape 4 — Renseignement sur les menaces

```bash
cd tasko-defense/outils
# La clé AbuseIPDB est FACULTATIVE : sans elle, l'analyse tourne hors ligne
# (requests n'est importé que si la clé est définie).
export ABUSEIPDB_KEY="ta_cle_gratuite"   # abuseipdb.com, 1000 req/jour

# Analyser les logs d'un site attaqué (l'IP cliente est lue dans le bon champ)
python3 threat-intel.py /var/log/nginx/access.log --type web

# Tentatives SSH
python3 threat-intel.py /var/log/auth.log --type auth

# Captures du HONEYPOT (les attaquants s'y dévoilent le plus)
python3 threat-intel.py /var/log/tasko-honeypot/honeypot.log --type web

# Optionnel : rattacher le dossier au mandat qui a autorisé l'analyse
python3 threat-intel.py /var/log/nginx/access.log --type web \
    --mandat-ref TASKO-2026-monclient-001
```

Le dossier JSON (IOC + réputation + signatures, plus l'empreinte SHA-256 du log
source, les horodatages et des extraits de preuve) est accompagné d'un `.sha256`
et destiné aux autorités. Seules les IP **clientes** sont retenues (plus de faux
positifs tirés des User-Agent ou des payloads). Aucune machine attaquante n'est
contactée.

### Étape 5 — Réponse à incident (le jour J)

Si un client est compromis, suis `docs/playbook-incident.md`. L'ordre **non
négociable** :

```
ISOLER  →  PRÉSERVER  →  ÉRADIQUER  →  RÉTABLIR   (jamais : effacer d'abord)
```

```bash
# Sur le serveur compromis, en root, APRÈS avoir pris un snapshot VPS.
# Le dossier de preuves est écrit sur un support EXTERNE (argument obligatoire),
# jamais sur le disque compromis.
sudo bash tasko-defense/outils/incident/collecte-preuves.sh /mnt/preuves-externe
```
Le script fige l'état volatil (processus, réseau, sessions), copie les logs et
les artefacts de persistance, et **hache tout** (SHA-256). Il vérifie ensuite
l'intégrité : `sha256sum -c MANIFEST.txt` doit passer, et l'empreinte du manifest
est affichée pour être notée hors du serveur. Puis : threat-intel sur les logs
collectés → dossier autorités.

> Note : le snapshot Hostinger est un point de restauration **disque** (il ne
> garantit pas la capture de la RAM). Pour une image mémoire, fais intervenir un
> professionnel DFIR avant toute manipulation.

### Étape 6 — Centralisation Wazuh (surveillance continue)

Wazuh joue le rôle clé : il **détecte** en temps réel ET **conserve les logs hors
des serveurs surveillés** — donc des preuves qu'un attaquant ne peut pas effacer.

Sur chaque serveur surveillé (sites clients sous mandat, honeypot, nœud d'audit),
installe l'agent Wazuh et fais-lui ingérer :
- les logs web (Nginx/Apache)
- les logs d'authentification (SSH)
- le `honeypot.log` (format JSON déjà compatible)

```xml
<!-- Sur le honeypot : /var/ossec/etc/ossec.conf -->
<localfile>
  <log_format>json</log_format>
  <location>/var/log/tasko-honeypot/honeypot.log</location>
  <label key="@source">tasko-honeypot</label>
</localfile>
```

**Important :** ingérer le log ne suffit pas. Par défaut, aucune règle Wazuh ne
correspond aux champs du honeypot, donc aucune alerte n'est levée et l'événement
n'est pas archivé. Ajoute une règle locale sur le **manager**
(`/var/ossec/etc/rules/local_rules.xml`) :

```xml
<group name="tasko,honeypot,">
  <rule id="100200" level="5">
    <decoded_as>json</decoded_as>
    <field name="honeypot">\.+</field>
    <description>Tasko honeypot $(honeypot) — accès depuis $(source_ip)</description>
  </rule>
</group>
```

Valide avec `wazuh-logtest` (colle une ligne de `honeypot.log`). Pour tout
conserver même sans alerte, active `<logall_json>yes</logall_json>`.

### Étape 7 — Mode purple : valider que la détection se déclenche

Le mode purple rejoue des sondes **inertes et marquées** (un canari unique par
sonde) contre **ton propre honeypot** ou une pré-prod, puis vérifie qu'elles sont
bien capturées. Ce n'est pas une attaque : aucune n'exploite quoi que ce soit, la
cible est inerte/autorisée. **Tout passe par un mandat** — y compris ton honeypot
local (tu signes `mandats/honeypot-local.mandat.yaml`, dont tu es Prestataire ET
Client). Sans mandat couvrant la cible : refus, zéro sonde.

```bash
cd tasko-defense
# Contre TON honeypot local : signe d'abord mandats/honeypot-local.mandat.yaml
python3 -m tasko.cli purple --cible http://127.0.0.1:8080/ \
    --mandat mandats/honeypot-local.mandat.yaml \
    --honeypot-log /var/log/tasko-honeypot/honeypot.log --ssh --ssh-port 2222 \
    --journal journal-tests.jsonl --sortie rapport-purple.md

# Contre une pré-prod d'un client : mandat autorisant validation_detection
python3 -m tasko.cli purple --cible https://preprod.client.cm/ \
    --mandat mandats/client.mandat.yaml --ip-source 198.51.100.10
```

Chaque sonde marquée **DÉTECTÉ** doit déclencher une règle Wazuh ; une sonde
**NON DÉTECTÉ** révèle un trou de détection (règle manquante, log non ingéré) à
corriger. C'est la boucle purple : attaque simulée inerte → vérification bleue.

### Analyser une preuve trouvée (décodage défensif)

Quand un payload obscurci apparaît dans un log ou un web shell, `preuve` déroule
ses couches d'encodage (base64, hex, URL, gzip, `fromCharCode`, `\x/\u`…) pour en
révéler le texte, identifie le *type* d'un hash (sans le casser) et extrait les
IOC — sans rien exécuter, sans casser ni déchiffrer de secret :

```bash
python3 -m tasko.cli preuve --fichier /chemin/payload-trouve.txt --sortie analyse.md
python3 -m tasko.cli preuve --texte 'PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOw=='
```

### Exploitation contrôlée (Annexe D) — documenter, jamais automatiser

Tasko n'exécute jamais l'exploitation. Quand l'Annexe D est signée et que le
mandat autorise le type `exploitation`, l'opérateur réalise la PoC **à la main**
(dans le périmètre, sans extraire de données, sans persistance), puis la **scelle** :

```bash
python3 -m tasko.cli poc --mandat mandats/client.mandat.yaml \
    --cible https://client.cm/login --titre "SQLi /login" --reference CVE-XXXX-YYYY \
    --severite élevée --etapes "..." --resultat "exploitabilité démontrée, lecture seule" \
    --preuve capture1.png --preuve trace.txt --journal journal-tests.jsonl --sortie poc-client
```

Le dossier produit horodate, hache chaque preuve (chaîne de possession) et
rappelle les limites Annexe D. Sans Annexe D signée, la commande **refuse**.

**Gagner du temps de saisie** (sans automatiser l'exploitation) : pré-remplis un
brouillon depuis un finding de scan — la cible, le titre, la CVE et la sévérité
sont recopiés automatiquement ; tu ne saisis que la PoC (étapes, résultat, preuves) :

```bash
python3 -m tasko.cli poc-brouillon --dossier rapports/<date>              # liste les findings
python3 -m tasko.cli poc-brouillon --dossier rapports/<date> --finding 1 \
    --sortie brouillon.yaml
#   ... tu remplis les champs « À REMPLIR » du brouillon (la PoC faite à la main) ...
python3 -m tasko.cli poc --depuis-brouillon brouillon.yaml \
    --mandat mandats/client.mandat.yaml --journal journal-tests.jsonl --sortie poc-client
```

Le brouillon ne pré-remplit que la **paperasse** ; l'acte d'exploitation reste
manuel, autorisé (Annexe D) et de ta responsabilité. Le scellement passe toujours
par le verrou (refus sans Annexe D signée).

---

## Cycle opérationnel type (résumé)

| Cadence | Action |
|---------|--------|
| **À chaque nouveau client** | Mandat signé (étape 0) |
| **Quotidien** | Honeypot tourne ; Wazuh surveille ; threat-intel sur logs honeypot |
| **Hebdomadaire** | Scan web/réseau des sites clients (heures creuses, sous mandat) |
| **À chaque alerte Wazuh** | Investigation ; si compromission → réponse à incident |
| **Après correction** | Re-scan pour vérifier que la faille a disparu |

---

## Ce que Tasko fait — et ne fait pas

| ✅ Tasko fait (légal, défensif) | ❌ Tasko ne fait pas |
|--------------------------------|----------------------|
| Scanner les sites sous mandat signé | Scanner sans autorisation écrite |
| Documenter l'attaquant via ses traces (logs) | Accéder/sonder la machine de l'attaquant |
| Observer via honeypot sur sa propre infra | Hack back / contre-attaque |
| Préserver les preuves pour les autorités | Attribution nominative (= rôle des autorités) |
| Recouper avec des bases publiques | Test de charge/DoS en production |
| Pentest encadré (Annexe D du mandat) | Exploitation hors périmètre |

C'est cette discipline qui fait la différence entre une boîte respectée et une
boîte à risque. La réputation et la licence d'opérer de Tasko valent plus que
n'importe quelle fonctionnalité agressive.

---

## Limites honnêtes

- Pour un incident grave touchant des données clients, **implique tôt un
  professionnel DFIR et/ou les autorités** : une manipulation amateur des preuves
  peut compromettre une affaire.
- L'**attribution réelle** (qui est derrière une IP qui peut être usurpée ou
  relayée) est un travail d'enquête réservé aux autorités. Tasko fournit les
  preuves, pas le verdict.
- **Wazuh demande de l'ingénierie** : déploie-le quand ton équipe peut l'exploiter,
  pas par effet de mode.
- **Fais valider tous les modèles juridiques** (mandat, annexes) par un juriste
  local avant usage commercial.
