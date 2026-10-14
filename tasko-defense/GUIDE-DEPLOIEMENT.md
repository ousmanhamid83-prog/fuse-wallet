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

### Étape 1 — Préparer le nœud d'audit (VPS)

```bash
# Sur ton VPS Hostinger (Ubuntu)
sudo apt update && sudo apt install -y python3-pip nmap nikto
pip3 install requests

# Outils de scan web
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
gem install wpscan

# Récupère ce dépôt sur le VPS
# (scp, git, ou upload via hPanel)
```

### Étape 2 — Lancer un audit (sous mandat)

```bash
cd tasko-defense/outils/scan

# 2a. Scan web (configure sites.txt d'abord — uniquement les sites sous mandat)
export WPSCAN_API_TOKEN="ton_token"
bash scan-web.sh

# 2b. Scan authentifié (adapte zap-auth.yaml : URL, champs login, regex)
export ZAP_USER="compte_test"; export ZAP_PWD="motdepasse"
docker run -v $(pwd):/zap/wrk/ -e ZAP_USER -e ZAP_PWD \
  -t ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -cmd -autorun /zap/wrk/zap-auth.yaml

# 2c. Scan réseau (UNIQUEMENT le VPS du client, jamais du mutualisé partagé)
bash scan-reseau.sh ip-du-serveur-client
```

Trie les findings par sévérité (**critical/high** d'abord), livre le rapport au
client, et relance après correction pour vérifier.

### Étape 3 — Déployer le honeypot (sur infra isolée)

```bash
cd tasko-defense/outils

# Ouvre SEULEMENT les ports honeypot dans le pare-feu (jamais tes vrais services)
sudo ufw allow 2222/tcp   # faux SSH
sudo ufw allow 8080/tcp   # faux panneau admin

# Lance le honeypot en continu (systemd recommandé)
python3 honeypot.py
```

Service systemd (`/etc/systemd/system/honeypot.service`) :
```ini
[Unit]
Description=Tasko Honeypot
After=network.target
[Service]
WorkingDirectory=/opt/tasko-defense/outils
ExecStart=/usr/bin/python3 /opt/tasko-defense/outils/honeypot.py
Restart=always
User=honeypot
[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl enable --now honeypot
```

### Étape 4 — Renseignement sur les menaces

```bash
cd tasko-defense/outils
export ABUSEIPDB_KEY="ta_cle_gratuite"   # abuseipdb.com, 1000 req/jour

# Analyser les logs d'un site attaqué
python3 threat-intel.py /var/log/nginx/access.log --type web

# Analyser les tentatives SSH
python3 threat-intel.py /var/log/auth.log --type auth

# Analyser les captures du HONEYPOT (les attaquants s'y dévoilent le plus)
python3 threat-intel.py honeypot.log --type web
```

Le dossier JSON produit (IOC + réputation + signatures d'attaque) est **prêt à
transmettre aux autorités** pour l'attribution. Aucune machine attaquante n'est
contactée.

### Étape 5 — Réponse à incident (le jour J)

Si un client est compromis, suis `docs/playbook-incident.md`. L'ordre **non
négociable** :

```
ISOLER  →  PRÉSERVER  →  ÉRADIQUER  →  RÉTABLIR   (jamais : effacer d'abord)
```

```bash
# Sur le serveur compromis, en root, APRÈS avoir pris un snapshot VPS
sudo bash tasko-defense/outils/incident/collecte-preuves.sh
```
Le script fige l'état (processus, réseau, logs) et **hache tout** (preuve
d'intégrité). Puis : threat-intel sur les logs collectés → dossier autorités.

### Étape 6 — Centralisation Wazuh (surveillance continue)

Wazuh joue le rôle clé : il **détecte** en temps réel ET **conserve les logs hors
des serveurs surveillés** — donc des preuves qu'un attaquant ne peut pas effacer.

Sur chaque serveur surveillé (sites clients sous mandat, honeypot, nœud d'audit),
installe l'agent Wazuh et fais-lui ingérer :
- les logs web (Nginx/Apache)
- les logs d'authentification (SSH)
- le `honeypot.log` (format JSON déjà compatible)
- le `security.json` d'AfriGuard si déployé

```xml
<!-- Sur le honeypot : /var/ossec/etc/ossec.conf -->
<localfile>
  <log_format>json</log_format>
  <location>/opt/tasko-defense/outils/honeypot.log</location>
  <label key="@source">tasko-honeypot</label>
</localfile>
```

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
