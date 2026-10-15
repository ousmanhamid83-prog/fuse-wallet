# Runbook — auditer tes machines, documenter une PoC, récupérer tes fichiers

Trois chantiers **défensifs**, tous couverts par Tasko Defense **sans** moteur
d'exploitation automatisé. L'exploitation, quand elle est nécessaire, reste un
acte **manuel, autorisé et documenté** (Annexe D).

---

## 1. Auditer tes propres machines

Objectif : trouver les failles de **ton** parc pour les corriger. Cadré par un
mandat d'auto-audit (tu es Prestataire **et** Client).

```bash
cd tasko-defense

# a) Signe le mandat de ton parc : édite mandats/auto-audit.mandat.yaml
#    - mets TES IP/plages dans perimetre.ips (jamais une IP tierce)
#    - passe signe: true
python3 -m tasko.cli info --mandat mandats/auto-audit.mandat.yaml

# b) Scan web de tes sites (sous mandat ; rapport + Annexe C générés)
cd outils/scan
export MANDAT=../../mandats/auto-audit.mandat.yaml
export WPSCAN_API_TOKEN="ton_token"
bash scan-web.sh https://ton-site-a-toi/

# c) Scan réseau d'une de TES machines (dédiée)
bash scan-reseau.sh 192.168.1.10          # une IP de TON parc

# d) Valider que ta détection se déclenche (purple, sondes inertes)
cd ../../
python3 -m tasko.cli purple --cible http://127.0.0.1:8080/ \
    --mandat mandats/auto-audit.mandat.yaml \
    --honeypot-log /var/log/tasko-honeypot/honeypot.log
```

Les rapports (findings triés par sévérité) et l'Annexe C (journal des tests)
sont produits automatiquement dans `outils/scan/rapports/<date>/`.

### À l'échelle : un parc de milliers de machines

Pas besoin de lister les IP une par une. Deux leviers :

1. **Déclare ton parc par plages (CIDR) ou via un fichier d'inventaire** dans le
   mandat — une seule fois :
   ```yaml
   perimetre:
     ips: ["10.0.0.0/8", "192.168.0.0/16"]   # couvre des milliers de machines
     ips_fichier: "inventaire-parc.txt"        # OU un fichier (une IP/plage/ligne, # commentaire)
     heberge_dedie: true
   ```
2. **Audite tout le parc en un lot** avec `audit-parc.sh`. Chaque hôte de
   l'inventaire est vérifié contre le mandat AVANT d'être scanné ; un hôte hors
   mandat est **ignoré** (jamais scanné), le lot continue :
   ```bash
   cd outils/scan
   export MANDAT=../../mandats/auto-audit.mandat.yaml
   export AUDIT_IP=198.51.100.10          # (optionnel) ton IP source
   export WPSCAN_API_TOKEN=xxxx           # pour un audit web
   bash audit-parc.sh parc-hosts.txt reseau   # un hôte/IP par ligne
   bash audit-parc.sh sites.txt web           # une URL par ligne
   ```
   Résultats agrégés + Annexe C dans `outils/scan/audits-parc/<date>/`, avec un
   `resume.txt` (scannés / ignorés hors mandat / échecs).

> C'est de l'audit automatisé **à l'échelle** : on scanne (on TROUVE) tout le parc
> autorisé. L'exploitation, elle, reste manuelle et ciblée (Annexe D, §2).

---

## 2. Documenter une PoC d'exploitation (Annexe D) — manuelle

Quand un finding doit être **prouvé exploitable** pour prioriser sa correction :
tu réalises la PoC **à la main** (dans le périmètre, sans extraire de données,
sans persistance), et l'outil la **scelle**. Aucun exploit n'est exécuté par Tasko.

```bash
# Pré-remplir un brouillon depuis un finding du scan (gain de temps de saisie)
python3 -m tasko.cli poc-brouillon --dossier outils/scan/rapports/<date>
python3 -m tasko.cli poc-brouillon --dossier outils/scan/rapports/<date> \
    --finding 1 --sortie brouillon.yaml
#   ... tu remplis les champs « À REMPLIR » (étapes, résultat, preuves) ...

# Sceller (exige annexe_d_signee: true dans le mandat)
python3 -m tasko.cli poc --depuis-brouillon brouillon.yaml \
    --mandat mandats/auto-audit.mandat.yaml --journal journal-tests.jsonl \
    --sortie poc-finding-1
```

Pour autoriser l'exploitation : passe `exploitation: true` **et**
`annexe_d_signee: true` dans le mandat (après avoir rempli et signé l'Annexe D de
`mandat/mandat-audit-v2.md`).

---

## 3. Récupérer tes propres fichiers (accès perdu)

Ce n'est **pas** de l'exploitation : c'est de la **récupération de données / de
compte**. Dans l'ordre à essayer :

1. **Sauvegardes / snapshots** — la première piste, toujours (sauvegarde locale,
   cloud, snapshot VPS).
2. **Récupération de compte officielle** — reset via le fournisseur (OS, hébergeur,
   fournisseur de messagerie), disque/clé de récupération.
3. **Gestionnaire de mots de passe** — si l'accès perdu est un secret que tu
   possèdes (coffre, clés de récupération, 2FA backup codes).
4. **Récupération au niveau du système de fichiers** (sur **tes** disques) :
   - fichiers supprimés / partition perdue : `testdisk`, `photorec` ;
   - disque défaillant : copie bas niveau avec `ddrescue` **avant** toute réparation
     (travaille sur l'image, jamais sur le disque d'origine) ;
   - `sudo apt install -y testdisk gddrescue`
5. **Chiffrement que tu possèdes** : déchiffre avec **ta** clé/passphrase
   (LUKS, VeraCrypt, GPG). Si la clé est perdue, il n'y a pas de contournement
   légitime — c'est le but du chiffrement.
6. **Support endommagé / cas critique** : service professionnel de data recovery.

> Important : la récupération se fait avec **tes** identifiants / **ta** clé, sur
> **tes** supports. Aucun contournement d'un chiffrement ou d'un compte que tu ne
> possèdes pas — ça, aucun outil de Tasko ne le fait.

---

## Ce que Tasko ne contient pas (et pourquoi)

Pas de moteur d'exploitation automatisé / semi-automatisé, pas de cassage de
secrets. Une boîte d'audit sérieuse **ne possède ni ne distribue** ce genre d'arme :
c'est ce qui la rend licenciable et défendable en justice. La valeur d'audit vient
du cadre (mandat), de la découverte, de la PoC manuelle documentée, et du rapport.
