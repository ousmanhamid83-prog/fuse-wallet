# Playbook — Réponse à incident & préservation des preuves
## Tasko Defense — usage défensif

Ce document couvre **trois moments** :
- réagir **maintenant** à une intrusion (§ Réaction immédiate)
- la procédure **préventive** à avoir prête à l'avance (§ Préparation)
- **préserver les preuves** sans les abîmer (§ Préservation)

> Principe directeur : **ton rôle = trouver les failles + préserver les preuves +
> notifier.** L'identification nominative de l'attaquant et son arrestation sont
> du ressort des autorités (police judiciaire, ANTIC au Cameroun, ANSICE au
> Tchad). Tu fournis les preuves ; eux mènent l'enquête. Ne tente jamais de
> « contre-attaquer » ou de remonter activement vers la machine de l'attaquant :
> c'est illégal dans presque tous les pays, même en réaction à une attaque.

---

## ⚠️ La règle qui prime sur tout

**N'efface rien dans la panique.** Le réflexe « je réinstalle vite pour réparer »
détruit toutes les preuves dont les autorités ont besoin. L'ordre correct est :

```
ISOLER  →  PRÉSERVER  →  ÉRADIQUER  →  RÉTABLIR
(jamais : effacer d'abord)
```

---

## 1. Réaction immédiate (intrusion en cours / suspectée)

### Décision n°1 — l'attaque est-elle encore active ?

**Confiner sans détruire.** Deux options, avec un compromis à connaître :

- **Isoler le réseau** (couper l'accès Internet du serveur, ou bloquer l'IP
  attaquante au pare-feu) → stoppe l'attaquant **tout en gardant la mémoire vive
  intacte** (processus en cours, connexions). C'est l'option à privilégier pour
  préserver un maximum de preuves.
- **Éteindre le serveur** → stoppe tout immédiatement, mais **perd les preuves en
  mémoire** (RAM). À réserver aux cas où des données continuent de fuir et que
  l'isolement réseau n'est pas possible.

> Sur Hostinger VPS : tu peux gérer le pare-feu (ufw/iptables) et l'accès réseau
> depuis le hPanel sans éteindre la machine.

### Décision n°2 — figer l'état AVANT de toucher à quoi que ce soit

1. **Prends un snapshot du VPS** (hPanel Hostinger → Snapshots). Ça fige tout le
   disque sans y toucher → c'est ta **preuve maîtresse**.
2. **Lance `collecte-preuves.sh`** (fourni) en root → capture l'état volatil
   (mémoire/réseau/processus), copie les logs, et **hache tout** (intégrité).
3. **Note** qui a fait quoi, quand (en UTC), où les preuves sont stockées.

### Décision n°3 — évaluer l'étendue

- Quelles **données clients** ont pu être consultées/exfiltrées ? (déclenche
  l'obligation de notification)
- Par où l'attaquant est-il entré ? (la faille à corriger — utilise tes scans
  web/réseau du pack précédent)
- Y a-t-il une **persistance** ? (nouveaux comptes, cron suspect, web shell dans
  `uploads/`, service inconnu — le script les liste)

---

## 2. Préparation (le préventif — à faire AVANT tout incident)

Avoir ceci prêt change tout le jour J :

- **Contacts d'urgence** notés à l'avance : autorité (ANTIC / ANSICE), hébergeur
  (Hostinger), conseil juridique, et le responsable interne décisionnaire.
- **Snapshots automatiques** activés sur le VPS (récupération + preuve).
- **Logs centralisés et conservés** : sans logs, pas de preuves. Garde au moins
  90 jours de journaux (auth, web, système) hors du serveur (ex. via Wazuh).
- **Sauvegardes testées** : pour rétablir sur une base saine après éradication.
- **Inventaire** : liste des sites, serveurs, et données clients hébergées (pour
  savoir vite ce qui est touché).
- **Ce playbook + `collecte-preuves.sh`** stockés *hors* du serveur (si le serveur
  tombe, tu y as toujours accès).

> Wazuh (qu'on prévoyait de déployer) joue ici un double rôle : il **détecte**
> l'intrusion en temps réel ET **conserve les logs** hors du serveur compromis —
> donc des preuves que l'attaquant ne peut pas effacer en nettoyant la machine.

---

## 3. Préservation des preuves (forensiquement sain)

Pour que les preuves soient **recevables** par les autorités/un tribunal :

### Les 4 principes

1. **Ne pas altérer l'original.** On travaille sur des copies, jamais sur le
   système compromis directement. Le snapshot + les copies de logs servent de base.
2. **Tracer la chaîne de possession.** Pour chaque preuve : *quoi, quand (UTC),
   qui l'a collectée, comment, où elle est stockée*. Le script écrit déjà un
   `journal-collecte.txt` et un `MANIFEST.txt`.
3. **Prouver l'intégrité.** Chaque fichier est haché en **SHA-256** au moment de
   la collecte. Si une empreinte correspond toujours plus tard, la preuve n'a pas
   été modifiée. C'est ça qui la rend crédible.
4. **Stockage en lecture seule.** Copie le dossier de preuves sur un support
   externe (clé USB, stockage chiffré) que tu ne modifies plus.

### Ce qu'on collecte, dans l'ordre (volatilité décroissante)

| Priorité | Preuve | Pourquoi |
|----------|--------|----------|
| 1 | Mémoire vive (snapshot VPS) | Disparaît à l'extinction ; contient processus/clés/connexions |
| 2 | Connexions réseau, processus | État de l'attaque au moment T |
| 3 | Sessions, comptes, logins échoués | Qui s'est connecté, par où |
| 4 | Cron, services, fichiers récents | Mécanismes de persistance / web shells |
| 5 | Journaux (auth, web, système) | Chronologie complète de l'attaque |

`collecte-preuves.sh` automatise les priorités 2 à 5 et hache l'ensemble. La
priorité 1 (mémoire) se fait via le **snapshot Hostinger** avant de lancer le script.

### Après la collecte

- Reconstruis le service sur une **instance propre** (pas sur la machine
  compromise), en gardant snapshot + dossier de preuves intacts.
- Corrige la faille d'entrée (scans web/réseau) avant de remettre en ligne.
- Change tous les secrets potentiellement exposés (mots de passe, clés API, jetons).

---

## 4. Notification (procédure que tu connais déjà — pour mémoire)

- **Autorité** : ANTIC (Cameroun) / ANSICE (Tchad) + dépôt de plainte (police
  judiciaire / gendarmerie). Fournis le dossier de preuves intact.
- **Clients affectés** : informe ceux dont les données ont pu être touchées
  (obligation légale selon les données concernées).
- **Conseil juridique** : pour les délais et obligations exacts selon le type de
  données et la juridiction.

---

## Limites honnêtes

- Pour un incident grave touchant des données clients, **fais intervenir tôt un
  professionnel DFIR et/ou les autorités** : une manipulation amateur des preuves
  peut compromettre une affaire judiciaire. Ce playbook te fait gagner les
  premières heures critiques, il ne remplace pas un expert.
- L'**attribution** (savoir qui est vraiment derrière, au-delà d'une IP qui peut
  être usurpée ou relayée) est un travail d'enquête réservé aux autorités.
- Ce playbook sert à **comprendre, prouver et notifier** — jamais à riposter.
