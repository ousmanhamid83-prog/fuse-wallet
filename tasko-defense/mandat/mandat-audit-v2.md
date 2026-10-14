# MANDAT D'AUTORISATION D'AUDIT DE SÉCURITÉ
## (Règles d'Engagement — *Rules of Engagement*)

> **Version corrigée.** Le DoS et le « hack back » figurent en **actions
> interdites** : aucune clause ne peut les autoriser, car le hack back vise un
> système tiers que le Client ne possède pas, et le DoS détruit la disponibilité.
> Pour un test offensif légitime, utiliser l'**Annexe D — Pentest encadré**.
>
> Remplir les champs [entre crochets], faire signer AVANT tout test, conserver
> l'original. Faire valider par un juriste (Tchad / CEMAC) avant usage commercial.

---

### ENTRE LES SOUSSIGNÉS

**Le Prestataire :**
[TON ENTREPRISE] — [forme juridique]
RCCM n° : [__________]
Siège : [adresse]
Représenté par : [Nom, Prénom], en qualité de [fonction]
Ci-après « le Prestataire ».

**Le Client (propriétaire des systèmes audités) :**
[RAISON SOCIALE] — [forme juridique]
RCCM n° : [__________]
Siège : [adresse]
Représenté par : [Nom, Prénom], en qualité de [fonction]
Ci-après « le Client ».

---

### ARTICLE 1 — OBJET ET AUTORISATION EXPLICITE

Le Client, **propriétaire légitime** (ou gestionnaire dûment habilité) des systèmes
décrits à l'Article 2, **autorise expressément** le Prestataire à réaliser des tests
de sécurité **défensifs** sur ces seuls systèmes, dans les limites du présent mandat.

Le Client **déclare et garantit** détenir les droits nécessaires pour autoriser cet
audit. Pour tout système hébergé chez un tiers (Hostinger, Cloudflare…) ou mutualisé,
le Client obtient l'accord de l'hébergeur lorsqu'il est requis et en informe le
Prestataire **par écrit** avant le début des tests.

---

### ARTICLE 2 — PÉRIMÈTRE (SCOPE)

#### 2.1 Cibles AUTORISÉES (et elles seules)

| Type | Identifiant exact | Remarques |
|------|-------------------|-----------|
| Domaine / site | [https://site-client.xx] | Site principal |
| Sous-domaines | [tous les sous-domaines de X] | admin, api… |
| Adresses IP / plages | [ex. 102.23.45.0/24] | Serveurs du Client uniquement |
| Application / API | [https://api.site-client.xx] | Endpoints API |
| Comptes de test fournis | [compte dédié à l'audit] | Jamais des comptes d'utilisateurs réels |

#### 2.2 EXCLUSIONS explicites (hors périmètre)

- Tout système, domaine, IP ou service **non listé** au § 2.1.
- Toute infrastructure mutualisée partagée avec des tiers non consentants.
- [Passerelles de paiement tierces, services SaaS externes, etc.]

#### 2.3 Types de tests AUTORISÉS

- [x] Découverte / cartographie (scan de ports, énumération de services)
- [x] Scan de vulnérabilités web (OWASP ZAP, Nuclei, WPScan…)
- [x] Scan de vulnérabilités réseau (Nmap, scripts NSE défensifs)
- [x] Test authentifié via comptes de test fournis par le Client
- [ ] **Test d'intrusion avec exploitation contrôlée** — uniquement si coché ET
      encadré par l'**Annexe D** (cibles, limites, environnement de test)
- [ ] **Ingénierie sociale / phishing** des employés — uniquement si coché et
      encadré par une annexe dédiée, avec information préalable de la direction

#### 2.4 Actions INTERDITES en toutes circonstances

- **Attaques par déni de service (DoS / DDoS)** ou tout test dégradant la
  disponibilité du service. *(Un test de charge éventuel relève de l'Annexe D,
  en environnement de test isolé, et n'est pas un DoS.)*
- **« Hack back » / contre-attaque** : tout accès, sondage ou « traçage actif »
  d'un système **tiers**, y compris une machine soupçonnée d'être à l'origine d'une
  attaque. Le Client ne peut pas autoriser l'accès à un système qu'il ne possède pas.
- **Modification, suppression ou exfiltration de données réelles** du Client ou de
  ses utilisateurs.
- Tout test **au-delà des fenêtres temporelles** de l'Article 4 ou **hors périmètre**
  du § 2.1.

---

### ARTICLE 3 — IDENTIFICATION DES INTERVENANTS

| Nom / Prénom | Rôle | IP source de l'audit (fixe) | Contact |
|--------------|------|------------------------------|---------|
| [__________] | Auditeur | [IP fixe d'où partent les scans] | [tél / email] |

Le Prestataire scanne **depuis des adresses IP fixes identifiées** afin que le Client
distingue l'audit autorisé d'une attaque réelle.

---

### ARTICLE 4 — FENÊTRES TEMPORELLES

- **Période de validité :** du [date de signature] au [date de fin].
- **Fenêtres de test :** [ex. tous les jours de 01h00 à 05h00, heure de N'Djamena].
- Tout test hors fenêtre requiert un accord écrit préalable (email suffit).

> Cohérence des dates : la période doit **commencer à la date de signature** et aller
> vers le futur. Un mandat signé après sa date de fin n'autorise rien.

---

### ARTICLE 5 — PROCÉDURE D'URGENCE ET D'ESCALADE

En cas d'incident (indisponibilité, comportement anormal, **compromission
préexistante** découverte) :

1. Le Prestataire **arrête immédiatement** les tests.
2. Il prévient sans délai :
   - Contact Client : [Nom] — [tél 24/7] — [email]
   - Contact Prestataire : [Nom] — [tél 24/7] — [email]
3. Face à une compromission réelle, le Prestataire **ne corrige ni ne « trace »** de
   sa propre initiative : il **documente**, **préserve les preuves** (procédure de
   réponse à incident), et laisse le Client décider de la notification aux autorités
   (ANTIC / ANSICE / police judiciaire).

---

### ARTICLE 6 — LIVRABLES ET CONFIDENTIALITÉ

- **Livrable :** rapport listant les vulnérabilités, leur sévérité (CVSS) et des
  recommandations de correction. **But : corriger**, jamais exploiter.
- **Confidentialité :** résultats strictement confidentiels, conservés le temps
  nécessaire, stockés chiffrés, transmis par canal chiffré au seul contact désigné.

---

### ARTICLE 7 — RESPONSABILITÉS ET LIMITES

- Le Prestataire agit selon les règles de l'art, dans le seul périmètre autorisé.
- Il n'est pas responsable des vulnérabilités préexistantes ni des incidents non liés
  à ses tests.
- Un audit reflète l'état de sécurité au moment du test, dans les limites convenues.
- **Face à un attaquant :** le Prestataire fournit au Client les **preuves** collectées
  sur les systèmes **du Client**. L'**identification de l'attaquant**, l'**attribution**,
  l'**accès à tout système tiers** et les **poursuites** relèvent exclusivement des
  **autorités**. Toute demande d'aller au-delà ne sera exécutée que sur présentation
  d'une **réquisition judiciaire écrite**, dans le cadre légal qu'elle définit.

---

### ARTICLE 8 — PREUVE DE L'AUTORISATION

Le Prestataire conserve une copie signée et horodatée du mandat, ainsi que les
journaux de ses tests (IP, dates, outils, empreintes), comme **preuve du caractère
autorisé et défensif** de son intervention.

---

### SIGNATURES

Fait à [lieu], le [date], en deux exemplaires originaux.

**Pour le Client** — Nom : ____________  Fonction : ____________  Signature + cachet :

**Pour le Prestataire** — Nom : ____________  Fonction : ____________  Signature + cachet :

---

## ANNEXE A — Liste détaillée des cibles
*(à joindre et parapher si le périmètre est long)*

## ANNEXE B — Comptes de test fournis par le Client
*(identifiants dédiés à l'audit — jamais des comptes réels)*

## ANNEXE C — Journal des tests
*(date, heure UTC, cible, outil, IP source)*

---

## ANNEXE D — TEST D'INTRUSION AVEC EXPLOITATION CONTRÔLÉE
*(à remplir et signer uniquement si la case correspondante est cochée au § 2.3)*

Cette annexe encadre un pentest **offensif mais légitime** : l'exploitation contrôlée
sert à **prouver** qu'une faille est réellement exploitable, afin de la corriger en
priorité — jamais à causer un dommage ni à atteindre un tiers.

#### D.1 Cibles spécifiques du pentest
| Cible | Environnement | Remarque |
|-------|---------------|----------|
| [URL / IP] | [**test / pré-prod** de préférence] | Éviter la production si possible |

#### D.2 Limites de l'exploitation autorisée
- Exploitation **uniquement** pour démontrer la faille (preuve de concept), avec
  capture d'écran / trace, **sans** pivoter au-delà de la cible autorisée.
- **Aucune** donnée réelle extraite, modifiée ou supprimée. Si une faille donne accès
  à des données, le Prestataire **s'arrête** et le documente, sans télécharger.
- **Aucune** persistance laissée (web shell, compte, backdoor) : tout artefact de test
  est retiré et listé dans le rapport.
- **Aucun** test de déni de service ; un éventuel **test de charge** se fait en
  environnement isolé, avec un seuil convenu, et n'est pas couvert par ce mandat sans
  accord écrit séparé.

#### D.3 Fenêtre et supervision
- Fenêtre dédiée : [date / heure].
- Supervision : le contact technique du Client est joignable pendant toute la fenêtre.
- Snapshot de sauvegarde pris par le Client **avant** le test (rollback possible).

#### D.4 Signatures spécifiques à l'Annexe D
Le Client reconnaît les risques inhérents à un test d'exploitation et confirme avoir
réalisé une sauvegarde.

Pour le Client : ____________   Pour le Prestataire : ____________   Date : ________
