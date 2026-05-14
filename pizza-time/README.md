# Pizza Time — MVP2

Site web de commande/livraison pour Pizza Time N'Djamena.

## Lancer en local

Le site a besoin d'être servi via HTTP (Service Worker + géoloc nécessitent un contexte sécurisé).

### Option 1 — Python (déjà installé partout)

```bash
cd pizza-time
python3 -m http.server 8000
```

Puis ouvrir : http://localhost:8000

### Option 2 — Node

```bash
cd pizza-time
npx serve
```

### Option 3 — Live Server VSCode

Clic droit sur `index.html` → **Open with Live Server**

## Comptes de test

- **Admin** : mot de passe `admin1234` (onglet Admin)

## Tester un flow complet

1. Ajouter quelques produits au panier
2. Cliquer **Commander 🚀**
3. Remplir : nom, téléphone (ex `66 12 34 56`), adresse
4. Optionnel : **Utiliser ma position GPS** (autoriser la permission)
5. Confirmer → ouverture auto du tracking
6. La moto bouge sur la carte avec route OSRM réelle (~1 min de simulation)
7. Aller dans **Admin** → `admin1234` → voir le dashboard

## Stack

- Tailwind CSS (CDN)
- Leaflet + OpenStreetMap
- OSRM (routage gratuit)
- localStorage pour la persistance (sera remplacé par Supabase en MVP3)
- PWA installable

## Fichiers

- `index.html` — App complète
- `manifest.json` — PWA manifest
- `sw.js` — Service Worker (cache + offline)
