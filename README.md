# CineNAS

Gestionnaire de films auto-hébergé en PHP — affiche tous vos films (y compris dans les sous-répertoires) avec affiches, notes, synopsis et filtres dynamiques via l'API TMDB.

## Fonctionnalités

### Affichage
- 🎬 **Vue grille** avec affiche, titre, année, note étoilée et synopsis (via TMDB)
- 📋 **Vue liste** avec tri par nom, taille, date, tag
- 🔍 **Recherche** filtrée en temps réel

### Navigation & filtres
- 🏷️ **Tags** : les sous-répertoires deviennent des tags affichés sur chaque vignette
  - 1 clic → **exclure** (rouge) · 2 clics → **inclure** (bleu) · 3 clics → neutre
  - Plusieurs tags inclus/exclus simultanément
- 👁️ **Filtre vus/non vus** : bouton cyclique (Tous → Non vus → Vus)
- ⭐ **Filtre par note** minimum TMDB
- 🎭 **Filtre par genre** TMDB
- Tous les films de tous les sous-répertoires sont affichés dans une liste plate

### Synchronisation TMDB
- 🔄 **Sync** en un clic — s'applique uniquement aux films **visibles** (respecte les filtres actifs)
- ↺ **Re-sync individuel** par vignette
- Posters mis en cache localement (`.posters/`) — pas de re-téléchargement si déjà présent
- Métadonnées stockées par répertoire dans `.movies_meta.json`

### Autres
- 🔐 **Authentification** par mot de passe (hash bcrypt)
- 🔗 **Liens** vers TMDB et Allociné pour chaque film
- ⬇️ **Téléchargement** direct des fichiers
- ✅ Compatible **PHP 5.6+** (32-bit inclus)

## Prérequis

- PHP 5.6 ou supérieur
- Apache ou Nginx
- `allow_url_fopen = On` dans php.ini (pour les appels TMDB)
- Un compte TMDB gratuit pour les métadonnées

## Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/yannrichet/CineNAS.git
cd CineNAS
```

### 2. Créer le fichier de configuration

```bash
cp config.sample.php config.php
```

### 3. Générer un hash de mot de passe

```bash
php -r "echo password_hash('votre_mot_de_passe', PASSWORD_BCRYPT) . PHP_EOL;"
```

Coller le résultat dans `config.php` à la ligne `FM_PASSWORD_HASH`.

### 4. Obtenir un token TMDB

1. Créer un compte sur [themoviedb.org](https://www.themoviedb.org/)
2. Aller dans **Compte → Paramètres → API**
3. Faire une demande d'accès (usage personnel)
4. Copier le **Jeton d'accès en lecture de l'API** (commence par `eyJ...`)
5. Le coller dans `config.php` à la ligne `FM_TMDB_API_KEY`

### 5. Configurer le serveur web

Pointer le `DocumentRoot` (ou un VirtualHost) vers le répertoire du projet.

Exemple Apache :
```apache
<VirtualHost *:8888>
    DocumentRoot /chemin/vers/CineNAS
    <Directory /chemin/vers/CineNAS>
        AllowOverride None
        Require all granted
    </Directory>
</VirtualHost>
```

## Structure des fichiers

```
CineNAS/
├── index.php              # Application principale (tout-en-un)
├── config.php             # Secrets (exclu du dépôt git)
├── config.sample.php      # Modèle de configuration à copier
└── Films/
    ├── .movies_meta.json  # Cache TMDB (généré automatiquement)
    ├── .posters/          # Affiches mises en cache localement
    ├── Action/            # Sous-répertoire → tag "Action"
    ├── Comédie/           # Sous-répertoire → tag "Comédie"
    └── film.mkv
```

## Organisation des films

Placez vos films dans `FM_ROOT` (défini dans `config.php`).  
Les **sous-répertoires de premier niveau** deviennent automatiquement des **tags** :

```
Films/
├── Action/           → tag "Action"
│   ├── Mad Max.mkv
│   └── John Wick.mkv
├── Enfants/          → tag "Enfants"
│   └── Toy Story.mkv
└── Interstellar.mkv  → pas de tag
```

Tous les films (à toutes les profondeurs) apparaissent dans la liste principale.

## Paramètres URL

| Paramètre | Valeur | Effet |
|-----------|--------|-------|
| `?tag=Action` | nom de tag | Affiche uniquement ce tag (inclus) |
| `?watched=all` | `all` / `watched` / `unwatched` | Filtre par statut vu |

## Compatibilité PHP 5.6

Ciblé délibérément pour les NAS et serveurs anciens :
- Pas de types scalaires ni union types
- Pas de fonctions fléchées (`fn()`)
- Gestion des entiers 32-bit pour les fichiers > 2 Go

## Licence

MIT
