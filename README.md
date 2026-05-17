# php-film-manager

Gestionnaire de films auto-hébergé en PHP, avec affichage des affiches, notes et synopsis via l'API TMDB.

![Vue grille avec affiches de films](https://image.tmdb.org/t/p/w300/placeholder.jpg)

## Fonctionnalités

- 🎬 **Vue grille** avec affiche, titre, année, note et synopsis (via TMDB)
- 📋 **Vue liste** avec tri par nom, taille, date
- 🔐 **Authentification** par mot de passe (hash bcrypt)
- 🔄 **Synchronisation TMDB** en un clic pour tous les films
- 🔗 **Liens** vers TMDB et Allociné pour chaque film
- ⬇️ **Téléchargement** direct des fichiers
- 🔍 **Recherche** filtrée en temps réel
- 📁 Navigation dans les sous-répertoires
- ✅ Compatible **PHP 5.6+** (32-bit inclus)

## Prérequis

- PHP 5.6 ou supérieur
- Apache ou Nginx
- `allow_url_fopen = On` dans php.ini (pour les appels TMDB)
- Un compte TMDB (gratuit) pour les métadonnées

## Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/votre-user/php-film-manager.git
cd php-film-manager
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

Pointer le DocumentRoot (ou un VirtualHost) vers le répertoire du projet.

Exemple Apache :
```apache
<VirtualHost *:8888>
    DocumentRoot /chemin/vers/php-film-manager
    <Directory /chemin/vers/php-film-manager>
        AllowOverride None
        Require all granted
    </Directory>
</VirtualHost>
```

## Structure des fichiers

```
php-film-manager/
├── index.php            # Application principale (tout-en-un)
├── config.php           # Secrets (exclu du dépôt git)
├── config.sample.php    # Modèle de configuration à copier
├── .movies_meta.json    # Cache TMDB (généré automatiquement)
└── .gitignore
```

## Utilisation

1. Ouvrir le site dans un navigateur
2. Se connecter avec le mot de passe configuré
3. Naviguer dans les dossiers
4. Cliquer sur **🎬 Sync métadonnées** pour récupérer les affiches et infos TMDB
5. Basculer entre vue **Grille** et vue **Liste** via les boutons en haut

## Compatibilité PHP 5.6

Ce projet cible délibérément PHP 5.6 pour les NAS et serveurs anciens :
- Pas de types scalaires ni union types
- Pas de fonctions fléchées (`fn()`)
- Pas de `??` (null coalescing)
- `openssl_random_pseudo_bytes()` en fallback de `random_bytes()`
- Gestion des entiers 32-bit pour les fichiers > 2 Go

## Licence

MIT
