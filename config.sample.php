<?php
/**
 * config.php — Configuration du gestionnaire de films
 * =====================================================
 *
 * INSTALLATION :
 *   Copiez ce fichier en config.php et remplissez les valeurs.
 *
 *     cp config.sample.php config.php
 *
 * SÉCURITÉ :
 *   config.php est exclu du dépôt git (.gitignore).
 *   Ne commitez jamais config.php — il contient vos secrets.
 *
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │  FM_PASSWORD_HASH                                                   │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │  Hash bcrypt du mot de passe de connexion au site.                 │
 * │                                                                     │
 * │  Générer un hash avec la commande suivante :                        │
 * │                                                                     │
 * │    php -r "echo password_hash('votre_mot_de_passe', PASSWORD_BCRYPT) . PHP_EOL;"
 * │                                                                     │
 * │  Copier le résultat (commence par $2y$) ci-dessous.               │
 * └─────────────────────────────────────────────────────────────────────┘
 */
define('FM_PASSWORD_HASH', '$2y$12$REMPLACEZ_PAR_VOTRE_HASH_BCRYPT');

/**
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │  FM_TMDB_API_KEY                                                    │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │  Jeton d'accès Bearer à l'API TMDB (The Movie Database).           │
 * │  C'est un token JWT "Read Access Token" (v4), pas une clé v3.      │
 * │                                                                     │
 * │  Pour l'obtenir :                                                   │
 * │    1. Créer un compte sur https://www.themoviedb.org/               │
 * │    2. Aller dans : Compte → Paramètres → API                       │
 * │    3. Faire une demande d'accès API (usage personnel/hobbyiste)     │
 * │    4. Copier le "Jeton d'accès en lecture de l'API"                │
 * │       (long token JWT commençant par eyJ...)                        │
 * │                                                                     │
 * │  Documentation : https://developer.themoviedb.org/docs             │
 * │                                                                     │
 * │  Laisser vide ('') pour désactiver les métadonnées TMDB.           │
 * └─────────────────────────────────────────────────────────────────────┘
 */
define('FM_TMDB_API_KEY', '');

/**
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │  FM_TMDB_LANG                                                       │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │  Langue pour les titres, synopsis et affiches TMDB.                │
 * │  Format BCP 47 : langue-RÉGION                                      │
 * │  Exemples : fr-FR  en-US  de-DE  es-ES  it-IT                     │
 * └─────────────────────────────────────────────────────────────────────┘
 */
define('FM_TMDB_LANG', 'fr-FR');
