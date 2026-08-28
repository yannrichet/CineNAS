# AGENTS.md

Notes pour tout agent (ou humain) qui reprend ce projet, au-delà de ce que dit README.md.

## Le projet en une phrase

`index.php` est une application PHP **mono-fichier** (~2200 lignes) : gestionnaire de
films auto-hébergé, scan de répertoire + métadonnées TMDB + téléchargement/streaming.
Pas de framework, pas de build step, pas de dépendances Composer.

## Contrainte non négociable : PHP 5.6+ (32-bit inclus)

Le README l'annonce, mais c'est plus contraignant qu'il n'y paraît :
- Ciblé pour tourner sur de vieux NAS (Synology, etc.) avec un PHP 32-bit.
- Interdit : types scalaires, union types, fonctions fléchées (`fn()`), tout ce qui
  est PHP 7.0+. Vérifier avant d'utiliser une fonctionnalité récente.
- `PHP_OS_FAMILY` (constante) n'existe qu'à partir de PHP 7.2 — utiliser
  `stripos(PHP_OS, 'WIN')` à la place si besoin de détecter Windows.

## Le piège récurrent : `filesize()` sur PHP 32-bit

`zend_long` fait 32 bits sur un PHP 32-bit. Au-delà de **2 Go**, `filesize()`/
`stat()['size']` peuvent renvoyer une valeur fausse de deux façons différentes :

1. **2-4 Go** : la valeur wrap en négatif. Récupérable avec
   `sprintf('%u', (int)$val)` qui réinterprète le bit pattern en non-signé.
2. **≥ 4 Go** : l'info est **perdue avant même le wrap** (troncature au niveau du
   syscall/zend_long) — le résultat est positif mais faux, et aucun trick
   arithmétique en PHP pur ne peut la récupérer. La seule source fiable est un
   outil externe qui lit la vraie taille 64-bit, par ex. `stat -c%s` (shell_exec).

Toute la logique est centralisée dans `fm_filesize()` (index.php). **Ne jamais**
réintroduire un appel direct à `filesize()` ou `stat()['size']` ailleurs dans le
code pour un chemin qui peut afficher/envoyer une taille — toujours passer par
`fm_filesize()`. C'est déjà arrivé deux fois (le scan du listing dupliquait la
logique buguée séparément de `fm_send_file()`).

Si vous touchez à ce code, testez avec l'environnement `diag/` (voir plus bas) et
un vrai fichier ≥ 4 Go, pas seulement un fichier sparse dans la fourchette 2-4 Go —
c'est justement la fourchette où le fix précédent (naïf) avait l'air de marcher.

## Environnement de diagnostic `diag/`

`diag/docker-compose.yml` lance deux conteneurs côte à côte : PHP 8.3 64-bit
(`linux/amd64`) et PHP 8.3 32-bit (`linux/386`), tous deux pointant sur le vrai
`index.php` du dépôt. Utile pour tout bug qui dépend de `PHP_INT_SIZE`.

Points d'attention si vous relancez cet environnement :

- **`docker compose` peut être en réalité Podman** sur certaines machines
  (`docker version` affiche "Emulate Docker CLI using podman"), et le plugin
  compose v1 externe (`docker-compose` python) ne parle pas le socket podman
  → `docker.errors.DockerException: ... http+docker`. Utiliser directement
  `podman-compose` dans ce cas.
- **Le `platform:` de service dans docker-compose.yml ne s'applique qu'au
  `run`, pas forcément au `build`** selon l'implémentation compose utilisée. Si
  les deux conteneurs affichent le même `PHP_INT_SIZE` après build, l'image de
  base 386 a probablement été réutilisée en cache pour les deux — forcer
  explicitement `podman build --platform linux/amd64 ...` (ou équivalent
  docker) et vérifier `podman image inspect <img> --format '{{.Architecture}}'`.
- **`volumes: - ..:/app` monte le dépôt entier**, pas une copie. L'entrypoint
  du conteneur (`diag/entrypoint.sh`) génère `config.php` et `testfile.mkv`
  directement à la racine du dépôt (déjà dans `.gitignore`) — et un `diag.php`
  vide peut aussi apparaître par effet de bord du bind-mount imbriqué. Toujours
  vérifier `git status` après une session diag et nettoyer les artefacts avant
  de commit.
- Identifiants : mot de passe `test1234` sur les deux ports (8064 = 64-bit,
  8032 = 32-bit). Le login passe par un token CSRF (`_csrf`) présent dans le
  formulaire — pas de login "bête" via curl sans le récupérer d'abord.

## Style du code existant

- Commentaires : uniquement quand le POURQUOI n'est pas évident (contrainte
  cachée, contournement d'un bug précis) — pas de description du QUOI.
- Beaucoup de commentaires en français dans le code et les messages de commit ;
  rester cohérent avec l'existant plutôt que d'introduire de l'anglais partout.
- Pas d'abstraction/refactor superflu : c'est un fichier unique volontairement
  simple, ne pas le découper en classes/namespaces sans qu'on le demande.

## Secrets

`config.php` (hash bcrypt + clé TMDB) ne doit jamais être commité — déjà dans
`.gitignore`, mais toujours vérifier `git status`/`git diff` avant un commit si
vous avez touché à la config ou à l'environnement diag.
