#!/bin/sh
set -e
cd /app

if [ ! -f config.php ]; then
  HASH=$(php -r "echo password_hash('test1234', PASSWORD_BCRYPT);")
  cat > config.php <<EOF
<?php
define('FM_PASSWORD_HASH', '$HASH');
define('FM_TMDB_API_KEY', '');
define('FM_TMDB_LANG', 'fr-FR');
EOF
  echo "config.php genere (mot de passe: test1234)"
fi

# Fichier de test creux (sparse) de ~3.9 Gio pour reproduire le cas reel.
# Extension .mkv pour que le scan de CineNAS le liste comme un film
# (n'occupe presque pas d'espace disque reel grace au sparse file).
if [ ! -f testfile.mkv ]; then
  truncate -s 4200000000 testfile.mkv
  echo "testfile.mkv cree (3.9 Gio sparse)"
fi

echo "PHP_INT_SIZE=$(php -r 'echo PHP_INT_SIZE;') PHP_VERSION=$(php -r 'echo PHP_VERSION;')"

exec php -S 0.0.0.0:8080 -t /app
