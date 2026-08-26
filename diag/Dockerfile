ARG PHP_BASE=php:8.3-cli-bookworm
FROM ${PHP_BASE}

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /app
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
