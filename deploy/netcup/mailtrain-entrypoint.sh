#!/bin/sh
set -eu

export NODE_ENV=production
export NODE_CONFIG_DIR=/app/server/config:/run/mailtrain-config

node /app/deploy/netcup/render-config.js

case "${MAILTRAIN_MODE:?MAILTRAIN_MODE is required}" in
  migrate)
    ADMIN_PASSWORD=$(sed -n '1p' "${MAILTRAIN_ADMIN_SECRET_FILE:?Admin secret file is required}")
    if [ -z "$ADMIN_PASSWORD" ]; then
      echo 'Mailtrain administrator secret is empty' >&2
      exit 1
    fi
    export ADMIN_PASSWORD
    cd /app/server
    exec node setup/docker-entrypoint-db-setup.js
    ;;
  secrets)
    cd /app/server
    exec node setup/security/secret-migration.js "${1:?Secret migration mode must be dry-run, migrate, or verify}"
    ;;
  app)
    cd /app/server
    exec node index.js
    ;;
  *)
    echo 'MAILTRAIN_MODE must be migrate, secrets, or app' >&2
    exit 1
    ;;
esac
