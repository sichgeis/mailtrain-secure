#!/bin/sh
set -eu

environment_file=${1:-.env}
[ -r "$environment_file" ] || { echo "Cannot read $environment_file" >&2; exit 1; }
set -a
. "$environment_file"
set +a

value_of() { eval "printf '%s' \"\${$1-}\""; }
required() {
  value=$(value_of "$1")
  [ -n "$value" ] || { echo "$1 is required" >&2; exit 1; }
}

for name in TRAEFIK_IMAGE MARIADB_IMAGE REDIS_IMAGE MONGO_IMAGE MAILTRAIN_IMAGE; do
  required "$name"
  value=$(value_of "$name")
  printf '%s' "$value" | grep -Eq '@sha256:[0-9a-f]{64}$' || {
    echo "$name must end in an immutable @sha256 digest" >&2
    exit 1
  }
done

for name in MAILTRAIN_TRUSTED_HOST MAILTRAIN_SANDBOX_HOST MAILTRAIN_PUBLIC_HOST; do
  required "$name"
  value=$(value_of "$name")
  printf '%s' "$value" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$' || {
    echo "$name is not a valid hostname" >&2
    exit 1
  }
done
[ "$MAILTRAIN_TRUSTED_HOST" != "$MAILTRAIN_SANDBOX_HOST" ] && \
[ "$MAILTRAIN_TRUSTED_HOST" != "$MAILTRAIN_PUBLIC_HOST" ] && \
[ "$MAILTRAIN_SANDBOX_HOST" != "$MAILTRAIN_PUBLIC_HOST" ] || {
  echo 'The three Mailtrain hostnames must be distinct' >&2
  exit 1
}

required ACME_EMAIL
required MAILTRAIN_MASTER_KEY_ID
MAILTRAIN_SECRET_GID=${MAILTRAIN_SECRET_GID:-10001}
TRAEFIK_UID=${TRAEFIK_UID:-65532}
case "$MAILTRAIN_SECRET_GID:$TRAEFIK_UID" in
  *[!0-9:]*|:*|*:) echo 'MAILTRAIN_SECRET_GID and TRAEFIK_UID must be numeric' >&2; exit 1 ;;
esac

secret_files='DB_ROOT_SECRET_FILE DB_MIGRATION_SECRET_FILE DB_RUNTIME_SECRET_FILE DB_REPORT_SECRET_FILE DB_CA_FILE DB_SERVER_CERT_FILE DB_SERVER_KEY_FILE REDIS_SECRET_FILE MONGO_ROOT_SECRET_FILE MONGO_SECRET_FILE MAILTRAIN_ADMIN_SECRET_FILE MAILTRAIN_SESSION_SECRET_FILE MAILTRAIN_MASTER_KEY_FILE'
for name in $secret_files TRAEFIK_ACME_FILE; do
  required "$name"
  file=$(value_of "$name")
  [ -r "$file" ] || { echo "$name is not readable" >&2; exit 1; }
done

for name in $secret_files; do
  file=$(value_of "$name")
  ownership=$(stat -c '%a:%g' "$file")
  [ "$ownership" = "440:$MAILTRAIN_SECRET_GID" ] || {
    echo "$name must have mode 0440 and group $MAILTRAIN_SECRET_GID (found $ownership)" >&2
    exit 1
  }
done
acme_ownership=$(stat -c '%a:%u' "$TRAEFIK_ACME_FILE")
[ "$acme_ownership" = "600:$TRAEFIK_UID" ] || {
  echo "TRAEFIK_ACME_FILE must have mode 0600 and owner $TRAEFIK_UID (found $acme_ownership)" >&2
  exit 1
}

docker compose --env-file "$environment_file" -f compose.yml config >/dev/null
echo 'Netcup deployment configuration validated'
