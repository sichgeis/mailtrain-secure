#!/bin/sh
set -eu

secret_file=/run/secrets/redis_secret
secret=$(sed -n '1p' "$secret_file")
case "$secret" in
  ''|*[!A-Za-z0-9_-]*) echo 'Redis secret must be non-empty base64url text' >&2; exit 1 ;;
esac
[ "${#secret}" -ge 32 ] || { echo 'Redis secret must contain at least 32 characters' >&2; exit 1; }

if [ "${1:-}" = health ]; then
  REDISCLI_AUTH=$secret exec redis-cli --no-auth-warning ping
fi

umask 077
{
  printf 'bind 0.0.0.0\n'
  printf 'protected-mode yes\n'
  printf 'requirepass %s\n' "$secret"
  printf 'appendonly yes\n'
  printf 'dir /data\n'
  printf 'rename-command CONFIG ""\n'
  printf 'rename-command FLUSHALL ""\n'
  printf 'rename-command FLUSHDB ""\n'
} > /run/redis/redis.conf
exec redis-server /run/redis/redis.conf
