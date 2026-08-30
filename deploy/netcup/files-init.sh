#!/bin/sh
set -eu

target=/app/server/files
[ -d "$target" ] || { echo 'Mailtrain files volume is not mounted' >&2; exit 1; }
chown -R 10001:10001 "$target"
find "$target" -xdev \( ! -user 10001 -o ! -group 10001 \) -print -quit | grep -q . && {
  echo 'Mailtrain files ownership migration failed' >&2
  exit 1
}
echo 'Mailtrain files volume ownership is ready for UID 10001'
