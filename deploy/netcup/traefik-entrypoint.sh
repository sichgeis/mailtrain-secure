#!/bin/sh
set -eu

valid_host() {
  printf '%s' "$1" | grep -Eq '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$'
}

trusted=$(printf '%s' "${MAILTRAIN_TRUSTED_HOST:?}" | tr '[:upper:]' '[:lower:]')
sandbox=$(printf '%s' "${MAILTRAIN_SANDBOX_HOST:?}" | tr '[:upper:]' '[:lower:]')
public=$(printf '%s' "${MAILTRAIN_PUBLIC_HOST:?}" | tr '[:upper:]' '[:lower:]')
valid_host "$trusted" && valid_host "$sandbox" && valid_host "$public" || {
  echo 'Mailtrain hostnames must be valid DNS names' >&2
  exit 1
}
[ "$trusted" != "$sandbox" ] && [ "$trusted" != "$public" ] && [ "$sandbox" != "$public" ] || {
  echo 'Mailtrain hostnames must be distinct' >&2
  exit 1
}

sed -e "s/__TRUSTED_HOST__/$trusted/g" \
    -e "s/__SANDBOX_HOST__/$sandbox/g" \
    -e "s/__PUBLIC_HOST__/$public/g" \
    /etc/traefik/dynamic-template.yml > /run/traefik/routes.yml
cp /etc/traefik/request-boundaries.yml /run/traefik/request-boundaries.yml

exec traefik \
  --global.checknewversion=false \
  --global.sendanonymoususage=false \
  --api.dashboard=false \
  --ping=true \
  --entrypoints.web.address=:80 \
  --entrypoints.web.http.redirections.entrypoint.to=websecure \
  --entrypoints.web.http.redirections.entrypoint.scheme=https \
  --entrypoints.websecure.address=:443 \
  --providers.file.directory=/run/traefik \
  --providers.file.watch=true \
  --certificatesresolvers.letsencrypt.acme.email="${ACME_EMAIL:?}" \
  --certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json \
  --certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web
