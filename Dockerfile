# syntax=docker/dockerfile:1.7
FROM node:24-alpine@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf AS builder

RUN apk add --no-cache make gcc g++ git python3

COPY server/package.json server/package-lock.json /app/server/
COPY client/package.json client/package-lock.json /app/client/
COPY shared/package.json shared/package-lock.json /app/shared/
COPY zone-mta/package.json zone-mta/package-lock.json /app/zone-mta/

RUN cd /app/client && npm ci
RUN cd /app/shared && npm ci --omit=dev
RUN cd /app/server && npm ci --omit=dev
RUN cd /app/zone-mta && npm ci --omit=dev

COPY . /app
RUN cd /app/client && npm run build && rm -rf node_modules

FROM node:24-alpine@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf

RUN apk add --no-cache bash dumb-init imagemagick netcat-openbsd \
    && addgroup -g 10001 -S mailtrain \
    && adduser -u 10001 -S -D -H -G mailtrain mailtrain \
    && mkdir -p /app/server/files /run/mailtrain-config \
    && chown -R mailtrain:mailtrain /app /run/mailtrain-config

WORKDIR /app
ENV MAGICK_CONFIGURE_PATH=/app/server/config/imagemagick
COPY --from=builder --chown=mailtrain:mailtrain /app/ /app/

USER mailtrain:mailtrain
EXPOSE 3000 3003 3004
ENTRYPOINT ["dumb-init", "--", "bash", "/app/docker-entrypoint.sh"]
