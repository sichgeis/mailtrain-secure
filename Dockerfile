# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM node:24-alpine@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf AS builder

RUN apk add --no-cache \
    make=4.4.1-r4 \
    gcc=15.2.0-r5 \
    g++=15.2.0-r5 \
    git=2.54.0-r0 \
    python3=3.14.7-r1

COPY server/package.json server/package-lock.json /app/server/
COPY client/package.json client/package-lock.json /app/client/
COPY shared/package.json shared/package-lock.json /app/shared/
COPY zone-mta/package.json zone-mta/package-lock.json /app/zone-mta/
COPY .npmrc /app/.npmrc

RUN cd /app/client && npm ci
RUN cd /app/shared && npm ci --omit=dev
RUN cd /app/server && npm ci --omit=dev
RUN cd /app/zone-mta && npm ci --omit=dev

COPY . /app
RUN rm -rf /app/client/dist /app/server/coverage \
    && cd /app/client \
    && npm run build \
    && rm -rf node_modules /app/server/test /app/zone-mta/test

FROM node:24-alpine@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf

RUN apk add --no-cache \
    bash=5.3.9-r1 \
    dumb-init=1.2.5-r4 \
    imagemagick=7.1.2.30-r0 \
    libcrypto3=3.5.8-r0 \
    libssl3=3.5.8-r0 \
    netcat-openbsd=1.234.1-r0 \
    && rm -rf \
        /usr/local/lib/node_modules/npm \
        /usr/local/lib/node_modules/corepack \
        /usr/local/bin/npm \
        /usr/local/bin/npx \
        /usr/local/bin/corepack \
        /usr/local/bin/yarn \
        /usr/local/bin/yarnpkg \
        /usr/local/bin/pnpm \
        /usr/local/bin/pnpx \
        /opt/yarn-v* \
    && addgroup -g 10001 -S mailtrain \
    && adduser -u 10001 -S -D -H -G mailtrain mailtrain \
    && mkdir -p /app/server/files /run/mailtrain-config \
    && chown -R mailtrain:mailtrain /app /run/mailtrain-config

WORKDIR /app
ENV MAGICK_CONFIGURE_PATH=/app/server/config/imagemagick
COPY --from=builder --chown=mailtrain:mailtrain /app/server /app/server
COPY --from=builder --chown=mailtrain:mailtrain /app/shared /app/shared
COPY --from=builder --chown=mailtrain:mailtrain /app/zone-mta /app/zone-mta
COPY --from=builder --chown=mailtrain:mailtrain /app/client/dist /app/client/dist
COPY --from=builder --chown=mailtrain:mailtrain /app/client/static /app/client/static
COPY --from=builder --chown=mailtrain:mailtrain /app/locales /app/locales
COPY --from=builder --chown=mailtrain:mailtrain /app/deploy/netcup /app/deploy/netcup
COPY --from=builder --chown=mailtrain:mailtrain /app/docker-entrypoint.sh /app/docker-entrypoint.sh
COPY --from=builder --chown=mailtrain:mailtrain /app/LICENSE /app/LICENSE

USER mailtrain:mailtrain
EXPOSE 3000 3003 3004
ENTRYPOINT ["dumb-init", "--", "bash", "/app/docker-entrypoint.sh"]
