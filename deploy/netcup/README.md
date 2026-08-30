# Netcup production deployment

This directory is a reviewable production template, not an automatic deployment. It keeps the trusted, sandbox, and public applications on three distinct HTTPS hostnames; publishes only Traefik ports 80 and 443; and leaves Mailtrain, MariaDB, Redis, and MongoDB on private Docker networks.

## Prepare

1. Copy `.env.example` to a private `.env`. Set five complete image references ending in `@sha256:<64 lowercase hex>`. Build `MAILTRAIN_IMAGE` from the reviewed commit and record both its digest and source commit. Never use `latest`.
2. Choose three distinct DNS names. Point all three at the Netcup server, set the ACME email, and pre-create the ACME file with mode `0600` and ownership matching the configured Traefik UID.
3. Generate independent base64url secrets of at least 32 characters for the database root, migration, runtime, report, Redis, Mongo root/application, initial administrator, and session. Generate the Stage 7 32-byte base64 master key separately. Store each value outside the repository.
4. On the Linux host, create the secrets directory as `root:10001` mode `0750` and every Compose secret and MariaDB TLS file as `root:10001` mode `0440`. Set `MAILTRAIN_SECRET_GID=10001`, or consistently choose another unused shared group ID. Local Compose file secrets retain host permissions; root-owned mode `0600` files are not readable by these non-root containers. Keep the ACME file separate at mode `0600`, owned by `TRAEFIK_UID`.
5. Provision a private CA and MariaDB server certificate whose SAN covers `mariadb`; mount the CA, certificate, and key through the required file variables. Do not disable certificate verification.
6. Run `./validate-env.sh .env`, inspect `docker compose --env-file .env -f compose.yml config`, and save the resolved image digests without saving secret contents. The validator enforces the host UID/GID and mode contract before Compose starts.

The migration container uses the database-scoped migration principal and must finish before the runtime starts. The runtime principal has DML plus schema-local `CREATE`, `ALTER`, `DROP`, and `INDEX` because Mailtrain creates subscriber/import tables during normal list and import operations. It has no global privileges or grant option. The report principal is read-only and reports remain disabled. Removing runtime DDL requires a later application schema redesign; pretending the application is CRUD-only would break existing behavior. MariaDB initialization scripts run only for an empty data volume; for an existing database, create and audit these three principals manually in staging before using this template.

LDAP and CAS extensions are no longer downloaded during startup. If needed, pin them in a reviewed derived image and lockfile. Do not restore runtime package installation.

## Backup and restore rehearsal

Before first cutover and every schema or secret migration, take coordinated backups of MariaDB, MongoDB, Redis persistence, the `mailtrain-files` volume, Traefik ACME state, deployment configuration, and every encryption key needed by retained backups. Use an option file or secret file for backup credentials, never command-line passwords. Encrypt, checksum, copy off-host, and test retention.

Restore into an isolated staging project with outbound SMTP blocked. Verify table and collection counts, canonical hashes of non-secret records, files, authentication, a smoke campaign to test recipients, all three distinct origins, and the Stage 7 secret verification command. Rehearse rollback using the prior pinned image/config digests plus the matching database, files, and key backup. An image-only rollback is safe only when the schema is backward compatible.

No production migration is performed by these files on their own. A plain `docker compose up -d` starts only the unprofiled datastores. Use this explicit approval sequence after staging validation:

1. Start datastores with `docker compose --env-file .env -f compose.yml up -d mariadb redis mongo`.
2. For a new or existing files volume, run `docker compose --env-file .env -f compose.yml --profile maintenance run --rm files-init`. Inspect the output and verify UID 10001 can create and remove a test file in the volume. This narrowly capable, one-shot root container is the only ownership migration path; it never joins a network or mounts secrets.
3. Take and verify the coordinated backup described above.
4. Run `docker compose --env-file .env -f compose.yml --profile migration run --rm migrate`.
5. Review the complete migration output, schema state, row counts, canonical hashes, and Stage 7 secret-migration verification. Stop and restore if any check differs.
6. Only after explicit operator approval, start the long-running services with `docker compose --env-file .env -f compose.yml --profile runtime up -d mailtrain traefik`.

The runtime service does not depend on the migration service and refuses to start with a pending schema migration.

## Firewall and runtime validation

Apply both the Netcup provider firewall and host `nftables`/`DOCKER-USER` policy for IPv4 and IPv6. Permit SSH only from administrative source ranges and permit public TCP 80/443. Block 3000, 3003, 3004, 3306, 6379, 27017, and 2525 from outside. Open port 25 only if this host is intentionally an inbound VERP MX and that separate risk has been reviewed. Docker-published traffic can bypass simplistic UFW rules, so verify from an external IPv4 and IPv6 host.

After startup, verify:

- unknown hostnames receive a Traefik 404;
- trusted maps to 3000, sandbox to 3003, and public to 3004 without a 421 response;
- the high-priority Mailgun webhook route stays on trusted port 3000 with the 64 KiB limit;
- no backend or datastore port is externally reachable;
- every process has a nonzero UID, `NoNewPrivs` is enabled, effective capabilities are empty, and writes outside declared tmpfs/data mounts fail;
- unauthenticated Redis and Mongo access fails, MariaDB requires TLS, and each database principal has only its documented `SHOW GRANTS` output;
- CPU, memory, PID, file-descriptor, and writable-tmpfs limits are active;
- backup and restore complete successfully.

Restrict Mailtrain egress with host firewall policy to approved DNS, HTTP/HTTPS, and configured mail destinations. The application-level outbound-fetch policy is not a replacement for container/host egress controls.

## Operations and rollback

Update one immutable image digest at a time in staging, rerun validation and smoke tests, then use a reviewed maintenance window. Keep reports disabled and secrets mounted read-only. Monitor health, authentication failures, datastore latency, queue depth, and disk use.

Use the [credential rotation runbook](credential-rotation.md) for database, Redis, MongoDB, session, and encryption-key changes. Changing a mounted secret file alone is not a rotation: it can immediately lock running and restarted services out of their datastores.

On incident, stop new sends, preserve logs without request bodies or credentials, and decide whether rollback is code-only or requires the rehearsed data restore. Restore the prior complete configuration and matching keyring; validate all three origins and a test send before reopening traffic. Never rotate credentials, deploy, merge a branch, or run a live-data migration merely because this template changed.
