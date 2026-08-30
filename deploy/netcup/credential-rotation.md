# Datastore credential rotation

This is an operator-reviewed runbook. Exercise it on an isolated restore before production. Record usernames, key IDs, timestamps, and verification results, but never secret values. Take a coordinated backup and retain the old configuration for the rollback window.

## MariaDB

Use a protected client option file or an interactive standard-input prompt; never place a password in process arguments or shell history. Create a versioned replacement principal such as `mailtrain_runtime_2026_08`, grant only the same database-scoped privileges documented in `mariadb-init.sh`, and require TLS. Do not modify the old principal yet.

Point a new secret file and the corresponding username variable at the replacement account, validate file ownership and mode, render the configuration, and prove connection, `SHOW GRANTS`, migration or runtime behavior, and a test send in staging. Cut over the relevant container and verify it is actually authenticating as the new principal. Keep the old account disabled from new use but available for the agreed rollback window; then revoke and drop it. Rotate root, migration, runtime, and report accounts separately.

Rotate the MariaDB root account in a separate maintenance window. Connect using a protected old-root option file, run `ALTER USER 'root'@'localhost' IDENTIFIED BY ?` through a client API or interactive prompt that binds/reads the new secret without putting it in arguments, and verify a second protected option file can authenticate and inspect users. Atomically replace `DB_ROOT_SECRET_FILE`, restart MariaDB, and verify the official health check and administrative recovery procedure. If verification fails while the original authenticated session is still open, restore the old credential with `ALTER USER`; otherwise use the rehearsed offline MariaDB recovery procedure. The initialization script does not update root on an existing volume.

## MongoDB

Connect with an administrator through a protected configuration file or a script that reads a mounted secret file. Create a versioned `zone-mta` application user with only `readWrite` on `zone-mta`. Update `MAILTRAIN_MONGO_USER` and `MONGO_SECRET_FILE`, validate, restart the application in the maintenance window, and verify authenticated queue access plus rejection of administrative operations. Remove the old user after the rollback window. The empty-volume initialization script is not a rotation mechanism.

Rotate the MongoDB root account separately while authenticated with the old root secret. Use a protected JavaScript file that reads the new secret from a mode-`0440` mount and calls `db.getSiblingDB('admin').updateUser(rootUser, {pwd: newSecret})`; do not interpolate it into the shell or command line. Verify a new administrative connection, atomically switch `MONGO_ROOT_SECRET_FILE`, restart MongoDB, and confirm both its health check and an administrative recovery query. Keep the authenticated maintenance session open until verification; use it to call `updateUser` with the old mounted secret if rollback is required. Rehearse documented offline recovery before production because the old password stops working immediately.

## Redis

This compatibility configuration uses the authenticated default user and therefore has no overlap window. Stop Mailtrain and queue workers, retain the old Redis configuration and secret, change the mounted Redis secret atomically, restart Redis, update/restart Mailtrain, and verify authenticated `PING`, queues, and a test send before reopening traffic. On failure, stop clients and restore both old Redis configuration and old application secret together. A future Redis ACL migration may permit dual-user rotation, but must first be tested against every Mailtrain client.

## Application and encryption secrets

Rotate the session secret only in an announced window because all sessions become invalid. Use the Stage 7 dry-run, migrate, verify, and key-rotation commands for `MAILTRAIN_MASTER_KEY`; preserve every key needed to restore retained backups. Confirm the active key ID and encrypted-record verification before retiring an old key. Initial administrator credentials are bootstrap-only: rotate or disable the account through the application after first login and remove the bootstrap secret from the runtime host when it is no longer required.

For every rotation, verify logs and process listings contain no secret, exercise rollback before revocation, and update the encrypted credential inventory and expiry date.
