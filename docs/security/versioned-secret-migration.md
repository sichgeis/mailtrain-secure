# Versioned secret migration

Stage 7 replaces retrievable credentials with versioned AES-256-GCM envelopes and replaces API/reset tokens with keyed SHA-256 lookup hashes. It does not run a production migration or rotate any live credential automatically.

## Key material

Generate a dedicated 32-byte master key in a secret-management environment:

```sh
openssl rand -base64 32
```

Mount the value into the application as `MAILTRAIN_MASTER_KEY` and assign a non-secret identifier such as `MAILTRAIN_MASTER_KEY_ID=production-2026-01`. The key must remain outside Git, Compose files, logs, command-line arguments, database backups, and application configuration stored in the database.

New deployments require both variables. An existing deployment may temporarily set `MAILTRAIN_ALLOW_PLAINTEXT_SECRETS=true` while preparing the migration, but new secret writes and token issuance still require a master key. Remove the compatibility flag only after verification succeeds.

## Migration procedure

Take and verify a restorable database backup first. Rehearse the full procedure against a staging restore before touching production.

Run the commands from the `server` directory with the normal database configuration and externally mounted master key:

```sh
npm run security:secrets -- dry-run
npm run security:secrets -- migrate
npm run security:secrets -- verify
```

`dry-run` reports record counts without writing. `migrate` locks and updates one record per transaction, so it is resumable and idempotent. `verify` exits with status 2 if plaintext or invalid secret records remain. Output contains counts only; it never prints secret values or tokens.

After a successful staging rehearsal, repeat the backup, dry-run, migration, verification, application smoke test, and rollback rehearsal for the intended maintenance window. Then disable plaintext compatibility and restart the application. Keep the backup under the same access controls as production data.

## Rotation

Install a new `MAILTRAIN_MASTER_KEY` and `MAILTRAIN_MASTER_KEY_ID`. Temporarily provide the prior keys as a JSON object in `MAILTRAIN_PREVIOUS_MASTER_KEYS`, sourced from the secret manager rather than a checked-in file:

```text
{"production-2026-01":"<base64-old-key>"}
```

Then run:

```sh
npm run security:secrets -- rotate
npm run security:secrets -- verify
```

Encrypted SMTP/SES, DKIM, and PGP material is rewritten under the active key. Remove old encryption keys only after verification and rollback-window review.

API and reset tokens use lookup hashes rather than reversible encryption. A lookup hash cannot be converted to a new key without the original token. API tokens presented under a retained key are rehashed to the active key after successful authentication; unused old API tokens require the corresponding retained lookup key or must be reset. Reset tokens expire after one hour and should be allowed to expire or be reissued before retiring the old key.

## User-visible token behavior

Personal API tokens are displayed exactly once when created or reset. A later page load reports only whether a token exists. Lost tokens cannot be recovered and must be reset. Password-reset tokens are stored only as keyed hashes and are deleted when consumed.
