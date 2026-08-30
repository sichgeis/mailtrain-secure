# Stage 8 validation

Stage 8 is implemented on `codex/security-08-netcup-deployment` as test-first commit `57441025` followed by implementation commit `3cab5c6c`. It is proposed in draft pull request #29 and is neither merged nor deployed.

## Local evidence

- The rebuilt pinned Node 24 production image completed all 66 fast/unit/security tests.
- Harness lint and all eight focused Netcup deployment tests passed.
- Docker build completed, and runtime inspection reported Node `v24.20.0`, user `mailtrain:mailtrain`, and UID/GID `10001:10001`.
- The production Compose model resolved with synthetic non-production values; shell and JavaScript syntax checks and `git diff --check` passed.
- An independent operations-security re-review found no remaining blocker after the secret-file permission contract, manual migration gate, isolated files-volume initializer, authenticated dependency checks, Mongo argument handling, and root/application credential-rotation procedures were corrected.

## GitHub evidence

GitHub Actions run `33282370058` passed for implementation head `3cab5c6c`:

- fast/build, including production image build and non-root inspection;
- MariaDB 10.11 integration and legacy-fixture migration;
- MySQL 8.4 integration and legacy-fixture migration;
- Playwright login, subscription, and three-origin smoke coverage.

The documentation-only validation commit must receive the same required checks before this stage is considered complete.

## Operational boundary

These artifacts are templates and runbooks only. No production deployment, schema migration, credential rotation, default-branch merge, or live-data change was performed. Operators must supply real immutable image digests, hostnames, TLS material, and externally mounted secrets, then pass the documented backup, restore, migration-review, firewall, and rollback gates.
