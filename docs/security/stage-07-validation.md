# Stage 7 validation

Draft PR: [#28](https://github.com/sichgeis/mailtrain-secure/pull/28)

The implementation remains unmerged and has not been applied to production data.

## Test-first sequence

1. `feb73f37 test: define versioned secret migration boundaries`
2. `40508e7f security: add versioned encrypted secret storage`

## Local validation

- Node.js 24 harness lint passed.
- Fast unit/security suite passed: 57 tests.
- Client production build passed. Existing Sass and Babel dependency deprecation warnings remain tracked by the runtime/dependency stage.
- `git diff --check` passed.
- An independent authorization review identified a lazy-token-rotation race; the implementation commit resolves it by holding a row lock through lookup and rehash.

## GitHub Actions

Security CI run [33280934234](https://github.com/sichgeis/mailtrain-secure/actions/runs/33280934234) passed all jobs:

- Fast tests, coverage, dependency baselines, and client build.
- MariaDB 10.11 schema upgrade plus seeded plaintext-secret dry-run, migration, verification, and idempotence check.
- MySQL 8.4 schema upgrade plus the same seeded migration checks.
- Playwright login and origin-isolation smoke tests.

The synthetic fixture verifies that public mailer settings remain unchanged, SMTP credentials and PGP material round-trip only through authenticated envelopes, plaintext token columns are cleared, and access/reset lookup hashes match only under the configured key and purpose.

GitHub emitted informational warnings that some pinned action releases currently target the deprecated Node.js 20 action runtime while the workflow forces Node.js 24. This is not an application test failure and remains part of the supply-chain completion stage.
