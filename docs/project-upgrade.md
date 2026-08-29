# Mailtrain Security Hardening Program

## Outcome

Produce a private, reviewable Mailtrain v2 hardening line that preserves application and database behavior while closing the confirmed authorization, network, file, session, secret-handling, dependency, and deployment weaknesses. The target runtime is Node.js 24 LTS. The supported database matrix is MariaDB 10.4+ and MySQL 8. The target deployment is Docker Compose behind Traefik with distinct trusted, sandbox, and public HTTPS origins.

## Boundaries

- Do not merge pull requests, deploy, release, rotate production credentials, or access live production data.
- Keep `Mailtrain-org/mailtrain` as the `upstream` remote and the private `sichgeis/mailtrain-secure` repository as `origin`.
- Preserve the `v2` branch as the review base. All implementation is delivered through staged draft pull requests.
- Use synthetic fixtures only. Existing host/systemd behavior and schema are the compatibility reference.
- Custom JavaScript reports are disabled by default. Building a secure isolated report executor is deferred.

## Completion Evidence

- Required CI passes fast security/unit tests, MariaDB and MySQL integration tests, Playwright smoke tests, lint, build, migrations, clean install, dependency audit, and image scanning.
- Regression coverage proves the RBAC escalation, webhook forgery/SSRF, multipart exhaustion, outbound SSRF, path traversal, stored XSS, session fixation, query-token, log-redaction, throttling, and secret-migration fixes.
- Synthetic legacy data upgrades without loss on MariaDB and MySQL, verified by non-secret row counts and canonical hashes.
- Netcup deployment artifacts expose only Traefik, maintain three origins, run non-root, isolate datastores, mount secrets read-only, and document backup/restore and rollback rehearsal.
- Every accepted stage is committed, pushed, and represented by a draft pull request whose head is green.

## Baseline

- Upstream: `Mailtrain-org/mailtrain` branch `v2`
- Baseline commit: `7c6f34ef25dba981de58aec9785af48f3ea3315d`
- Private repository: `sichgeis/mailtrain-secure`
- Default branch: `v2`
- First implementation branch: `codex/security-01-test-harness`

## Stages

| Stage | Status | Objective |
| --- | --- | --- |
| 1. Test and CI foundation | Complete; draft PR review pending | Node 24-compatible layered test harness, dual-database CI, Playwright smoke coverage, deterministic installs, and preserved artifacts. |
| 2. Authorization boundaries | Complete; draft PR review pending | Enforce share-role ceilings and global-role assignment authority. |
| 3. Immediate deployment and report safety | Complete; draft PR review pending | Remove default credentials/direct exposure and disable unsafe reports by default. |
| 4. Webhook and request boundaries | Complete; draft PR review pending | Authenticate provider events and bound multipart/body processing. |
| 5. Outbound network and filesystem controls | Pending | Centralize safe outbound fetching and close Mosaico traversal. |
| 6. Authentication, browser, logging, and abuse controls | Pending | Header tokens, hardened sessions, CSP/origins, XSS controls, throttling, and redaction. |
| 7. Versioned secret migration | Pending | Encrypt recoverable secrets and hash bearer/reset tokens with safe migration and rotation tooling. |
| 8. Netcup deployment and datastore isolation | Pending | Traefik Compose, non-root containers, private authenticated datastores, least-privilege principals, and rollback guidance. |
| 9. Runtime, dependency, and supply-chain completion | Pending | Supported dependencies, reproducible builds, SBOM/image scanning, and no unaccepted critical/high production advisories. |

## GitHub Tracking

- Umbrella tracker: [#17](https://github.com/sichgeis/mailtrain-secure/issues/17)
- Test harness: [#1](https://github.com/sichgeis/mailtrain-secure/issues/1)
- Test/CI foundation draft: [PR #18](https://github.com/sichgeis/mailtrain-secure/pull/18)
- Authorization escalation: [#2](https://github.com/sichgeis/mailtrain-secure/issues/2)
- Authorization-boundaries draft: [PR #23](https://github.com/sichgeis/mailtrain-secure/pull/23)
- Default credential and backend exposure: [#3](https://github.com/sichgeis/mailtrain-secure/issues/3)
- Unsafe reports: [#4](https://github.com/sichgeis/mailtrain-secure/issues/4)
- Immediate deployment and report-safety draft: [PR #24](https://github.com/sichgeis/mailtrain-secure/pull/24)
- Webhook authenticity and AWS SSRF: [#5](https://github.com/sichgeis/mailtrain-secure/issues/5)
- Multipart exhaustion: [#6](https://github.com/sichgeis/mailtrain-secure/issues/6)
- Webhook/request-boundaries draft: [PR #25](https://github.com/sichgeis/mailtrain-secure/pull/25)
- Campaign/RSS outbound SSRF: [#7](https://github.com/sichgeis/mailtrain-secure/issues/7)
- Runtime and dependencies: [#8](https://github.com/sichgeis/mailtrain-secure/issues/8)
- Credential URL/log leakage: [#9](https://github.com/sichgeis/mailtrain-secure/issues/9)
- Sessions and browser security: [#10](https://github.com/sichgeis/mailtrain-secure/issues/10)
- Mosaico traversal: [#11](https://github.com/sichgeis/mailtrain-secure/issues/11)
- Stored XSS and origin isolation: [#12](https://github.com/sichgeis/mailtrain-secure/issues/12)
- Abuse controls and PII logs: [#13](https://github.com/sichgeis/mailtrain-secure/issues/13)
- Reproducible supply chain: [#14](https://github.com/sichgeis/mailtrain-secure/issues/14)
- Secret encryption and token hashing: [#15](https://github.com/sichgeis/mailtrain-secure/issues/15)
- Netcup and datastore hardening: [#16](https://github.com/sichgeis/mailtrain-secure/issues/16)

## Decisions and Risks

- API authentication will accept `Authorization: Bearer` and the existing `access-token` header. Query tokens are disabled by default behind an explicit temporary compatibility flag.
- Secret storage uses a versioned AES-256-GCM envelope backed by an externally mounted key. Bearer/reset lookups use keyed SHA-256 hashes. Tokens become show-once values.
- Outbound requests default to public HTTP/HTTPS on ports 80/443 and revalidate resolved addresses after redirects.
- The legacy toolchain may not install or build on Node 24. Stage 1 may update build/test-only dependencies needed to establish the harness; broader production dependency changes remain Stage 9.
- GitHub personal-plan restrictions may prevent some repository rules or security features. Unavailable controls must be recorded rather than silently omitted.
- GitHub dependency alerts and automated security-update proposals are enabled. Secret scanning and `v2` branch protection are unavailable for this private repository on the current personal plan (GitHub API responses `422` and `403` respectively); no repository visibility or CI requirement was weakened as a workaround.

## Stage Loop

For every implementation stage: add or harden the relevant test first, implement the smallest coherent fix, run focused checks, run the complete applicable suite, review the diff for security and compatibility, record evidence here, commit, push, and open a draft pull request. A stage is complete only when its acceptance criteria pass at the pushed head.

## Validation Evidence

- Baseline `npm ci --ignore-scripts` failed because the inherited lockfile v1 was inconsistent (`compressjs` and `elliptic` resolutions). All application lockfiles are now npm lockfile v3 generated with Node 24.6.0/npm 11.5.1.
- Node 24 fast/security suite: 9 passing tests. Coverage is 100% for the destructive-database guard; the worker environment allowlist is also exercised.
- Node 24 client clean install and build pass with Dart Sass and an explicit SHA-256 Webpack build hash. Remaining Sass deprecation warnings belong to the inherited CoreUI/Bootstrap styles and are tracked for Stage 9.
- Synthetic MySQL 8 initialization and Knex migration pass locally, validating 67 tables. The authoritative CI matrix passes on MariaDB 10.11 and MySQL 8.4.
- Playwright smoke passes a real synthetic-admin login, subscription rendering, and trusted/sandbox/public origin separation against isolated local MySQL and Redis containers. It also caught and now covers successful login without a `next` query parameter.
- GitHub Actions run [33274056364](https://github.com/sichgeis/mailtrain-secure/actions/runs/33274056364) is green at commit `cfa09074`: fast/build, MariaDB 10.11, MySQL 8.4, and Playwright all pass.
- Authorization grants now require the requested entity permissions and every namespace descendant permission to be subsets of the grantor effective profile. Privilege-bearing global roles additionally require the explicit `manageGlobalRoles` permission; unprivileged local users and equal/weaker namespace roles remain supported.
- The complete `campaignsAdmin -> child namespace master -> global master` chain, including global-master creation and update through a simulated legacy over-privileged share, is blocked on MariaDB and MySQL. The read-only role-grant audit inventories historic explicit shares and privileged global assignments without exposing PII or modifying rows.
- GitHub Actions run [33275000741](https://github.com/sichgeis/mailtrain-secure/actions/runs/33275000741) is green at commit `5a8a8aff`: 12 fast/security tests, build, MariaDB 10.11 RBAC integration, MySQL 8.4 RBAC integration, and Playwright all pass.
- Docker startup now requires an externally supplied strong administrator bootstrap password, passes it through the process environment instead of command-line arguments, and applies it only when the administrator did not exist before initialization. Existing administrator password and API-token changes are preserved across restarts.
- The production Compose baseline no longer publishes Mailtrain ports 3000, 3003, or 3004 on the host. It exposes them only to the private Compose network for a reverse proxy to consume.
- Database-stored JavaScript reports, their routes, client navigation, scheduler, and processor remain disabled unless both report flags are explicitly enabled. Unsafe compatibility mode emits a high-visibility warning that Node vm is not a security boundary.
- GitHub Actions run [33275597917](https://github.com/sichgeis/mailtrain-secure/actions/runs/33275597917) is green at commit `68153b3d`: 19 Node 24 fast/security tests, focused lint, coverage, client build, MariaDB 10.11 integration, MySQL 8.4 integration, and Playwright all pass.
- Provider webhooks now fail closed and use their supported authenticity mechanism: AWS SNS signature/topic/certificate validation, SparkPost Basic Authentication plus batch replay detection, SendGrid ECDSA over raw bytes, Mailgun timestamped HMAC, Postal RSA-SHA256 over raw bytes, and header bearer credentials for ZoneMTA/DKIM. Provider routes are disabled until explicitly configured.
- AWS confirmation accepts only the signed topic's regional SNS HTTPS origin, never follows redirects, and bounds certificate/confirmation fetch duration and certificate size. Provider timestamps and bounded in-process replay caches reject stale or repeated events before state changes.
- Mailgun multipart handling accepts no files, at most eight parts, and at most 8192 bytes per field. Concurrent oversized requests, file parts, excessive fields, malformed payloads, forged signatures, private SNS destinations, and valid fixtures are covered. Matching 2 MiB general and 64 KiB Mailgun Traefik buffering limits are defined for the Stage 8 router topology.
- GitHub Actions run [33276615648](https://github.com/sichgeis/mailtrain-secure/actions/runs/33276615648) is green at commit `8977c590`: 28 Node 24 fast/security tests, focused lint, coverage, client build, MariaDB 10.11 integration, MySQL 8.4 integration, and Playwright all pass.
- The inherited full-repository Grunt lint baseline has 796 pre-existing errors. Stage 1 therefore enforces a clean focused lint gate for the new harness while the broader lint modernization remains part of the runtime/dependency stage.
- Production dependency audits remain deliberately non-blocking in Stage 1 and are retained as CI artifacts. The accepted critical/high baseline is tracked by issues #8 and #14; Stage 9 makes it a blocking release criterion.

## Current Blocker

None.

## Next Action

Start Stage 5 from the green Stage 4 head: characterize AWS confirmation, RSS, campaign URL rendering, redirect, preview, and Mosaico path behavior before introducing the shared outbound-fetch and fixed-base filesystem policies.
