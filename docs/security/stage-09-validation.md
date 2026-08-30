# Stage 9 validation

Stage 9 is implemented on `codex/security-09-runtime-supply-chain` and proposed in draft pull request #30. It is neither merged nor deployed.

## Test-first sequence

The stage began with runtime, lockfile, OpenPGP, password-validation, and AWS SES characterization tests (`8c50ae30` through `46e6ad30`) before the main implementation (`3dfcb319`). Full CI then exposed four additional compatibility regressions that were each captured before being fixed:

- modern Knex no longer injects Bluebird into migrations: `b3e8ff79` then `11b0b2b7`;
- maintained MJML compilation is asynchronous: `4a0267a8` then `e0e55a2f`;
- Webpack 5 requires an explicit browser `process` shim: `c1660fba` then `569d172f`;
- css-loader 7 defaults to named CSS-module exports while the legacy client imports a default object: `010d4e4c` then `6b0edc59`.

## Local evidence

- Node `v24.20.0` ran the focused runtime/security tests and the complete fast suite successfully.
- The Node 24 browser build completed successfully with the compatibility shims above.
- Remaining build output is limited to legacy Sass deprecations, dynamic MJML bundling warnings, and existing `react-sortable-tree` peer metadata. These warnings do not bypass any audit or scan gate.
- The unrelated, pre-existing whitespace-only change in `client/src/root.js` was left unstaged and was not included in this branch.

## GitHub evidence

[GitHub Actions run `33285670207`](https://github.com/sichgeis/mailtrain-secure/actions/runs/33285670207) passed for implementation head `6b0edc59`:

- 82 of 82 fast unit/security tests passed under Node `v24.20.0`;
- the maintained built-in ZoneMTA tests and real ZoneMTA process integration passed;
- MariaDB 10.11 and MySQL 8.4 both initialized the synthetic legacy fixture and completed migration verification;
- all five Playwright smoke cases passed, covering trusted login, public subscription rendering, origin separation, browser headers, session cookies, and session rotation;
- deterministic production audits reported zero high or critical advisories in every workspace: server has three low advisories, while client, shared, and ZoneMTA report zero advisories;
- the production image ran as UID/GID `10001:10001` on Node `v24.20.0` and produced digest `sha256:d663dd46a426860a427fc7f791373fd61f1723b62ddc0c2ab2c80b6f680f0808`;
- the SPDX SBOM contains 1,044 packages and is retained with the run artifacts;
- Trivy scanned that exact loaded image and reported zero critical or high findings.

The documentation-only validation commit must receive the same required checks before this stage is considered complete.

## Operational boundary

No production deployment, default-branch merge, live-data migration, or credential rotation was performed. The nine pull requests remain staged drafts for human review. The 609-vulnerability GitHub push notice describes the untouched `v2` default branch; Stage 9's production-only audit and exact-image scan results above apply to the stacked hardened head.
