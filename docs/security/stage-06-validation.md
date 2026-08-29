# Stage 6 validation evidence

Stage 6 is implemented in draft pull request [#27](https://github.com/sichgeis/mailtrain-secure/pull/27), stacked on the green Stage 5 branch. It remains unmerged and undeployed.

The implementation commit is `0ae2c068`. It follows the regression-test commit `29a4d3ac`. Follow-up harness commits `c6f0c373` and `8e02083d` removed eval-based Webpack output, exercised real origin routes, and kept fast tests independent of client dependencies.

Local Node 24 validation:

- Focused lint: passed.
- Fast/security tests: 50/50 passed.
- Focused coverage: passed with 90.5% statement coverage.
- Client build: passed with `devtool: false`; existing Sass/Babel deprecation warnings remain.
- Docker Compose configuration and entrypoint shell syntax: passed with synthetic HTTPS origin values.
- Independent authentication-boundary review: no remaining Stage 6 merge blockers after session, CAS, rate-limit, query-token, sanitizer, and restricted-capability fixes.

GitHub Actions run [33279872368](https://github.com/sichgeis/mailtrain-secure/actions/runs/33279872368) passed every required job:

- Fast tests, coverage, deterministic installs, and client build: passed.
- MariaDB 10.11 migration/integration suite with Redis: passed.
- MySQL 8.4 migration/integration suite with Redis: passed.
- Playwright login, session rotation, subscription, CSP, and three-origin smoke suite: passed.

No production database, deployment, merge, credential rotation, or live-data action was performed.
