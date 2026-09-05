# Security hardening round 2

Baseline: `a79bf00e1a81bebf9b886d847efe0afb8a568152`. Synthetic data only; no deployment by this task.

## Changes and rollout contract

- Sandbox routes no longer expose trusted account/API/administration endpoints. Editor factories validate target type, identity, editor type and effective permissions; template and campaign Mosaico flows have real browser coverage.
- Account credential/email/delete operations require authority over the target's global role and all effective shares, including other namespaces.
- Editor messages require the exact peer window and origin, typed payloads, bounded outstanding requests, deadlines and single-use responses. Mosaico's narrowly scoped CSP exception is unchanged.
- An additive `users.auth_version` migration invalidates sessions after password or global role/namespace changes. All login adapters reload database authorization. Directory display attributes are preserved separately from authority. Normal sessions have a 12-hour absolute lifetime; remembered sessions 30 days, in addition to existing idle expiry. Legacy sessions require re-login on rollout. Password changes/resets revoke API/reset tokens; deployment alone preserves existing API tokens. Editor capabilities require the original still-authenticated session, and fail after logout or revocation.
- Upload permissions are checked before multipart storage. Aborted streams and downstream failures clean only temporary upload files, never durable originals.
- `security.imageTransforms` defaults: 2 active transformations, 20 queued jobs, 30-second deadlines, 8 MiB output ceiling, 120 misses/IP/minute. Identical in-flight transformations coalesce; disconnects cancel work when no clients remain. Cache hits bypass throttling. Existing public image URLs remain supported; dimensions are normalized before cache lookup.
- Subscription and quick-report CSV downloads neutralize formula/control prefixes by default, including column headers. `?format=raw` is an explicitly labeled machine-import option, unsafe for spreadsheet use.
- Patched TOML, qs, cookie and debug dependencies, compatible build-tool transitive updates, Mocha 12 and flatted 3.4.4. Registry audits on 2026-09-05 report zero production advisories across server, client, shared and ZoneMTA, and zero advisories in the current server/client development graphs. This is not a claim that archived lockfiles, vendored assets or the entire application are vulnerability-free. Daily CI repeats separately recorded production/development audits and exact-built-image scanning; GitHub alert counts from unused/legacy lockfiles must be triaged separately.

## Local evidence

- Node 24.20.0 server fast/security tests: 113 pass, plus focused lint, including session, capability, CSV, upload cleanup, image-pool and updated-tooling regressions.
- Synthetic MariaDB migration and RBAC integration pass, including password replacement, reset replay rejection, version increment and token revocation.
- Browser template AND cloned-template campaign editors initialize with restricted capabilities. Forbidden sandbox account routes and uploads are denied. Logout invalidates the original capability; changing account version invalidates the browser session.
- ImageMagick was installed locally to execute the real durable-image transformation/cache-repair regression; no production image or data was accessed.
- Client build and unit tests pass. ZoneMTA unit/plugin tests: 9 pass; its datastore test requires the dedicated CI Mongo/Redis job.
- All eight local browser checks pass. Initial five-gate CI passed at `a361dff6a6cd4fe08268e09ccc20682debd8c98d`: [run 33982426761](https://github.com/sichgeis/mailtrain-secure/actions/runs/33982426761). All five gates also passed after the build/test dependency fixes at `f75adf45696d322fdc44bf60bf5611af30291803`: [run 33982767818](https://github.com/sichgeis/mailtrain-secure/actions/runs/33982767818). PR #86's checks remain the authoritative gate for its exact final documentation-closeout head.

## Final source review

Reviewed the complete diff plus permission generation, editor consumers, session serialization, upload lifecycle, image subprocess disposal, migration grants and dependency caller compatibility. No unresolved merge-blocking finding remains. This is a same-agent adversarial review, not independent third-party certification.

Additional checks confirmed safe CSV headers and that an actual administrator identity can manage a privileged synthetic target after normal startup permission rebuild; the standalone legacy SQL fixture initially had empty administrator permission rows until that rebuild. No authorization bypass was added to accommodate the fixture. LDAP/CAS display fields remain distinct from current database permissions. API-token issuance uses a version predicate to prevent issuance after a concurrent password revocation.

## Deployment smoke checklist

1. Build from the exact reviewed merged SHA, retain digest/SBOM and scan the exact image. A scan of a newly built image is not evidence about a previously deployed digest: scan that deployed digest separately and retain its report.
2. Back up, apply the additive migration using the deployment's authorized migration principal, then start the new image. Expect existing sessions to require login. Do not rotate API tokens merely for rollout.
3. Verify trusted login/logout and local password/reset revocation using a synthetic account; test configured external auth if used. Check namespace administration cannot reset a privileged account.
4. Create/save/reopen a synthetic Mosaico template and campaign, upload an image, view historical public images and verify cache rows/files survive reconciliation. Confirm separate origins and route-scoped CSP remain intact.
5. Download safe and raw CSV fixtures and compare ordinary values, formula-prefixed values and headers. Raw mode must remain explicitly chosen.
6. Confirm overload responses are bounded 429 with Retry-After and cache hits continue working. Never generate production stress traffic; use isolated staging for load testing.
7. Do not send real campaign mail as part of smoke testing without its separate authorization. Preserve rollback image and evidence.

## Remaining limitations

Production smoke identified a predefined-Mosaico compatibility gap after PR #86: `mosaicoWithFsTemplate` uses the same editor as `mosaico`, but the new factory required literal type equality. The follow-up adds an explicit editor/type allowlist, not a general fallback. Only database-backed `mosaico` gains a base-template permission; predefined variants retain only their authorized template/campaign permissions. No session, CSP, origin, filesystem or role checks are relaxed.

The new browser regression reproduced the original authorized-token request returning 403 before the fix. Afterward, both variants pass actual template and campaign create, toolbar save and reload, plus wrong-editor denial, unrelated-upload denial, sandbox account-route denial and logout revocation. The fast suite passes 114 tests and focused lint passes. The follow-up PR's five CI gates remain the merge requirement; no deployment was performed by this source-code task.

This is a targeted source/runtime hardening round, not a penetration-test certification. Live LDAP/CAS servers, mail delivery, deployed-image scanning and production smoke checks belong to the infrastructure acceptance run. Redis remains required for multi-process/shared session deployment. Restricted-token storage and transform pools are per application process; deployments with multiple replicas must account for aggregate capacity. Custom JavaScript reports remain disabled, not sandboxed.
