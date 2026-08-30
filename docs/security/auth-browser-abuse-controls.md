# Authentication, browser, logging, and abuse controls

Stage 6 changes the security defaults at the HTTP boundary. Existing API clients should move credentials to `Authorization: Bearer <token>`. The historical `access-token` request header remains supported. Query-string tokens are rejected by default because URLs commonly enter browser history, proxy logs, referrers, and monitoring systems.

An emergency compatibility window can be enabled with:

```yaml
security:
  legacyQueryTokens:
    enabled: true
```

This setting emits a redacted deprecation warning and should have an owner and removal date. Rotate any API, DKIM, ZoneMTA, or reset credential that may previously have appeared in URL or application logs. Password-reset links now carry the secret in a URL fragment; the client captures it and immediately removes the fragment from the visible URL and browser history state.

## Production browser boundary

Production startup now requires three distinct HTTPS origins, a persistent session secret of at least 32 high-entropy characters, Secure cookies, and a bounded proxy-trust setting. A representative environment-specific configuration is:

```yaml
www:
  trustedUrlBase: https://mail.example.com
  sandboxUrlBase: https://mail-sandbox.example.com
  publicUrlBase: https://mail-public.example.com
  secret: externally-mounted-high-entropy-session-secret
  proxy: 1
security:
  sessions:
    name: __Host-mailtrain.sid
    secure: true
    maxAgeMs: 43200000
    rememberMaxAgeMs: 2592000000
```

Do not use `proxy: true` in production: it trusts forwarding headers from every peer. Set the exact hop count or trusted proxy range for the Netcup/Traefik topology. Mailtrain validates the request Host, rejects cross-origin unsafe requests on trusted and sandbox applications, regenerates local, LDAP, and CAS sessions at login, destroys local and CAS sessions at logout, and sets `HttpOnly`, `Secure`, `SameSite=Lax`, and bounded expiry attributes. Production session and CSRF cookies use the `__Host-` prefix so sibling origins cannot plant parent-domain replacements; login/logout also clear the historical `mailtrain.sid` cookie during migration.

Mailtrain and the supplied Traefik middleware set HSTS, CSP, `nosniff`, Referrer-Policy, and Permissions-Policy. Trusted pages cannot be framed. Public pages cannot be framed. The sandbox origin may be framed only by the configured trusted origin. Keep all three origins separate at DNS, TLS, routing, cookies, and application configuration layers.

Archived campaign and RSS-preview HTML is structurally sanitized before rendering. Report HTML is sanitized and placed in an iframe without script, form, navigation, or same-origin privileges. This can remove legacy active content, embedded forms, remote CSS imports, SVG, media, and unsafe style declarations. Test representative templates in staging. Do not weaken the CSP or iframe sandbox to restore active content; reports remain disabled by default.

## Abuse controls and logs

The `security.rateLimits` section configures login, password-reset, subscription, subscription-mutation, and webhook policies. Keys combine a keyed digest of the client IP with an account, list, or provider scope. Redis-backed deployments use atomic expiring counters. Memory-backed deployments use bounded storage and fail closed when full. Limit responses are generic and include `Retry-After`; datastore errors fail closed with a service error.

Tune limits using synthetic staging traffic before rollout. Traefik request limits remain a separate first layer. Provider authentication is always required even when a request is below its rate limit.

HTTP logging now uses a correlation ID and redacts Bearer/header/query credentials, reset paths, email addresses, and the sandbox token path segment. Subscriber form bodies, recipient addresses, provider message identifiers, link destinations, and VERP payloads are no longer written to routine logs. Review external proxy, APM, and load-balancer logging independently; application redaction cannot clean records produced before Mailtrain receives a request.

Restricted sandbox access links still use a replayable, short-lived, single-purpose path capability for initial cross-origin document loading. It expires after two minutes, is removed from Mailtrain's internal routed URL, and is redacted from application access logs. Issuance and refresh require login, CSRF validation, and throttling; expired entries are proactively removed and global/per-user storage is bounded. Treat sandbox browser history and any upstream proxy logs as sensitive until this legacy bootstrap mechanism is replaced by a one-time capability exchange that does not put the secret in a request target.
