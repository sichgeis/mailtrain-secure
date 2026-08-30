# Webhook request boundaries

All provider webhooks now fail closed. A provider route returns an error before changing campaign state unless that provider is explicitly enabled and its verification material is configured. Keep verification keys and shared secrets in an externally mounted production configuration or secret store; never commit them or put them in a webhook URL.

## Provider migration

Configure only the providers the deployment uses under `security.webhooks`:

- AWS SNS requires an exact `topicArns` allowlist. Mailtrain verifies the SNS signature, timestamp, certificate URL, and topic before confirming a subscription or processing an event. Confirmation permits only the regional SNS HTTPS origin and never follows redirects.
- SparkPost requires Basic Authentication configured on the SparkPost webhook target. Set the matching `username` and `password`. The provider batch ID is required for replay detection.
- SendGrid requires Signed Event Webhook. Store its ECDSA public verification key in `publicKey`; Mailtrain verifies the signature over the untouched request bytes and timestamp.
- Mailgun requires the account Webhook Signing Key in `signingKey`. Legacy multipart events accept only the expected text fields, no files, at most eight parts, and at most 8192 bytes per field.
- Postal requires its signing public key in `publicKey`. If `keyIds` is non-empty, the `X-Postal-Signature-KID` must also match an allowed value. Mailtrain verifies `X-Postal-Signature-256` over the untouched request body.
- Standalone ZoneMTA requires `security.webhooks.zoneMta.enabled=true` and a high-entropy `token`. Set the same value as `MAILTRAIN_ZONE_MTA_TOKEN`; callbacks send it in `Authorization: Bearer`. The bundled ZoneMTA generates and shares its internal callback token automatically over loopback.

The ZoneMTA sender-configuration endpoint no longer accepts `api_token` in the query string. Callers must send the send configuration's existing DKIM API key as `Authorization: Bearer <token>`. Keep this endpoint on the trusted private route; it is not mounted on Mailtrain's sandbox or public origins.

## Reverse proxy boundary

The Traefik dynamic fragment at `deploy/traefik/request-boundaries.yml` defines a 2 MiB general application limit and a 64 KiB Mailgun limit. Attach `mailtrain-request-limit@file` to every Mailtrain router. Route `/webhooks/mailgun` through a higher-priority trusted-origin router with `mailtrain-mailgun-request-limit@file`. The complete three-origin router and network topology is added in the Netcup deployment stage.

Mailtrain additionally caps parsed JSON, text, and form bodies with `www.postSize`, bounds multipart parts and fields independently, and sets `security.requestTimeoutMs` plus `security.headersTimeoutMs` on every HTTP server. Proxy limits should be no larger than the corresponding application limits.

## Rollout

Enable and test one provider at a time with a synthetic event. Confirm a forged signature, stale timestamp, replay, oversized multipart field, and file upload all fail without changing campaign state. Only then update that provider's production callback. Existing send, campaign, list, and report records require no migration.
