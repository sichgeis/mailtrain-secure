# Outbound and legacy-file security controls

Mailtrain routes RSS feeds, RSS previews, URL-backed campaign rendering, and AWS SNS certificate and confirmation requests through one outbound policy. The default policy permits only public HTTP and HTTPS destinations on ports 80 and 443. It rejects loopback, private, link-local, carrier-grade NAT, documentation, multicast, and other non-public address ranges before connecting and after every redirect.

The transport resolves the hostname itself and pins the validated address into the connection. Every redirect triggers a fresh resolution and validation. Request duration, redirect count, and response size are bounded by `security.outbound` in `server/config/default.yaml`.

URL-backed campaigns include subscriber-specific merge fields. They therefore fail closed unless their exact origin is listed in `security.outbound.allowedSubscriberDataOrigins`. Include only a trusted HTTPS origin, including a non-default port when applicable. Approval is origin-scoped rather than hostname-prefix based. For example:

```yaml
security:
  outbound:
    allowedSubscriberDataOrigins:
      - https://campaign-renderer.example.com
```

AWS SNS certificate downloads and subscription confirmations inherit the same address and size protections and additionally refuse redirects.

Database-backed file URLs remain the normal path. Legacy Mosaico image paths are resolved inside `client/static/mosaico/uploads`. Absolute paths, traversal segments (including repeated URL encoding), and symlinks that escape this directory are rejected. The container also points ImageMagick at a restrictive policy that disables delegates and all coders except bounded GIF, JPEG, PNG, and WebP processing. Host installations should export `MAGICK_CONFIGURE_PATH` with the absolute path to `server/config/imagemagick` before starting Mailtrain.

If an existing installation uses non-standard feed or rendering ports, private network destinations, or a private AWS-compatible endpoint, it will now fail closed. Do not broadly relax the public-address policy. Put the service behind an approved HTTPS origin or add a narrowly reviewed policy extension with regression tests.
