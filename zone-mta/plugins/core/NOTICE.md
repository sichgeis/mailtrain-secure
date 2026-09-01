# ZoneMTA core plugin provenance

`default-headers.js` and `delivery-loop.js` are vendored from the ZoneMTA
`v3.10.18` source tag at commit
`cf94b992e3a5eb81f0bdf28455210227e68a44a9` because the corresponding
`@zone-eu/zone-mta@3.10.18` npm package omits its configured `plugins/`
directory.

- `default-headers.js` upstream blob:
  `03a2d1f53353645f9f14367d70955a3340ff6fb8`
- `delivery-loop.js` upstream blob:
  `957ec93549f24b15ff931800e2a9178be335b3e1`

The only source adaptation is changing `default-headers.js` internal relative
imports to resolve the same `address-tools` and `sending-zone` modules from the
pinned `@zone-eu/zone-mta` dependency. The source is licensed under
EUPL-1.2; the dependency's license text is distributed at
`node_modules/@zone-eu/zone-mta/LICENSE`.
