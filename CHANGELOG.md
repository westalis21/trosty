# Changelog

## Unreleased

- `trosty-core`: SecretName/SecretStore (keychain-backed + in-memory),
  Scrubber (value + base64/base64-nopad/hex/percent variants,
  chunk-boundary-safe streaming), expander (fail-closed), .env parsing,
  dir→project mapping, append-only audit log.
- CLI: `add`, `ls`, `rm`, `import --project`, `exec --`, `doctor`.
- Known limitation: `exec` output masking may mangle non-ASCII characters
  split across read boundaries; secrets themselves are matched as ASCII.
