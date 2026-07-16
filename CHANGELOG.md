# Changelog

## Unreleased

- `trosty-core`: SecretName/SecretStore (keychain-backed + in-memory),
  Scrubber (value + base64/base64-nopad/hex/percent variants,
  chunk-boundary-safe streaming, byte-level masking that stays correct
  around non-UTF8 output and non-ASCII secrets), expander (fail-closed),
  .env parsing, dir→project mapping, append-only audit log.
- CLI: `add`, `ls`, `rm`, `import --project`, `exec --`, `doctor`.
- PTY session: `trosty` starts your shell with live byte-level output masking (SIGWINCH-aware resize).
- Session: status bar (scroll region, alt-screen aware), Ctrl+G peek, hot-reload of secrets on index change.
- Known limitation: masking matches known secret values and their
  standard encodings (base64/hex/percent); an arbitrary transformation
  of a value — e.g. a custom cipher or bespoke encoding the attacker
  controls — is not caught. Only known-value matching is in scope.
- Claude Code hooks adapter (`trosty hook` / `hook install` / `hook uninstall`):
  PostToolUse masks Bash output, PreToolUse expands `{{name}}`, UserPromptSubmit
  blocks raw secrets. Fail-closed throughout. `doctor` reports hook status.
