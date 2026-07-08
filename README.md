# trosty

**A protective terminal layer for working with secrets next to AI tools.**

AI coding agents are brilliant and careless at the same time: they read your
`.env`, echo your keys, and happily paste whatever they saw into a prompt that
leaves your machine. trosty makes that a non-event.

> Status: **early development** — the design is settled, the code is being
> built in public. Star/watch to follow along.

## The idea

Your AI (and your screen) only ever see secret **names** — `{{stripe_key}}`.
Real values live in the OS keychain (macOS Keychain / Windows DPAPI / Linux
libsecret) and appear only at the moment a command actually runs.

```
$ trosty add stripe_key        # value goes straight to the keychain
$ trosty                       # start a protected PTY session in your terminal

┌─ rostyslab · 4 secrets · 🔒 ─┐
$ cat .env
STRIPE_KEY={{rostyslab/stripe_key}}   # masked live, press peek-key to reveal 3s
```

- **Paste a real value into an AI chat by accident?** It is masked before the
  prompt leaves your machine (Claude Code hooks integration).
- **`{{name}}` in a command?** Expanded to the real value at execution time,
  and the output is masked back.
- **Projects:** a directory is a project. trosty spots `.env` files and
  imports them under a namespace (`rostyslab/db_url`) in one keystroke —
  think direnv, but the values never sit in plaintext.

## v0.1 scope

- `trosty-core`: vault (keyring), scrubber (value + base64/hex/url-encoded
  variants, chunk-boundary safe), expander, projects, audit log
- PTY session with live masking, status line, and peek
- Claude Code hooks adapter (prompt + tool-output masking)
- Fail-closed everywhere: if protection can't run, the operation doesn't

Later layers: placeholders-in-env (real values never enter the AI's
environment at all), then a localhost reverse-proxy with API-key custody.

## Development

```
cargo test --workspace
cargo clippy --workspace --all-targets
```

## License

[AGPL-3.0-only](LICENSE). Contributions require signing the [CLA](CLA.md).
