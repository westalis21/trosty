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

> Status: the PTY session, `add`/`exec`/`import`, live output masking, the
> status line, and secret peek all work today — see **Usage** below.

- **Paste a real value into an AI chat by accident?** It is masked before the
  prompt leaves your machine (Claude Code hooks integration).
- **`{{name}}` in a command?** Expanded to the real value at execution time,
  and the output is masked back.
- **Projects:** a directory is a project. trosty spots `.env` files and
  imports them under a namespace (`rostyslab/db_url`) in one keystroke —
  think direnv, but the values never sit in plaintext.

## Usage (v0.1)

```sh
trosty add demo/key            # value prompted, stored in the OS keychain
trosty                         # start a protected shell session (live masking)
# inside a session: Ctrl+G peeks a secret value for 3s
trosty exec -- <cmd>           # one-shot: expand {{name}} args, mask output
trosty import .env --project p # bulk-import into a namespace
```

The session's bottom-row status bar shows the lock state, current project,
and secret count, and updates live — including a visible degradation
message if a hot-reload of the secret store ever fails — whenever the
secret source changes on disk.

## v0.1 scope

- `trosty-core`: vault (keyring), scrubber (value + base64/hex/url-encoded
  variants, chunk-boundary safe), expander, projects, audit log
- PTY session with live masking, status line, and peek
- Claude Code hooks adapter (prompt + tool-output masking)
- Fail-closed everywhere: if protection can't run, the operation doesn't

## Roadmap after v0.1

- **v0.1.1 — API-key custody proxy:** localhost reverse-proxy; tools get
  `ANTHROPIC_BASE_URL=127.0.0.1` + a fake key, the real key lives in the
  keychain and is swapped in on egress; outbound requests scrubbed.
- **Placeholders-in-env (tracked, known v0.1 gap):** today a child
  process still sees real values in its environment. This layer replaces
  them with references that resolve only at egress / via per-protocol
  shims — `echo $KEY` will have nothing to leak.
- Then: TUI manager, per-tool virtual keys, spend limits, audit viewer.

## Development

```sh
cargo test --workspace          # unit + CLI integration tests
cargo test -- --ignored         # real-keychain roundtrip (manual, macOS)
cargo clippy --workspace --all-targets -- -D warnings
```

## License

[AGPL-3.0-only](LICENSE). Contributions require signing the [CLA](CLA.md).
