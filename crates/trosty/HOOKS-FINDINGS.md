# Claude Code hooks — capability findings (Plan 3, Task 1)

**Date:** 2026-07-16
**Source of truth:** official docs `code.claude.com/docs/en/hooks` (fetched
2026-07-16) + known Claude Code hook payload schema.

> **Provenance note:** the fixtures in `tests/fixtures/` are constructed from
> the documented + known payload schema, NOT captured from a live Claude Code
> session in the authoring session. Field names below are confirmed against
> the docs. The one item that genuinely needs a live run — the PreToolUse
> `updatedInput` reflection check — is marked PENDING and must be confirmed in
> the Plan 3 manual E2E (plan Task 9, step 8) before relying on expansion in
> real dogfooding.

## Confirmed input field names

| Event | Key fields used by the adapter |
|---|---|
| `PreToolUse` | `hook_event_name`, `tool_name`, `tool_input.command` |
| `PostToolUse` | `hook_event_name`, `tool_name`, `tool_response` (object: `stdout`/`stderr`/…) for Bash |
| `UserPromptSubmit` | `hook_event_name`, `prompt` |

The handlers additionally accept the alternate names `tool_output` (string
form) and `user_prompt` defensively, so a build that differs degrades to a
correct result, never to a leak.

## Confirmed output mechanisms (from docs)

- `PostToolUse` → `hookSpecificOutput.updatedToolOutput` **replaces** the
  tool result the model reads. ✅ output masking is achievable.
- `PreToolUse` → `hookSpecificOutput.updatedInput` **replaces** tool args
  before the tool runs; `permissionDecision: "deny"` blocks it. ✅
- `UserPromptSubmit` → **cannot** rewrite the prompt; only `decision:
  "block"` + `reason` or `hookSpecificOutput.additionalContext`. ✅ guard-only.

## PreToolUse expansion — reflection check (CONFIRMED via live E2E 2026-07-16)

**Question:** when the hook returns `updatedInput` with `{{name}}` expanded to
the real value, does that expanded value become visible to the model (in its
context or in `transcript_path`)? If yes, expansion would leak — defeating its
purpose.

**Result: `EXPAND: GO` — CONFIRMED.** Live E2E run (`trosty hook install` into
a scratch settings file + real Claude Code session). Findings from the session
transcript:

- The assistant's `tool_use` (the command it authored) and the `tool_result`
  contain **only the `{{name}}` placeholder** — the model never receives the
  expanded value. The model's own summary echoed `{{demo/token}}`.
- The expanded real value appears **only** in a transcript-only diagnostic
  entry `type: "attachment"` / `"hook_success"` (fields: `hookName`, `stdout`,
  `exitCode`, `durationMs`). Its model-injected `content` field is **empty**;
  the raw value sits in `stdout`, which Claude Code logs for observability and
  does **not** feed back into model context.
- A second occurrence in an unrelated session's transcript was the finding
  value being typed into guidance text — not a trosty path.

**Residual note (accepted, not a model/API leak):** because `updatedInput`
must carry the real command for expansion to work, the expanded value is
written to the **local** Claude Code transcript file (`hook_success.stdout`
diagnostic record) in plaintext. This is a local-disk footprint on the same
machine, alongside the legitimately-written command output — never sent to the
LLM. Only the guard-only variant (no expansion) avoids it, at the cost of the
feature. Kept as expansion (GO).
