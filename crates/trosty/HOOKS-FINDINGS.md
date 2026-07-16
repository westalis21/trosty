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

## PreToolUse expansion — reflection check (PENDING live E2E)

**Question:** when the hook returns `updatedInput` with `{{name}}` expanded to
the real value, does that expanded value become visible to the model (in its
context or in `transcript_path`)? If yes, expansion would leak — defeating its
purpose.

**Current decision:** `EXPAND: GO` (Task 5 implements expansion). Rationale:
`updatedInput` is an execution-time substitution; the assistant's own message
retains the `{{name}}` placeholder it authored. **Must be confirmed** in the
manual E2E (plan Task 9, step 8). If the live run shows the expanded value
reflected back, switch Task 5 to guard-only per the plan's NO-GO note (deny
unknown/locked, no expansion) — PostToolUse masking is unaffected either way.
