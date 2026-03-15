---
name: sniper-operator
description: Use when operating a local Sniper proxy through sniper-cli for session switching, Capture record review, Scope updates, Replay tabs, fuzzer runs, held-request control, Web Socket inspection, auto-replace updates, color tag and note annotations, or Sniper skill installation.
---

# Sniper Operator

Use `sniper-cli` for all Sniper operations. Prefer JSON output and avoid scraping the desktop UI.

## When to use

- Inspect or switch Sniper sessions
- Read Capture HTTP or Web Socket records
- Change Scope patterns
- Open, update, or send Replay tabs
- Seed Replay or Fuzzer from Capture HTTP history
- Set Fuzzer templates and payloads, then run them
- Toggle request holding and forward or drop held requests
- List or replace auto-replace rules
- Set color tags and notes on HTTP records
- Install Sniper skills into Codex or Claude

## Workflow

1. Make sure Sniper Desktop is running, or pass `--api http://127.0.0.1:PORT`.
2. Start with `sniper-cli session list` and switch deliberately before mutating anything.
3. Prefer `--stdin` or `--request-file` for large raw requests.
4. Treat Replay target override fields as the connection target only. The raw `Host:` header stays in the request text.
5. Summarize large JSON responses instead of pasting them in full.

## Common commands

```bash
sniper-cli session list
sniper-cli session switch --id <uuid>
sniper-cli capture http list --limit 20
sniper-cli capture http get --id <uuid>
sniper-cli capture http replay --id <uuid>
sniper-cli capture http fuzzer --id <uuid>
sniper-cli capture http annotate --id <uuid> --color red --note "suspicious"
sniper-cli capture http annotate --id <uuid> --clear-color --clear-note
sniper-cli scope get-scope
sniper-cli scope set-scope --pattern '*.example.com'
sniper-cli replay list
sniper-cli replay open --transaction-id <uuid>
sniper-cli replay send --tab-id <tab-id>
sniper-cli fuzzer set-template --transaction-id <uuid>
sniper-cli fuzzer set-payloads --file payloads.txt
sniper-cli fuzzer run
sniper-cli capture intercept on
sniper-cli capture intercept list
sniper-cli capture intercept forward --id <uuid>
sniper-cli capture web-socket list --limit 20
sniper-cli capture web-socket get --id <uuid>
sniper-cli capture auto-replace list
sniper-cli capture auto-replace set --file rules.json
sniper-cli skills install --claude
```

## Guardrails

- If `sniper-cli` is missing from `PATH`, say so briefly instead of falling back to GUI scraping.
- Do not switch sessions silently before changing scope, Replay state, or queued-request decisions.
- Use `capture http get`, `replay list`, or `capture web-socket get` before making assumptions about stored request state.
