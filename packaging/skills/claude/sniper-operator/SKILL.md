---
name: sniper-operator
description: Use when operating a local Sniper proxy through sniper-cli for session switching, HTTP history review, target scope updates, repeater tabs, fuzzer runs, intercept control, websocket inspection, or Sniper skill installation.
---

# Sniper Operator

Use `sniper-cli` for all Sniper operations. Prefer JSON output and avoid scraping the desktop UI.

## When to use

- Inspect or switch Sniper sessions
- Read HTTP history or websocket history
- Change target scope patterns
- Open, update, or send Repeater tabs
- Set Fuzzer templates and payloads, then run them
- Toggle intercept and forward or drop queued requests
- Install Sniper skills into Codex or Claude

## Workflow

1. Make sure Sniper Desktop is running, or pass `--api http://127.0.0.1:PORT`.
2. Start with `sniper-cli session list` and switch deliberately before mutating anything.
3. Prefer `--stdin` or `--request-file` for large raw requests.
4. Treat Repeater target override fields as the connection target only. The raw `Host:` header stays in the request text.
5. Summarize large JSON responses instead of pasting them in full.

## Common commands

```bash
sniper-cli session list
sniper-cli session switch --id <uuid>
sniper-cli history list --limit 20
sniper-cli history get --id <uuid>
sniper-cli target get-scope
sniper-cli target set-scope --pattern '*.example.com'
sniper-cli repeater list
sniper-cli repeater open --transaction-id <uuid>
sniper-cli repeater send --tab-id <tab-id>
sniper-cli fuzzer set-template --transaction-id <uuid>
sniper-cli fuzzer set-payloads --file payloads.txt
sniper-cli fuzzer run
sniper-cli intercept on
sniper-cli intercept list
sniper-cli intercept forward --id <uuid>
sniper-cli websocket list --limit 20
sniper-cli websocket get --id <uuid>
sniper-cli skills install --claude
```

## Guardrails

- If `sniper-cli` is missing from `PATH`, say so briefly instead of falling back to GUI scraping.
- Do not switch sessions silently before changing scope, Repeater state, or intercept decisions.
- Use `history get`, `repeater list`, or `websocket get` before making assumptions about stored request state.
