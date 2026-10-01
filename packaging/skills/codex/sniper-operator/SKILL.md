---
name: sniper-operator
description: Inspect captured HTTP/HTTPS traffic and debug APIs through a local Sniper proxy, driving it with sniper-cli rather than the desktop UI. Covers reviewing captured requests and responses, replaying them with changes, holding and editing live traffic, scope, fuzzer runs, WebSocket frames, match-replace rules, colour tags and notes, opening a browser already wired to Sniper, and session switching. Not for routing LLM API calls or hosting a reverse proxy.
---

# Sniper Operator

Use `sniper-cli` for all Sniper operations. Prefer `--output compact` JSON envelopes and avoid scraping the desktop UI.

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
- Open a browser that already sends its traffic through Sniper
- Install Sniper skills into Codex or Claude

## Workflow

1. Make sure Sniper Desktop is running, or pass `--api http://127.0.0.1:PORT`.
2. Start with `sniper-cli session list` and switch deliberately before mutating anything.
3. Prefer `sniper-cli call <operation> --input <json|@file|->` for automation; successful `call` output is wrapped in the envelope `data` field. Legacy subcommands keep raw JSON success output. On any failure, use `error.code`, `error.retryable`, and `error.hint`.
4. Prefer `sniper-cli call <operation> --input <json|@file|->` for automation, using operation names from `sniper-cli manifest`.
5. Prefer `--stdin` or `--request-file` for large raw requests.
6. Treat Replay target override fields as the connection target only. The raw `Host:` header stays in the request text.
7. For any manifest operation with `side_effect: "write"`, run `--dry-run` first and use `--yes` only after reviewing the plan.
8. Sniper preserves captured sensitive values such as cookies and authorization headers; summarize large or sensitive JSON responses instead of pasting them in full.
9. To open a browser that already sends its traffic through Sniper, run `sniper-cli capture browser open --dry-run`, review it, then run it with `--yes`, instead of asking the user to set a proxy or trust a certificate. Add `--agent` only when you will drive the browser yourself; leave it off when the person just wants a wired browser to look at, because for a Chromium-family browser it opens a DevTools port that any local process can use (and it is refused while the proxy listens beyond loopback). `capture browser list` shows what is installed, what each driver offers, which browser opens now (`default`) and which one the person saved (`preferred`). Leave the saved choice alone unless the person asks you to change it (`capture browser prefer --browser <name|auto>`, a setting that outlives this session). Without `--browser` the saved choice opens, and with none saved ego when it is installed, otherwise Chrome or another Chromium-family browser, so do not assume a DevTools endpoint: read `control` in the result. `{"driver":"cdp","endpoint":…}` means attach a CDP client (Playwright `connectOverCDP`, chrome-devtools-mcp `--browserUrl`) to that endpoint. `{"driver":"ego-cli","server_name":…}` means use the ego-browser skill and put `--ego-server-name=<server_name>` on **every** `ego-browser` command; without it you drive the user's own logged-in ego and nothing is captured. `ego-browser` prints script output on stderr, so read it with `2>&1`. Act on the page the way a person does (snapshot, click an `@ref`, wait for the URL) rather than jumping to URLs. If a browser is already open on that profile with the same settings you get another window (`"reused": true`); with different settings the call is refused and says why, and a DevTools port cannot be added to a running browser, so quit it first or add `--fresh`. `--fresh` gives a throwaway profile (up to eight). Read each `warnings` entry and any `hint` before you rely on the browser: one that could not start is still a 200, and `control` is absent when it ended.
10. To find where a value appeared — a token, an id, a field name — use `capture http search --value <text>` instead of fetching records one by one. `capture http list --query` matches metadata only and returns nothing for a value that lives in a body. Treat an empty search as absence only when `complete` is `true`; otherwise `stopped_by` names the limit to raise.

## Common commands

```bash
sniper-cli --output compact manifest
sniper-cli --output compact schema input replay.send
sniper-cli --output compact call capture.http.list --input '{"limit":20,"page":true}'
sniper-cli --output compact call replay.send --input '{"tab_id":"<tab-id>"}' --dry-run
sniper-cli --output compact call replay.send --input '{"tab_id":"<tab-id>"}' --yes
sniper-cli --output compact session list
sniper-cli session switch --id <uuid> --dry-run
sniper-cli session switch --id <uuid> --yes
sniper-cli --output compact capture http list --limit 20
sniper-cli --output compact capture http get --id <uuid>
sniper-cli --output compact capture http search --value <text> --side response-body
sniper-cli --output compact capture browser list
sniper-cli capture browser open --dry-run
sniper-cli --output compact capture browser open --yes
sniper-cli --output compact capture browser open --agent --dry-run
sniper-cli --output compact capture browser open --agent --yes
sniper-cli capture browser prefer --browser <name|auto> --dry-run
sniper-cli capture browser prefer --browser <name|auto> --yes
sniper-cli capture http replay --id <uuid> --dry-run
sniper-cli capture http replay --id <uuid> --yes
sniper-cli capture http fuzzer --id <uuid> --dry-run
sniper-cli capture http fuzzer --id <uuid> --yes
sniper-cli capture http annotate --id <uuid> --color red --note "suspicious" --dry-run
sniper-cli capture http annotate --id <uuid> --color red --note "suspicious" --yes
sniper-cli scope get-scope
sniper-cli scope set-scope --pattern '*.example.com' --dry-run
sniper-cli scope set-scope --pattern '*.example.com' --yes
sniper-cli replay list
sniper-cli replay open --transaction-id <uuid> --dry-run
sniper-cli replay open --transaction-id <uuid> --yes
sniper-cli replay send --tab-id <tab-id> --dry-run
sniper-cli replay send --tab-id <tab-id> --yes
sniper-cli fuzzer set-template --transaction-id <uuid> --dry-run
sniper-cli fuzzer set-template --transaction-id <uuid> --yes
sniper-cli fuzzer set-payloads --file payloads.txt --dry-run
sniper-cli fuzzer set-payloads --file payloads.txt --yes
sniper-cli fuzzer run --dry-run
sniper-cli fuzzer run --yes
sniper-cli capture intercept on --dry-run
sniper-cli capture intercept on --yes
sniper-cli capture intercept list
sniper-cli capture intercept forward --id <uuid> --dry-run
sniper-cli capture intercept forward --id <uuid> --yes
sniper-cli capture web-socket list --limit 20
sniper-cli capture web-socket get --id <uuid>
sniper-cli capture auto-replace list
sniper-cli capture auto-replace set --file rules.json --dry-run
sniper-cli capture auto-replace set --file rules.json --yes
sniper-cli capture oast configure --provider custom --url https://oast.example --token-stdin --dry-run
printf "%s" "$OAST_TOKEN" | sniper-cli capture oast configure --provider custom --url https://oast.example --token-stdin --yes
sniper-cli skills install --codex --dry-run
sniper-cli skills install --codex --yes
```

## Guardrails

- If `sniper-cli` is missing from `PATH`, say so briefly instead of falling back to GUI scraping.
- Do not switch sessions silently before changing scope, Replay state, or queued-request decisions.
- Use `capture http get`, `replay list`, or `capture web-socket get` before making assumptions about stored request state.
