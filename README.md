# Sniper

Sniper is a lightweight, fast, open-source desktop web proxy for people who want a clean workflow without dragging in a huge platform.

It is built for:

- a simple proxy UI
- a lean runtime
- simple day-to-day proxy work: capture, inspect, replay, fuzz, scope
- automation through `sniper-cli` and AI skills

If you want a clean tool that feels approachable, but lighter and easier to automate, Sniper is the idea.

## Why Sniper

Sniper focuses on the core workflow most people actually need:

- capture HTTP and HTTPS traffic
- inspect requests and responses quickly
- replay and modify traffic
- run lightweight fuzzing against captured requests
- organize work by session and scope
- automate the same flow from CLI or AI tools

The project is intentionally shaped as a focused proxy first, not an everything-suite.

## Highlights

- native desktop app
- lightweight Rust proxy core
- HTTP forwarding
- HTTPS MITM for arbitrary upstream hosts
- persistent local root CA generation
- `http://sniper` / `https://sniper` certificate bootstrap portal
- session-based workspaces
- HTTP records
- Web Socket records
- queued request review
- replay workspace
- fuzzer workspace
- tools workspace for decoding, encoding, hashing, JWT inspection, and transformations
- target scope and site map
- event log
- JSON-first CLI
- installable Codex and Claude skills

## Who it is for

Sniper is a good fit if you want:

- a simple proxy with a clean layout
- something lighter than a heavy all-in-one platform
- a tool that is pleasant for manual testing
- a proxy that can also be driven from automation

## Quick start

Run the desktop app:

```bash
cargo run --bin sniper-desktop
```

By default:

- proxy listener: `127.0.0.1:18080`
- UI listener: auto-selected local port

Custom listeners:

```bash
SNIPER_PROXY_ADDR=127.0.0.1:28080 SNIPER_UI_ADDR=127.0.0.1:13000 cargo run --bin sniper-desktop
```

Then:

1. Start `sniper-desktop`
2. Point your browser, mobile device, or CLI client at the proxy listener
3. Open `https://sniper` from a proxied client
4. Download and trust the local root CA
5. Start browsing through the proxy

## Core workflow

Sniper keeps the UI simple and workbench-oriented:

- `Session`: manage isolated workspaces
- `Scope`: define scope and inspect captured hosts and paths
- `Capture`: use `Intercept`, `HTTP`, `Web Socket`, `Replace`, and `Settings`
- `Replay`: modify and resend captured requests
- `Fuzzer`: run payload-based request tests
- `Tools`: decode, encode, hash, inspect JWTs, and transform data
- `Logger`: watch runtime events and actions

## Sessions

Each session keeps its own:

- HTTP records
- Web Socket captures
- event log
- scope
- replay workspace state
- fuzzer workspace state
- rules and runtime state

Sessions are stored under:

```text
~/.sniper/sessions/<session-id>
```

## CLI

Sniper ships with `sniper-cli` so the same workflow can be driven from scripts, automation, and AI tooling.

```bash
cargo run --bin sniper-cli -- --help
```

Available command groups:

- `session list|create|switch`
- `capture http list|get|replay|fuzzer|annotate`
- `capture intercept on|off|list|forward|drop`
- `capture web-socket list|get`
- `capture auto-replace list|set`
- `scope get-scope|set-scope`
- `replay list|open|update|send`
- `fuzzer set-template|set-payloads|run`
- `skills install`

Example commands:

```bash
cargo run --bin sniper-cli -- session list
cargo run --bin sniper-cli -- session create --name "Bug bounty"
cargo run --bin sniper-cli -- scope set-scope --pattern '*.example.com' --pattern api.example.com
cargo run --bin sniper-cli -- capture http list --limit 10
cargo run --bin sniper-cli -- capture http replay --id <transaction-id>
cargo run --bin sniper-cli -- capture http fuzzer --id <transaction-id>
cargo run --bin sniper-cli -- capture http annotate --id <transaction-id> --color red --note "suspicious"
cargo run --bin sniper-cli -- replay list
printf 'GET / HTTP/1.1\nHost: example.com\n\n' | cargo run --bin sniper-cli -- replay open --stdin
cargo run --bin sniper-cli -- capture intercept list
cargo run --bin sniper-cli -- capture auto-replace list
```

Notes:

- CLI output is JSON by default
- replay keeps raw `Host:` separate from the connection override target
- fuzzer operates on the active session workspace
- CLI discovers the running desktop app from the local runtime state file
- older aliases like `history`, `target`, `repeater`, and `websocket` still work for compatibility

## AI skills

Sniper can also be used automatically from AI tools.

Both Codex and Claude skill templates are included, and both use `sniper-cli` only. They do not depend on UI scraping.

Install them explicitly:

```bash
cargo run --bin sniper-cli -- skills install --codex
cargo run --bin sniper-cli -- skills install --claude
cargo run --bin sniper-cli -- skills install --all
```

Default macOS install paths:

- Codex: `$CODEX_HOME/skills`, fallback `~/.codex/skills`
- Claude: `$CLAUDE_HOME/skills`, fallback `~/.claude/skills`

This means Sniper can be used by an AI agent to:

- switch sessions
- read captured traffic from `capture http`
- update scope
- open and send replay requests
- seed replay/fuzzer workspaces from HTTP history
- run payload sets
- inspect Web Socket sessions
- manage queued requests
- manage auto-replace rules

## Certificate bootstrap

Sniper creates and reuses a local root CA on first launch.

- default storage: `~/.sniper/certificates`
- override with: `SNIPER_DATA_DIR=/custom/path`
- download from: `http://sniper` or `https://sniper`
- export from the desktop settings modal as PEM or DER

Typical HTTPS setup:

1. Start `sniper-desktop`
2. Configure a client to use the Sniper proxy
3. Visit `https://sniper`
4. Download the root certificate
5. Trust it in your OS or browser
6. Restart the client if needed

## Build and run

Run the desktop app:

```bash
cargo run --bin sniper-desktop
```

Run the CLI:

```bash
cargo run --bin sniper-cli -- --help
```

Run tests:

```bash
cargo test
```

## macOS release packaging

Sniper can be packaged as a signed macOS `.app` and `.dmg`.

Create a local `.app` bundle:

```bash
./packaging/macos/make-app.sh
```

Create a `.dmg` from the app bundle:

```bash
./packaging/macos/make-dmg.sh
```

Create both release artifacts:

```bash
./packaging/macos/release-macos.sh
```

Artifacts are written to:

```text
dist/
```

Signing behavior:

- if `DEVELOPER_ID_APP` is set, the app is signed with your Developer ID
- otherwise the bundle is ad-hoc signed for local testing

Optional notarization:

- set `APPLE_ID`
- set `APPLE_TEAM_ID`
- set `APPLE_APP_PASSWORD`

Then `release-macos.sh` will notarize and staple the `.app`, and notarize the `.dmg`.

Optional icon:

- set `APP_ICON=/absolute/path/to/AppIcon.icns`

Example:

```bash
DEVELOPER_ID_APP="Developer ID Application: Your Name (TEAMID)" \
APPLE_ID="you@example.com" \
APPLE_TEAM_ID="TEAMID" \
APPLE_APP_PASSWORD="app-specific-password" \
./packaging/macos/release-macos.sh
```

## Project layout

- `src/bin/sniper-desktop.rs`: native desktop shell
- `src/bin/sniper-cli.rs`: JSON-first automation CLI
- `src/proxy.rs`: proxy core, HTTPS MITM, replay sending, special-host handling
- `src/api.rs`: local UI/API server
- `src/session.rs`: session registry and snapshots
- `src/workspace.rs`: replay/fuzzer workspace persistence
- `src/store.rs`: HTTP transaction store
- `src/model.rs`: normalized models
- `src/certificate.rs`: root CA generation and export
- `web/`: desktop UI
- `packaging/skills/`: Codex and Claude skill templates
- `packaging/macos/`: macOS `.app` and `.dmg` packaging scripts
- `docs/architecture.md`: architecture notes

## Status

Sniper is already usable as a focused desktop traffic proxy with session storage, replay, fuzzing, Web Socket capture, tools, CLI automation, and AI skill integration.

It is still evolving, but the goal stays simple:

- keep the proxy fast
- keep the UI clean
- keep the workflow focused
- make automation first-class
