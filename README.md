# Sniper

Sniper is a lightweight, fast, open-source interception proxy for people who want a familiar workflow without dragging in a huge platform.

It is built for:

- a familiar proxy UI
- a lean runtime
- simple day-to-day proxy work: capture, inspect, replay, fuzz, scope
- automation through `sniper-cli` and AI skills

If you want a clean tool that feels approachable like a classic proxy suite, but lighter and easier to automate, Sniper is the idea.

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
- HTTP history
- Web Socket history
- intercept queue
- replay workspace
- fuzzer workspace
- tools workspace for decoding, encoding, hashing, JWT inspection, and transformations
- target scope and site map
- event log
- JSON-first CLI
- installable Codex and Claude skills

## Who it is for

Sniper is a good fit if you want:

- a simple proxy with a familiar layout
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
- `Target`: define scope and inspect captured hosts and paths
- `Proxy`: use `Intercept`, `HTTP`, `Web Socket`, `Auto replace`, and `Settings`
- `Replay`: modify and resend captured requests
- `Fuzzer`: run payload-based request tests
- `Tools`: decode, encode, hash, inspect JWTs, and transform data
- `Logger`: watch runtime events and actions

## Sessions

Each session keeps its own:

- HTTP history
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
- `history list|get`
- `target get-scope|set-scope`
- `repeater list|open|update|send`
- `fuzzer set-template|set-payloads|run`
- `intercept on|off|list|forward|drop`
- `websocket list|get`
- `skills install`

Example commands:

```bash
cargo run --bin sniper-cli -- session list
cargo run --bin sniper-cli -- session create --name "Bug bounty"
cargo run --bin sniper-cli -- target set-scope --pattern '*.example.com' --pattern api.example.com
cargo run --bin sniper-cli -- history list --limit 10
cargo run --bin sniper-cli -- repeater list
printf 'GET / HTTP/1.1\nHost: example.com\n\n' | cargo run --bin sniper-cli -- repeater open --stdin
cargo run --bin sniper-cli -- intercept list
```

Notes:

- CLI output is JSON by default
- replay keeps raw `Host:` separate from the connection override target
- fuzzer operates on the active session workspace
- CLI discovers the running desktop app from the local runtime state file

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
- read captured traffic
- update scope
- open and send replay requests
- run fuzzing payloads
- inspect Web Socket sessions
- control intercept flow

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
- `docs/architecture.md`: architecture notes

## Status

Sniper is already usable as a focused desktop interception proxy with session storage, replay, fuzzing, Web Socket capture, tools, CLI automation, and AI skill integration.

It is still evolving, but the goal stays simple:

- keep the proxy fast
- keep the UI familiar
- keep the workflow focused
- make automation first-class
