<p align="center">
  <img src="web/sniper-logo-wide.png" width="360" alt="Sniper" />
</p>

<p align="center">
  <strong>Lightweight, fast, open-source desktop web proxy</strong><br/>
  for people who want a clean workflow without dragging in a huge platform.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/lang-Rust-orange?style=flat-square&logo=rust" />
  <img src="https://img.shields.io/badge/platform-macOS-blue?style=flat-square&logo=apple" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" />
</p>

<p align="center">
  <img src="web/screenshot.png" width="800" alt="Sniper UI" />
</p>

---

## Features

| Category | What you get |
|---|---|
| **Proxy** | HTTP forwarding, HTTPS MITM, persistent root CA, `https://sniper` cert portal |
| **Capture** | HTTP history, WebSocket sessions, intercept queue, match & replace rules |
| **Replay** | Modify and resend any captured request |
| **Fuzzer** | Payload-based request testing with markers |
| **Tools** | Decode, encode, hash, JWT inspector, data transformations |
| **Sessions** | Isolated workspaces — each with its own records, scope, and state |
| **Scope** | Domain/path filtering with site map visualization |
| **Themes** | 12 themes — 7 dark + 5 light, gold-accent design language |
| **CLI** | `sniper-cli` — JSON-first automation for scripting |
| **AI Skills** | Built-in Claude & Codex skill templates using `sniper-cli` |

## Tech stack

| Layer | Technology |
|---|---|
| Core | **Rust** — proxy, MITM, TLS, session management |
| HTTP | `hyper` + `tokio` async runtime |
| TLS | `rustls` + `rcgen` for on-the-fly certificate generation |
| UI server | `axum` serving embedded SPA |
| Frontend | Vanilla **JS** + **CSS** — zero framework, zero build step |
| Desktop shell | Native **WebView** (`wry`) |
| Packaging | macOS `.app` + `.dmg` with code signing & notarization |

## Quick start

```bash
# Run the desktop app
cargo run --bin sniper-desktop

# Or run the headless proxy + UI server
cargo run --bin sniper
```

Default listeners:
- Proxy: `127.0.0.1:8080`
- UI: `127.0.0.1:23001`

Then:
1. Point your browser at the proxy
2. Visit `https://sniper` to download the root CA
3. Trust the certificate in your OS/browser
4. Start capturing

## Core workflow

```
Session → Scope → Capture → Replay → Fuzz
                    │
          ┌─────────┼─────────┐
      Intercept    HTTP    WebSocket
```

- **Session** — isolated workspaces with their own records and state
- **Scope** — define target domains/paths, auto-filter traffic
- **Capture** — inspect HTTP, intercept & modify, WebSocket frames, auto-replace
- **Replay** — resend with modifications, override host/port
- **Fuzzer** — insert markers, run payload lists
- **Tools** — decode/encode/hash/JWT in one place

## CLI

```bash
sniper-cli session list
sniper-cli capture http list --limit 10
sniper-cli capture http replay --id <id>
sniper-cli scope set-scope --pattern '*.example.com'
sniper-cli fuzzer run
```

Full JSON output, scriptable, AI-agent friendly.

## AI integration

```bash
sniper-cli skills install --claude   # Install Claude skill
sniper-cli skills install --codex    # Install Codex skill
sniper-cli skills install --all      # Install all
```

AI agents can drive the full workflow through CLI — capture, scope, replay, fuzz — no UI scraping needed.

## Project layout

```
src/
├── proxy.rs           # Proxy core, HTTPS MITM, replay
├── api.rs             # UI/API server (axum)
├── session.rs         # Session registry & snapshots
├── certificate.rs     # Root CA generation & export
├── store.rs           # HTTP transaction store
├── model.rs           # Normalized data models
├── intercept.rs       # Request intercept queue
├── match_replace.rs   # Auto match & replace rules
├── fuzzer.rs          # Payload fuzzer engine
├── websocket.rs       # WebSocket capture
├── bin/
│   ├── sniper-desktop.rs   # Native desktop shell (wry)
│   └── sniper-cli.rs       # JSON-first CLI
web/                   # Frontend SPA (vanilla JS/CSS)
packaging/
├── macos/             # .app & .dmg packaging scripts
└── skills/            # Claude & Codex skill templates
```

## Build

```bash
cargo run --bin sniper-desktop   # Desktop app
cargo run --bin sniper-cli       # CLI
cargo test                       # Tests
./packaging/macos/release-macos.sh   # macOS .app + .dmg
```

## Status

Sniper is usable as a focused desktop traffic proxy with session storage, replay, fuzzing, WebSocket capture, tools, CLI automation, and AI skill integration.

The goal stays simple: **fast proxy, clean UI, focused workflow, first-class automation.**
