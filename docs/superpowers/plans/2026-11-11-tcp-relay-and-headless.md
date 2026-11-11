# TCP relay improvements and macOS headless server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the headless server on macOS and turn the TCP relay into a tool that keeps working under load, can be driven by agents, decrypts TLS, replays, and reaches clients and protocols it could not before.

**Architecture:** `src/tcp_capture.rs` keeps one `TcpCapture` per session. It grows from one listener to a saved list of listeners (state.json), each with protocol, TLS mode and reach options. Connections keep one record each under `tcp-history/`; new record fields are `#[serde(default)]` so older records still load. The UI stays in `web/tcp-capture.js` and the Capture ▸ Settings listener section; the CLI gets a `tcp` command group.

**Tech Stack:** Rust (tokio, rustls/tokio-rustls, serde), vanilla JS, node tests, Python runtime helpers.

**Spec:** The review given in chat on 2026-11-11 (no separate spec). The user approved every item in it ("전부진행"). Decisions not in the review are rulings in the ledger.

## Global Constraints

- AGENTS.md applies: `example.com` (or loopback) only in fixtures; never log captured bytes, headers or tokens; atomic writes; no fsync on the proxy runtime; loopback is the default and anything else must be guarded; `cargo fmt`; no new warnings (sniper-desktop baseline 37); rebuild after web edits.
- Old TCP history records and old state.json must still load: every new field is `#[serde(default)]`.
- Runtime tests run against an isolated instance (`SNIPER_DATA_DIR` in the scratchpad, managed proxy variables kept). No real browsers. Upstreams are local Python servers.
- UI copy is short English, sentence case; Apple-like minimal controls; tables keep row select, ↑/↓, header sort, column resize.
- Commits: `/usr/bin/git commit -q --only <paths> -F <msgfile>`, imperative subject, body with cause and fix, trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. No push without asking.
- Test commands: `PATH="$HOME/.cargo/bin:$PATH" cargo test --release --lib <filter>`, full `cargo test --release --no-fail-fast`, `node --test "tests/*.test.cjs"`.

## Review Focus

- Session switch with listeners running, intercepts held and replays in flight: the old session's relays stop, the new session's saved listeners start, no decision crosses sessions.
- Restart with saved listeners whose ports are taken: startup continues; the listener shows the error.
- Records written before this plan load unchanged (`restore_tests.rs`), and records with the new fields round-trip through `detail()`'s stored-equals-memory check.
- TLS detection on a server-first protocol (banner before the client speaks) must relay, not wait.
- A listener open to other devices refuses clients outside its list and never relays a remote client to Sniper's own UI, proxy or browser driver ports.
- CONNECT sniffing must not change ordinary HTTPS or HTTP-over-CONNECT handling.

---

### Task 1: macOS app ships the headless server

**Files:** `packaging/macos/make-app.sh`, `packaging/macos/release-macos.sh` (only if it lists bundle binaries), `packaging/homebrew/sniper.rb`, `README.md`.

- Build `--bin sniper` with the others (single-arch and universal paths) and copy it to `Contents/MacOS/sniper-server`. The bundle already holds `Sniper`; APFS is case-insensitive by default, so `sniper` would collide.
- Cask: `binary "#{appdir}/Sniper.app/Contents/MacOS/sniper-server", target: "sniper"`.
- README: run it in the background (`nohup sniper > … &`), defaults, one runtime per data directory.
- [ ] Build the app; check `Contents/MacOS` lists `Sniper`, `sniper-cli`, `sniper-server`; `codesign --verify --deep` passes; `ruby -c` on the cask.
- [ ] Runtime: start `Contents/MacOS/sniper-server` with a scratch `SNIPER_DATA_DIR`; `/api/runtime` answers 200; `sniper-cli` finds it through the data directory.
- [ ] Commit "Ship the headless server in the macOS app".

### Task 2: Several TCP listeners, saved per session

**Files:** `src/tcp_capture.rs`, `src/session.rs` (state snapshot), `src/state.rs`, `src/api.rs`, `web/tcp-capture.js`, `web/index.html`, `web/styles.css`, tests (`src/tcp_capture.rs` tests, `src/tcp_capture/restore_tests.rs`, `tests/tcp-*.test.cjs`).

**Interfaces (produced):**
- `TcpListenerConfig { id: Uuid, local_port: u16, target_host: String, target_port: u16, enabled: bool }` (later tasks add `protocol`, `tls`, `remote`, `allowed_clients`, all `#[serde(default)]`).
- `TcpCapture::apply_listeners(&self, Vec<TcpListenerConfig>)` starts enabled ones not running, stops the rest; per-listener `error: Option<String>` (port in use and so on).
- `TcpStatus { enabled, listeners: Vec<TcpListenerStatus>, history_count, history_limit, active_count, active_limit, load_error, persistence_error }`; `TcpListenerStatus` = config + `running`, `error`.
- API (all with `SessionWriteQuery`): `GET /api/tcp/status`; `POST /api/tcp/listeners` (create); `PUT /api/tcp/listeners/:id`; `DELETE /api/tcp/listeners/:id`. `enabled` in the body starts or stops it. `/api/tcp/start` and `/api/tcp/stop` go away.
- Session state: `tcp_listeners: Vec<TcpListenerConfig>` in state.json, saved with `persist_session_state_mutation_locked`.
- Record field `local_port: u16` (default 0) names the listener a connection came through.
- Limit: 16 listeners per session.

- [ ] Tests first: two listeners relay to two loopback targets at once and their records carry their `local_port`; a listener saved enabled starts when the session loads; a taken port leaves that listener with an error and the others running; a session switch stops the old session's listeners and starts the new one's; old records without `local_port` load.
- [ ] Implement; UI: the Capture ▸ Settings TCP section becomes a listener table (port, target, on/off switch, ⋯ edit/remove, Add); TCP history gets a Listener column.
- [ ] Runtime: isolated instance, two Python echo servers, two listeners, restart keeps them and starts them.
- [ ] Commit "Keep several TCP listeners per session and start them again".

### Task 3: A full TCP history no longer stops the relay

**Files:** `src/tcp_capture.rs`, `src/state.rs`, `src/api.rs`, `web/tcp-capture.js`, `web/index.html`, tests.

- At `MAX_CONNECTIONS` the relay keeps forwarding and does not record; `TcpStatus.unrecorded_count` counts these connections since the last clear.
- `DELETE /api/tcp/connections` removes every ended, saved record (files and memory) and keeps live or unsaved ones; returns `{ removed }`.
- UI: a quiet notice "History is full. N connections were not recorded." with Clear; Clear also in the TCP history toolbar.
- [ ] Tests: the 257th connection is relayed byte for byte and leaves no record; clear removes ended records and their files, keeps an open one, resets the count; a clear while a connection ends does not lose that connection's record.
- [ ] Commit "Keep relaying when TCP history is full, and let it be cleared".

### Task 4: Hold only what matters, release everything at once

**Files:** `src/tcp_capture.rs`, `src/state.rs`, `src/api.rs`, `web/tcp-capture.js`, `web/index.html`, tests.

- `POST /api/tcp/intercept/forward-all` and `/drop-all` act on every held range of the session; return `{ count }`.
- Turning intercept off forwards every held range unchanged, as HTTP intercept does (`api.rs` "Turning interception off lets go of what it held").
- `InterceptPolicy.filter: Option<{ kind: "text" | "hex" | "regex", value: String }>`; only a read whose bytes match is held. A match across two reads is not found (read chunks are not messages). Regex is `regex::bytes` with a size limit; a bad pattern is a 400.
- UI: Forward all and Drop all next to Forward and Drop; a "Hold only when it contains" field with a Text/Hex/Regex choice.
- [ ] Tests: forward-all releases ranges on two connections; turning off forwards held ranges and the client receives the original bytes; a text filter holds `PING` and passes `PONG`; hex and regex filters likewise; an invalid regex is rejected.
- [ ] Commit "Release held TCP reads at once, and hold only matching ones".

### Task 5: Edit held bytes as text

**Files:** `web/tcp-capture.js`, `web/index.html`, `tests/tcp-intercept-ui.test.cjs`.

- Pending editor gets Hex | Text. Text shows printable UTF-8 as is, a real newline for `\n`, and `\r`, `\t`, `\\`, `\xNN` for the rest; parsing reverses it exactly.
- [ ] Tests: round trip of all 256 byte values and of invalid UTF-8; `a\r\nb` shows as two lines with `\r`; switching modes keeps an unsent edit.
- [ ] Commit "Edit held TCP bytes as text".

### Task 6: TCP through the upstream proxy

**Files:** `src/tcp_capture.rs`, `src/state.rs` (hands the session's `UpstreamProxy` to the capture), `src/upstream_proxy.rs` (reuse `connect`), `web/tcp-capture.js`, tests.

- When the session's upstream proxy is on and the target is not bypassed, a connection opens through `UpstreamProxy::connect` (HTTP CONNECT or SOCKS5). Otherwise the direct path with its self-target check stays.
- Record field `via_proxy: bool`.
- A self-target failure says: "The target resolves to this listener. If a hosts entry sends the name here, enter the server's IP as the target."
- [ ] Tests: with a local CONNECT proxy configured, bytes reach the target through it and the record says `via_proxy`; a bypassed host goes direct.
- [ ] Commit "Send TCP relay connections through the upstream proxy".

### Task 7: Decrypt TLS on a listener

**Files:** `src/tcp_capture.rs` (or `src/tcp_capture/tls.rs`), `src/certificate.rs`, `web/tcp-capture.js`, `web/index.html`, tests.

- Listener `tls: "off" | "decrypt" | "upstream"`.
  - `decrypt`: after the upstream connection opens, wait for whichever side speaks first. A client that starts with a TLS record (`16 03 0x`) is answered with a certificate from Sniper's CA for its SNI (or the target name), and the upstream connection is wrapped in TLS with the same SNI. Anything else, including a server that speaks first, is relayed as is.
  - `upstream`: the client speaks plain; the upstream connection is wrapped in TLS.
  - Upstream certificates are checked as HTTP's are (`upstream_insecure`).
- Records: `client_tls: bool`, `server_tls: bool`. Capture and intercept see plaintext.
- [ ] Tests: a TLS client through a `decrypt` listener to a TLS echo server: plaintext recorded both ways; a server-first plaintext protocol relays without waiting; a plain client on a `decrypt` listener relays; `upstream` mode reaches a TLS server from a plain client.
- [ ] Runtime: `openssl s_client -CAfile <Sniper CA>` through the listener to a local TLS echo server.
- [ ] Commit "Decrypt TLS on TCP listeners".

### Task 8: TCP Replay

**Files:** `src/tcp_capture.rs` (or `src/tcp_capture/replay.rs`), `src/state.rs`, `src/api.rs`, `web/tcp-capture.js`, `web/index.html`, `web/styles.css`, tests.

- `POST /api/tcp/replay { target_host, target_port, tls: bool, messages: [base64], wait_ms, from? }`: connects (upstream proxy rules as Task 6), sends each message, then reads until `wait_ms` of silence (default 1000, 50–30000) or close; 64 messages, 120 s in all. The result is a record with `source: "replay"` and `replayed_from`, saved like any other (not saved when history is full; the response says `recorded: false`).
- UI: Replay on a selected connection opens an editor with its client→server reads as messages (Hex | Text, add/remove), target and TLS prefilled; Send shows the exchange; replays show in history with a Replay marker.
- [ ] Tests: replay of two messages to an echo server records both directions in order; silence ends a step; a closed connection ends the run; limits are enforced.
- [ ] Commit "Replay a TCP conversation".

### Task 9: Larger captures, search and export

**Files:** `src/tcp_capture.rs`, `src/api.rs`, `web/tcp-capture.js`, `web/index.html`, tests.

- `MAX_CAPTURE_BYTES` 1 MiB, `MAX_CHUNKS` 4096, `MAX_RECORD_FILE_BYTES` sized to fit (old records still pass).
- `GET /api/tcp/connections?contains=<value>&kind=text|hex` scans saved records within a 64 MiB read budget; the response says when the budget ran out.
- `GET /api/tcp/connections/:id/raw?direction=client_to_server|server_to_client` returns the captured bytes as an attachment.
- UI: search box with Text/Hex; ⋯ menu with Save client bytes, Save server bytes, Copy as hex.
- [ ] Tests: a 600 KiB exchange is kept whole; search finds a record by text and by hex and skips others; raw export returns exact bytes per direction.
- [ ] Commit "Keep more of each TCP connection, and search and export it".

### Task 10: Listeners other devices can reach

**Files:** `src/tcp_capture.rs`, `src/proxy.rs` (share the guarded-target check), `src/state.rs`, `web/tcp-capture.js`, `web/index.html`, tests.

- Listener `remote: bool`, `allowed_clients: Vec<String>` (IP or CIDR, required when `remote`). Remote listeners bind every interface; a client outside the list is closed at once and counted (`refused` on the listener status).
- A non-loopback client is never relayed to Sniper's own UI or proxy listener or a browser driver port (new failure `guarded_target`), as `remote_client_targets` guards the proxy.
- [ ] Tests: `remote` without clients is rejected; an allowed `fe80::1` client is relayed; another address is refused and counted; a remote client aimed at the UI port gets `guarded_target`.
- [ ] Commit "Let other devices reach a TCP listener they are allowed on".

### Task 11: View messages instead of reads

**Files:** `web/tcp-capture.js`, `web/index.html`, `tests/tcp-stream-render.test.cjs`.

- Detail view "Split by": Reads (default), Delimiter (hex, default `0a`), Length prefix (1, 2 or 4 bytes, big or little endian). Each direction's stream is cut into messages; a message is placed where its last byte arrived; a trailing partial message is marked.
- [ ] Tests: delimiter split across reads, length-prefix big and little endian, partial tail.
- [ ] Commit "Split a TCP conversation into messages".

### Task 12: UDP listeners

**Files:** `src/tcp_capture.rs` (or `src/tcp_capture/udp.rs`), `web/tcp-capture.js`, `web/index.html`, tests.

- Listener `protocol: "tcp" | "udp"`. A UDP listener keeps one flow per client address, with its own upstream socket connected to the target; each datagram is one chunk; a flow ends after 60 s without datagrams or when the listener stops. Intercept holds datagrams up to 16 KiB; larger ones pass. TLS and the upstream proxy do not apply to UDP (direct only).
- Record field `protocol` (default `tcp`).
- [ ] Tests: two clients get separate flows and their own replies; datagram boundaries are kept; idle flows end; intercept drops a datagram.
- [ ] Commit "Relay and record UDP".

### Task 13: Non-HTTP traffic through the HTTP proxy lands in TCP history

**Files:** `src/proxy.rs`, `src/tcp_capture.rs`, tests.

- After a CONNECT, the first bytes decide: TLS goes to the existing interception, an HTTP request line goes to the existing HTTP path, anything else (and a server that speaks first) is relayed and recorded in TCP history with `source: "connect"`, intercept included.
- Passthrough tunnels also record their bytes in TCP history (`source: "passthrough"`).
- [ ] Tests: a plaintext custom protocol through CONNECT is relayed and recorded; HTTPS through CONNECT is unchanged (existing tests); a passthrough host's tunnel bytes are recorded.
- [ ] Commit "Record non-HTTP CONNECT tunnels in TCP history".

### Task 14: sniper-cli tcp and the operator skill

**Files:** `src/bin/sniper-cli.rs`, `tests/cli_discovery_schema_contract.rs`, `packaging/skills/claude/sniper-operator/SKILL.md`, `packaging/skills/codex/sniper-operator/SKILL.md`.

- `sniper-cli tcp status | listeners (list|add|set|remove) | list [--contains] | get | raw | clear | intercept (get|set) | pending | decide | forward-all | drop-all | close | replay`, writes confirmed like the other write commands, each also as a `call` operation with its schema.
- [ ] Tests: CLI parse and request-body tests per command; the discovery contract lists every operation.
- [ ] Commit "Drive the TCP relay from sniper-cli".

### Task 15: Documentation

**Files:** `README.md`, `docs/guides/tcp-relay.md` (new), `docs/architecture.md`, `AGENTS.md` (Where things live row).

- [ ] Commit "Document the TCP relay".

### Final

- [ ] Full Rust and node suites, `cargo fmt --check`, warning count, deploy to `~/Desktop/Sniper.app`, end-to-end runtime pass, review of the whole branch.
