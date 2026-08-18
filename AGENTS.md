# Working on Sniper

Notes for anyone — human or coding agent — making changes to this repository.

This file covers what you need to make a change *safely*. It deliberately does
not repeat [README.md](README.md) (what Sniper is, how to install it, the CLI
surface) or [docs/architecture.md](docs/architecture.md) (why it is built this
way). Read those for context; read this before you edit.

## 1. Orientation

Sniper is an intercepting proxy for web security testing: a Rust backend with an
embedded web UI. Three binaries come out of one crate.

| Binary | What it is |
| --- | --- |
| `sniper-desktop` | The shipped app. A native window (wry/WebKit) that hosts the UI and runs the proxy in-process. |
| `sniper` | The same server without a window. Useful for testing and for driving Sniper from elsewhere. |
| `sniper-cli` | A JSON-first CLI that talks to a running instance over its local HTTP API. |

The frontend in `web/` is plain HTML/CSS/JS with **no build step**. It is
compiled into the binary with `rust-embed` (`src/api.rs`), which has one
consequence worth internalising: **editing a `.js` or `.html` file does nothing
until you rebuild.**

## 2. Build, run, test

```bash
cargo run --bin sniper-desktop    # desktop app
cargo run --bin sniper            # headless server
cargo test --release --lib        # unit tests, ~20s
cargo test --release              # everything, including tests/
cargo fmt                         # required before committing
```

Three things that will cost you time if you learn them the hard way:

- **One runtime per data dir.** Sniper locks its data directory. Starting a
  second instance against the default `~/.sniper` fails — and worse, starting
  *one* instance against it attaches to whatever real session the developer has
  open. Never run a scratch build without setting `SNIPER_DATA_DIR`. Even
  `sniper --help` boots far enough to take the lock.
- **Universal builds need the rustup toolchain.** If Homebrew's Rust comes first
  on `PATH` the `x86_64-apple-darwin` standard library is missing and the build
  dies with `can't find crate for core`. Prefix release builds with
  `PATH="$HOME/.cargo/bin:$PATH"`.
- **Run the suite with `--release`.** `cargo test` works, but the release
  profile is what the packaging path builds, and the full suite finishes in
  about 20 seconds there — quick enough to run on every change.

## 3. Runtime testing

Unit tests do not exercise the proxy. Anything that touches capture, intercept,
replay, scope or persistence should be verified against a running instance
before you call it done. Run it isolated — never against `~/.sniper`:

```bash
SNIPER_DATA_DIR=/tmp/sniper-test \
SNIPER_UI_ADDR=127.0.0.1:18899 \
SNIPER_PROXY_ADDR=127.0.0.1:18890 \
  ./target/release/sniper &
```

Then drive it over the local API and send traffic through the proxy:

```bash
curl -s -X POST http://127.0.0.1:18899/api/runtime \
  -H 'content-type: application/json' \
  -d '{"intercept_enabled":true,"intercept_scope_only":false}'

curl -s -x http://127.0.0.1:18890 http://127.0.0.1:18891/some/path   # your own upstream
curl -s http://127.0.0.1:18899/api/intercepts
curl -s http://127.0.0.1:18899/api/transactions
```

Stand up a throwaway upstream (a few lines of Python is fine) rather than
pointing tests at a real host. Poll the queues instead of sleeping a fixed
interval — intercepts appear asynchronously.

## 4. Where things live

`README.md` lists the modules. This is the reverse index: what to open for a
given change, including the parts that are easy to miss.

| Change | Files |
| --- | --- |
| Proxy path, MITM, replay | `src/proxy.rs` |
| HTTP API and the UI server | `src/api.rs` (largest module, ~17k lines) |
| Session lifecycle and on-disk format | `src/session.rs`, `src/state.rs` |
| Transaction storage, filtering, sorting | `src/store.rs` |
| Scope matching | `src/scope.rs` — **the only matcher**; do not add a second one |
| Intercept queues | `src/intercept.rs` |
| Frontend | `web/app.js`, `web/index.html`, `web/styles.css` |

Changes that must land in more than one place:

- **A new history column** needs `HISTORY_COLUMN_DEFS` in `web/app.js`, the sort
  key whitelist in `validate_transaction_sort_key` (`src/api.rs`), *and* the
  `value_parser` list in `src/bin/sniper-cli.rs`. Miss the second and sorting
  returns 400; miss the third and the CLI rejects a key the UI offers.
- **A new API endpoint** usually wants a `sniper-cli` subcommand too. The CLI is
  how automation and AI agents drive Sniper; an API-only feature is invisible to
  them.
- **Scope semantics** are shared by the history filter, intercept, and the site
  map. Change `src/scope.rs` and all three follow.

## 5. Persistence invariants

This is the most dangerous area in the codebase. A session is spread across
several files under the session's storage directory:

| File | Holds |
| --- | --- |
| `snapshot.json` | Session metadata |
| `state.json` | Small, frequently-changing components |
| `workspace.json` | UI workspace: replay tabs, layout |
| `transactions.ndjson` | Captured transactions, one JSON object per line |
| `transactions.meta.ndjson` | The same records without bodies — the load path |
| `transactions.journal`, `websockets.journal` | Append-only, compacted on size |

The invariants:

1. **Bodies live on disk and are read back by byte offset.** A record in memory
   may carry a `BodyLocator { offset, len }` instead of its body. Any code that
   rewrites `transactions.ndjson` moves every offset, so it **must** return the
   new locators and hand them to `TransactionStore::adopt_written_locators`.
   Skip this and opening a record silently shows another request's traffic —
   no error, no crash, wrong data.
2. **Every write is atomic**: temp file, fsync, rename (`write_json`,
   `TempJsonFile` in `src/session.rs`). Do not write in place.
3. **Never fsync on the proxy runtime.** A large session takes seconds to
   persist. Blocking inside a tracked proxy task keeps the session permanently
   "busy" and blocks session switching. Use `spawn_blocking`, or the debounced
   `SessionContext::schedule_state_persist`.
4. **The workspace uses optimistic concurrency** — `revision` plus
   `client_id`/`client_version`, gated by `can_replace_snapshot`
   (`src/workspace.rs`). A client that has not finished loading must not commit;
   an empty snapshot that would discard stored replay tabs is rejected server
   side. Both guards exist because a real session lost every replay tab.
5. **Retention trims, it does not drop.** Hitting a cap must not discard
   captured traffic.

When you touch this layer, test across a restart. Most of these failures are
invisible until the process comes back up.

## 6. Frontend conventions

- Vanilla JS, no framework, no bundler, no `package.json`. Keep it that way
  unless there is a strong reason.
- `web/app.js` is large and organised by feature area. Match the surrounding
  style rather than introducing a new one.
- Rebuild after every frontend edit (see §1).
- **Watch out for omitted fields.** Many structs in `src/model.rs` use serde's
  `skip_serializing_if = "Option::is_none"`, so a cleared value is *absent* from
  the response rather than `null`. Merging with `Object.assign` then keeps the
  stale value. Reset such fields explicitly when merging a summary.
- The intercept editors round-trip a request through text and parse it back.
  That normalises headers and can rewrite `Content-Length`, so the server cannot
  tell an edit from a re-parse. The client reports whether the operator actually
  changed anything.

## 7. Security posture

Sniper is a security tool that holds other people's traffic. Treat that
seriously.

- **The local API is unauthenticated** and is therefore forced to a loopback
  address (`validate_ui_socket_addr` in `src/config.rs`). Never relax that.
- **Never log captured traffic content** — bodies, headers, cookies, or tokens —
  into event logs, error messages, or temp files.
- **Never put a real hostname in a test fixture, UI placeholder, or example.**
  Use `example.com`. Fixtures are public the moment they are pushed; this
  repository has already had to walk one back.
- No hardcoded secrets, obviously. There are none today; keep it that way.

## 8. Releases

Version work happens on a branch (`release/0.2.9`), not on `main`.

1. Bump `version` in `Cargo.toml`, then `cargo update -w` to sync `Cargo.lock`.
2. Merge to `main` and push.
3. Build the artifacts from a clean worktree at `origin/main`:

```bash
PATH="$HOME/.cargo/bin:$PATH" ALLOW_ADHOC_RELEASE=1 DMG_ARCH=universal \
  ./packaging/macos/release-macos.sh
```

4. Tag `vX.Y.Z` (lightweight, at the released commit), push the tag, and publish
   with `gh release create` attaching `dist/Sniper-X.Y.Z-universal.dmg`.

Two constraints worth knowing:

- **The DMG must be universal** (`arm64` + `x86_64`). Updater clients from
  v0.2.4 pick the newest DMG without checking architecture, so a single-arch
  release would hand an Intel binary to an Apple Silicon machine. The release
  script enforces this.
- **Releases are currently ad-hoc signed**, not Developer ID signed or
  notarized, which is why `ALLOW_ADHOC_RELEASE=1` is needed. That flag also
  skips the clean-worktree, origin/main and duplicate-tag checks — verify those
  by hand. Moving to real signing needs a Developer ID certificate plus
  `APPLE_ID`, `APPLE_TEAM_ID` and `APPLE_APP_PASSWORD`.

### Testing the desktop app on macOS

`cargo run --bin sniper-desktop` is fine for most work, but anything involving
the window itself — menus, full screen, code signing, the self-updater, TCC
prompts — only behaves correctly from a real `.app` bundle. Build one and keep
it somewhere stable (`~/Desktop/Sniper.app` is the convention here):

```bash
./packaging/macos/make-app.sh          # writes dist/Sniper.app
mv ~/Desktop/Sniper.app ~/Desktop/Sniper.app.prev
ditto dist/Sniper.app ~/Desktop/Sniper.app
rm -rf ~/Desktop/Sniper.app.prev
```

- **Use `ditto`, never `cp`.** `cp` does not preserve the bundle's extended
  attributes and breaks the code signature.
- **Swap by rename** as above. Overwriting a bundle whose executable is
  currently mapped can crash the running app; renaming leaves it alone until the
  user quits.
- `Contents/MacOS/Sniper` must be the **`sniper-desktop`** build. `make-app.sh`
  does this correctly; hand-assembling a bundle with the headless `sniper`
  binary produces an app that starts a server and never opens a window.

## 9. Conventions

- `cargo fmt` before committing. No warnings introduced.
- Comments explain **why**, not what. The existing code documents the reasoning
  behind a decision — the failure it prevents, the alternative rejected. Match
  that. A comment restating the line below it is noise.
- Commit messages: imperative one-line subject describing the behaviour change
  ("Stop discarding captured traffic"), then a body explaining the cause and the
  fix. Look at `git log` for the register.
- Prefer fixing the shared function over guarding each caller.
- Don't add a dependency for something a few lines can do.
