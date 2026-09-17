# Using Sniper from Claude Code

Claude Code drives Sniper through [`sniper-cli`](../../README.md#cli), not through the
UI. A bundled skill teaches it the command surface — which operation to reach for,
that writes need `--dry-run` before `--yes`, and that captured records carry real
credentials. This page covers installing that skill, confirming it loaded, and what
to ask for once it has.

The runtime examples below were run against an isolated instance on
`127.0.0.1:18903` with a throwaway upstream on `127.0.0.1:18913`. Output is real
and trimmed for length. The install commands need no running instance.

## Install the skill

```bash
sniper-cli skills install --claude --dry-run
sniper-cli skills install --claude --yes
```

`--dry-run` prints the plan and writes nothing:

```json
{
  "api": { "local": true },
  "command": "skills install",
  "dry_run": true,
  "input": { "all": false, "claude": true, "claude_dir": null, "codex": false, "codex_dir": null },
  "notes": ["Use --yes to apply this side-effecting operation after reviewing the dry-run."],
  "operation": "skills.install",
  "requires_confirmation": true,
  "side_effect": "write"
}
```

`--yes` reports where the skill landed. This run redirected `CLAUDE_HOME` to a
scratch directory so it would not overwrite a real install:

```json
{ "installed": [ { "agent": "claude", "path": "<scratch>/.claude/skills/sniper-operator" } ] }
```

The destination flags are `--codex`, `--claude`, `--all`, `--codex-dir` and
`--claude-dir`; `--yes` with none of them exits `1` and names the three it accepts.
There is no `--force` and no uninstall; a second `--yes` overwrites `SKILL.md` in
place, so a locally edited skill is lost without warning. The default destination is
`$CLAUDE_HOME/skills` when `CLAUDE_HOME` is set and `~/.claude/skills` otherwise,
putting the skill at `~/.claude/skills/sniper-operator/SKILL.md` — byte-identical to
[`packaging/skills/claude/sniper-operator/SKILL.md`](../../packaging/skills/claude/sniper-operator/SKILL.md).
Use `--claude-dir` to install into a project's `.claude/skills` instead.

Two things `skills install` does not do. It never touches `PATH` — put `sniper-cli`
there yourself, as the [CLI section of the README](../../README.md#cli) describes. And
it needs no running Sniper: `"api": {"local": true}` means the whole operation is a
local file write, so the install works before Sniper has ever been started.

## Confirm Claude Code picked it up

```bash
ls ~/.claude/skills/sniper-operator/SKILL.md
claude -p "Answer in one line. Is a skill named sniper-operator available to you?" < /dev/null
```

```
Yes — a skill named `sniper-operator` is available to me.
```

The second command is the one that matters. A file on disk only proves the install
ran; this proves the running agent loaded it. Restart any Claude Code session that
was open before the install.

## Point the CLI at the right instance

With no `--api`, `sniper-cli` reads `runtime-state.json` out of the data directory —
`~/.sniper` by default, or `$SNIPER_DATA_DIR`. A scratch instance is therefore
reachable without any flag, as long as the CLI is given the same data directory the
server was started with:

```bash
# from a source checkout, an instance that owns /tmp/sniper-test
SNIPER_DATA_DIR=/tmp/sniper-test \
SNIPER_UI_ADDR=127.0.0.1:18903 \
SNIPER_PROXY_ADDR=127.0.0.1:18904 \
  cargo run --bin sniper &

# the CLI, pointed at the same directory
SNIPER_DATA_DIR=/tmp/sniper-test sniper-cli --output compact session list
```

Both lines are needed. `SNIPER_DATA_DIR` only tells the CLI where to look; run the
second line against a directory no instance owns and it exits `6` with `could not
discover`, the error two sections down. Only a source checkout has the headless
`sniper` binary — the macOS app bundle ships `sniper-desktop` and `sniper-cli`, and
the desktop app owns `~/.sniper`, which is what the CLI reads with no variable set.

Two overrides skip that lookup entirely and probe an address directly: `--api
http://127.0.0.1:PORT`, and `SNIPER_API_ADDR` with the same value. Either works with
no data directory present. Tell Claude Code the port once and it will pass `--api` on
every call.

## What to ask for

**"What has the proxy caught?"** — `capture http list` returns metadata only, which
makes it the cheap way to survey a session:

```bash
sniper-cli --output compact capture http list --limit 2
```

```json
[{"content_type":"application/json","duration_ms":3,"has_response":true,
  "host":"127.0.0.1:18913","id":"ba342404-…","label":"#7 GET 127.0.0.1:18913/api/orders",
  "method":"GET","path":"/api/orders","request_bytes":0,"response_bytes":36,
  "sequence":7,"started_at":"2026-09-17T01:40:15.293195Z","status":200, …}, …]
```

**"Scope this to my target and drop the noise."**

```bash
sniper-cli scope set-scope --pattern '*.example.com' --dry-run
sniper-cli --output compact scope set-scope --pattern '*.example.com' --yes
```

```json
{"scope_patterns":["*.example.com"],"session_id":"47417766-…"}
```

Scope filters views and holds; it does not stop capture. With scope set to
`*.example.com`, a request to the local upstream was still recorded as `#8`. Patterns
are normalised — `127.0.0.1:18913` comes back as `127.0.0.1`, port dropped.

**"Hold the next request so I can look at it before it goes out."**

```bash
sniper-cli --output compact capture intercept on --yes
sniper-cli --output compact capture intercept list
sniper-cli --output compact capture intercept forward --id <uuid> --yes
```

```json
[{"host":"127.0.0.1:18913","id":"6aad29c1-…","method":"GET","path":"/api/orders",
  "peer_addr":"127.0.0.1:63379","scheme":"http","started_at":"2026-09-17T01:40:25.114230Z"}]
{"action":"forward","id":"6aad29c1-…","ok":true,"session_id":"47417766-…"}
```

`intercept_scope_only` defaults to `true`, and an out-of-scope request is forwarded
rather than queued (`src/proxy.rs` returns `Forward` before the hold). With scope on
`*.example.com`, the same local request went straight through — curl got its response
at normal speed and the queue stayed `[]`. Nothing hangs and nothing errors, so set
scope to the host you are testing first or the hold silently does nothing.

**"Resend that 404 and tell me whether it is consistent."**

```bash
sniper-cli --output compact replay open --transaction-id <uuid> --yes
sniper-cli --output compact replay send --tab-id <tab-id> --yes
```

`replay open` returns a tab carrying `request_text` plus a separate
`target_host`/`target_port`. The target is the connection destination only; the
`Host:` header inside the request text is untouched, so overriding one does not
change the other. `replay send` returns a full transaction record and tags it
`"notes": ["Sent from Replay."]`.

## What the agent sees

`capture http list` returns no headers and no bodies. `capture http get`,
`replay open` and `replay send` return both, verbatim — request headers, response
headers, and a `body_preview`. Any cookie, `Authorization` header or token in a
capture goes straight into the model's context when one of those runs, and from
there into whatever transcript or log your Claude Code setup keeps. Sniper does not
redact and the skill only asks the agent to summarise rather than paste. Deciding
which captures an agent may open is your job, not the tool's.

Beyond the captures themselves the agent sees only what the CLI returns: no traffic
from another session unless it passes `--session-id`, and nothing about the desktop
window. It does see the Replay workspace — `replay list` returns every tab, its
request text and its send history. The configured OAST token is the one stored value
that comes back masked as `********`.

## When it does not work

Sniper not running, explicit `--api`:

```json
{"error":{"code":"API_UNAVAILABLE","message":"failed to probe Sniper API at http://127.0.0.1:18903: error sending request for url (http://127.0.0.1:18903/api/settings)","retryable":true,"hint":"Start Sniper Desktop, or pass --api http://HOST:PORT explicitly."},"ok":false,"operation":"session.list"}
```

Nothing to discover — no `--api`, no instance for that data directory:

```json
{"error":{"code":"API_UNAVAILABLE","message":"could not discover Sniper API address; pass --api or start sniper-desktop first","retryable":true,…},"ok":false}
```

`--api` pointing at something that answers HTTP but is not Sniper:

```json
{"error":{"code":"API_UNAVAILABLE","message":"Sniper API probe returned 404 Not Found","retryable":true,…},"ok":false}
```

All three exit `6`. `sniper-cli` missing from `PATH` exits `127` with
`env: sniper-cli: No such file or directory`, and the skill tells the agent to say so
rather than fall back to scraping the UI.

If Claude Code answers a Sniper question without running `sniper-cli`, the skill did
not load. Re-run the install, then re-run the `claude -p` check above.

## Limits

Skill installation and the CLI are built for macOS and Windows; every command on this
page was run on macOS, and the paths shown are macOS paths. Nothing here needs
`sniper-desktop` specifically — the headless `sniper` binary serves the same API,
which is what the examples used. The local API is unauthenticated and bound to
loopback by design ([architecture](../architecture.md)); a remote headless listener
adds a bootstrap token, but `sniper-cli` is only ever tested same-machine.
