# Using Sniper from Codex

Sniper ships a Codex skill, `sniper-operator`, that teaches Codex to drive a
running Sniper instance through `sniper-cli` instead of reading the desktop UI.
The CLI speaks JSON and has a machine-readable operation catalog, so an agent
can list captured traffic, narrow scope, annotate a record or resend a request
without anyone screen-scraping a WebView.

This page covers the Codex side. The Claude Code equivalent is
[claude-code.md](claude-code.md); the two are close enough that the differences
are listed explicitly at the end rather than left for you to guess.

## Install the skill

`sniper-cli skills install` writes the skill. Like every operation the manifest
marks `side_effect: "write"`, it refuses to act until you pass `--dry-run` or
`--yes`.

```console
$ sniper-cli skills install --codex --dry-run
{
  "api": {
    "local": true
  },
  "command": "skills install",
  "dry_run": true,
  "input": {
    "all": false,
    "claude": false,
    "claude_dir": null,
    "codex": true,
    "codex_dir": null
  },
  "notes": [
    "Use --yes to apply this side-effecting operation after reviewing the dry-run."
  ],
  "operation": "skills.install",
  "requires_confirmation": true,
  "side_effect": "write"
}
```

The dry run reports the plan but not the resolved destination, so the applied
run is where you learn the path. The destination is `$CODEX_HOME/skills` when
`CODEX_HOME` is set to a non-blank value, and `~/.codex/skills` otherwise
(`default_codex_skills_dir` in [`src/skills.rs`](../../src/skills.rs));
`--codex-dir` overrides both. Setting `CODEX_HOME` makes the run below
reproducible without writing into your own Codex config:

```console
$ CODEX_HOME=/tmp/codex-home sniper-cli --output compact skills install --codex --yes
{"installed":[{"agent":"codex","path":"/tmp/codex-home/skills/sniper-operator"}]}
```

Drop the `CODEX_HOME` prefix for a real install and the path becomes
`~/.codex/skills/sniper-operator`. Verify against the filesystem rather than
trusting the JSON:

```console
$ ls /tmp/codex-home/skills/sniper-operator/
SKILL.md

$ diff /tmp/codex-home/skills/sniper-operator/SKILL.md packaging/skills/codex/sniper-operator/SKILL.md
$ echo $?
0
```

Two things to know about that file. It is a **copy of the template embedded in
the binary that wrote it**, not a link to the repository, so a Sniper upgrade
does not refresh an existing install — re-run it after upgrading. On the machine
this page was written on, a skill installed by an older build was 2708 bytes
against the 4769-byte current
[`packaging/skills/codex/sniper-operator/SKILL.md`](../../packaging/skills/codex/sniper-operator/SKILL.md),
81 diff lines apart. And `--yes` **overwrites** an existing `SKILL.md`; if you
have hand-edited yours, copy it aside first.

Installing both agents into one directory is rejected, because both would write
the same `SKILL.md`:

```console
$ sniper-cli --output compact skills install --all --codex-dir /tmp/x --claude-dir /tmp/x --yes
{"error":{"code":"CLI_ERROR","details":{},"hint":null,"message":"codex and claude skill destinations resolve to the same SKILL.md path: /tmp/x/sniper-operator/SKILL.md","retryable":false},"meta":{},"ok":false,"operation":"skills.install","schema_version":"2026-06-22","warnings":[]}
```

`sniper-desktop` can install on launch, but only when
`SNIPER_INSTALL_AGENT_SKILLS` is set to `1`, `true` or `yes` — any other value,
including `on`, is ignored — and that path writes only when no `SKILL.md` is
already there. A normal launch installs nothing.

## Point the CLI at the right instance

With no `--api` and no `SNIPER_API_ADDR`, `sniper-cli` discovers an instance
from its data directory — by default `~/.sniper`, which is whatever session you
have open in the desktop app. That is usually what you want interactively and
almost never what you want while testing. Set the address explicitly:

```bash
export SNIPER_API_ADDR=http://127.0.0.1:23001
```

`SNIPER_API_ADDR` is probed and does not fall back. A wrong address fails with a
named error and a non-zero exit code rather than silently attaching elsewhere:

```console
$ SNIPER_API_ADDR=http://127.0.0.1:18915 sniper-cli --output compact session list
{"error":{"code":"API_UNAVAILABLE","details":{},"hint":"Start Sniper Desktop, or pass --api http://HOST:PORT explicitly.","message":"SNIPER_API_ADDR=http://127.0.0.1:18915 did not point to a reachable Sniper API (failed to probe Sniper API at http://127.0.0.1:18915: error sending request for url (http://127.0.0.1:18915/api/settings))","retryable":true},"meta":{},"ok":false,"operation":"session.list","schema_version":"2026-06-22","warnings":[]}
$ echo $?
6
```

Nothing was listening on that port. An address that answers HTTP but is not
Sniper fails differently — `Sniper API probe returned 404 Not Found`, or
`Sniper API probe response did not match the expected /api/settings schema` —
and still exits `6`.

Exit codes observed: `0` success, `1` a CLI-level error, `2` bad input, `5` a
4xx from the API such as an unknown record id, `6` the API unreachable or a 5xx
from it. Codex can branch on those without parsing prose. The `2` an agent hits
most is not a malformed argument but `CONFIRMATION_REQUIRED` — a write run with
neither `--dry-run` nor `--yes`.

## What to ask for

Ask in terms of the workflow, not the flags. Each example below is a real run
against a throwaway upstream; the surrounding prose is what you would type at
Codex.

**"What has the proxy captured?"**

```console
$ sniper-cli capture http list --limit 1
[
  {
    "content_type": "application/json",
    "duration_ms": 3,
    "has_match_replace": false,
    "has_response": true,
    "has_user_note": false,
    "host": "127.0.0.1:18915",
    "id": "138cb8c8-e1ef-4347-a49e-d425f7bd42d6",
    "is_websocket": false,
    "kind": "http",
    "label": "#11 GET 127.0.0.1:18915/static/app.js",
    "method": "GET",
    "note_count": 0,
    "path": "/static/app.js",
    "request_bytes": 0,
    "response_bytes": 35,
    "scheme": "http",
    "sequence": 11,
    "started_at": "2026-09-17T01:43:33.859798Z",
    "status": 200
  }
]
```

The listing carries no bodies or headers. Those arrive only when you ask for one
record with `capture http get --id <uuid>`, which matters for the reasons in the
next section.

**"Flag that order request for me."** The dry run names the exact API call, so
Codex can show you what it is about to do before it does it:

```console
$ sniper-cli capture http annotate --id 4c8bec85-6d2d-414b-ac9f-2c60371bbd03 --color red --note "id looks enumerable" --dry-run
{
  "api": {
    "body": {
      "note": "annotation payload"
    },
    "method": "PATCH",
    "path": "/api/transactions/4c8bec85-6d2d-414b-ac9f-2c60371bbd03/annotations"
  },
  "command": "capture http annotate --id <uuid>",
  "dry_run": true,
  "input": {
    "clear_color": false,
    "clear_note": false,
    "color": "red",
    "id": "4c8bec85-6d2d-414b-ac9f-2c60371bbd03",
    "note": "id looks enumerable",
    "session_id": null
  },
  "notes": [
    "Use --yes to apply this side-effecting operation after reviewing the dry-run."
  ],
  "operation": "capture.http.annotate",
  "requires_confirmation": true,
  "side_effect": "write"
}
```

Re-running it with `--yes` returns the updated record summary, with
`annotation_revision` bumped and `note_preview` set.

**"Only look at the target."**

```console
$ sniper-cli --output compact scope set-scope --pattern '*.example.com' --yes
{"scope_patterns":["*.example.com"],"session_id":"67ae2dfd-8a18-466a-83d7-c3e5102f60a7"}
```

**"Open that request in Replay and send it again."** `replay open` returns the
new tab's `id`; feed it to `replay send`. Both are write operations, so both
take `--dry-run` first. Replay's target override changes the connection target
only — the raw `Host:` header in the request text is left alone, which is the
behaviour you want when testing routing but a surprise if you expected it to
rewrite the header. The override is also refused outright when the captured
request's host is a bare IP address, with `400 Bad Request: Replay target
override is not supported when the request host is an IP address`, so it cannot
be exercised against a local upstream addressed as `127.0.0.1`.

For anything not listed here, `sniper-cli manifest` is the catalog: 57
operations, 32 of them writes. `sniper-cli schema input <operation>` gives the
JSON Schema and `sniper-cli examples <operation>` a worked input. Codex can call
any of them uniformly with `sniper-cli call <operation> --input '<json>'`, whose
successful output is wrapped in an envelope with the result under `data`. The
older subcommands return raw JSON instead.

## What Codex sees

A capture is the real traffic. `capture http get` returns request and response
headers as they went over the wire, including `Cookie`, `Authorization` and any
session token in a body. When Codex reads a record, that material goes to the
model provider along with the rest of the context, and it may be written into a
transcript or a session file on disk. The skill tells the agent to summarise
large or sensitive responses rather than paste them, which reduces the exposure
but does not remove it — the agent still had to read the record to summarise it.

Deciding whether a given session is safe to expose is the operator's job, not
the skill's. Use a dedicated session for work you intend to drive with an agent,
and keep captures of real user traffic out of it.

## When it does not work

- **Nothing is captured although requests succeed.** Check `no_proxy` and
  `http_proxy` in your environment. `curl -x` honours `no_proxy`, and the usual
  developer value includes `127.0.0.1`, so requests to a local upstream bypass
  the proxy entirely and return a normal-looking response.
- **`sniper-cli: command not found`.** The binary ships inside the app bundle
  and Sniper does not edit your shell profile unless asked. See the CLI section
  of the [README](../../README.md).
- **Codex does not use the skill.** Confirm the file is where Codex looks:
  `ls ~/.codex/skills/sniper-operator/SKILL.md`, and check `CODEX_HOME` is not
  pointing somewhere else.

## Where Codex and Claude Code differ

Less than you would expect. The two skill templates are not byte-identical, but
the entire difference is which flag the install example passes:

```console
$ diff packaging/skills/claude/sniper-operator/SKILL.md packaging/skills/codex/sniper-operator/SKILL.md
79,80c79,80
< sniper-cli skills install --claude --dry-run
< sniper-cli skills install --claude --yes
---
> sniper-cli skills install --codex --dry-run
> sniper-cli skills install --codex --yes
```

The name, description, workflow, command list and guardrails are the same text.
What differs is the destination — `~/.codex/skills` against `~/.claude/skills`,
selected by `--codex` or `--claude` and overridden by `--codex-dir` or
`--claude-dir` — and `CODEX_HOME` against `CLAUDE_HOME`. `--all` installs both.
Everything on the Sniper side, including the dry-run contract, the envelope
format and the exit codes, is identical because both agents talk to the same
CLI.

## Limits

- Most of the CLI needs a running Sniper. It is a client of the local HTTP API,
  not a standalone proxy, so there is nothing to drive until `sniper-desktop` or
  the headless `sniper` is up. The exceptions answer out of the binary itself —
  `skills install`, `manifest`, `schema` and `examples` — which is why the
  install at the top of this page works before Sniper has ever been started, and
  why its dry run reports `"api": {"local": true}`.
- One instance per data directory. Sniper locks it, so a second instance against
  the same `SNIPER_DATA_DIR` will not start. Give an agent-driven instance its
  own data directory rather than sharing the one your desktop app has open.
- The skill directory is a plain file drop. Sniper writes `SKILL.md` and stops
  there; whether Codex loads it is Codex's business and this page does not
  verify that end of the handshake.
- macOS paths are used throughout. Windows ships the same three executables —
  see [packaging/windows/README.md](../../packaging/windows/README.md) — but the
  install locations here are the Unix ones.
- The local API is unauthenticated for same-machine clients, which is why the
  default UI listener is loopback. A non-loopback `SNIPER_UI_ADDR` is supported
  and does authenticate peers from other hosts — a one-time bootstrap token
  exchanged for a session cookie, described in the
  [architecture notes](../architecture.md) — but `sniper-cli` is only ever
  exercised same-machine, so point an agent at a loopback instance.
