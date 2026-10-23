# Using Sniper from Codex

Sniper ships a Codex skill, `sniper-operator`, that teaches Codex to drive a
running Sniper instance through `sniper-cli` instead of the desktop UI. The CLI
speaks JSON and lists its operations in a machine-readable catalog. The Claude
Code equivalent is [claude-code.md](claude-code.md); the
[differences](#where-codex-and-claude-code-differ) are at the end.

## Install the skill

```bash
sniper-cli skills install --codex --dry-run
sniper-cli skills install --codex --yes
```

The dry run shows the plan and writes nothing; the `--yes` run prints the path
it wrote. The skill goes to `$CODEX_HOME/skills` when `CODEX_HOME` is set and not
blank, and to `~/.codex/skills` otherwise. `--codex-dir` overrides both.

The installed file is a copy of the template embedded in the binary. The desktop
app overwrites the copy in the default folder on every launch, so it follows
Sniper updates and local edits do not last. A copy installed with `--codex-dir`
is not updated; install it again after an update. The desktop app also installs
it where it is missing when
`SNIPER_INSTALL_AGENT_SKILLS` is `1`, `true` or `yes`.

## Point the CLI at the right instance

With no `--api` and no `SNIPER_API_ADDR`, `sniper-cli` finds an instance through
its data directory, by default `~/.sniper`: the session open in the desktop app.
To drive a test instance instead, set its address:

```bash
export SNIPER_API_ADDR=http://127.0.0.1:23001
```

The CLI does not fall back to discovery. If nothing at that address is Sniper,
the command fails with `API_UNAVAILABLE` and exit code `6`.

Exit codes: `0` success, `1` CLI error, `2` bad input, `5` an API 4xx such as an
unknown record id, `6` the API is unreachable or returned a 5xx. The `2` an agent
hits most is `CONFIRMATION_REQUIRED`: a write run with neither `--dry-run` nor
`--yes`.

When a subcommand such as `session list` gets an HTTP error, it reports
`HTTP_STATUS_ERROR` with the status in `error.details.status`. A read is
`retryable` only on a 5xx. `session create`, `rename`, `switch` and `delete` are
never `retryable` and report `outcome: "unknown"`, because the status does not
show whether the change applied. Check `session list` before you write again.

## What to ask for

Ask in terms of the workflow, not the flags.

**"What has the proxy captured?"**

```bash
sniper-cli capture http list --limit 1
```

The listing has no headers or bodies. `capture http get --id <uuid>` returns
them for one record.

**"Flag that order request for me."**

```bash
sniper-cli capture http annotate --id <uuid> --color red --note "id looks enumerable" --dry-run
```

The dry run names the exact API call, so Codex can show you what it is about to
do. With `--yes` it returns the updated record summary.

**"Only look at the target."**

```bash
sniper-cli --output compact scope set-scope --pattern '*.example.com' --yes
```

**"Open that request in Replay and send it again."** `replay open` returns a
tab `id` for `replay send`. A target override changes only the connection
target, not the `Host:` header in the request text. It is refused when the
captured request's host is an IP address.

Stored findings and event logs are read-only: `findings list`,
`findings get --id <uuid>`, `findings count` and `event-log list` need no
`--yes`. Lists return the newest 100 entries by default, and `--session-id`
reads another session without switching to it.

For anything else, `sniper-cli manifest` lists every operation,
`sniper-cli schema input <operation>` gives its JSON Schema and
`sniper-cli examples <operation>` a sample input.
`sniper-cli call <operation> --input '<json>'` runs any operation and returns
the result under `data`; the older subcommands return raw JSON. See the
[CLI contract](../../README.md#cli).

## What needs your approval

Every write needs `--dry-run` to preview it or `--yes` to apply it, and the
skill tells Codex to review the dry run before it applies anything. These need
more care:

- **HTTP history retention** (`capture http retention set`) is off by default.
  Keep-newest permanently deletes the oldest unprotected rows above a soft
  total, so approve it explicitly. A saved policy does not mean the cleanup has
  finished, and a lost response does not mean nothing changed; do not retry
  automatically. See [the retention contract](http-history-retention.md).
- **Passive scanner changes** (`scanner config set-enabled`,
  `scanner builtin set-enabled`, `scanner custom create`, `update`, `delete`)
  send no traffic. A write that conflicts is not retried; read the config again
  before you retry. See
  [the passive scanner CLI contract](passive-scanner.md).
- **Recon discovery** (`recon start`) crawls an authorized target or consults
  external history providers. Preview with `--dry-run`, agree on the exact
  target, sources and positive budgets, then start with `--yes`. Every Recon
  call needs an explicit session UUID. Provider history and new urlscan scans
  require separate disclosure acknowledgments; a CLI timeout does not cancel
  the job, and Stop cannot cancel an accepted remote scan. Read
  [the Recon CLI contract](recon.md#cli-and-operator-skill) first.
- **Nuclei templates.** `templates library download` contacts GitHub, so ask
  first. `templates passive set-enabled` sends nothing. `templates scan start`
  sends the selected templates' requests to targets in Scope: run
  `templates scan preview`, ask, then start it with `--yes` and follow it with
  `templates scan get`. See [the template contract](nuclei-templates.md).
- **Observed socket peer capture** (`capture http upstream-peer set`) is off by
  default. Observations stay in session files, exports and full-record JSON,
  even after you turn it off. A peer can be a proxy, CDN or shared endpoint, so
  it does not show who owns the origin. Read the
  [capture, privacy and recovery contract](observed-socket-peer.md) first.

## What Codex sees

A capture is the real traffic. `capture http get` returns headers as sent,
including `Cookie`, `Authorization` and any token in a body. `findings get`
returns stored evidence that can hold the same values, and finding metadata and
event-log messages can be sensitive too. `recon list` includes unredacted
URLs, raw URL spellings and evidence locations, which can expose paths or
query values even without captured bodies. None of it is redacted. What Codex
reads goes to the model provider and can end up in a transcript or a session
file on disk. The skill tells Codex to summarise sensitive responses instead of
pasting them, but it still reads them.

Use a dedicated session for agent work, and keep captures of real user traffic
out of it.

## When it does not work

- **Nothing is captured although requests succeed.** Check `no_proxy` and
  `http_proxy`. `curl -x` honours `no_proxy`, which usually includes
  `127.0.0.1`, so requests to a local upstream bypass the proxy.
- **`sniper-cli: command not found`.** The binary ships inside the app bundle,
  and Sniper does not edit your shell profile unless asked. See the
  [README](../../README.md#cli).
- **Codex does not use the skill.** Check that
  `~/.codex/skills/sniper-operator/SKILL.md` exists and that `CODEX_HOME` does
  not point somewhere else.

## Where Codex and Claude Code differ

The two skill templates differ only in the install example, `--codex` instead
of `--claude`. The default destination is `~/.codex/skills` (or
`$CODEX_HOME/skills`) for Codex and `~/.claude/skills` (or
`$CLAUDE_HOME/skills`) for Claude Code; `--codex-dir` and `--claude-dir`
override them. `--all` installs both, but not into the same directory. The CLI,
its dry-run rule, envelope and exit codes are the same for both agents.

## Limits

- Most commands need a running `sniper-desktop` or headless `sniper`.
  `skills install`, `manifest`, `schema` and `examples` do not.
- Sniper locks its data directory, so a second instance on the same
  `SNIPER_DATA_DIR` does not start. Give an agent-driven instance its own data
  directory.
- Paths on this page are macOS paths. Windows ships the same three executables;
  see [packaging/windows/README.md](../../packaging/windows/README.md).
- The local API does not authenticate clients on the same machine, so the UI
  listens on loopback by default. A non-loopback `SNIPER_UI_ADDR` authenticates
  other hosts (see the [architecture notes](../architecture.md)). Point an agent
  at a loopback instance.
