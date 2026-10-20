# Using Sniper from Claude Code

Claude Code drives Sniper through [`sniper-cli`](../../README.md#cli), not the
UI. A bundled skill teaches it the commands, that writes need `--dry-run` before
`--yes`, and that captured records carry real credentials.

## Install the skill

```bash
sniper-cli skills install --claude --dry-run
sniper-cli skills install --claude --yes
```

`--dry-run` prints the plan and writes nothing; `--yes` writes the skill and
prints where it landed. The default destination is `$CLAUDE_HOME/skills`, or
`~/.claude/skills` when `CLAUDE_HOME` is unset. `--claude-dir` installs into
another folder, such as a project's `.claude/skills`.

The installed file is a copy of
[`packaging/skills/claude/sniper-operator/SKILL.md`](../../packaging/skills/claude/sniper-operator/SKILL.md).
The desktop app overwrites the copy in the default folder on every launch, so it
follows Sniper updates and local edits do not last. A copy installed with
`--claude-dir` is not updated; install it again after an update. `skills install`
needs no running Sniper and does not
change `PATH`; see the [CLI section of the README](../../README.md#cli).

### OpenCode

OpenCode reads the same skill. According to
[OpenCode's documentation](https://opencode.ai/docs/skills/), it looks for
`<name>/SKILL.md` in `~/.claude/skills`, `~/.config/opencode/skills` and
`~/.agents/skills`, and in a project's `.claude/skills`, `.opencode/skills` and
`.agents/skills`. The install above therefore covers OpenCode too. To give
OpenCode its own copy and leave `~/.claude` alone:

```bash
sniper-cli skills install --claude --claude-dir ~/.config/opencode/skills --yes
```

Installing into both folders leaves two skills with the same name, which
OpenCode may flag.

## Confirm Claude Code picked it up

```bash
ls ~/.claude/skills/sniper-operator/SKILL.md
claude -p "Answer in one line. Is a skill named sniper-operator available to you?" < /dev/null
```

The first command shows the file exists; the second shows that Claude Code
loaded it. Restart any Claude Code session that was open before the install.

## Point the CLI at the right instance

With no `--api`, `sniper-cli` reads `runtime-state.json` from the data
directory: `$SNIPER_DATA_DIR`, or `~/.sniper` by default, which the desktop app
owns. To reach a scratch instance, give the CLI the data directory it was
started with:

```bash
# from a source checkout, an instance that owns /tmp/sniper-test
SNIPER_DATA_DIR=/tmp/sniper-test \
SNIPER_UI_ADDR=127.0.0.1:18903 \
SNIPER_PROXY_ADDR=127.0.0.1:18904 \
  cargo run --bin sniper &

# the CLI, pointed at the same directory
SNIPER_DATA_DIR=/tmp/sniper-test sniper-cli --output compact session list
```

If no instance owns that directory, the CLI exits `6` with `could not discover`.
On macOS, the headless `sniper` binary comes only from a source checkout; the
app bundle ships `sniper-desktop` and `sniper-cli`.

`--api http://127.0.0.1:PORT`, or `SNIPER_API_ADDR` with the same value, skips
the lookup and probes that address directly. Tell Claude Code the port once and
it passes `--api` on every call.

## What to ask for

**"What has the proxy caught?"** `capture http list` returns metadata only,
which makes it the cheap way to survey a session:

```bash
sniper-cli --output compact capture http list --limit 2
```

**"Scope this to my target and drop the noise."**

```bash
sniper-cli scope set-scope --pattern '*.example.com' --dry-run
sniper-cli --output compact scope set-scope --pattern '*.example.com' --yes
```

Scope filters views and holds; it does not stop capture. Patterns are
normalised: `127.0.0.1:18913` is saved as `127.0.0.1`.

**"Hold the next request so I can look at it before it goes out."**

```bash
sniper-cli --output compact capture intercept on --yes
sniper-cli --output compact capture intercept list
sniper-cli --output compact capture intercept forward --id <uuid> --yes
```

`intercept_scope_only` defaults to `true`, so an out-of-scope request goes
straight through, with no error. Set scope to the host you are testing first.

**"Resend that 404 and tell me whether it is consistent."**

```bash
sniper-cli --output compact replay open --transaction-id <uuid> --yes
sniper-cli --output compact replay send --tab-id <tab-id> --yes
```

`replay open` returns a tab with `request_text` and a separate
`target_host`/`target_port`. The target is only the connection destination;
changing it does not change the `Host:` header in the request text, or the
reverse. `replay send` returns the full transaction record, tagged
`"notes": ["Sent from Replay."]`.

Stored findings and event logs are read-only: `findings list`,
`findings get --id <uuid>`, `findings count` and `event-log list` need no
`--yes`. Lists return the newest 100 entries by default, and `--session-id`
reads another session without switching to it. See the
[CLI contract](../../README.md#cli).

## What needs your approval

Every write needs `--dry-run` to preview it or `--yes` to apply it, and the
skill tells Claude Code to review the dry run before it applies anything. These
need more care:

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

## What the agent sees

`capture http list` returns no headers and no bodies. `capture http get`,
`replay open` and `replay send` return both verbatim, so any cookie,
`Authorization` header or token in a capture goes into the model's context and
into whatever transcript or log your Claude Code setup keeps. `findings get`
returns stored evidence that can hold the same values, and finding metadata and
event-log messages can be sensitive too. `recon list` includes unredacted
URLs, raw URL spellings and evidence locations, which can expose paths or
query values even without captured bodies. Sniper redacts none of it; the skill
only asks the agent to summarise instead of paste. Which captures an agent may
open is your decision.

The agent sees no traffic from another session unless it passes
`--session-id`, and nothing of the desktop window. It does see the Replay
workspace: `replay list` returns every tab with its request text and send
history. The configured OAST token is the only stored value that comes back
masked, as `********`.

## When it does not work

These all return `API_UNAVAILABLE` and exit `6`:

- `failed to probe Sniper API at ...`: Sniper is not running at the `--api`
  address.
- `could not discover Sniper API address`: no `--api`, and no instance owns the
  data directory.
- `Sniper API probe returned 404 Not Found`: the `--api` address answers HTTP
  but is not Sniper.

If `sniper-cli` is not on `PATH`, the command exits `127`; the skill tells the
agent to say so instead of falling back to the UI. If Claude Code answers a
Sniper question without running `sniper-cli`, the skill did not load: re-run the
install, then the `claude -p` check above.

When `session create`, `rename`, `switch` or `delete` gets an HTTP error, it
reports `HTTP_STATUS_ERROR` with `outcome: "unknown"`, because the status does
not show whether the change applied. Check `session list` before you write
again.

## Limits

The paths on this page are macOS paths. The headless `sniper` binary serves the
same API as `sniper-desktop`. The local API is unauthenticated and bound to
loopback by design ([architecture](../architecture.md)). A remote headless
listener adds a bootstrap token, but point the agent at a loopback instance.
