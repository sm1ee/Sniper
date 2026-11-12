# Using sniper-cli

`sniper-cli` drives a running Sniper over its local HTTP API and prints JSON.
Scripts and coding agents such as Claude Code and Codex use it to work on the
same captured traffic as the desktop app.

## Getting it on PATH

`sniper-cli` ships with the macOS app and the Windows packages, and Homebrew puts
it on `PATH`. Otherwise use **Add to PATH**, offered on first launch and under
**Settings ▸ Runtime ▸ Command line**, or on macOS launch with
`SNIPER_INSTALL_CLI_PATH=1 open -a Sniper`. On macOS, move Sniper.app to
Applications first; registration adds one entry to your zsh profile and to an
existing `~/.bash_profile` or `~/.bashrc`. On Windows it adds the app folder to
your user PATH; before you move a portable folder, read
[Windows PATH ownership](../../packaging/windows/README.md#cli-and-headless-mode).
Open a new terminal afterwards.

## Everyday commands

```bash
sniper-cli session list
sniper-cli --output compact capture http list --limit 10
sniper-cli --output compact capture http search --value access_token
sniper-cli capture browser open --yes
sniper-cli capture http replay --id <id> --dry-run
sniper-cli capture http replay --id <id> --yes
sniper-cli scope set-scope --pattern '*.example.com' --yes
sniper-cli fuzzer run --yes
sniper-cli findings list --limit 20
sniper-cli findings get --id <finding-uuid>
sniper-cli findings count
sniper-cli event-log list --limit 20
sniper-cli --output compact tcp list --contains PING
```

The TCP and UDP relay is under `sniper-cli tcp`; see the
[TCP and UDP relay guide](tcp-relay.md).

## Reads, writes and the manifest

Operations marked `side_effect: "write"` in `sniper-cli manifest` need
`--dry-run` to preview them or `--yes` to apply them. Subcommands print the API's
raw JSON. `call` runs any manifest operation by name and wraps its result in an
envelope; the result is in `data`. `--output compact` prints one-line JSON.

```bash
sniper-cli manifest
sniper-cli schema input replay.send
sniper-cli examples capture.http.list
sniper-cli --output compact call capture.http.list --input '{"limit":20,"page":true}'
sniper-cli --output compact call replay.send --input '{"tab_id":"<tab-id>"}' --dry-run
sniper-cli --output compact call replay.send --input '{"tab_id":"<tab-id>"}' --yes
printf "%s" "$OAST_TOKEN" | sniper-cli capture oast configure --provider custom --url https://oast.example --token-stdin --yes
```

## Findings and the event log

The `findings` and `event-log` commands are reads and need no `--yes`. They read
the active session, or another one with `--session-id <uuid>` without switching
to it; `call` returns the ID it used in `meta.session_id`. Lists return the
newest 100 entries by default, `--limit` must be positive, and there is no
paging. `findings get` returns evidence as captured, unredacted, so review it
before you give it to an agent or save it.

## Agent skills

```bash
sniper-cli skills install --all --dry-run
sniper-cli skills install --all --yes
```

This installs the `sniper-operator` skill for Claude Code and Codex.
`sniper-cli skills status --all` shows whether the installed copies match this
build. Each launch of the desktop app overwrites the copies in the default
folders (`~/.claude/skills` and `~/.codex/skills`, or `$CLAUDE_HOME/skills` and
`$CODEX_HOME/skills` when set), so edits there do not last. A copy installed
with `--claude-dir` or `--codex-dir` is left alone. OpenCode reads the Claude
Code skill (see the [Claude Code guide](../integrations/claude-code.md#opencode)).

## Contracts

- [Recon endpoint discovery](../integrations/recon.md): read, start and stop discovery jobs, with explicit target and service consent.
- [Nuclei templates](../integrations/nuclei-templates.md): the template library, passive templates, manual and auto scans.
- [Service Map](../integrations/service-map.md): the passive map of captured origins and what `scope service-map` returns.
- [Passive scanner configuration](../integrations/passive-scanner.md): turn built-in checks on or off and manage custom rules.
- [Saved configuration edits](../integrations/saved-configuration-edits.md): change a saved intercept rule or a Replay tab's label.
- [Saved Replay tabs](../integrations/saved-replay-tabs.md): close, duplicate and pin saved HTTP Replay tabs.
- [Saved data v1](../integrations/saved-data-v1.md): opt-in `saved.v1.*` operations with durable mutation receipts.
- [HTTP history retention](../integrations/http-history-retention.md): automatic cleanup, off by default; when on, it permanently deletes the oldest unprotected rows.
- [Observed socket peer capture](../integrations/observed-socket-peer.md): off by default; when on, record the socket peer of future responses, which may be a proxy or CDN.
