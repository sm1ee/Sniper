# Sniper in an agent harness

This page is for people deciding whether Sniper belongs in an agent harness. It
covers where Sniper sits, what goes in and comes out, what the agent can see,
and when to leave it out.

## What Sniper is

Sniper is a local intercepting proxy and traffic-inspection layer. It sits
beside the thing under test, records what crossed the wire, and gives a human
and an agent the same records through the same API.

It is not an LLM API gateway: it holds no provider keys and does no model
routing, retries, token metering or spend limits. Between a harness and a model
provider it only records those calls. It is not a reverse proxy or a hosting
platform either. It is a *forward* proxy: a client is configured to send its
traffic through Sniper, which forwards it to whatever host the client asked for.

## Three ways in, one core

[`web/architecture.svg`](../../web/architecture.svg), shown in the
[README](../../README.md), is the map. Three paths reach one core:

- **Proxied traffic:** a browser, app or service points at the proxy listener.
  Sniper terminates HTTPS with its own CA, so the core sees the plaintext.
- **The desktop app** (`sniper-desktop`): a native window that hosts the web UI
  and runs the core in the same process. This is the operator's view.
- **`sniper-cli`:** a JSON-first CLI that talks to a *running* instance over its
  loopback HTTP API. This is the agent's view.

The desktop app and the CLI are clients of the same local API, so they see the
same records at the same time, and the core writes them to a session directory
on disk. See [docs/architecture.md](../architecture.md) for why the boundaries
fall where they do.

## A worked example

Run the harness instance isolated. Sniper allows one runtime per data
directory, so an instance without its own `SNIPER_DATA_DIR` either refuses to
start (`another Sniper runtime is already using data dir ...`) or, if nothing
else is running, attaches to the operator's real session.

```bash
SNIPER_DATA_DIR=/tmp/sniper-doc-harness \
SNIPER_UI_ADDR=127.0.0.1:18927 \
SNIPER_PROXY_ADDR=127.0.0.1:18928 \
  ./target/release/sniper &

# poll rather than sleeping; add a timeout if this runs unattended
until curl -s -m 1 -o /dev/null http://127.0.0.1:18927/api/settings; do :; done
```

Point the app under test at the proxy. Here that is a throwaway JSON server on
`127.0.0.1:18937`, given four requests:

```bash
for p in /api/orders /api/profile /api/missing; do
  curl -s -o /dev/null --noproxy "" -x http://127.0.0.1:18928 \
    -H 'authorization: Bearer REDACTED-TEST-VALUE' http://127.0.0.1:18937$p
done
curl -s -o /dev/null --noproxy "" -x http://127.0.0.1:18928 \
  -H 'content-type: application/json' -d '{"item":"demo"}' \
  http://127.0.0.1:18937/api/orders
```

`--noproxy ""` keeps a `no_proxy` entry for loopback from making curl ignore
`-x` and connect directly, which would capture nothing.

The agent reads the capture through the CLI, not the UI. Filtering happens on
the server, so the agent gets only the rows it asked for. Without `--limit`, a
page holds up to 5000 rows:

```console
$ sniper-cli --api http://127.0.0.1:18927 --output compact capture http list --status-range 4xx --page
{"filtered_total":1,"has_more":false,"hidden_connect_total":null,"items":[{"content_type":"application/json","duration_ms":3,"has_match_replace":false,"has_response":true,"has_user_note":false,"host":"127.0.0.1:18937","id":"81cb7fc3-41b6-47e8-b719-c596e8ae056a","is_websocket":false,"kind":"http","label":"#3 GET 127.0.0.1:18937/api/missing","method":"GET","note_count":0,"path":"/api/missing","request_bytes":0,"response_bytes":22,"scheme":"http","sequence":3,"started_at":"2026-09-17T01:52:05.535326Z","status":404}],"limit":5000,"offset":0,"total":4}
```

HTTPS rows look the same with `"scheme":"https"`, and each tunnel also leaves a
`CONNECT` row with `"scheme":"tcp"`, so expect them when you count rows.

Writes need explicit confirmation. Every operation the manifest marks
`side_effect: "write"` returns `CONFIRMATION_REQUIRED` unless you pass
`--dry-run` or `--yes`.
`--dry-run` prints the operation, the input it resolved and a preview of the
API call, which is what an agent should show a reviewer before `--yes`:

```console
$ sniper-cli --api http://127.0.0.1:18927 --output compact scope set-scope --pattern '127.0.0.1:18937' --dry-run
{"api":{"body":{"scope_patterns":null,"session_id":null},"method":"POST","path":"/api/runtime"},"command":"scope set-scope","dry_run":true,"input":{"clear":false,"file":null,"patterns":["127.0.0.1:18937"],"session_id":null,"stdin":false},"notes":["Use --yes to apply this side-effecting operation after reviewing the dry-run."],"operation":"scope.set","requires_confirmation":true,"side_effect":"write"}
```

Review `input`, not `api.body`: the previewed body shows the request's shape,
so `scope_patterns` reads `null` there while `input` carries the real patterns.

Instead of `--api`, the CLI can take `SNIPER_API_ADDR=http://127.0.0.1:18927`,
or `SNIPER_DATA_DIR=/tmp/sniper-doc-harness`, from which it finds the running
instance.

## Data boundaries

- **What the agent receives.** `capture http list` returns metadata only:
  method, host, path, status, sizes, timing, MIME type. `capture http get`
  returns the full record: every request and response header, values included,
  and a body preview. `Authorization` headers, cookies, session tokens and API
  keys come back in full, and anything the agent fetches goes wherever the
  model's context goes.
- **What stays on disk.** The session directory under `SNIPER_DATA_DIR` holds
  the captures and survives restarts. `session delete` or removing the data
  directory discards them.
- **What the operator is responsible for.** Setting scope so only intended hosts
  are captured, deciding whether an agent gets `list` or also `get`, keeping the
  data directory off shared storage, and reviewing `--dry-run` plans before
  `--yes`.

Same-machine clients are always trusted, and a loopback UI listener (the
default, and the right choice for a harness) has no authentication at all, so
anything that can run a process on the host can read the captures. Binding the
UI to a non-loopback address adds authentication only for clients on another
host: they need the one-time token Sniper prints at startup.

## You do not need Sniper if

- **You control both ends and can log.** Structured request logging in your
  client or server is simpler and needs no CA.
- **You want fixed responses, not observation.** A stub server or a recorded
  cassette gives determinism; Sniper records reality and does not replay it for
  you.
- **You only need the LLM calls.** Provider SDKs and gateways already log
  requests and responses with token accounting.
- **The traffic is not HTTP.** Sniper captures HTTP, HTTPS and WebSocket only.
- **Nothing drives traffic.** Passive capture records what a client sends.
  [Recon](../integrations/recon.md) can explicitly crawl an authorized target;
  it is a separate, consented operation, not something an agent should start
  automatically to fill gaps in captured traffic.

## Limits

- Use the headless `sniper` binary in a harness.
- `sniper-cli` talks to a running instance. It does not start one, and it exits
  with `API_UNAVAILABLE` when nothing is listening.
- Parallel harness instances need one data directory and one port pair each.
- Scope patterns are stored as a bare host: scheme, port and path are stripped,
  so `--pattern '127.0.0.1:18937'` is stored as `127.0.0.1`. Matching also
  ignores the port, case and a trailing DNS root dot.
- HTTPS capture requires the client to trust Sniper's root CA. A client that
  pins certificates fails instead of being captured.

For the CLI surface an agent should use, see the shipped skill template at
[`packaging/skills/claude/sniper-operator/SKILL.md`](../../packaging/skills/claude/sniper-operator/SKILL.md).
Before changing any of this, read [AGENTS.md](../../AGENTS.md).
