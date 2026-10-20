# Sniper in an agent harness

This page is for people building or running an agent harness who are deciding
whether Sniper belongs in it. It covers where Sniper sits, what goes in and what
comes out, what the agent can actually see, and when you should leave it out.

## What Sniper is not

Two assumptions come up often enough to be worth ruling out first.

**Sniper is not an LLM API gateway.** It does not hold provider keys, route
between models, retry, meter tokens or enforce spend. If you put Sniper on the
path between your harness and a model provider you get captured HTTP records of
those calls and nothing else — no routing, no budget, no fallback. That is
occasionally what you want while debugging a client, but it is not a gateway.

**Sniper is not a reverse proxy or a hosting platform.** There is no virtual
host config, no upstream pool, no TLS termination for a service you own. Sniper
is a *forward* proxy: a client is configured to send its traffic through it, and
Sniper forwards that traffic on to whatever host the client asked for. Nothing
reaches Sniper because of DNS or a load balancer.

What it is: a local intercepting proxy and a traffic-inspection layer. It sits
beside the thing under test, records what crossed the wire, and exposes those
records to a human and to an agent through the same API.

## Three ways in, one core

[`web/architecture.svg`](../../web/architecture.svg), shown in the
[README](../../README.md), is the map. Three paths reach one core:

- **Proxied traffic.** A browser, a mobile app or a service is pointed at the
  proxy listener. HTTPS is terminated with Sniper's own CA and forwarded on, so
  the core gets a copy of the plaintext.
- **The desktop app** (`sniper-desktop`). A native window hosting the web UI,
  running the core in the same process. This is the operator's view.
- **`sniper-cli`.** A JSON-first CLI that talks to a *running* instance over its
  loopback HTTP API. This is the agent's view.

The desktop app and the CLI are two clients of the same local API, so they see
the same records at the same time. Neither one owns the data; the core writes it
to a session directory on disk. See [docs/architecture.md](../architecture.md)
for why the boundaries fall where they do.

## A worked example

Run the harness instance isolated. Sniper locks its data directory and allows
one runtime per directory, so a scratch instance that does not set
`SNIPER_DATA_DIR` either refuses to start — `another Sniper runtime is already
using data dir ...` — or, if nothing else is running, attaches to the operator's
real session.

```bash
SNIPER_DATA_DIR=/tmp/sniper-doc-harness \
SNIPER_UI_ADDR=127.0.0.1:18927 \
SNIPER_PROXY_ADDR=127.0.0.1:18928 \
  ./target/release/sniper &

# poll rather than sleeping; startup is not instant
until curl -s -m 1 -o /dev/null http://127.0.0.1:18927/api/settings; do :; done
```

That loop has no timeout: it spins forever if the server never comes up. Bound
it if it runs unattended.

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

`--noproxy ""` is there because a `no_proxy` entry covering loopback in the
environment will otherwise make curl ignore `-x` and connect directly, which
captures nothing. Without `no_proxy` set the flag is unnecessary.

The agent then reads the capture. It does not scrape the UI; it calls the CLI:

```console
$ sniper-cli --api http://127.0.0.1:18927 --output compact capture http list --limit 50 --page
{"filtered_total":4,"has_more":false,"hidden_connect_total":null,"items":[...],"limit":50,"offset":0,"total":4}
```

The `items` array is elided above. `limit` echoes what was asked for; it reads
`5000`, the default, when `--limit` is omitted.

Filtering happens server side, so the agent pays for only the rows it asked for.
This output is unedited:

```console
$ sniper-cli --api http://127.0.0.1:18927 --output compact capture http list --status-range 4xx --page
{"filtered_total":1,"has_more":false,"hidden_connect_total":null,"items":[{"content_type":"application/json","duration_ms":3,"has_match_replace":false,"has_response":true,"has_user_note":false,"host":"127.0.0.1:18937","id":"81cb7fc3-41b6-47e8-b719-c596e8ae056a","is_websocket":false,"kind":"http","label":"#3 GET 127.0.0.1:18937/api/missing","method":"GET","note_count":0,"path":"/api/missing","request_bytes":0,"response_bytes":22,"scheme":"http","sequence":3,"started_at":"2026-09-17T01:52:05.535326Z","status":404}],"limit":5000,"offset":0,"total":4}
```

Reduced to one line per row — by a formatter of your own, not by a Sniper
command — that is the whole session:

```console
201 POST 127.0.0.1:18937/api/orders 4ms
404 GET 127.0.0.1:18937/api/missing 3ms
200 GET 127.0.0.1:18937/api/profile 3ms
200 GET 127.0.0.1:18937/api/orders 5ms
```

HTTPS rows look the same with `"scheme":"https"`, and each tunnel also leaves a
`CONNECT` row with `"scheme":"tcp"` in the same list. An agent counting rows
should expect them.

Meanwhile `http://127.0.0.1:18927/` serves the UI to a human, backed by the same
records — `GET /` returns `200 text/html`, from the same listener the CLI reads
through. There is no second copy and no export step between the two views.

Writes fail closed. Every operation the manifest marks `side_effect: "write"` —
32 of the 57 operations in this build, a count that will drift — refuses to run
without `--dry-run` or `--yes`:

```console
$ sniper-cli --api http://127.0.0.1:18927 --output compact scope set-scope --pattern '127.0.0.1'
{"error":{"code":"CONFIRMATION_REQUIRED","details":{"operation":"scope.set"},"hint":"Run the same command with --dry-run to inspect the plan, then --yes to apply.","message":"operation `scope.set` requires --dry-run or --yes","retryable":false},"meta":{},"ok":false,"operation":"scope.set","schema_version":"2026-06-22","warnings":[]}
```

`--dry-run` prints the operation, the input it resolved, and a preview of the
API call — which is what you want an agent to show a reviewer before `--yes`:

```console
$ sniper-cli --api http://127.0.0.1:18927 --output compact scope set-scope --pattern '127.0.0.1:18937' --dry-run
{"api":{"body":{"scope_patterns":null,"session_id":null},"method":"POST","path":"/api/runtime"},"command":"scope set-scope","dry_run":true,"input":{"clear":false,"file":null,"patterns":["127.0.0.1:18937"],"session_id":null,"stdin":false},"notes":["Use --yes to apply this side-effecting operation after reviewing the dry-run."],"operation":"scope.set","requires_confirmation":true,"side_effect":"write"}
```

Review `input`, not `api.body`. The previewed body is the request's shape rather
than the exact payload: `scope set-scope` reports `scope_patterns` as `null`
there and carries the real patterns in `input`.

Connection details can come from the environment instead of a flag: either
`SNIPER_API_ADDR=http://127.0.0.1:18927`, or `SNIPER_DATA_DIR=/tmp/sniper-doc-harness`,
from which the CLI discovers the running instance.

## Data boundaries

Be precise about this, because the honest answer is not reassuring by default.

**What the agent receives.** `capture http list` returns metadata only: method,
host, path, status, sizes, timing, MIME type. `capture http get` returns the
full record — every request and response header and a body preview. In the test
above the request carried an `authorization` header, and `capture http get`
returned it in full, value included. Cookies, session tokens and API keys are
preserved the same way. Anything the agent fetches lands in the model's context
and goes wherever that context goes.

**What stays on disk.** The session directory under `SNIPER_DATA_DIR` holds the
captures, with bodies read back by byte offset. It survives restarts: after
killing and relaunching the server above, all four records were still listed,
bodies included, and the scope pattern was still set. `session delete` or
removing the data directory is what discards them.

**What the operator is responsible for.** Setting scope so only intended hosts
are captured; deciding whether an agent gets `list` or also `get`; keeping the
data directory off shared storage; reviewing `--dry-run` plans before `--yes`.
A loopback UI listener — the default, and what a harness should use — has no
authentication at all, and same-machine clients stay trusted even when the
listener is bound elsewhere. Anything that can run a process on the host can
read the captures. Binding the UI to a non-loopback address is the one case that
authenticates, and only for clients on another host: they must present a
one-time bootstrap token Sniper prints at startup.

## You do not need Sniper if

- **You control both ends and can log.** If the client is yours, structured
  request logging in the client or the server is simpler and does not need a CA.
- **You want fixed responses, not observation.** A stub server or a recorded
  cassette gives determinism; Sniper records reality and does not replay it for
  you.
- **You only need the LLM calls.** Provider SDKs and gateways already expose
  request and response logs with token accounting.
- **The traffic is not HTTP.** Sniper captures HTTP, HTTPS and WebSocket. It
  does not parse other protocols.
- **Nothing is driving traffic.** Sniper captures what a client sends. It does
  not crawl or generate load.

## Limits worth knowing before you commit

- The desktop app ships for macOS and Windows. The headless `sniper` binary is
  the one to use in a harness; Linux validation is still pending.
- `sniper-cli` talks to a running instance. It does not start one, and it exits
  with `API_UNAVAILABLE` when nothing is listening.
- One runtime per data directory. Parallel harness instances need one data
  directory and one port pair each.
- Scope patterns are normalised to a bare host when they are stored: scheme,
  port and path are stripped, so `--pattern '127.0.0.1:18937'` is stored as
  `127.0.0.1`. Matching ignores the port too, along with case and a trailing
  DNS root dot.
- HTTPS capture requires the client to trust Sniper's root CA. Anything doing
  certificate pinning will fail rather than be captured.

For the CLI surface an agent should use, see the shipped skill template at
[`packaging/skills/claude/sniper-operator/SKILL.md`](../../packaging/skills/claude/sniper-operator/SKILL.md).
Before changing any of this, read [AGENTS.md](../../AGENTS.md).
