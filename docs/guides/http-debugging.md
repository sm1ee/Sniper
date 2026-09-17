# Debugging HTTP with Sniper

Sniper is an intercepting proxy: a client sends its traffic to Sniper instead of
straight to the server, Sniper forwards it and keeps a copy of every request and
response. That is enough to answer the questions an HTTP debugging session
usually starts with — what did the client actually send, what came back, and
what happens if one header is different.

The desktop UI and `sniper-cli` are two front ends over the same running
process, so either can drive the whole loop; both paths are shown below where
the choice matters. For what Sniper is and how to install it see
[README.md](../../README.md); for why it is built this way see
[architecture.md](../architecture.md).

## Starting it

The shipped app is `sniper-desktop`, a window that runs the proxy in-process;
`sniper` is the same server without the window. Both default to a proxy
listener on `127.0.0.1:8080` and differ on the UI and local API: `sniper`
defaults to `127.0.0.1:23001`, while `sniper-desktop` asks the OS for a free
port, so its UI port changes from run to run unless `SNIPER_UI_ADDR` pins it.

Sniper locks its data directory, so only one instance can use a given one.
The example below runs a throwaway instance on its own directory and ports, so
you can try any of this without disturbing an existing session:

```bash
SNIPER_DATA_DIR=/tmp/sniper-doc-http \
SNIPER_UI_ADDR=127.0.0.1:18901 \
SNIPER_PROXY_ADDR=127.0.0.1:18902 \
  ./target/release/sniper &

until curl -s -o /dev/null -m 1 http://127.0.0.1:18901/api/runtime; do sleep 0.2; done
```

```
INFO sniper: starting sniper proxy_addr=127.0.0.1:18902 ui_addr=127.0.0.1:18901 ... data_dir=/tmp/sniper-doc-http
INFO sniper::proxy: proxy listener ready proxy_addr=127.0.0.1:18902
INFO sniper::api: ui listener ready ui_addr=127.0.0.1:18901 advertised_ui_addr=127.0.0.1:18901
```

The UI is at `http://127.0.0.1:18901` in a browser, or in the native window if
you started `sniper-desktop`. The installed app proxies on `8080`; its UI port
is printed as **UI listener** under **Capture ▸ Settings ▸ Runtime details**.

Point traffic at a throwaway server rather than at someone else's site:

```bash
cat > /tmp/sniper-doc-http-upstream.py <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def respond(self):
        self.rfile.read(int(self.headers.get("content-length") or 0))
        body = json.dumps({"method": self.command, "path": self.path}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = respond

    def log_message(self, *args):
        pass

HTTPServer(("127.0.0.1", 18911), Upstream).serve_forever()
PY
python3 /tmp/sniper-doc-http-upstream.py &
```

## Pointing a client at it

A browser needs its proxy setting — system network settings on macOS and
Windows, or a browser-level proxy extension — set to HTTP proxy
`127.0.0.1:8080`. For a command-line client, `curl -x` is the same thing:

```bash
unset http_proxy HTTP_PROXY https_proxy HTTPS_PROXY all_proxy ALL_PROXY no_proxy NO_PROXY

curl -s -x http://127.0.0.1:18902 'http://127.0.0.1:18911/api/orders?status=open'
curl -s -x http://127.0.0.1:18902 -X POST http://127.0.0.1:18911/api/orders \
  -H 'content-type: application/json' -d '{"sku":"A-1"}'
```

```
{"method": "GET", "path": "/api/orders?status=open"}
{"method": "POST", "path": "/api/orders"}
```

The `unset` matters: a shell that exports `no_proxy` covering loopback makes
curl ignore `-x` and connect directly, and nothing is captured.

## Watching requests arrive

In the UI: the **Capture** tab, **HTTP** sub-tab. Rows appear as traffic flows.

From the CLI:

```bash
./target/release/sniper-cli --api http://127.0.0.1:18901 --output compact \
  capture http list --limit 10
```

That returns a JSON array. Summarised, the two requests above are:

```
#2 POST   http://127.0.0.1:18911/api/orders -> 200 (3 ms)
#1 GET    http://127.0.0.1:18911/api/orders?status=open -> 200 (8 ms)
```

`capture http list` also takes `--host`, `--method`, `--status`,
`--status-range`, `--mime`, `--since` and `--query`, plus `--page` for
pagination metadata.

## Reading one transaction

Clicking a row in the UI opens the detail panel. The CLI equivalent is:

```bash
./target/release/sniper-cli --api http://127.0.0.1:18901 --output compact \
  capture http get --id <transaction-id>
```

The result is one object with `method`, `scheme`, `host`, `path`, `status`,
`duration_ms`, and `request` and `response` objects each holding `headers`,
`body_preview`, `body_size`, `body_encoding`, `content_type` and
`preview_truncated`. Piped through a formatter, the POST above reports:

```
POST http://127.0.0.1:18911/api/orders -> 200 in 3 ms
request bytes  : 13 response bytes: 41
```

## Trusting the CA, and what that means

HTTPS is opaque to a proxy unless the proxy terminates TLS itself. Sniper
generates one root CA on first run, keeps it in the data directory, and mints a
leaf certificate per host as traffic arrives. A client only accepts those leaves
if it trusts that root.

The root is served by a built-in host that only exists inside the proxy:

```bash
curl -s -x http://127.0.0.1:18902 http://sniper/cert/root.pem -o /tmp/sniper-doc-root-ca.pem
openssl x509 -in /tmp/sniper-doc-root-ca.pem -noout -subject -issuer -dates
```

```
subject=O=Sniper, CN=Sniper Root CA
issuer=O=Sniper, CN=Sniper Root CA
notBefore=Sep 17 00:00:00 2026 GMT
notAfter=Sep 14 00:00:00 2036 GMT
```

Open `http://sniper` (or `https://sniper`) in a proxied browser for the same
file as a page, with **Download PEM** and **Download DER** buttons; DER is also
at `http://sniper/cert/root.der` and on the local API at
`/api/certificates/root.der`. In the desktop UI, **Capture ▸ Settings ▸ Root
CA** reveals the folder the certificate files sit in rather than downloading
one.

Trusting it is a real decision: a machine that trusts this root accepts a
certificate for *any* host from whoever holds the matching private key, which
sits unencrypted in your data directory. Trust it on the machine you test with,
and remove it when you are done. The difference is visible once the throwaway
upstream speaks TLS:

```bash
pkill -f /tmp/sniper-doc-http-upstream.py
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout /tmp/sniper-doc-upstream.key -out /tmp/sniper-doc-upstream.crt \
  -subj "/CN=localhost" -addext "subjectAltName=IP:127.0.0.1"
```

Serve it with the same handler wrapped in TLS:

```bash
cat > /tmp/sniper-doc-https-upstream.py <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
import json, ssl

class Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = json.dumps({"method": "GET", "path": self.path, "tls": True}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/tmp/sniper-doc-upstream.crt", "/tmp/sniper-doc-upstream.key")
srv = HTTPServer(("127.0.0.1", 18911), Upstream)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
PY
python3 /tmp/sniper-doc-https-upstream.py &
```

Then compare a client that does not trust the root with one that does:

```bash
curl -s -S -x http://127.0.0.1:18902 https://127.0.0.1:18911/api/orders
curl -s -x http://127.0.0.1:18902 --cacert /tmp/sniper-doc-root-ca.pem \
  https://127.0.0.1:18911/api/orders
```

```
curl: (60) SSL certificate problem: self signed certificate in certificate chain
... curl's certificate help text ...
{"method": "GET", "path": "/api/orders", "tls": true}
```

Once decrypted, HTTPS requests appear in history like any other, alongside the
`CONNECT` row for the tunnel:

```
#8 GET     https://127.0.0.1:18911/api/orders -> 200
#7 CONNECT tcp://127.0.0.1:18911 -> 200
```

## Filtering by scope

Scope is the list of hosts you care about. In the UI it is the **Scope** tab,
an include list and an exclude list; the **In scope** pill above the HTTP
history filters the table to it. From the CLI:

```bash
./target/release/sniper-cli --api http://127.0.0.1:18901 --output compact \
  scope set-scope --pattern '127.0.0.1' --dry-run
./target/release/sniper-cli --api http://127.0.0.1:18901 --output compact \
  scope set-scope --pattern '127.0.0.1' --yes
./target/release/sniper-cli --api http://127.0.0.1:18901 --output compact scope get-scope
```

```
{"api":{"body":{"scope_patterns":null,"session_id":null},"method":"POST","path":"/api/runtime"},"command":"scope set-scope","dry_run":true,"input":{"clear":false,"file":null,"patterns":["127.0.0.1"],"session_id":null,"stdin":false},"notes":["Use --yes to apply this side-effecting operation after reviewing the dry-run."],"operation":"scope.set","requires_confirmation":true,"side_effect":"write"}
{"scope_patterns":["127.0.0.1"],"session_id":"7111fb35-94c4-4a40-95dc-3137eeec1bd6"}
{"scope_patterns":["127.0.0.1"]}
```

That first line is the dry run. Every write operation takes `--dry-run` first:
it prints the API call it would make, marks itself `"dry_run":true`, and
changes nothing. `--yes` applies it.

Scope matches hosts only. `*.example.com` covers the domain and everything under
it, `log-*.example.com` is a glob, `api.example.com` is exact, and a port or
path in a pattern is discarded — `127.0.0.1:18911/api/*` is stored as
`127.0.0.1`. The scoped view of history is a UI toggle and an API parameter
(`in_scope_only`); `capture http list` has no equivalent flag, so filter it with
`--host` instead.

## Replaying a request with a change

In the UI: right-click a history row, **Send to Replay** (⌘R), edit the raw
request in the Replay tab, press **Send**. The CLI does the same three steps:

```bash
./target/release/sniper-cli --api http://127.0.0.1:18901 --output compact \
  replay open --transaction-id <transaction-id> --yes

printf 'GET /api/orders?status=closed HTTP/1.1\r\nhost: 127.0.0.1:18911\r\naccept: */*\r\n\r\n' \
  > /tmp/sniper-doc-http-replay.txt
./target/release/sniper-cli --api http://127.0.0.1:18901 --output compact \
  replay update --tab-id <tab-id> --request-file /tmp/sniper-doc-http-replay.txt --yes

./target/release/sniper-cli --api http://127.0.0.1:18901 --output compact \
  replay send --tab-id <tab-id> --yes
```

`replay open` returns the tab, including its `id` and the connection target it
took from the capture:

```
tab 36fca91d-7d2c-4e07-a9e3-b837340f3b1a
target http://127.0.0.1:18911
GET /api/orders?status=open HTTP/1.1
```

A tab opened from the CLI is the same tab the UI shows. The send lands in
history as a new record:

```
#3 GET    http://127.0.0.1:18911/api/orders?status=closed -> 200 (0 ms)
#2 POST   http://127.0.0.1:18911/api/orders -> 200 (3 ms)
#1 GET    http://127.0.0.1:18911/api/orders?status=open -> 200 (8 ms)
```

`--host`, `--port` and `--scheme` on `replay open` and `replay update` change
where the request is sent without touching the `Host:` header in the request
text. They are refused when the captured request's own host is an IP literal,
which is the case everywhere in this guide:

```
invalid replay target: Replay target override is not supported when the request host is an IP address
```

An override therefore needs a capture whose `Host:` header is a name.

## Where sessions live on disk

A session is a workspace: its own captured traffic, scope, replay tabs and
settings. Sessions live under the data directory — `~/.sniper` by default, or
whatever `SNIPER_DATA_DIR` names — and `session list` reports the path:

```bash
./target/release/sniper-cli --api http://127.0.0.1:18901 --output compact session list
```

That returns a JSON array. Summarised, the one session is:

```
Default session  request_count=8  active=true
  storage_path /tmp/sniper-doc-http/sessions/7111fb35-94c4-4a40-95dc-3137eeec1bd6
```

The data directory holds `certificates/`, `sessions/`, `runtime-state.json`,
`startup-settings.json` and `ui-settings.json`. Each session directory holds
`snapshot.json`, `state.json`, `workspace.json`, `transactions.ndjson`,
`transactions.meta.ndjson` and two `.journal` files. Bodies are read back from
`transactions.ndjson` by byte offset, so these files are not safe to hand-edit
while Sniper is running.

A new session starts empty and becomes the active one immediately:

```bash
./target/release/sniper-cli --api http://127.0.0.1:18901 --output compact \
  session create --name 'orders-api' --yes
./target/release/sniper-cli --api http://127.0.0.1:18901 --output compact session switch --id <id> --yes
```

## What the CLI hands back

Captures are stored as they were sent. Cookies, `Authorization` headers and
request bodies are all in what `capture http get` returns, so anything you pipe
it into — a log file, a pasted snippet, a coding agent reading the output —
receives them. Nothing redacts them; deciding what may leave the machine is
the operator's job.

The local API is unauthenticated on its default loopback bind, which means any
process running as you can read the capture. `SNIPER_UI_ADDR` can bind a
non-loopback address instead; clients from another host then need the one-time
bootstrap token Sniper prints at startup. `sniper-cli` without `--api` connects
to whichever instance it discovers from `runtime-state.json` in the default data
directory, which may not be the one you just started — pass `--api` explicitly
when more than one is running.

## What this does not do

- Nothing is captured until a client is pointed at the proxy. Sniper does not
  hook a browser or the system on its own.
- HTTPS is only readable by clients that trust the Sniper root. Certificate-
  pinned apps reject it by design; those hosts have to go in **SSL passthrough
  hosts** under **Capture ▸ Settings**, and their traffic then tunnels through
  unread.
- The MITM path speaks HTTP/1.1 to the client side (`src/proxy.rs` serves both
  the plain and the terminated-TLS connection with `http1()`), so it is not the
  tool for reproducing an HTTP/2-specific problem.
- Scope is host-based. There is no path-level scope.
- One instance per data directory. A second `sniper` against the same one exits
  with `another Sniper runtime is already using data dir ...` rather than
  sharing it.
- `sniper-cli` covers the operations in `sniper-cli manifest`. The in-scope
  history toggle, the site map and the Tools tab are not among them.
- Findings come from a passive scan of traffic that already flowed. Nothing
  crawls or probes a target on its own.

When you are done with the throwaway instance, stop it and delete its directory:
its capture, its root CA and its session files are all under `SNIPER_DATA_DIR`.
Other commands do write outside it — `sniper-cli skills install` writes into the
Claude and Codex skill directories, and `SNIPER_INSTALL_CLI_PATH=1` edits your
shell profile.
