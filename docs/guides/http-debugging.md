# Debugging HTTP with Sniper

Sniper is an intercepting proxy. This guide shows how to see what a client sent
through it, what came back, and what happens when you change a request. The
desktop UI and `sniper-cli` drive the same running process.

For installation see [README.md](../../README.md); for design see
[architecture.md](../architecture.md).

## Starting it

`sniper-desktop` is the app, a window that runs the proxy in-process. `sniper` is
the same server without the window. Both take proxy traffic on `127.0.0.1:8080`.
`sniper` serves the UI and local API on `127.0.0.1:23001`. `sniper-desktop` takes
a free port on each run unless `SNIPER_UI_ADDR` sets one, and shows it as
**UI listener** under **Capture ▸ Settings ▸ Runtime details**.

Sniper locks its data directory, so a second instance on it exits with
`another Sniper runtime is already using data dir ...`. Try the steps below on a
throwaway instance with its own directory and ports, not on your own session.
Its UI is at `http://127.0.0.1:18901`.

```bash
SNIPER_DATA_DIR=/tmp/sniper-doc-http \
SNIPER_UI_ADDR=127.0.0.1:18901 \
SNIPER_PROXY_ADDR=127.0.0.1:18902 \
  ./target/release/sniper &

until curl -s -o /dev/null -m 1 http://127.0.0.1:18901/api/runtime; do sleep 0.2; done
```

Send test traffic to a throwaway server, not to someone else's site:

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

## Opening the UI from another machine

A UI address other than loopback, such as `192.168.1.10`, or `0.0.0.0` for every
interface, turns on authentication:

```bash
SNIPER_DATA_DIR=/tmp/sniper-headless \
SNIPER_UI_ADDR=192.168.1.10:23001 \
  cargo run --bin sniper
```

Clients on other hosts open the URL with the one-time bootstrap token that Sniper
prints at startup. The UI is plain HTTP, so across an untrusted network use an SSH
tunnel or an authenticated TLS reverse proxy.

## Pointing a client at it

Set the browser's HTTP proxy to `127.0.0.1:8080` in the system network settings
on macOS and Windows, or with a browser proxy extension. For curl, use `-x`:

```bash
unset http_proxy HTTP_PROXY https_proxy HTTPS_PROXY all_proxy ALL_PROXY no_proxy NO_PROXY

curl -s -x http://127.0.0.1:18902 'http://127.0.0.1:18911/api/orders?status=open'
curl -s -x http://127.0.0.1:18902 -X POST http://127.0.0.1:18911/api/orders \
  -H 'content-type: application/json' -d '{"sku":"A-1"}'
```

The `unset` matters: if `no_proxy` covers loopback, curl ignores `-x` and Sniper
captures nothing.

### Or open a browser that is already wired

Sniper can also open a browser with the proxy and certificate set up: click
**Open browser** in the top bar or in an empty history. Its arrow lists every
browser, marks the default, and has **Make default**. Two checkboxes apply to
that opening only: **Let an agent drive it** (`--agent`) and
**Throwaway profile (discard logins on quit)** (`--fresh`).

From the CLI:

```bash
./target/release/sniper-cli --api http://127.0.0.1:18901 --output compact \
  capture browser list
./target/release/sniper-cli --api http://127.0.0.1:18901 --output compact \
  capture browser open --browser chrome --agent --yes
```

`capture browser list` shows every browser Sniper knows on this platform,
installed or not. `"default": true` marks the one that opens when you name none,
and `"preferred": true` the saved choice; each is left out when false. A missing
browser has `"installed": false` and an `install_url` to the vendor's download
page (the menu's **Install** link). A missing requirement, such as ego's command
or agent skill, has a `hint` that says where to look. Sniper never installs a
browser or a skill.

`capture browser prefer --browser <name|auto> --yes` saves the default per user,
and `auto` (**Use auto** in the menu) clears it. `--browser` takes `chrome`,
`edge`, `brave`, `chromium`, `ego`, `aside` or `browseros-neo`. With nothing
saved, Sniper opens the first installed of ego, Aside, BrowserOS neo, Chrome,
Edge, Brave and Chromium. If the saved browser was uninstalled, it falls back to
that order and says so in `warnings`.

| Browser | Platforms | An agent drives it through |
|---|---|---|
| Chrome, Edge, Brave, Chromium | macOS, Windows, Linux | the DevTools protocol (Playwright, chrome-devtools-mcp) |
| [ego](https://lite.ego.app/) | macOS | ego's own CLI and agent skill |
| [Aside](https://aside.com/) | macOS, Windows | Aside's CLI REPL |
| [BrowserOS neo](https://docs.browseros.com/neo/install) | macOS, Windows | its MCP server |

`capture browser open` starts a process, so it needs `--yes`, or `--dry-run` to
see the request first. The result says how to reach the browser:

```json
{"browser":"chrome","driver":"cdp","control":{"driver":"cdp","endpoint":"http://127.0.0.1:53469"},
 "fresh":false,"pid":39189,"profile_dir":"…/browser-profiles/chrome",
 "proxy":"127.0.0.1:18902","url":"about:blank"}
```

The browser gets:

- The proxy and Sniper's root CA for that browser process, with nothing added to
  the operating system or any certificate store.
- Loopback through the proxy, so a local app appears in the history. Chromium
  sends `localhost` and `127.0.0.1` direct by default.
- Its own profile, apart from your everyday one. `--fresh` uses a throwaway
  profile that is deleted when the browser quits. On macOS, closing the last
  window does not quit it.
- A DevTools port, only with `--agent`. The port lets any local process drive a
  browser that holds your logins. For BrowserOS neo, `--agent` turns on its own
  server instead. ego and Aside have no port, and their `control` is always
  returned.

#### Keep logins between launches

Each browser keeps one profile at `<SNIPER_DATA_DIR>/browser-profiles/<browser>`.
Sign in once in the window Sniper opened. Later launches reuse that login if you
keep the same data directory and do not use `--fresh`. Sniper does not copy
logins from another profile. If a site keeps asking you to sign in, compare the
profile path in `chrome://version` between launches.

For a one-off clean test, use `--fresh`; the saved profile stays as it is. To
clear saved logins, clear site data in the browser Sniper opened; Sniper has no
reset of its own. Do not clear site data or Aside's password vault to
troubleshoot a repeated sign-in prompt.

Aside and ego have accounts and first-run screens of their own:

- Sniper does not skip Aside's account screen. Aside supports local profiles
  without an account ([changelog](https://docs.aside.com/changelog/native),
  v1.0.728.1), but [its own AI models](https://docs.aside.com/help/ai) need one.
  If onboarding comes back after a restart, check the version: v1.0.922.1 fixed
  that. The `aside` CLI signs in separately (`aside account status`), and Sniper
  does not touch its credentials.
- Finish ego's first-run onboarding before you use the agent workflow. It
  registers the `ego-browser` command
  ([quick start](https://lite.ego.app/document/en/docs/quick-start)). Sniper does
  not create ego Spaces. An agent that creates one with ego's
  [native API](https://github.com/citrolabs/ego-lite/blob/main/docs/native-bindings-api.md)
  should address it by numeric ID, since names can repeat. A completed Space
  belongs to the user; do not claim it automatically.

#### Two ways to drive it

The browser decides the `driver`, and the result's `control` says how to reach it:

| | `chrome`, `edge`, `brave`, `chromium` | `ego` | `aside` | `browseros-neo` |
|---|---|---|---|---|
| `driver` | `cdp` | `ego-cli` | `aside-cli` | `browseros-mcp` |
| `control` | `{"driver":"cdp","endpoint":"http://127.0.0.1:<port>"}` | `{"driver":"ego-cli","server_name":"…","command":"ego-browser --ego-server-name=… nodejs -e '<script>'"}` | `{"driver":"aside-cli","command":"aside repl '<code>'"}` | `{"driver":"browseros-mcp","endpoint":"http://127.0.0.1:<port>/mcp"}`, with `--agent` |
| Agent actions | a CDP client you bring | built in | built in, through its REPL | built in, through MCP |
| Snapshot with `@ref`s, handoff to the user, visible cursor | no | yes | not documented | not documented |
| Platforms | macOS, Windows, Linux | macOS | macOS, Windows | macOS, Windows |
| Needs on this machine | nothing | ego lite, its command, and its agent skill | Aside and its `aside` command | BrowserOS neo |

An agent that opens a browser without naming one should read `driver` and
`control` from the result, not assume a DevTools endpoint.

For `cdp`, connect any CDP client to `control.endpoint`, such as Playwright's
`connectOverCDP` or chrome-devtools-mcp with `--browserUrl`. Sniper bundles none.

For `ego-cli`, use ego's own agent skill, and pass the server name from `control`
on every `ego-browser` command:

```bash
ego-browser --ego-server-name=sniper-18902-3f2a9c1d nodejs -e '
const task = await taskSpace("check the menu");
const page = task.page("p1");
await page.goto("https://example.com/", { timeout: 40000 });
console.log(String(await page.snapshot()));
' 2>&1
```

- Without the server name you drive your everyday ego, with your own profile and
  no proxy, so nothing is captured. ego's skill does not mention this flag.
- `console.log` inside `ego-browser nodejs` writes to stderr and leaves stdout
  empty. Read it with `2>&1`; a readiness check with `2>/dev/null` never
  succeeds.
- Click as a person does: take a snapshot, pick an element by its `@ref` or a
  `loc=` locator, `page.click` it, then `waitForURL` or take a new snapshot.
  `page.goto` skips what the site's script does on a click and sends a different
  request.

For `aside-cli`, drive Aside through `aside repl '<code>'` with deterministic
steps, not through its own assistant (`aside "<task>"`, `aside exec`). The
`aside` command drives whichever Aside is running, so quit any other Aside first
or nothing is captured. Sniper sends Aside's shared daemon (`127.0.0.1:21420`)
direct, which keeps its account and password-manager traffic out of the history.
On a profile's first launch Aside does not show the requested page; opening
again shows it.

For `browseros-mcp`, open with `--agent` and connect an MCP client (Streamable
HTTP) to `control.endpoint`. Without `--agent` the server stays off. With it, the
browser also listens on every network interface (ports 9010 and 9011 by
default). The browser always opens a DevTools port on loopback (9110 by default),
which Sniper cannot turn off. Calls from its pages to the server stay out of the
history. A `--fresh` profile may return a warning instead of `control`: its
bundled server cannot open the shared `~/.browserclaw` database once a newer
server has updated it. Use the persistent profile, which keeps the newer server.

#### Opening again, limits and warnings

- Opening again while a browser runs on the same profile opens another window in
  it (`"reused": true`).
- If the running browser was started for a different proxy, or without the
  DevTools port you now ask for, the open is refused and says which. Quit the
  browser fully and open it again (with `--agent` if you need the port), or open
  a separate one with `--agent --fresh`.
- Different browsers run side by side. Up to eight `--fresh` browsers can be open
  at once.
- A DevTools port is refused while the proxy listens beyond loopback, because
  such a proxy relays requests to local ports. The check runs only when a browser
  opens, so quit any browser with a DevTools port before you rebind the proxy
  beyond loopback.
- A browser that fails to start or exits at once is reported in `warnings` (a
  toast in the UI) with the end of its output. A persistent profile keeps the
  full output in `sniper-launch.log`.
- A new browser also talks to its vendor (updates, variations, crash reporting),
  mostly on a new profile's first launch. Filter the history to your target's
  host to hide that traffic.

## Sending traffic through another proxy

In **Capture → Settings**, turn on **Proxy chain** and enter the upstream proxy,
such as `http://127.0.0.1:8081` or `socks5h://127.0.0.1:1080`, with an optional
username and password. Captured traffic, Replay, Fuzzer and Sequence then go
through it. If it fails, requests fail; Sniper does not fall back to a direct
connection. Hosts under **Connect directly to** (scope patterns such as
`*.example.com`) skip it.

Settings are per session, and the password is stored in the session files on
disk. `sniper-cli capture proxy` reads the settings, and
`sniper-cli capture proxy --stdin --yes` replaces them from JSON with `enabled`,
`url`, `username`, `password` and an optional `bypass_hosts` array.

## Watching requests arrive

In the UI, the **Capture** tab's **HTTP** sub-tab shows recorded traffic that
matches the current filters. The capture control reports:

- **Capturing**: HTTP capture is enabled.
- **Paused**: HTTP capture is disabled; traffic still passes through.
- **Capture unconfirmed**: Sniper could not confirm the outcome of an explicit
  Capture change, so recording may be on or off. The tooltip shows the last
  confirmed state and what another click will request. Sniper does not retry the
  change automatically.

From the CLI:

```bash
./target/release/sniper-cli --api http://127.0.0.1:18901 --output compact \
  capture http list --limit 10
```

The result is a JSON array. In short, the two requests above are:

```
#2 POST   http://127.0.0.1:18911/api/orders -> 200 (3 ms)
#1 GET    http://127.0.0.1:18911/api/orders?status=open -> 200 (8 ms)
```

`capture http list` also takes `--host`, `--method`, `--status`,
`--status-range`, `--mime`, `--since` and `--query`, plus `--page` for
pagination metadata. `--query` matches request metadata only: method, host,
path, status and MIME type. To find a value in headers or bodies, search:

```bash
./target/release/sniper-cli --api http://127.0.0.1:18901 --output compact \
  capture http search --value A-1 --side request-body
```

Matches are grouped by transaction, each with its `side`, `offset` and
`context`. An empty result means the value is absent only when `complete` is
`true`. Otherwise `stopped_by` says whether `--max-matches` or `--byte-budget`
ran out.

## Reading one transaction

Click a row in the UI to open the detail panel. From the CLI:

```bash
./target/release/sniper-cli --api http://127.0.0.1:18901 --output compact \
  capture http get --id <transaction-id>
```

The result has `method`, `scheme`, `host`, `path`, `status`, `duration_ms`, and
`request` and `response` objects. Each holds `headers`, `body_preview`,
`body_size`, `body_encoding`, `content_type` and `preview_truncated`.

A gzip body with several members is decoded as a whole. If a member is damaged
or the result passes the 16 MiB decoding limit, Sniper keeps the encoded bytes
rather than a partial result. `body_size` stays the wire size; a decoded body
adds `decoded_body_size` and `content_decoded`. Captures made before this change
keep their previews; capture the traffic again to see the rest.

## Rendering a response

The **Render** tab in HTTP history, Replay and the Fuzzer's results draws HTML
and images in a sandboxed frame, with scripts, forms, links and network access
off. **Settings ▸ Display ▸ Render ▸ Load images, styles and fonts** lets it fetch
the images, stylesheets and fonts a page names, through Sniper and the proxy
chain. Those requests go to the target and any other host the page names, and
HTTP history does not record them. Scripts never run.

## Findings in the history

With **Findings** on in HTTP (or **Mark in HTTP** in Findings), requests with a
finding get a severity badge in Notes, a row tint (Settings ▸ Display) that the
colour filter can gather, and the highlighted evidence. A note or colour tag you
set takes precedence.

## Trusting the CA, and what that means

Sniper reads HTTPS by terminating TLS. It creates one root CA on first run,
keeps it in the data directory, and signs a certificate for each host as traffic
arrives. Get the root from the proxy's built-in host, `sniper`:

```bash
curl -s -x http://127.0.0.1:18902 http://sniper/cert/root.pem -o /tmp/sniper-doc-root-ca.pem
openssl x509 -in /tmp/sniper-doc-root-ca.pem -noout -subject -issuer -dates
```

In a proxied browser, `http://sniper` (or `https://sniper`) has **Download PEM**
and **Download DER** buttons. DER is also at `http://sniper/cert/root.der` and at
`/api/certificates/root.der` on the local API. In the desktop UI,
**Capture ▸ Settings ▸ Root CA** opens the folder that holds the files.

A machine that trusts the root accepts a certificate for *any* host from whoever
holds the private key, and the key sits unencrypted in your data directory.
Trust it on the machine you test with, and remove it when you are done.

A client that does not trust the root fails; curl reports
`SSL certificate problem: self signed certificate in certificate chain`.
`--cacert /tmp/sniper-doc-root-ca.pem` trusts the root for one curl command.
Decrypted HTTPS requests appear in the history like any other, next to a
`CONNECT` row for the tunnel.

## Filtering by scope

In the UI, the **Scope** tab shows an include list and an exclude list beside the
captured hosts and paths. The **In scope** pill above the HTTP history filters
the table to scope. From the CLI:

```bash
./target/release/sniper-cli --api http://127.0.0.1:18901 --output compact \
  scope set-scope --pattern '127.0.0.1' --dry-run
./target/release/sniper-cli --api http://127.0.0.1:18901 --output compact \
  scope set-scope --pattern '127.0.0.1' --yes
./target/release/sniper-cli --api http://127.0.0.1:18901 --output compact scope get-scope
```

Every write command takes `--dry-run`: it prints the API call it would make,
marks the output `"dry_run":true`, and changes nothing. `--yes` applies it.

Scope matches hosts only:

- `*.example.com` matches the domain and everything under it.
- `log-*.example.com` is a glob.
- `api.example.com` is exact.
- A port or path in a pattern is dropped: `127.0.0.1:18911/api/*` is stored as
  `127.0.0.1`.

The API takes the scoped view as `in_scope_only`, but `capture http list` has no
such flag; filter with `--host` instead.

## Replaying a request with a change

In the UI, right-click a history row, choose **Send to Replay** (⌘R), edit the raw
request in the Replay tab, and press **Send**. The CLI takes the same three steps:

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

`replay open` returns the tab with its `id` and the target it took from the
capture, and the UI shows the same tab. Each send adds a new row to the history.

`--host`, `--port` and `--scheme` on `replay open` and `replay update` change
where the request goes without touching its `Host:` header. If the captured host
is an IP address, as everywhere in this guide, they are refused with
`Replay target override is not supported when the request host is an IP address`.

A request read with `--request-file` or `--stdin` has no scheme of its own.
`--scheme`, or the scheme of a URL given to `--host`, sets it and is not an
override. Such a request can go to `127.0.0.1` over plain HTTP if `--host` and
`--port` match its `Host:` header.

`--label` on `replay open` and `replay update` names the tab, so an agent sending
several requests can mark what each one tests:
`replay update --tab-id <tab-id> --label "closed orders" --yes`. `--label ""`
clears the name. A label-only update also works on a saved WebSocket tab and
sends no request. Labels collapse whitespace and are limited to 80 characters.
`--label` with request or target options needs an HTTP tab.

## Where sessions live on disk

A session holds its own captured traffic, scope, replay tabs and settings.
Sessions live under the data directory: `~/.sniper` by default, or whatever
`SNIPER_DATA_DIR` names. `session list` shows each session's `storage_path`. A
new session starts empty and becomes the active one at once.

```bash
./target/release/sniper-cli --api http://127.0.0.1:18901 --output compact session list
./target/release/sniper-cli --api http://127.0.0.1:18901 --output compact \
  session create --name 'orders-api' --yes
./target/release/sniper-cli --api http://127.0.0.1:18901 --output compact session switch --id <id> --yes
```

The data directory holds `certificates/`, `sessions/`, `runtime-state.json`,
`startup-settings.json` and `ui-settings.json`. Each session directory holds
`snapshot.json`, `state.json`, `workspace.json`, `transactions.ndjson`,
`transactions.meta.ndjson` and two `.journal` files. Sniper reads bodies back from
`transactions.ndjson` by byte offset, so do not edit these files while Sniper is
running.

## What the CLI hands back

Captures are stored as sent, and nothing redacts them. `capture http get`
returns cookies, `Authorization` headers and request bodies to anything you pipe
it into: a log file, a pasted snippet, a coding agent. You decide what leaves the
machine.

The local API has no authentication on its default loopback bind, so any process
running as you can read the capture. If `SNIPER_UI_ADDR` binds a non-loopback
address, clients from another host need the one-time bootstrap token Sniper
prints at startup.

Without `--api`, `sniper-cli` connects to the instance named in
`runtime-state.json` in the default data directory, which may not be the one you
started. Pass `--api` when more than one instance is running.

## What this does not do

- Sniper captures only clients that use the proxy.
- Certificate-pinned apps reject the Sniper root. Add their hosts to
  **SSL passthrough hosts** under **Capture ▸ Settings** to tunnel their traffic
  through unread.
- The MITM path speaks HTTP/1.1 to the client, so it is not the tool for an
  HTTP/2-specific problem.
- `sniper-cli manifest` lists what the CLI covers. The in-scope history toggle and
  the Tools tab are not in it.
- Findings come from a passive scan of traffic that already flowed; nothing
  crawls or probes a target on its own. Each issue is listed once per host,
  endpoint or value, and links to the first request that showed it.

## Cleaning up

Stop the throwaway instance and delete its `SNIPER_DATA_DIR`, which holds its
capture, root CA and session files. Some commands write outside it:
`sniper-cli skills install` writes to the Claude and Codex skill directories, and
`SNIPER_INSTALL_CLI_PATH=1` edits your shell profile.
