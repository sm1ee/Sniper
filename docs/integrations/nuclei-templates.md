# Nuclei templates

Sniper runs the community templates of
[projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
(MIT license) with its own engine, which implements a subset of the template
language. It does not need the `nuclei` program. In **Scan ▸ Active Scan**,
download the latest release or import a release archive, then use templates in
two ways:

- **Passive**: turned-on templates check captured traffic and never send a
  request.
- **Template Scan**: on demand, Sniper sends the templates you pick to the
  targets you name, and keeps what matched.

## Passive templates

Two kinds of template can run passively:

- **Global matchers** (`global-matchers: true`): matchers meant for every HTTP
  response, such as WAF detection or secret patterns.
- **Captured GET**: one `GET {{BaseURL}}` request with no headers, body,
  payloads or random values. Its matchers judge each captured GET response as if
  the template had sent that request.

A turned-on template checks a captured response only when the session's
**Passive Scan** is on, the response's host matches a Scope include pattern,
and the response is not an image, font, audio or video. With no Scope include
patterns, templates check nothing.

Findings appear in **Capture ▸ Findings** under the category `nuclei`, with rule
id `nuclei-passive:<template-id>`, or `nuclei-passive:<template-id>:<matcher>`
for a named matcher. Extracted values are the evidence. Turning templates on or
off affects later traffic; **Rescan** in Findings applies the change to the
retained history.

Rescan also covers two gaps: rows recovered from the journal after a crash,
which get only the built-in findings, and responses that skipped templates
under load. At most four template evaluations run at once; a response beyond
that skips them rather than slow capture, and the library status counts it as
`passive_skipped_under_load`.

## Template Scan

### What it sends

A template can be sent when each of its HTTP request blocks is made of:

- a method other than `CONNECT`, and paths that start with `{{BaseURL}}` or
  `{{RootURL}}`, or raw requests;
- headers, a body, `variables`, `payloads`, `{{randstr}}` and the helper
  functions, including the random and time ones;
- `redirects`, `host-redirects`, `max-redirects`, `stop-at-first-match` and
  `disable-cookie`.

The target sets the scheme, host and port; a template only adds a path, and a
`Host` header may only be `{{Hostname}}`. Paths are sent as written, `%2e%2e`
and `..;` included; only characters a request line cannot hold are
percent-encoded. Each request carries
`User-Agent: Mozilla/5.0 (compatible; Sniper/<version>)`, `Accept: */*` and
`Accept-Language: en` unless the template sets its own.

Raw requests are read as Nuclei reads them. The request line's path is joined
to the target's path the way Nuclei joins it, and an absolute URL there keeps
only its path and query. `@timeout:` replaces the 15-second limit for that
request, up to five minutes; a request with `@Host:`, `@tls-sni:` or `@once` is
not sent. Request text and bodies written with bare line feeds are sent with
CRLF, as Nuclei sends them.

A template's requests to one target run as one session, as in Nuclei:

- Request blocks run in the order written, and each judges its own answers.
  `stop-at-first-match` ends only its own block. A block without matchers or
  extractors only prepares the next, as a login does; a template where no
  block has any is not sent. A match that only `internal: true` matchers made
  is not reported, as in Nuclei: such a block is a precondition.
- A `flow` that joins block calls with `&&`, `||` and parentheses
  (`http(1) && http(2)`, `http("login")`) decides which blocks run. A call is
  true when its block matched, reported or not, or, for a block without
  matchers, when it extracted something. Blocks the flow does not reach are
  not sent. Any other flow is a script, and its template is not sent.
- A cookie a response sets goes with the later requests to the same host,
  unless their block sets `disable-cookie: true`.
- A named `internal` extractor's first value fills the later requests that use
  its name (`{{csrf}}`), in its own block and the blocks after it. A template
  variable of the same name keeps its own value.
- Matchers and extractors can read earlier answers of their block by request
  number: `status_code_1`, `body_2`, `part: header_1`.

`{{7*7}}` and other markers that name no variable or function are sent as
written.

Payloads run as Nuclei runs them: every request of the template is sent once
per value of a single set, per index across sets with `attack: pitchfork`, or
per combination with `attack: clusterbomb`. A set is a list, the lines of a
string, or a file of the release such as `helpers/wordlists/users.txt`, read
line by line; the library keeps the release's `helpers/` text files for this.
A template that would send more than 10,000 requests to one target is listed,
not sent.

### Out-of-band callbacks

A template that sends `{{interactsh-url}}` matches when the target calls that
URL back, as a blind SSRF, injection or XXE does. The URLs come from the
session's Interactsh server, set up in **Capture ▸ OAST**:

- Each `{{interactsh-url}}` in a request is a URL of its own, so a callback
  names the request that caused it. `{{interactsh-server}}` is the server's
  domain.
- When a callback comes, the answer to its request is judged again with it:
  `interactsh_protocol` (`http`, `dns`, …), `interactsh_request` (lower case
  for DNS, as in Nuclei) and `interactsh_ip`. Sniper does not keep the
  server's reply, so `interactsh_response` is empty.
- An answer waits up to 60 seconds for its callback, and the scan waits two
  polls of the server after its last request. While the scan's session is not
  the active one, the scan polls the server itself.
- Without a registered Interactsh server, the BOAST and Custom providers
  included, OAST templates are left out: the preview counts them as
  `oast_unavailable` and the scan warns.
- The matched exchange and its finding name the callback's protocol and
  address.

### Where it sends

- A target is an `http://` or `https://` origin, optionally with the path the
  application lives under (`https://app.example.com/shop`), without
  credentials, query or fragment. A scan takes at most 20 targets.
  `{{BaseURL}}` keeps the path; `{{RootURL}}` leaves it out.
- Every target's host must match a Scope include pattern. Sniper checks this at
  the start and again before each target's requests, so narrowing Scope stops
  further requests to a host you removed.
- Sniper's own proxy and UI listeners and its `sniper` page are never
  targets, by address or by a name that resolves to this machine.
- Redirects are followed only when the template asks (`redirects` or
  `host-redirects`), for at most ten hops, and only while each hop stays in
  Scope and away from Sniper. When a hop would leave, its redirect is the
  response judged, and the job counts it as `redirects_not_followed`. Hops
  follow Go's HTTP client, as in Nuclei; `Authorization` and `Cookie` headers
  stay with their host.
- With **Apply Match & Replace rules** on (off by default), the session's
  request rules apply. A request that a rule would send to another scheme or
  host is not sent and counts as `blocked`.

### What it leaves out

Templates tagged `intrusive`, `default-login`, `bruteforce`, `token-spray`,
`credential-stuffing`, `fuzz`, `fuzzing`, `dast` or `osint`, and templates that
send `PUT`, `DELETE` or `PATCH` (`method:put`, `method:delete`,
`method:patch`), are left out unless you allow each risk by name. Templates
tagged `dos` are never sent.

### Pace, limits and stopping

- **Preview** counts the templates and the requests they send before any
  redirect, lists refused targets with the reason, and lists what each risk
  left out. It sends nothing to a target.
- Starting needs an explicit acknowledgment: the checkbox under **Preview** in
  the app, `"acknowledged": true` in the API, `--yes` in the CLI.
- Rate: 1 to 50 requests a second across the scan, default 10. Concurrency: 1
  to 8 templates at once, default 4. A template's requests go one after
  another.
- `max_requests` caps a scan at 1 to 50,000 requests, default 10,000, redirect
  hops included. A scan whose planned requests already exceed it does not
  start.
- A target that fails 20 requests in a row is dropped for the rest of the scan.
- One scan runs at a time per session, and it keeps running when you switch
  sessions. **Stop** drops the requests in flight. Quitting or updating Sniper,
  or deleting the session, stops the scan; a scan that was running during a
  crash is listed as `interrupted`.

### What it keeps

- HTTP history keeps only the exchanges a template matched, each noted
  `Sent by Template Scan.` with the template and scan id. The scan's request
  log shows the latest 200 requests with method, URL, status, time and error,
  never headers or bodies.
- Findings appear under the category `nuclei` with rule id
  `nuclei:<template-id>` or `nuclei:<template-id>:<matcher>`, once per
  template, matcher and endpoint. **Rescan** keeps them.
- The session keeps at most ten scans, each with up to 1,000 results, its
  counts and its warnings.

## What never runs

Sniper lists every template but never runs the `code`, `javascript`,
`headless`, `network`, `dns`, `file`, `ssl`, `websocket` or `whois` protocols,
a `flow` that does more than call blocks, self-contained templates,
workflows, or anything else outside the supported subset. A template either compiles completely or is listed as
unsupported with a reason, such as `protocol:dns`, `req:payload_file` or
`extractor:xpath`.

Not supported yet: fuzzing aggression levels in `payloads`, `iterate-all`, a
request that reads an earlier answer (`{{body_1}}` in a path), a matcher that
reads an earlier request's callback (`interactsh_protocol_2`), `unsafe` raw
requests, fuzzing, and race and pipeline requests. A template whose variable
is left for whoever runs it (`username: '{{username}}'`) is not sent.

## Supported subset

- Matchers: `word`, `regex`, `status`, `size`, `binary` and `dsl`, with `part`,
  `condition`, `negative`, `internal`, `name`, `case-insensitive`,
  `encoding: hex`, `match-all` and `matchers-condition`. A scan's matchers can
  also read the request (`part: request`) and the values it was built with.
- Extractors: `regex` (with `group`), `kval` (response headers and cookies),
  `dsl` and `json`. They run before the matchers, which can use a named
  extractor's first value.
- A `json` extractor's queries are the part of jq templates use: paths
  (`.a.b`, `."a-b"`, `.[0]`, `.[-1]`, `.[]`, `?`), `|`, `,`, `//`, `and`,
  `or`, comparisons, `+`, `-`, `select`, `contains`, `has`, `first`,
  `tostring`, `length`, `keys`, `not` and `empty`. A query using anything
  else lists its template as unsupported.
- The expression language and the helper functions community templates use,
  including `compare_versions`. Expressions follow govaluate's typing, versions
  go-version's rules, and regular expressions Go's: `\d`, `\w`, `\s` and `\b`
  are ASCII. As in Nuclei, every helper also answers to its name without
  underscores (`trimprefix`).
- A hash or an encoding of `body` (`md5`, `mmh3(base64_py(body))` for
  favicons, `base64`, `len`) reads the bytes the server sent, not their text.
- `generate_jwt` signs HS256 tokens, without the fourth argument (a lifetime);
  `date_time` writes the `%Y`, `%M`, `%D`, `%H`, `%m` and `%s` fields, not a Go
  layout. `generate_java_gadget` is not supported.
- `header` holds the status line and Go-canonical header names, and header
  values are available by lower snake name (`content_type`). Matchers see the
  response the server sent, even when a Match & Replace rule rewrote it.
- `{{Hostname}}` includes the port only when the URL names one; `{{Host}}` is
  the bare host.

A passive matcher reads at most 2 MiB of a body, a scan's at most 10 MiB. When a
body was truncated, a template whose result the missing bytes could change (a
negated body matcher, a size, an expression that reads the body) skips that
response.

On release v10.5.0, 2,086 of 11,698 HTTP templates can run passively and 9,784
can be sent by Template Scan, 446 of them out-of-band.

## The library

The library is shared by every session and stored under
`<data dir>/templates/`.

### Download

A download asks `api.github.com` for the latest release tag, then fetches that
release's checksums file and source `.tar.gz` from `github.com`. It uses the
environment's proxy settings and follows redirects only to GitHub hosts over
HTTPS. If the archive does not match the release's published SHA-256, nothing
is installed. There is no automatic update. A download needs an explicit
acknowledgment: the checkbox above **Download latest** in the app,
`"acknowledged": true` in the API, `--yes` in the CLI.

### Import

Where GitHub is unreachable, import a release `.tar.gz` of at most 64 MiB. An
imported archive is not checksum-verified, and the library says so. Limits:
512 MiB unpacked, 100,000 entries, 30,000 templates and 2 MiB per template.
Only regular `*.yaml` files outside dot-directories are read; when a template
id repeats, the first file wins.

## API

| Method and path | Purpose |
| --- | --- |
| `GET /api/templates/library` | Status: installed release, counts (`passive_supported`, `active_supported`), passive templates on, and any download or import in progress (`state`: `loading`, `idle`, `downloading`, `importing`, `failed`). |
| `POST /api/templates/library/check` | Ask GitHub for the newest tag; returns `latest`, `current`, `update_available`. |
| `POST /api/templates/library/download` | Body `{"acknowledged": true}`. Starts a download; 202, or 409 while busy. |
| `POST /api/templates/library/import` | Body: the `.tar.gz` (`application/gzip`). Starts an import; 202, or 409 while busy. |
| `GET /api/templates` | List; query `search`, `severity` (comma-separated), `protocol`, `support` (`passive`, `active`, `unsupported`), `tag`, `enabled`, `sort` (`on`, `severity`, `name`, `mode`, `tags`) with `direction` (`asc`, the most severe first for severity, or `desc`), `limit` (at most 30,000), `offset`. Each template's `requests` is the most one scan sends a target before redirects; a flow can stop sooner. |
| `GET /api/templates/:id` | One template with its description, references and YAML. |
| `POST /api/templates/passive` | Body `{"ids": [...], "enabled": bool}` or `{"filter": {...list query...}, "enabled": bool}`. Ids that cannot run passively are ignored and counted. |
| `POST /api/templates/scans` | Body: `session_id`, `targets`, `ids` or `filter` (a list query), `allow_risks`, `rate`, `concurrency`, `max_requests`, `apply_match_replace`, plus `"preview": true` to count or `"acknowledged": true` to start. A start returns the scan; 409 while one runs. |
| `GET /api/templates/scans?session_id=` | The session's scans, newest first, without results or request logs. |
| `GET /api/templates/scans/:id?session_id=` | One scan with its results (each naming the matched history record) and its latest requests. |
| `POST /api/templates/scans/:id/stop` | Body `{"session_id"}`. Stops the running scan. |

## CLI

```bash
sniper-cli templates library status
sniper-cli templates library check
sniper-cli templates library download --dry-run
sniper-cli templates library download --yes
sniper-cli templates library import --file nuclei-templates.tar.gz --yes
sniper-cli templates list --support passive --search wordpress
sniper-cli templates get --id tech-detect
sniper-cli templates passive set-enabled --enabled true --id tech-detect --yes
sniper-cli templates passive set-enabled --enabled false --tag waf --yes
sniper-cli templates passive set-enabled --enabled true --all --yes
sniper-cli templates scan preview --target https://app.example.com --severity high,critical
sniper-cli templates scan start --target https://app.example.com --severity high,critical --yes
sniper-cli templates scan start --target https://app.example.com --id git-config --rate 5 --yes
sniper-cli templates scan list
sniper-cli templates scan get --id <scan-id>
sniper-cli templates scan stop --id <scan-id> --yes
```

`download` and `import` wait until the release is installed and print the final
status. `passive set-enabled` takes exactly one of ids, a filter or `--all`; a
scan takes exactly one of ids or a filter, and `--allow-risk` once per risk.
`scan start` returns when the scan starts; `scan get` follows it. The scan
commands use the active session unless `--session-id` names another.
