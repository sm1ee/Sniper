# Observed socket peer capture

Observed socket peer capture is a per-session option, **Off by default**. While
it is On, Sniper stores the upstream socket address of each eligible ordinary
HTTP(S) response it captures. Opening Service Map or settings never turns it on.
It sends no probes, resolves no DNS, inspects no TLS, infers no origin IP and
builds no IP map.

## What is recorded

Each observation holds the remote address the HTTP client reports when the
response headers arrive, before local edits, and the route of the attempt that
succeeded: `direct`, `http_proxy`, `socks_proxy` or `unknown`. If the client
reports no address, it records `remote_addr_unavailable`. HTTP error responses
count; connection failures, local responses, Replay, WebSocket, CONNECT and
rendered-resource fetches do not. Eligibility is fixed when a request is first
sent, so switching the option affects only requests sent afterwards.

A peer can be a proxy, CDN or other intermediary. It does not show who owns the
origin or what sits behind it.

## Turning it on

The **Upstream socket peer** card in Capture Settings has a switch with explicit
Save and Cancel. It shows the saved switch and `effective_enabled` separately:
capture stays Off while HTTP capture is paused, the configuration is invalid or
persistence is uncertain. A successful save clears the persistence-uncertain
block. After an uncertain save, read the settings for the same session before
saving again.

```bash
sniper-cli capture http upstream-peer get --session-id <active-session-uuid>
sniper-cli capture http upstream-peer set --session-id <active-session-uuid> --enabled true --dry-run
sniper-cli capture http upstream-peer set --session-id <active-session-uuid> --enabled true --yes
sniper-cli call capture.http.upstream_peer.set --input '{"session_id":"00000000-0000-0000-0000-000000000000","enabled":false}' --dry-run
```

The canonical operations are `capture.http.upstream_peer.get` and
`capture.http.upstream_peer.set`. Both need the current active session UUID;
`set` takes only that and a JSON boolean `enabled`, and needs `--yes`. A run
reads the settings once and sends at most one POST. It never switches sessions,
follows redirects, retries or reads back.

The API is:

- `GET /api/transactions/upstream-peer-settings?session_id=UUID&expected_active_session_id=UUID`
- `POST` to the same path with `{"enabled":true,"expected_config_token":"<unchanged GET token>"}`

The response contains:

- `session_id`: the selected UUID
- `enabled`: the saved switch
- `config_revision`: an unsigned 64-bit integer as a decimal string
- `config_token`: a 64-character hex token bound to this feature, session, configuration and revision
- `status.effective_enabled`: whether new traffic records observations now
- `status.blocked_reason`: null, `persistence_uncertain`, `invalid_configuration` or `http_capture_paused`
- `changed`: POST only; whether the saved switch changed

A change increments the revision; a no-op keeps it. A missing or stale token, an
inactive session or an active-session conflict never writes, and an inactive
session is never loaded or activated.

## Reading one observation

Peer fields never appear in transaction summaries, event streams, the default
Service Map or default evidence. To read one observation, pass the session and
evidence token from the map:

```bash
sniper-cli target service-map-evidence --session-id <returned-session-uuid> --evidence-id <returned-token> --include-socket-peer
```

The API takes `include_socket_peer=true` on the evidence GET. When the token
validates, the response has a `socket_peer` envelope:

- `observed`: `observation.address` has a typed IPv4 or IPv6 `ip` and a 16-bit `port`; `reason` is null
- `unavailable`: `address` is null and `reason` is `remote_addr_unavailable`
- `not_recorded`: `observation` is null

An observation also has `source: "http_response_remote_addr"`, `observed_at`
and `route`, and is at most 512 bytes. `not_recorded` covers old rows,
ineligible rows and dropped data alike; it does not mean a direct route or a
failed connection. Stale, edited, deleted or cross-session evidence returns the
ordinary unavailable response.

## Matching rows by socket peer

```bash
sniper-cli scope service-map socket-peer-matches --session-id <active-session-uuid> --evidence-id <returned-token>
```

`target.service_map.socket_peer_matches.get` lists other rows in the active
session with the same recorded direct peer: source, route, address family, IP
and port. The API is `GET /api/target/service-map/socket-peer-matches` with the
same `session_id` and `evidence_id`. Proxy and unknown routes never match, and IPv4 never matches
IPv4-mapped IPv6. Results show up to 100 origins with three samples each, within
256 KiB, from a default 10,000-row window (50,000 maximum). Scope rules too
complex for the fixed work budget return unavailable with `scope_work_limit`;
use a smaller window or simpler rules. See the
[full matching, limits and count contract](service-map.md#explicit-recorded-socket-peer-matches).

## Retention and sharing

Observations are saved in session files, exports and full-record JSON. Treat
them as sensitive infrastructure data before sharing those files. Turning the
switch Off stops new recording but erases nothing, and there is no backfill.
