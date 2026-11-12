# TCP and UDP relay

For protocols that are not HTTP: databases, mail, game and IoT clients, anything
a proxy setting cannot reach. Sniper records each connection's bytes, holds them
for review, and resends a conversation.

Traffic gets in two ways:

- **A listener.** Sniper listens on a local port and relays every connection to
  one target. Point the app at the local port.
- **The HTTP proxy.** A client that tunnels with `CONNECT` and then speaks
  neither TLS nor HTTP is relayed and recorded too, as is every tunnel to a
  passthrough host. Nothing needs setting up.

## Listeners

Add one under **Capture ▸ Settings ▸ TCP**, or with the CLI:

```bash
sniper-cli tcp listeners add --local-port 9000 --target-host db.example.com --target-port 5432 --yes
```

A session can have up to 16. They are saved with it and start again when it
opens; one whose port is taken shows why and the others still start.

| Setting | What it does |
|---|---|
| **TLS** | Off relays bytes as they are. **Decrypt** answers a client's TLS with a certificate from Sniper's CA and reaches the target over TLS, so the record holds plain text; a client that does not start TLS is relayed as it is. **TLS to target** adds TLS towards the target only. |
| **Protocol** | **UDP** keeps one flow per client address, one chunk per datagram; a flow ends after 60 s without one. |
| **Other devices** | Listens on every interface for the addresses and CIDR networks listed; anyone else is refused and counted. Sniper's own ports stay out of reach, and the list may not be empty. |

Connections go through the upstream proxy when it is on, except to this machine
and to bypassed hosts.

## Through the HTTP proxy

After a `CONNECT`, Sniper looks at the client's first bytes without taking them:

- TLS goes to HTTPS interception, as before.
- An HTTP request line is served as plain HTTP and recorded in HTTP history.
- Anything else is relayed and recorded in TCP history as **Proxy**. A client
  that stays quiet for half a second may be waiting for a server that speaks
  first, such as SMTP or MySQL; Sniper then dials the target to find out.

Tunnels to passthrough hosts are recorded as **Passthrough**, still encrypted,
and never held.

## History

**Capture ▸ TCP** lists the connections. Each reads as a conversation in Hex or
Text. **Split by** cuts it
into messages at line ends, a delimiter, or a 1, 2 or 4-byte length prefix.
Search finds connections by their bytes as text, hex or a regex, and the ⋯ menu
saves one direction's raw bytes.

History keeps 256 connections and the first 1 MiB of each. A full history keeps
relaying and counts what it did not record until you **Clear** it.

## Intercept

Intercept holds **reads**, not messages: a read is whatever arrived at once.
Hold one direction or both, every read or only those matching a filter. A held
read can be edited, forwarded or dropped; **Forward all** and **Drop all** act on
everything held, and turning Intercept off forwards it.

## Replay

**Replay** opens a new connection to the target and sends each message in turn,
reading replies until the target stays silent for the wait you set. The exchange
is recorded like any other connection.

```bash
sniper-cli tcp replay --target-host db.example.com --target-port 5432 --message PING --dry-run
```

## CLI

Everything above is under `sniper-cli tcp`: `status`, `listeners`, `list`,
`get`, `raw`, `clear`, `intercept`, `pending`, `decide`, `forward-all`,
`drop-all`, `close` and `replay`. Writes need `--dry-run` or `--yes`.
