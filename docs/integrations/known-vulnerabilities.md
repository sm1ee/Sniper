# Known vulnerabilities

Sniper lists the known advisories for the front-end library versions it
detects, such as jQuery 3.4.1 loaded by a page. It fetches three public data
files itself and matches them on this machine; nothing about a target leaves
it.

A match comes from the version string alone. It is a lead to confirm, not a
confirmed vulnerability, so every such finding is Info.

## Data

| Source | Use | Host | Terms |
| --- | --- | --- | --- |
| retire.js repository | JavaScript library versions and their advisories | raw.githubusercontent.com | Apache-2.0 |
| CISA KEV | CVEs known to be exploited | www.cisa.gov | CC0 |
| FIRST EPSS | How likely a CVE is to be exploited | epss.empiricalsecurity.com | FIRST EPSS usage agreement; see EPSS at https://www.first.org/epss |

- **Requests.** One GET per file, through the environment's proxy. The hosts
  see your address and `Sniper/<version>`, nothing else.
- **Updates.** A minute after launch, then every hour, Sniper fetches a file
  that never loaded, failed last time or loaded a day ago. **Settings ▸
  Runtime ▸ Vulnerability data** turns this off; **Update now** fetches all
  three regardless.
- **Failures.** Each file loads or fails on its own, and the status shows
  why one failed. Matching starts once all three have loaded.
- **Checks.** A file over its size limit or that does not parse is refused,
  and the previous one stays. No source signs its file, so the status says
  "not verified (TLS only)".
- **Offline.** **Import** loads `jsrepository-v4.json`,
  `known_exploited_vulnerabilities.json` or the EPSS `.csv.gz` from disk. The
  next successful fetch replaces it.
- **Storage.** `<data dir>/vulndata/`, shared by every session.

## Matching

- 32 front-end products map to retire.js components. A product without an
  entry gets no advisories.
- A version too partial to place in a range matches nothing. `jquery@3`, a
  CDN URL that serves the newest 3.x, could be any 3.x release.
- Each advisory lists its id (the CVE, else the GHSA id, else the retire.js
  component and fixed version), severity, KEV, EPSS, fixed version, summary
  and links. Exploited ones come first, then by EPSS and severity.

## Findings and the Service Map

- One finding per page host, library and version: category `known_cve`, rule
  id `known-cve:<product>`, title `Known vulnerabilities: <name> <version>`,
  evidence `<product>@<version>`.
- A library a page loads from a CDN belongs to the page's host, so the **In
  scope** filter keeps it.
- The advisory list is read from the current data whenever the finding opens,
  so new data never duplicates a finding. Traffic captured before the data
  arrived needs one **Rescan**.
- In the Service Map a library with advisories shows their count, and **KEV**
  when one is exploited.

## API and CLI

| Route | `sniper-cli` | Answer |
| --- | --- | --- |
| `GET /api/vulndata` | `vulndata status` | Each source's date, origin, size, SHA-256 and last error; the switch; the index revision |
| `POST /api/vulndata/update` | `vulndata update` | 202 with the status; 409 while an update runs |
| `POST /api/vulndata/import` | `vulndata import --file <path>` | The body is the file, at most 16 MiB; 400 when it is not one of the three |
| `POST /api/vulndata/auto-update` | `vulndata auto-update --enabled <true\|false>` | The status |
| `GET /api/vulndata/lookup?product=<id>&version=<v>` | `vulndata lookup --product <id> --version <v>` | The advisories; 409 until the data has loaded |
