# Browser drivers: opening a wired browser that people and agents can drive

Status: phases 1 and 2 implemented on `release/0.2.12`. Phase 3 is not started.

## Problem

`capture browser open` opens a browser that already sends its traffic through
Sniper and trusts its certificate. People use it from the UI; agents use it from the
CLI. Agents need to *drive* that browser, and the ways to do so differ:

- Chromium-family browsers are driven over the DevTools protocol (CDP). Sniper can
  open the port, but the agent has to bring a client.
- ego lite ships its own agent CLI and skill: a snapshot of the page with `@ref`s,
  clicks and typing, dialogs, uploads, handoff to the user, a visible cursor.

Both must keep working, the user must be able to choose, and adding the next
browser must not mean another `if` in five places. Before this design the launcher
branched on "is it ego" in six places.

## Decisions

1. **Two axes, kept apart.** *Which executable* is a row in `BrowserKind`. *How an
   agent drives it* is a `Driver` (`cdp`, `ego-cli`). Every decision about driving
   lives in `Driver`; `launch_at` never asks which browser it has.
2. **Sniper wires the browser; it does not drive it.** Sniper owns the proxy, the
   certificate trust, the profile and the lifetime, which is the same for every
   driver. It hands out a *control* and stops. It does not implement clicking or
   typing.
3. **One contract for callers.** `open --agent` means "make this drivable" whatever
   the driver does for that. The result carries `control`, tagged by `driver`:
   `{"driver":"cdp","endpoint":…}` or `{"driver":"ego-cli","server_name":…,"command":…}`.
   Callers read `control`; they do not know which browser they opened.
4. **The catalog is data.** `capture browser list` returns every browser Sniper
   knows on the platform with `installed`, `driver`, `platforms`, `capabilities`,
   `requirements` and `install_hint`. Docs and UI read it instead of hard-coding
   per-browser knowledge. A browser not built for the platform is left out.
5. **Sniper never installs a browser or its skill.** ego is a third-party program
   whose app is a separate download and whose installer does not verify what it
   fetches and removes the macOS quarantine flag. Sniper detects, reports
   `requirements` and an `install_hint`, and leaves installing to the user.
6. **A DevTools port is opt-in.** It lets any local process drive a browser that
   holds the profile's logged-in sessions, so it is opened only when asked, and
   refused while the proxy listens beyond loopback (a network-reachable proxy relays
   requests to local ports). The check sits with the driver. A port cannot be added
   to a running browser: getting one means quitting it, or opening a throwaway
   profile.
7. **ego is always named, so `--agent` changes nothing for it.** It gets a server
   name on every launch, whether or not `--agent` was passed, and `control` is always
   returned. The name is derived from the proxy port *and the profile*, so it is
   stable for a profile and a leftover ego from another data directory never
   answers to it. The opt-in in decision 6 is about the port only: ego's CLI is
   reachable by any process of the same user either way.
8. **Rich actions come from the driver, not from Sniper.** A thin action layer in
   Sniper (`browser snapshot|click|fill`) is deliberately deferred. The driver
   structure lets it be added later without touching the launcher. Build it if
   people hit "no CDP client available".

## What was verified, and what was not

Verified against a running Sniper:

- A plain CDP client drives Sniper's Chrome: click by coordinates, typing,
  JavaScript dialogs, new windows, screenshots, file input, downloads, the
  accessibility tree.
- ego, started by the launcher with its own profile and server name, is driven by
  its skill CLI (`taskSpace`, `goto`, `snapshot`, `click`, `waitForURL`, `evaluate`,
  `finish`) and its traffic is captured. A click navigation reaches the server as a
  same-origin request with a `Referer`; a `goto` does not.
- ego relaunches itself in four of six runs on a new profile, about nine seconds
  after it starts. In the other two (one re-opened every 1.5 s while it started, one
  was left alone for 40 s) it did not, and what decides it is unknown. When it does,
  the process Sniper started exits with status 0 and a detached one (parent pid 1,
  same executable, the same switches) takes the profile's `SingletonLock`; in
  between the lock is absent for under half a second. Tracking the pid Sniper
  started therefore loses the browser, and the next open ran the binary again, which
  handed its window to the running browser and exited within 500 ms. That was
  reported as "could not start" although the window had opened. Sniper now finds the
  browser through the lock (macOS and Linux), reads the proxy it was started for
  from its command line after checking that the command line names this profile,
  treats a launch that exits cleanly while a browser holds the lock as a handed-off
  window, and keeps a throwaway profile until the lock is released, including from
  the startup sweep of abandoned profiles. Not covered by a test: the whole of
  `launch_at` against a relaunching browser, because a fake browser script is not
  the executable the lock holder is compared with. Verified by hand against real ego
  instead.

Not verified:

- ego's handoff to the user and its visible cursor. `capabilities` reports them as
  ego documents them.
- A brand-new ego profile beyond starting. One started, relaunched itself and held
  its lock like any other, but its first-run screens and the capture of its traffic
  were not exercised; the earlier capture runs used a copy of a profile set up by
  hand.
- That ego's CLI keeps its current behaviour. Sniper relies on `--ego-server-name`,
  on script output going to stderr, and on how the CLI finds the app; none of that
  is a versioned contract.
- The Windows code paths. They could not be compiled locally.

## Phases

1. **Done.** Driver-neutral contract (`--agent`, `control`, `driver`), catalog with
   capabilities and requirements, policy moved into the driver, documentation and
   skills updated (named ego instance, stderr, acting like a person).
2. **Done.** The user's choice is saved as `browser.preferred` in `ui-settings.json`
   (user-level, not per session) and set through `POST /api/browser/preference` or
   `capture browser prefer`. Resolution order: explicit request, saved preference,
   automatic order; a saved browser that has gone missing falls back with a warning.
   The UI is one split-button component mounted by `[data-browser-launcher]`: the
   button opens the default, the arrow lists browsers with "Make default" and the
   one-shot "agent" and "throwaway" boxes. Two decisions worth keeping:
   - `browser` is server-owned. A whole-snapshot save from the UI cannot change it,
     so a stale page cannot overwrite a choice made from the CLI.
   - Setting it does not bump `server_revision`. A bump would make a UI save that
     was already in flight look stale and be rejected.
   - Placement: the top bar, chosen by the user after the capture tab bar and the
     filter row were compared on screen. An empty history offers the same button. The
     component mounts by attribute, so moving it is an HTML edit.
   - Automatic order: ego first when installed, then Chrome, Edge, Brave, Chromium.
     The user chose this over "ego last". The menu still lists Chrome first with ego
     under it. Superseded on 2026-10-08: the agent browsers are now listed first too, so one table (`ALL`) serves both.
   - A successful open is silent. Only warnings, errors, and the control endpoint of
     an agent-driven browser are shown, since a window appearing is its own
     confirmation.
3. **Not started.** Split `src/browser.rs` into a module: `kinds` (the table),
   `driver`, `profile`, `registry`, `launch`. A mechanical move; the tests move with
   it.

## Open questions

- Should `auto` prefer ego only when its command and skill are both present? Today
  it prefers ego whenever the app is installed, and the window opens either way; only
  agent control needs the command and skill.
- Should the catalog report ego's version, so a change in its CLI is visible?
