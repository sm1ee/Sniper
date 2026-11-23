# Session ports, phase 2: a browser for a session

> Steps use checkbox (`- [ ]`) syntax for tracking. One commit for each task.

**Goal:** `POST /api/browser/launch` and `sniper-cli capture browser open` take
a session. A browser opened for a session that is not the default goes through
that session's own port and has a profile of its own.

**Spec:** `docs/superpowers/specs/2026-11-19-session-proxy-ports-design.md`,
decision 10, and "Phase 1 as built".

**Architecture:** `LaunchContext` learns which session the browser is for and
where the main listener is. `launch_at` picks the profile and makes the two
refusals from that. The API handler turns a session id into a launch target:
it opens the session's port and gives its address.

## Global constraints

- The default session's launch does not change: the main listener and the
  shared profile `browser-profiles/<kind>`.
- Any other session: its own port, opened if it is closed, and the profile
  `browser-profiles/session-<id>/<kind>`. Profiles stay outside the session
  folder: a session folder that is copied must not carry logged-in cookies.
- A driver that cannot be pointed at one window (`Driver::shared_instance_hint`,
  which is Aside) is refused for a session that is not the default.
- A driver port is refused while the *main* listener is bound beyond loopback,
  whichever port the browser is pointed at.
- No test starts a real browser. A launch is tested with the fake-browser
  scripts of `browser::tests::spawn::Fixture`, and at runtime with a script
  standing in for Chromium under a scratch `HOME`.

## Review focus

1. A browser of an earlier run that still holds a session's profile: its driver
   port must be guarded again after a restart (`recover_driver_ports` reads only
   the top level of `browser-profiles` today). → B2.
2. A deleted session's profile that a browser still holds must not be removed
   under it, and must go once the browser has quit. → B2.
3. A launch for the default session named by its id must stay today's launch,
   not open a port. → B3.
4. A launch for a session must not be refused because the main listener is
   offline, and must be refused when the session's port cannot open. → B3.
5. The plain `capture browser open` body must stay what it is. → B4.

---

### B1: `launch_at` knows the session

**Files:** `src/browser.rs`.

**Interfaces:** `LaunchContext` gains `session: Option<Uuid>` and
`main_proxy_addr: SocketAddr`; `LaunchContext::new` sets them to `None` and to
`proxy_addr`. `LaunchContext::for_session(self, session: Uuid, main_proxy_addr:
SocketAddr) -> Self`.

- [ ] Tests (fixture): a session's browser gets `session-<id>/<kind>` and the
  session port as its proxy, while the default profile is untouched; a
  throwaway launch for a session still gets `fresh-<uuid>`; Aside is refused
  for a session and opened without one; a driver port is refused for a session
  while the main listener is beyond loopback, although the session port is on
  loopback.
- [ ] Implement.

### B2: Session profiles are recovered, swept and removed

**Files:** `src/browser.rs`.

**Interfaces:**
- `pub fn recover_driver_ports(data_dir)` also reads `session-*/<kind>`.
- `pub fn sweep_session_profiles(data_dir: &Path, exists: impl Fn(Uuid) -> bool)`.
- `pub fn remove_session_profiles(data_dir: &Path, session: Uuid)`.

- [ ] Tests: a running browser on a session profile has its port guarded again;
  a sweep removes the profiles of a session that is gone, leaves one a browser
  still holds, leaves the profiles of a session that exists, and leaves
  directories that are not session profiles.
- [ ] Implement.

### B3: The API opens a browser for a session

**Files:** `src/api.rs`, `src/state.rs`.

**Interfaces:** `BrowserLaunchPayload.session_id: Option<Uuid>`.
`async fn browser_launch_target(state, session_id) -> Result<LaunchTarget,
Response>` with `LaunchTarget { proxy_addr, main_proxy_addr, session }`.

- [ ] Tests: no session and the active session's id give the main listener and
  no session, and are refused while the proxy is offline; another session gives
  its port, opens it, and is not refused while the main listener is offline; an
  unknown session is 404; deleting a session removes its profiles.
- [ ] Implement; sweep session profiles at start-up and at each launch.

### B4: CLI and documents

**Files:** `src/bin/sniper-cli.rs`, `docs/guides/cli.md`, the operator skill,
`AGENTS.md`.

- [ ] `capture browser open --session-id <uuid>`; the body carries `session_id`
  only when it is given.

### B5: Runtime test, deploy, review

- [ ] Isolated instance with a scratch `HOME` and a script for Chromium: a
  launch for a session reports the session port and the session profile, and
  the script was given that proxy; a launch without a session reports the main
  listener and the shared profile; deleting the session removes its profile
  once the script has ended.
- [ ] Deploy. One reviewer.
