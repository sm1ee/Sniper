# Safe skill maintenance

These commands operate on skill files on the **CLI host**, even with a remote
`--api`. They do not contact an API or a network service. The bundled templates
come from the running binary; upgrading the binary alone does not replace
existing installed skills. Automatic updates are disabled by default; separate
explicit host-local consent is described below.

## Inspect before changing anything

```bash
sniper-cli skills status --all
sniper-cli skills update-preview --all
sniper-cli schema input skills.enroll
sniper-cli schema output skills.update_preview
sniper-cli examples skills.stage_update
```

`status` compares active installed bytes with this binary's bundled template.
`update-preview` adds receipt-based
baseline information and staging eligibility. Neither writes files. Completed
previews can include missing, unmanaged, modified, or error rows; inspect each
row rather than interpreting exit zero as “everything is current.” No installed
source text is returned. Hashes identify bytes, not authorship or trust.

## Experimental enrollment

Select exactly one agent. Directory overrides identify skills roots, matching
`skills status` and the existing installer. A non-null directory override requires
its matching agent selector: `--codex-dir` requires `--codex`, and
`--claude-dir` requires `--claude`. `--all` selects both agents for `install`,
`status`, and `update-preview`; enrollment, staging, activation, result inspection,
and rollback require exactly one agent. The automatic-update commands also
require exactly one agent; only `enable-auto-updates` accepts directory overrides.
Previously ignored overrides for unselected agents now fail with
`INVALID_INPUT`, including in dry run. JSON `null` overrides remain equivalent
to omission. Overrides never redirect another agent's selected root.

```bash
sniper-cli skills enroll --codex --dry-run
sniper-cli skills enroll --codex --yes
```

Enrollment requires an existing regular `sniper-operator/SKILL.md` whose bytes
exactly match this binary's bundled template. It writes a local baseline receipt
beside that file. Receipts bind the selected absolute path and agent; moving an
installation or selecting it through another path alias can invalidate that
binding. It never changes the active skill. Enrollment does not enable
automatic updates or grant network access. Existing malformed or conflicting
receipts are preserved and reported rather than silently overwritten.

An older installation without a receipt remains **unmanaged**, even if it looks
like a historical Sniper template. Preview still compares its hashes. This
version cannot infer whether that file contains user edits, so it cannot enroll
or stage updates for it automatically. Review and preserve those files manually;
do not use the legacy `skills install --yes` command as an automatic fallback,
since that command can overwrite an existing installation.

## Review an unmanaged edited installation

You can compare the new bundle without replacing the active skill. Choose a
separate, unused skills root, verify that destination, and preview a copy there:

```bash
sniper-cli skills install --codex --codex-dir ./new-skill-review --dry-run
```

After reviewing that destination, replace `--dry-run` with `--yes` to create
the separate copy:

```bash
sniper-cli skills install --codex --codex-dir ./new-skill-review --yes
```

Use `--claude` and `--claude-dir` for that host's template.
The legacy installer can overwrite files at its selected destination; this is
why the review root must be separate and unused. Dry run does not reserve or
inspect that path. Use the returned installation path rather than guessing it.

Back up the active file, compare it with the separate bundle, and manually merge
the updated guidance while preserving your edits. Review before activation and
avoid concurrent writers, as described below. A customized merged skill can
legitimately remain `modified_or_outdated` and `unmanaged`; do not erase edits
just to make its hash match the bundle.

## Experimental candidate staging

After a later binary supplies a new bundle, preview identifies an enrolled file
that still matches its recorded baseline. Choose a **new** staging directory
whose parent already exists; do not point it at the active skill directory.

```bash
sniper-cli skills update-preview --codex
sniper-cli skills stage-update --codex --staging-dir /tmp/sniper-skill-candidate --dry-run
sniper-cli skills stage-update --codex --staging-dir /tmp/sniper-skill-candidate --yes
```

The stage command writes only the bundled candidate and a staging receipt in
the new directory. It never replaces active `SKILL.md`, including when another
editor changes that file during staging. A successful result explicitly says
`activated:false`. Existing staging paths are not overwritten. Failed or
interrupted operations can leave partial or complete visible files; keep them
for inspection and use a new path for a deliberate retry. Neither candidate-file
existence nor a parseable receipt alone proves successful completion or durability.

`--dry-run` validates command input only. It does not read installed files,
reserve a destination, verify enrollment, or guarantee that execution will
succeed. Use `update-preview` for a read-only observation, then inspect the
actual execution result. Files can change between those steps. Path checks are bounded observations, not
a sandbox against another process maliciously replacing ancestor directories.

## Explicit activation and rollback (partial milestone)

Activation is an explicit, experimental step. It is not an unattended updater:
there is no startup hook, scheduled activation, automatic fallback, or agent
reload. A newer binary alone still does not alter an installed skill.

Review the staged candidate and choose a new operation UUID before applying.
Use exactly the canonical lowercase hyphenated spelling; uppercase, compact,
braced and URN spellings are refused even in dry run. Keep this ID with the
selected agent, skills root and staging directory. The example ID below is for
illustration; choose a fresh UUID for your own transaction.

```bash
sniper-cli skills apply-update --codex --staging-dir /tmp/sniper-skill-candidate --operation-id 22222222-2222-2222-2222-222222222222 --dry-run
sniper-cli skills apply-update --codex --staging-dir /tmp/sniper-skill-candidate --operation-id 22222222-2222-2222-2222-222222222222 --yes
sniper-cli skills update-result --codex --operation-id 22222222-2222-2222-2222-222222222222
```

Use the same `--codex-dir` or `--claude-dir` on every command when the
installation has an explicit root. Apply requires the exact staged candidate
and staging receipt to agree with the selected agent, absolute installation,
unchanged enrolled baseline and running binary's bundle. A changed candidate,
changed active file, invalid or mismatched receipt, unsupported object or
conflicting transaction is refused. Preserve those objects and inspect the
reason instead of bypassing the checks with legacy install.

Different bundle bytes must have a strictly newer semantic-version precedence
than the enrolled baseline. An older version is a downgrade; equal precedence
with different bytes is a version conflict, including build-metadata-only
changes. Existing previews/staging describe byte eligibility; they are not a
promise that these stricter activation checks will pass.

Successful activation changes both active bytes and the managed baseline. Its
v2 enrollment receipt records the bundled-binary source, contract revision and
last operation ID, while keeping automatic updates disabled. Receipts are local
consistency records, not tamper-proof proof of authorship or trust.

Apply saves durable transaction artifacts before exchanging active objects.
Linux uses atomic exchange. Hosted macOS 15 ARM64 CI at `e7cbe95` verified
128 focused transaction, policy and CLI tests, including native ACL fixtures,
and native desktop compilation
([run 38423109820](https://github.com/sm1ee/Sniper/actions/runs/38423109820)).
These checks do not validate actual GUI behavior, Intel Macs or user-installed
skills. Windows activation, rollback and transaction-result inspection return
`platform_unsupported`. A filesystem that cannot provide the required exchange
or metadata guarantees is refused; there is no overwrite fallback. Path checks
are bounded observations, not a sandbox against malicious ancestor replacement.
Avoid concurrent editors and retain every transaction and displaced object.

A repeated successful apply with the same ID and exact bound request reports
that transaction instead of installing again. Reusing the ID with a different
stage or bundle is refused. Eligible partial apply transactions can resume under
the same ID only when the recorded object placements can be proven, and only
after inspecting the recorded and current state. Do not
blindly retry after interruption or invent a replacement ID to bypass recovery.

There is a cap of 128 retained operation directories per installation. Nothing
is automatically deleted or pruned to make room. Incomplete or corrupted
preparation artifacts and markers cannot be automatically repaired. Preserve
them and seek manual reconciliation; do not remove a directory or marker to
force an otherwise blocked operation.

Result inspection reads the filesystem but is read-only: it never resumes or
repairs a transaction. Only global `--dry-run` is argument-only with no file I/O.
`state` describes `prepared`, `applied`, `rolled_back`, or `recovery_required`;
`current_state` separately reports `baseline`, `updated`, `changed`, or
`unavailable`. A historical `applied` receipt does not prove that today's active
file remains unchanged. Inspect `error_code` when present. Every successful
result includes `allows_automatic_updates:false` and `agent_reloaded:false`.

To deliberately restore the original baseline of a partial or completed update,
use the original apply ID, not a new rollback ID:

```bash
sniper-cli skills rollback-update --codex --operation-id 22222222-2222-2222-2222-222222222222 --dry-run
sniper-cli skills rollback-update --codex --operation-id 22222222-2222-2222-2222-222222222222 --yes
sniper-cli skills update-result --codex --operation-id 22222222-2222-2222-2222-222222222222
```

Rollback restores the exact original skill and enrollment receipt by exchange,
preserving displaced objects rather than discarding them. This is a
transaction-bound recovery action, not a generic file restore. Inspect the result
and retained artifacts before deciding what to keep. Unexpected edited or
replaced objects can block rollback; there is no force-overwrite option. If rollback is interrupted,
inspect the same transaction before continuing; never delete recovery artifacts
to force a new attempt.

A staged candidate is not an installed update, and changing a file is not proof
that an already running agent has reloaded its instructions. Follow that host's
reload/restart behavior and verify the active skill separately.

### Manual activation remains separate

After a manual activation, an old enrollment receipt can make preview report
`modified`; that means the active hash differs from the enrolled baseline, not
that Sniper knows who changed it. In particular, `status` can report `current`
while `update-preview` reports `modified` after manually installing the current
bundle. These observations are consistent. Explicit managed activation updates
the receipt as part of its transaction; it does not silently adopt prior manual
changes or customized files.

### Optional advanced receipt recovery

A receipt is not required to use the active skill. Recovery is only for users
who deliberately want a new managed baseline. After reviewing and backing up
the active file and existing receipt, archive the old
`sniper-operator/.sniper-enrollment.json` yourself, then explicitly run `skills
enroll` with the current binary. The CLI does not remove or reset receipts for
you. Enrollment still requires exact current bundle bytes. Preserve customized
active files and leave them unmanaged or modified rather than erasing edits
merely to obtain an enrolled status.

Do not use this manual receipt procedure while an activation transaction is
pending or recovery-required. Keep its receipt and transaction artifacts intact
and inspect its original operation ID first.

## Opt-in host-local automatic updates

Automatic updates are **Off by default**. Enrollment, application startup,
upgrading Sniper, reading a skill, and `--yes` on another command do not grant
consent. An agent must not enable this feature on the user's behalf without
explicit approval of future updates to the selected installation.

```bash
sniper-cli skills auto-update-status --codex
sniper-cli skills enable-auto-updates --codex --dry-run
sniper-cli skills enable-auto-updates --codex --yes
sniper-cli skills auto-update-once --codex --yes
sniper-cli skills disable-auto-updates --codex --yes
```

Use `--claude` for Claude. Select exactly one agent; `--all` is not accepted.
`auto-update-status` is read-only. Enable, disable and one-shot execution require
`--yes` outside dry run. The corresponding canonical operations are
`skills.auto_update_status`, `skills.enable_auto_updates`,
`skills.disable_auto_updates`, and `skills.auto_update_once`; discover their
exact inputs and outputs through `manifest`, `schema`, and `examples`.

Enable only records consent for one **existing, unchanged managed baseline**;
it does not install a skill, enroll an unmanaged file, adopt edits, stage a
candidate, or update the active file immediately. Optional `--codex-dir` and
`--claude-dir` overrides are accepted only by enable and require their matching
selector. The policy binds the selected absolute target and filesystem objects.
Status, disable and one-shot execution take only the agent selector and always
use that stored target. They reject directory overrides rather than redirecting
existing consent to another installation. Changing the agent's default directory
later does not move the consent.

Policy and attempt records are host-local under
`<Sniper data directory>/host-skill-updates`, separate from session data,
workspace exports and UI settings. `SNIPER_DATA_DIR` selects that host-local data
directory for the CLI. A remote `--api` never changes the policy location and is
never contacted. There is no network template fetch: the only candidate is the
executing binary's bundled template, with strictly newer semantic-version
precedence for different bytes. There is no force overwrite, automatic enrollment,
legacy-install fallback, artifact pruning, or agent reload.

After the desktop WebView has been built, its first idle event schedules one
background pass over enabled policies, off the UI thread. It is not a repeating
timer. Teardown cancels any not-yet-started next-agent pass and waits for the
active worker; it does not abandon an in-flight guarded transaction. Headless
server startup, ordinary CLI commands, and environment-triggered installers do
not run these updates. `auto-update-once` is the explicit host-local alternative.

Inspect `state`, not just exit zero or `enabled`:

- `disabled`: no policy, or consent has been disabled
- `enabled`: consent exists; this does not prove a later attempt will be eligible
- `current`: the one-shot check needed no newer bundled update
- `updated`: the guarded attempt completed; `agent_reloaded` remains false
- `paused`: changed or uncertain state requires inspection and fresh authorization

`enabled` describes stored consent and can remain true while paused. `path`,
`policy_id`, `revision`, `generation`, and `operation_id` identify the bound
policy and retained attempt; absent policies return null identifiers. Read
`error_code` when present. Durable pauses report `policy_paused`; the optional
`pause_reason` retains the bounded original cause. A pending attempt can be
paused without a recorded cause. Status reads never create or repair a policy,
resume an attempt, or enable updates. Global `--dry-run` is argument-only: zero
filesystem or API I/O, no eligibility guarantee, and no reservation of consent.
For these four operations, canonical `call --dry-run` accepts inline JSON only;
`--input @file` and `--input -` are rejected before opening files or reading stdin.
Other operations retain their existing explicit input-source behavior.

Edited, replaced, missing, unsupported, conflicting or uncertain objects are
preserved. Pending attempts consume that authorization; restarting Sniper or
retrying the one-shot command does not mint a replacement operation ID or silently
resume an uncertain mutation. Preserve policy history, staging and transaction
artifacts. Inspect `auto-update-status` and, where an operation ID is present,
`update-result` with that original ID and the recorded installation root. Do not
remove a lock, rewrite policy files, use legacy install, or invent an operation ID
to bypass a refusal.

After resolving a pause safely and reviewing the target, explicitly re-enable
using the exact current revision from status:

```bash
sniper-cli skills auto-update-status --codex
sniper-cli skills enable-auto-updates --codex --policy-revision 3 --dry-run
sniper-cli skills enable-auto-updates --codex --policy-revision 3 --yes
```

`3` is illustrative; use the returned revision, and repeat the original directory
override on enable if the installation uses a nondefault root. An existing policy
cannot be re-enabled without its current revision. A stale revision fails rather
than overwriting newer consent. Successful re-enable creates a new authorization
generation, and still does not update the active file immediately. Disabled and
paused policies never re-enable themselves. Disabling preserves active bytes and
all recovery artifacts; it does not undo an already committed update.

The same safe activation platform limits apply. Linux exchange has native fixture
coverage. The hosted macOS 15 ARM64 checks linked above cover the automatic-update
policy, transaction guards and desktop compilation. Actual GUI behavior, Intel
Macs and user-installed skills remain unverified. Windows host-policy operations
are currently unsupported. Unsupported filesystems fail closed with no overwrite
fallback. These checks are bounded observations,
not a sandbox against malicious concurrent ancestor replacement.

## Automation result handling

Input errors exit 2. A safely refused or failed managed skill operation
returns a structured `MANAGED_SKILL_ERROR`, exits 5, and includes a stable reason
under `error.details.reason`. It is not automatically retryable. Inspect the
command result and any output. For apply or rollback, use `skills update-result`
with the same agent, root and original operation ID first. Preserve every
transaction artifact and displaced object. A `recovery_required` error means
the outcome is uncertain; do not blindly retry or change the operation ID. For
enrollment/staging, rerun `skills status` and `skills update-preview` for the
selected agent before making a new deliberate attempt. For automatic-update
commands, inspect `skills auto-update-status` for the same agent and its original
attempt before deciding on any fresh authorization. Enrollment can
leave a valid visible receipt that preview recognizes as a baseline even when
the command reports a write or sync error. Preserve existing receipts and staged
files; do not overwrite them or reuse a staging path to force a retry.

Local writes happen before the JSON result is printed. An output-delivery failure
does not prove that no files were written: stdout errors can exit 1 after the local
write completed, while this CLI exits 0 on `BrokenPipe` when an output consumer
closes. An apply or rollback may already have changed active files when its output is
lost. Inspect `skills update-result` with the original operation ID; that read
does not repeat the mutation. For enrollment or staging, inspect `skills status`,
`skills update-preview`, and existing receipt/candidate files instead. Preserve
all artifacts before deciding on any deliberate retry. For enable, disable or
one-shot automatic updates, inspect `auto-update-status` first: lost output is
not evidence that consent or active files stayed unchanged.

The receipt and version fields describe the recorded baseline; differing version
strings alone do not prove provenance. Preview/staging candidate eligibility is
based on byte hashes; activation additionally enforces strictly newer semantic
version precedence for different bytes.

Common refusals provide operation-specific guidance:

- `skills.stage_update` / `already_current`: active bytes already match the
  bundle. Use `skills status`; no candidate is needed.
- `skills.enroll` / `already_exists`: the receipt path exists. This does not
  prove successful enrollment; it can be malformed, a directory, or a link.
  Preserve it and inspect `skills update-preview`.
- `skills.stage_update` / `already_exists`: the staging directory or an output
  path exists. Inspect any partial output, then choose a new directory outside
  the active skill directory whose parent already exists.
- `skills.enroll` / `installed_not_current`: enrollment requires exact bundle
  bytes. Review differences and preserve edits rather than overwriting them.
- `skills.stage_update` / `installed_modified`: active bytes differ from the
  recorded baseline, including after manual activation with an old receipt.
  Check both `skills status` and `skills update-preview` before deciding whether
  optional receipt recovery is useful.
- `skills.apply_update` / `version_conflict` or `downgrade`: different bytes need
  strictly newer semantic-version precedence. Preserve the baseline and candidate.
- `skills.apply_update` / `request_conflict`: the operation ID is already bound
  to a different request. Inspect the original transaction; do not overwrite it.
- `recovery_required`: a mutation may have partially completed. Use
  `skills update-result` with the original operation ID and preserve all artifacts.
- `transaction_busy` or `pending_transaction`: another local transaction blocks
  this action. Inspect it and stop concurrent writers; do not bypass its lock.
- `platform_unsupported`, `swap_unsupported`, or `metadata_unsupported`: the
  required safe operation is unavailable. There is no legacy overwrite fallback.
