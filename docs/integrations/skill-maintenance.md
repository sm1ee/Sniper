# Safe skill maintenance

These commands operate on skill files on the **CLI host**, even with a remote
`--api`. They do not contact an API or a network service. The bundled templates
come from the running binary; upgrading the binary alone does not replace
existing installed skills.

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
`status`, and `update-preview`; enrollment and staging still require exactly
one agent. Previously ignored overrides for unselected agents now fail with
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

## Experimental workflow limitations

For everyday use, start with `status` and `update-preview`. Enrollment and
staging are experimental, not a complete update installer. This release has no
managed activate/apply command. Review the
candidate and compare it with the active file first. Preserve a backup of the
current active file, stop editors or other writers, and use your normal manual
file-management process only after deciding which changes to keep. A backup
made before a concurrent editor saves can miss that editor's last changes;
atomic replacement alone does not solve that race. Staging avoids the race by
not replacing the active file at all.

A staged candidate is not an installed update, and changing a file is not proof
that an already running agent has reloaded its instructions. Follow that host's
reload/restart behavior and verify the active skill separately.

Enrollment receipts are never rewritten by these commands. They are ordinary
local files, not tamper-proof evidence of provenance. After a manual
activation, the old receipt can make preview report `modified`; that means the
active hash differs from the enrolled baseline, not that Sniper knows who changed
it. In particular, `status` can report `current` while `update-preview` reports
`modified` after manual activation of the current bundle. These observations
are consistent: one compares the bundle, and the other compares the old baseline.
This does not mean the active skill failed to update.

### Optional advanced receipt recovery

A receipt is not required to use the active skill. Recovery is only for users
who deliberately want a new managed baseline. After reviewing and backing up
the active file and existing receipt, archive the old
`sniper-operator/.sniper-enrollment.json` yourself, then explicitly run `skills
enroll` with the current binary. The CLI does not remove or reset receipts for
you. Enrollment still requires exact current bundle bytes. Preserve customized
active files and leave them unmanaged or modified rather than erasing edits
merely to obtain an enrolled status.

## Automation result handling

Input errors exit 2. A safely refused or failed enrollment/staging operation
returns a structured `MANAGED_SKILL_ERROR`, exits 5, and includes a stable reason
under `error.details.reason`. It is not automatically retryable. Inspect the
command result and any output, and rerun `skills status` and `skills update-preview`
for the selected agent before making a new deliberate attempt. Enrollment can
leave a valid visible receipt that preview recognizes as a baseline even when
the command reports a write or sync error. Preserve existing receipts and staged
files; do not overwrite them or reuse a staging path to force a retry.

The receipt and version fields describe the recorded baseline; differing version
strings alone do not prove an upgrade or downgrade. Candidate eligibility is based
on byte hashes.

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
