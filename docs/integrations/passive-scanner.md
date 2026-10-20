# Passive scanner configuration

The `scanner` commands manage the passive checks on captured response body
previews and on request and response headers. They send no traffic. A change
applies to traffic processed afterwards and keeps existing findings; **Rescan**
in Findings applies the current rules to retained history and replaces the
session's findings.

## CLI

```bash
sniper-cli scanner config get
sniper-cli scanner custom list --session-id <session-uuid>
sniper-cli scanner custom get --id example-header
sniper-cli scanner config set-enabled --enabled false --dry-run
sniper-cli scanner config set-enabled --enabled false --yes
sniper-cli scanner builtin set-enabled --id header --enabled false --yes
sniper-cli scanner custom create --file rule.json --dry-run
sniper-cli scanner custom create --file rule.json --yes
printf '%s' '{"enabled":false,"description":""}' | sniper-cli scanner custom update --id example-header --stdin --yes
sniper-cli scanner custom delete --id example-header --yes
```

Every write needs `--yes`. `--dry-run` validates the JSON offline, so it cannot
check whether an ID exists. Use `--session-id` to read or edit an inactive
session without switching to it.

## Rules

`custom create` takes one complete rule with a stable ID:

```json
{
  "id": "example-header",
  "name": "Example header marker",
  "enabled": true,
  "target": "response_header",
  "header_name": "X-Example",
  "pattern": "example-marker",
  "severity": "info",
  "category": "example",
  "description": "Synthetic passive marker."
}
```

- `target` is `response_body`, `response_header` or `request_header`.
- `severity` is `info`, `low`, `medium`, `high` or `critical`.
- `pattern` must be a valid Rust regex.
- `header_name` defaults to `""`, which makes a header rule search every
  captured header.
- Body rules see the stored preview, which may be truncated.
- A rule field holds at most 64 KiB of UTF-8; a config holds at most 250 custom
  rules and 4 MiB.

`custom update` takes a non-empty partial rule without `id`: omitted fields
stay, `false` disables, and `""` clears optional text. Unknown fields, nulls,
blank IDs, names or patterns, and empty patches are rejected. `get`, `update`
and `delete` match the exact ID, and `create` rejects a duplicate ID. Custom
rule order and unrelated settings are kept. Stored patterns and text can hold
sensitive values, so review `list` and `get` output before you share it.

## `call` operations

The operations are `scanner.config.get`, `scanner.config.set_enabled`,
`scanner.builtin.set_enabled`, and `scanner.custom.list`, `.get`, `.create`,
`.update`, `.delete`. `create` takes a nested `rule`, and `update` takes `id`
and a nested `patch`; either can take `file` or `stdin: true` instead, but not
both. The outer `--input` also takes `@file` or `-` for stdin; do not combine
`--input -` with `stdin: true`.

```bash
sniper-cli call scanner.config.set_enabled --input '{"enabled":false}' --dry-run
sniper-cli call scanner.custom.create --input '{"file":"rule.json"}' --yes
sniper-cli call scanner.custom.update --input '{"id":"example-header","patch":{"enabled":false,"description":""}}' --yes
sniper-cli schema input scanner.custom.update
sniper-cli examples scanner.custom.create
```

## Output and conflicts

`config get` returns the config with `session_id`, `config_token` and the
built-in rule IDs and names. `custom list` and `custom get` return the rule
array or object. With `call`, the result is under `data` and the session ID in
`meta.session_id`.

A write reads the selected config and its `config_token`, changes only the
requested part, and saves it with one compare-and-swap. A stale config or a
changed active session returns 409, and a missing precondition returns 428.
Neither is retried, so read the config again before you retry. A write returns
`session_id`, `config_token`, `changed` and, where it applies, `id`; a request
that changes nothing returns `changed: false` without saving.

## API

`POST /api/scanner-config` needs complete `enabled`, `rules` and `custom_rules`
fields plus `expected_config_token` from the session's latest GET, and returns
`200` with the saved config.
