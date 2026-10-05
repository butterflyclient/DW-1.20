# Replay scripted-loot service

Service **195, task 1** now accepts the complete Replay HTTP-proxy request and
returns a published `scriptResponse` with the native status/header/body envelope.
This implements deterministic local script responses and their durable journal
lifecycle. Retail reward scripts and their inventory/currency effects are not
reconstructed by this route; an absent rule returns error 108.

## Target evidence

- Original Replay `0x142139BB0`: `startStructTask(195, 1)`.
- `0x14213EDC0`: POST to
  `/v1/users/<account-type>-<user>/loot-drop/<UInt32>/?client=...&context=...`,
  JSON body containing exactly one `clientData` string, and Content-Type
  `application/json`. The request stores context in 16 bytes and client data in
  1000 bytes; its JSON serialization buffer is 1024 bytes.
- `0x14213F0A0`: HTTP-proxy status/body parsing and `scriptResponse` extraction
  into a **16000-byte** native buffer. Both the unescaped string and the complete
  encoded JSON response must fit.
- `0x140F73F60`: the Replay wrapper calls the task constructor. Its current
  SQLite display alias incorrectly says `DWStats::writeStats`; the original
  call target, not that alias, identifies the domain.
- `0x14103E3C0`: the actual game caller sets context to the decimal title and
  uses constant client data `{"drop_versions":[0],"active_streams":[0]}` for
  successive crate openings. That data is **not** a unique transaction ID.

The existing AB-enrollment handler now shares the complete bounded HTTP-proxy
envelope parser and response writer. Other service transports are unchanged.

## Publication

Publish `data/loot-generation/<title>/<context>/catalog.json`. Use `_default`
for an empty context, while the JSON `context` remains `""`. Files are read on
each new request, so edits take effect without a server restart.

```json
{
  "schema": 1,
  "title": 5800,
  "context": "5800",
  "responses": [
    {
      "drop": 27,
      "client_data_sha256": "<64 lowercase hex characters>",
      "script_response": "<the exact response expected by the client script>",
      "enabled": true,
      "starts": 0,
      "expires": 0
    }
  ]
}
```

The hash is SHA-256 of the exact decoded `clientData` UTF-8 bytes. No whitespace
or JSON normalization occurs inside that opaque string. Matching is exact by
authenticated title, requested context, drop ID and data hash. Zero `expires`
means no expiration; otherwise `expires` must exceed `starts`. Every row is
validated, including disabled and expired rows. Duplicate drop/hash pairs and
invalid string/numeric/response-buffer fields reject the complete publication.

The local provider's signed owner may use `bnet-<id>` or `uno-<id>`. Foreign
owners return 101. Malformed native parameters return 106. Unknown rules, disabled
or inactive rules, and receipt capacity exhaustion return 108. Corrupt persisted
state/publications return 102 and are left intact.

## Accepted-task journal

Accepted responses are atomically stored in
`data/loot-generation/<title>/<context>/receipts/<signed-user>.json`, with schema,
title, context, owner, sequential journal ID, drop ID, client-data hash, exact
response and acceptance time. The original client data is neither persisted nor
logged. An identically shaped new task is still a distinct opening, including
when its client data matches a previous opening. Each accepted task appends one
record and advances `next_id`; old records
and their exact response snapshots remain intact after publication edits or a
server restart. A new task always uses the current publication. Removing or
disabling a rule makes new openings unavailable even when an earlier one succeeded.

The journal does not infer retry identity from the opaque payload. There is no
random reward generation or automatic inventory grant. A future retail rules
implementation must establish those semantics from
the actual game consumers before introducing debits or rewards.

Limits: 512 publication rows, 4096 receipts per owner/context, 4 MiB per stored
document, 15 context bytes, and the native body/string capacities above. Accepted
records are retained rather than silently evicted.

## Validation

`tools/loot_fixtures.py`, called by `tools/test-lobby.py`, independently constructs
the encrypted task wire data and checks exact headers/status/JSON, both owner
forms, bounded canonical URLs, JSON/header duplicates, buffer limits, corrupt
publications/receipts, disabled/time filtering, no mutation on failed requests,
live disk updates, repeated constant-data openings as separate tasks, ordered
capacity limits and real process-restart persistence.

The normal native menu validation remains a separate gate. A positive native
195/1 callback and its game-script consumer have not yet been exercised; protocol
fixtures alone do not establish that completion.
