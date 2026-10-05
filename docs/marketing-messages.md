# Published marketing messages

Replay starts service 104/task 6 at `0x142129BC0`. Its request carries context,
language and repeated location/count pairs. `bdCommsGetMessagesResponse` at
`0x142114EC0` consumes repeated field-1 message objects. Each message follows
the complete reader at `0x142114CF0`:

| Field | Type | Native capacity |
|---|---|---|
| 1 | UInt64 message ID | 64 bits |
| 2 | Language string | Fewer than 20 bytes |
| 3 | Content blob | 4096 bytes |
| 4 | Metadata blob | 2048 bytes |
| 5 | Payload blob | 1024 bytes |
| 6 | Payload-signature blob | 65 bytes |
| 7 | UInt64 assignment ID | 64 bits |
| 8 | UInt32 location ID | 32 bits |

Publish `data/marketing/<title>/<context>/catalog.json` with schema 1, numeric
`title`, exact string `context` and a `messages` array. Empty context uses the
`_default` folder. Each row supplies `id`, `assignment`, `location`, `language`,
`enabled`, `starts`, `expires`, `content`, `metadata`, `payload` and `signature`.
Times are unsigned Unix seconds; zero expiry means no expiry. An expiry must be
later than its start. The four blob fields are Base64 encoded and preserve their
bytes, including embedded zero bytes. No retail signature or redeemable reward
is invented from a message.

Publications are bounded to 4 MiB and 512 messages. ID/language/location tuples
must be unique. Every row is validated, including expired and disabled rows.
Invalid publications return storage failure 102. Requests must have unique
locations, at most 64 location pairs and 100 messages per location. Malformed
parameters return 106. The encoded reply is bounded to 256 KiB; exceeding that
bound returns 102 without a partial response.

Responses preserve requested location order and publication order within each
location, match exact language/context, apply enabled/start/expiry rules and
return at most the requested count. An absent publication or unmatched selection
remains a valid empty collection. The current native game uses title 5800,
context `cod-iw8-bnet-pc` and language `en`.

Replay's application parser treats content and metadata as JSON strings.
Publish valid JSON with a terminating zero byte for that consumer. Content can
substitute `{{metadataKey}}` values through its native parser. Blob capacities
still reflect the SDK binary contract. A message with no redeemable action can
leave payload and signature empty.

Task 104/7 records signed-owner view receipts. Its native object contains message
ID, location ID, assignment ID and language. Exact retries are deduplicated by
a content hash in the owner's context-specific journal. Publication does not
clear or rewrite those receipts.

Replay's native `MarkMessagesReadOnBackendAsync` constructs the report with an
empty context. That valid request uses the `_default` journal folder. It is not
rewritten into the fetch context, and empty context is not treated as invalid.

`marketing_fixtures.py` verifies all eight fields, blob boundaries, 64-bit values,
ordering, counts, selection, publication corruption and process restart.
`observe-game.py` resolves the actual manager through its linked getter, reads
the native response array, task/fetch state and parsed cache. Backend acceptance
is separate from native decoding and completion.

`prepare-native-marketing-test.py` publishes one inert local message and saves
exact catalog/view-journal restoration bytes first. Restore it after the native
test. The test changes no game code, grants no reward, fetches no external image
and starts no match.

The populated native test decoded the exact message/assignment IDs and blob
hashes through the real result reader, cleared the fetch task, and produced the
expected substituted JSON in the application's cache. The native viewed-message
command then sent its empty-context request successfully and persisted the
expected owned receipt. `record-native-marketing-proof.py` binds these results
to both executable hashes and exact restoration. The viewed completion callback
itself has not been independently observed, and redemption actions were not
exercised. These limits remain separate from the populated fetch proof.
