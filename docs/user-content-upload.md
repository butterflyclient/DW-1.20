# Whole user-file uploads

The content backend now supports preparation, actual HTTP PUT and durable commit
of an ordinary user file. These files share the native listing, metadata,
download and COPY mechanisms already used by content streaming.

## Contract and provenance

- `50/5` prepares a filename, UInt16 slot, UInt32 size, UInt16 category,
  optional 32-byte checksum blob and empty trailing string. This request is
  documented by OpenIW8's `bdContentStreaming::_preUpload`. Its Replay
  constructor is not present in the current export, so this route remains
  marked as source-oracle evidence in the coverage ledger.
- Preparation returns one complete `bdURL`: upload URL, UInt16 location zero,
  server filename and reserved UInt64 file ID. Replay's result reader is
  `0x142163B40`; the SDK accepts up to ten such results.
- HTTP PUT supplies exactly the prepared number of bytes to that capability.
- Replay's `0x1421339F0` starts `50/6` and writes filename, slot, location,
  server filename, size, category, metadata blob, packed UInt64 tag pairs and
  an empty trailing string. It binds either a `bdFileMetaData` or `bdFileID`.
- The response is the full metadata consumed by Replay `0x14213DBE0`. Its first
  typed UInt64 also satisfies the SDK's `bdFileID` reader. Replay's
  `0x1420FE060` task-result reader does not require an ID-only result to exhaust
  the remaining payload; exactly one result is returned.

The optional `X-Checksum` algorithm is not established for this Replay build.
Nonempty 32-byte checksum requests return 108 without reserving anything.
Other malformed lengths return 106. This limitation is explicit rather than
silently accepting an unchecked client checksum. Stored bytes are independently
verified by their SHA256 identity regardless of that optional mode.

## Persistence and ownership

`data/content-streaming/<title>/user-uploads.json` holds at most 128 pending
sessions. Each reserves a fresh file ID and a random capability, a signed owner,
filename, slot, category, exact byte count and a ten-minute expiry. Receiving
bytes publishes the immutable SHA256 blob before recording the completed stage.
Staging and completed stages survive a process restart. Repeated identical PUT
returns 200; changed bytes return 409, wrong sizes 400, and missing/expired or
noncanonical capabilities 404. HTTP Range is rejected for whole-file uploads.

`files.json` commits the new user file, the replacement of the same owner's
existing slot, and its retry receipt in one atomic publication. It retains at
most 4096 upload receipts and is bounded to 16 MiB. A full journal rejects new
operations rather than evicting receipts. Metadata, tags, timestamps, signed
owner, URL, summary size, copy count and origin occupy the full native layout.
Existing metadata/COPY catalogs do not need a migration.

The journal retains the original result snapshot. An exact retry after a server
restart or later slot replacement returns that original result without restoring
an older file. A different authenticated owner gets 101. Changed commit fields
get 106. Missing sessions get 108. Corrupt stages/catalogs/blobs fail without
publication. Reserved IDs remain reserved in pending sessions and receipts, even
after a newer operation has replaced the slot.

COPY removes the upload receipt marker when cloning a source; its new file has
its own copy receipt. Incrementing the source's copy counter does not change the
historical upload result, and retrying the old upload does not reset that counter.

## Validation

`tools/user_content_fixtures.py` independently encodes the requests and full
metadata reply. The encrypted-wire suite sends real HTTP PUT/COPY/download
requests and checks ownership, exact lengths, malformed rollback, metadata/tags,
expired capabilities, integrity failures, same-slot replacement, historical
retry snapshots and the uploaded-file/COPY interaction. Completed, incomplete
and zero-byte stages are tested across an actual fixture-server restart.

A fresh native Multiplayer menu run is recorded separately after deployment.
It confirms startup/connectivity on this server binary, not positive completion
of a native user-file upload callback. The latter remains an open validation
gate, as does the unbound preparation constructor and optional checksum mode.
