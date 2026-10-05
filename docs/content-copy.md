# Content streaming copy

The backend implements preparation, HTTP transfer and commit for copying
published pooled or public user content into a signed player's user-storage
slot. The game executable is unchanged.

## Contract provenance

| Contract | Evidence | Scope |
|---|---|---|
| Service 50 task 16 post-copy | Original Replay writer `0x142133750` | Exact target request and one `bdFileID` result |
| `bdPreCopyResult` | Original Replay reader `0x142163DD0`, constructor `0x142163C30` | Full base `bdURL`, destination string and UInt32 file size |
| HTTP copy | Original Replay `startCopy` at `0x142164900` | HTTP `COPY`, `Destination` and optional `X-TransactionID` |
| Service 50 tasks 15 and 20 preparation | OpenIW8 SDK source `_preCopy`, pooled and user wrappers | Source-oracle contracts; corresponding Replay writers/callers are not recovered |

Preparation takes a typed UInt64 source ID followed by a typed UInt16 destination
slot. It returns one result for primary bytes and a second when a summary exists.
Each result contains a source URL, UInt16 location zero, server-name token,
UInt64 reserved destination file ID, destination URL and UInt32 size.

Post-copy consumes the target writer's field order: filename, slot, server type,
server name, primary size, category, summary size, metadata blob, packed UInt64
tag pairs, typed Boolean pooled flag and source ID. Native metadata limits are
names shorter than 128 bytes, metadata at most 2048 bytes and 256 tag pairs.
The local primary and summary limits are each 16 MiB. Trailing, malformed and
mismatched parameters fail before commit.

## Persistence and ownership

`data/content-streaming/<title>/copies.json` holds up to 128 staged operations,
each expiring after 600 seconds. A stage retains a validated immutable source
snapshot, authenticated target owner, reserved ID/slot and completed-part flags.
The HTTP URLs contain random 128-bit capabilities. Copy accepts only the exact
locally minted source/destination pair and never fetches an arbitrary URL.
Missing/duplicate Destination headers, body data and ranges are rejected.

Each HTTP part verifies source size and SHA256 before publishing its completed
flag. First completion returns HTTP 201 and a completed-part retry returns 200.
Final commit verifies the bytes again. Physical immutable blobs are shared;
the resulting logical file has its own ID, signed owner, slot, name, category,
metadata, tags and source-origin field. Pooled multipart descriptors are removed
from the resulting ordinary user file.

All final effects share one atomic `files.json` publication: source copy-counter
increment, replacement of only the signed owner's selected user slot, new file
and durable retry receipt. Its `copy_receipts` journal retains up to 32768
token/owner/file/request-hash entries. A full journal rejects new operations
rather than evicting receipts and making old retries unsafe. Receipt IDs remain
reserved after their corresponding slots/files are replaced. Surviving copy
files must agree with their journal entry when the catalog is loaded.

An exact retry returns its original ID without restoring an older slot or
incrementing the source again. Changed parameters fail with 106; another owner
fails with 101. Expired/missing sessions and incomplete stages return 108.
Corrupt storage, blob integrity failures and exhausted UInt32 copy counters fail
without committing. A valid retained source snapshot can complete after source
publication is removed; an absent source counter is not recreated. Content is
public/readable under the existing publication model. Private ACL semantics
are not implemented.

## Validation limits

`tools/copy_content_fixtures.py` independently encodes requests and reads result
DTOs, sends actual HTTP COPY requests, and checks primary/summary bytes, metadata,
ownership, malformed rollback, slot replacement, expiry, corrupt storage,
counter exhaustion and process-restart staging/receipt behavior. It runs in
the isolated encrypted-wire suite in `tools/test-lobby.py`.

This fixture does not establish a positive native Replay copy callback. Native
menu startup is checked separately after deployment; preparation IDs remain
marked as source-oracle evidence in the coverage ledger. Full backend and
every native method remain open.
