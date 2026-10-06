# Replay server-validated stats

Service **4, task 14** consumes Replay's token-only request and applies an
explicitly authorized local stat batch. The authorization comes from a trusted
server publication. Client token bytes never become client-supplied stat rows.
This supports local authorizations; retail token signing, opaque payload decoding
and a positive native game callback are separate, unverified work.

## Target contract

Original Replay `0x1421286F0` constructs task `(4, 14)`, copies at most 10,240
token bytes into `bdValidationTokenResult`, and calls the task's blob writer.
There is no result binding. A successful response therefore has zero results.
The SDK token object is opaque to the caller; this route does not invent fields
inside a retail token. Inventory validation `(80, 58)` is a different request:
context, filename, input token and a bound validation-token result. Its separate
[inventory validation handler](inventory-validation.md) consumes trusted local
issuer publications; it never shares this stat-mutation handler.

## Local authorization publication

Publish `data/validated-stats/<title>/catalog.json` using an atomic replacement:

```json
{
  "schema": 1,
  "title": 5800,
  "authorizations": [
    {
      "token_sha256": "<SHA256 of the exact opaque token bytes>",
      "owner": 12345,
      "enabled": true,
      "starts": 0,
      "expires": 0,
      "stat_request_base64": "<base64 of the complete typed stat batch including its final zero>"
    }
  ]
}
```

This is trusted server data, not a client upload endpoint. A local authoritative
match provider can publish the token hash and its approved results before sending
that token to Replay. No arbitrary client blob is acknowledged successfully.
Authorizations are reread on every task, so publication changes need no restart.
Every row is validated, including unmatched, disabled and expired rows. All batch
owners must equal the publication row's owner; the selected owner must equal the
authenticated lobby user. Duplicate token hashes and malformed publications are
rejected in full.

The batch uses the existing same-Replay stats writer/parser: typed UInt32 board,
UInt64 owner, UInt8 replace/add/max mode, Int64 rating (or NAN), then at most ten
typed Int32 columns (or NAN). A following UInt32 begins another row. The existing
parser and merge code are shared with ordinary task 4/1. Missing columns and NAN
retain their established behavior; signed addition is checked for overflow.

Limits: 4 MiB authorization document, 4,096 publication entries, 10,240 token
bytes, 256 KiB decoded batch and 200 stat rows. Zero expiration means no expiry;
otherwise expiration must exceed start time. Both are unsigned epoch seconds.
The stat store remains bounded to 256 KiB.

## Atomic retries and errors

The stat batch and its token receipt are published together in the owner's
existing `leaderboard-stats/<title>/<user>.json`. `_validated_tokens` stores the
token hash, canonical authorization SHA256 and acceptance time. This avoids a
separate receipt file that could acknowledge an unapplied batch after failure.
At most 1,024 receipts are retained; existing entries are never silently evicted.
Ordinary stat writes preserve and validate these receipts.

An identical active authorization retries with zero results and no file change.
A changed authorization for an already accepted token returns 108 and applies
nothing. Removing, disabling or expiring an authorization makes its token
unavailable, including retries. New valid tokens can authorize later batches.
The original token bytes are neither logged nor persisted.

- 101: the matching authorization belongs to another account.
- 106: malformed native request, empty/oversize token, or signed batch overflow.
- 108: unknown/inactive authorization, authorization conflict or receipt capacity.
- 102: corrupt publication/receipt or persistence failure.

Every batch is merged in memory before the atomic file replacement. An invalid
later row or failed merge commits neither earlier rows nor a success receipt.

## Validation scope

`tools/validated_stats_fixtures.py` constructs the encrypted native task with an
independent client. It checks authorization absence, owner/time restrictions,
exact retry byte stability, conflicting publications, malformed unrelated rows,
receipt corruption, whole-batch overflow rollback, the SDK token-size boundary,
receipt capacity, preservation through ordinary writes and process-restart
idempotency. The passing receipt is protocol/persistence evidence. It does not
establish a native game callback, a retail token issuer or retail token semantics.
