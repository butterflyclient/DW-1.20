# Replay inventory validation

Service 80/task 58 returns a server-authorized validation-token result. It does
not turn opaque client tokens into inventory edits, purchase grants or stat rows.
Unknown, disabled and expired authorizations remain unavailable.

The untouched Replay constructor at `0x142129190` writes a context string with
16-byte capacity, a filename with 128-byte capacity and an input token blob with
10,240-byte capacity. It binds one `bdValidationTokenResult`. The original reader
at `0x14210C0C0` calls `0x1420EF8C0` twice, then `0x1420EF3B0`. Those operations
consume typed **Int64, Int64, blob**; the integer wire tag is 9. The result stores
the two integer fields at offsets 16/24, token bytes at 32 and token size at
10,272. Its retail prefix/token semantics are not inferred from those offsets.

A trusted local issuer can publish the complete authorized result through an
atomic replacement of `data/inventory-validation/<title>/catalog.json`:

```json
{
  "schema": 1,
  "title": 5800,
  "authorizations": [
    {
      "context": "iw8",
      "filename": "inventory.bin",
      "token_sha256": "<lowercase SHA256 of exact input token bytes>",
      "owner": 12345,
      "enabled": true,
      "starts": 0,
      "expires": 0,
      "result_prefix_i64": [0, 0],
      "result_token_base64": "<base64 of issued opaque output token bytes>"
    }
  ]
}
```

The prefix values must come from the issuer's result contract. The example does
not claim that zero has a retail meaning. Both values must fit signed Int64.
The context may be empty; filenames must be nonempty. Strings retain the native
capacity limits and printable ASCII validation. Neither string is used as a
filesystem path. The authenticated user, title, exact context, exact filename
and input token hash select the authorization. Matching tokens owned by another
user return 101. No external API lets clients publish these authorizations.

Limits are 4 MiB per publication, 4,096 rows and 10,240 bytes for both nonempty
input and output blobs. Duplicate context/filename/token-hash tuples, malformed
unmatched rows, invalid base64, integer overflow and invalid time ranges reject
the entire publication. Zero expiry means no expiration; other expiration times
must exceed the start time. Rows are reread on every request, so removal,
disablement, expiration or a newly published result takes effect without a
restart. Retries leave publication, inventory and stats files unchanged.

Errors distinguish malformed requests (106), unavailable/inactive tokens (108),
foreign ownership (101) and corrupt/unreadable publications (102). Tokens and
result bytes are not logged or copied into backend receipts.

The independent encrypted-client fixtures check the full typed DTO, exact retry
bytes, owner/context/filename/token separation, time windows, whole-publication
validation, native size/signed bounds and backend-restart persistence. This is
local issuer and native wire support. Retail token signing, automatic token
issuance after inventory uploads and a positive native game callback remain
open work.
