# Recoverable matchmaking transactions

Lobby creation and presence joining change a lobby, an owner search, and the
current-player index. Disbanding changes the lobby, every distinct member search,
and any index entries still pointing to that lobby. Independent file replacement
could previously leave these documents inconsistent after an interrupted write.

`src/matchmaking_store.cpp` now publishes one prepared transaction at
`data/matchmaking/<title>/transaction.json`. Its schema contains the title, a
monotonic revision, phase, and complete replacement snapshots. Every entry is
validated before any document replacement. The only permitted destinations are
`lobbies/<UInt64>.json`, `searches/<UInt64>.json`, and `current-lobbies.json`;
duplicate paths, foreign titles, inconsistent file IDs, duplicate JSON keys and
invalid document layouts reject recovery. Limits are 202 entries, 128 KiB per
document, 32 MiB per journal, 200 lobby members and 4096 indexed accounts.

The prepared record and every snapshot use `FlushFileBuffers` followed by
`MoveFileExW` with replacement and write-through. After all replacements, another
flushed record retains the revision with phase `applied` and an empty write list.
Keeping a completion marker avoids treating journal deletion as a durable
commit boundary. A left-over `.pending` file is not a committed transaction.

Recovery rolls forward the same snapshots. It runs before server listeners open
and before matchmaking tasks, lobby delivery validation, or tournament host
authorization read lobby state. The existing service-store mutex serializes live
reads and writes. If recovery still cannot finish, the task returns storage error
102 instead of exposing partial documents. Invalid startup journals prevent the
server from opening listeners and remain available for inspection.

Cancellation and host-document updates use this mechanism too. Disbanding
deduplicates searches shared by party members and clears an index entry only if
it still refers to the disbanded lobby. A newer lobby assignment is preserved.
Historical files without a journal remain readable without migration.

Notifications are produced only after a successful commit. Recovery does not
replay old connection callbacks or invent a success reply for a failed request.
A storage error after preparation can therefore mean that the operation later
finishes during recovery; clients must inspect/retry their native state rather
than assume that error 102 rolled the operation back. This is recoverable durable
publication under the server's mutex, not a transaction for external processes
reading individual files or simultaneous server instances sharing one data root.

`tools/matchmaking_transaction_fixtures.py` blocks real `.pending` file paths in
the isolated fixture directory. It observes partial creation and disband writes,
rejected reads, complete live recovery, invalid-journal preflight, newer index
preservation, and recovery before a restarted server accepts connections. These
checks use actual encrypted tasks and Windows filesystem failures. They do not
simulate a physical power cut, launch a map, or alter production player data.
