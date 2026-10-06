# Replay tournament publication and owned lifecycle

The server implements Replay tasks 145/19, 20, 21, 22, 23, 28 and 29. These are
backend handlers, without game executable changes or fabricated native fences.
Publications can provide an explicit bracket or generate one from authenticated
matchmaking parties. Capacity publications with round rules allocate closed
native lobbies after both teams are ready. Host-authorized result submissions
persist scores and advance winners. Native tournament gameplay and forfeits
remain separate validation and implementation work. Task 145/27 from another
source build is not silently substituted.

The following evidence comes from the original Replay executable and its
SQLite export; display aliases in that export can be misleading:

| Original Replay VA | Task | Request/result |
| --- | --- | --- |
| `0x142136110` | 145/19 ready | UInt64 tournament ID, UInt64 `0xFFFFFFFF`; no result binding |
| existing 145/20 writer, game `0x141075F30` | 145/20 state | No parameters; one `bdStringResult`, native callback `0x141077F20` accepts not-enrolled error 14526 |
| `0x1421366F0`, game `0x141076A10` | 145/21 result | One typed JSON string in a native 256-byte buffer; no bound result |
| `0x142135B60` | 145/22 leave all | No parameters or result binding |
| `0x142135260` | 145/23 acknowledge join | UInt64 tournament ID, typed Boolean accept; no result binding |
| `0x142136330` | 145/28 rejoin | UInt64 tournament ID; no result binding |
| `0x142136240` | 145/29 registration | Typed JSON string; one `bdStringResult` |

Native registration `0x1410758E0` supplies `data_center` and `tournament_name`
in a 256-byte JSON buffer. Its completion `0x141070FC0` reads numeric
`start_search_offset_seconds` from the response. Native bracket consumer
`0x141074530` reads `tournamentID`, `tournamentStatus`, `tournamentDefinition`,
`players`, `teams` and `rounds`. The handler validates their native array
indices and sizes before returning a document.

Publish `data/tournaments/<title>/catalog.json` with this envelope:

```json
{
  "schema": 1,
  "title": 5800,
  "tournaments": [
    {
      "id": 173,
      "name": "<UTC tournament time as a decimal string>",
      "data_center": "local",
      "expires": 2000000000,
      "registration_open": true,
      "start_search_offset_seconds": 3.5,
      "state": "<complete bracket object described below>"
    }
  ]
}
```

The example's `state` string is a schema placeholder; replace it with an object.
The server rejects that placeholder. A complete independently generated
example is available in `tools/tournament_fixtures.py`.

A bracket object contains:

- `tournamentID`: the publication's nonzero UInt64 ID.
- `tournamentStatus`: `FORMING` or `PLAYING`.
- `tournamentDefinition`: `teamSize` from 1 to 4, `numTeams` of 8 or 16,
  and `numPlayers` equal to their product. Forming brackets may contain empty slots.
- `players`: unique `{ "playerID": <UInt64> }` rows corresponding exactly to
  assigned team members.
- `teams`: 8 or 16 rows in native index order, each with `teamID` equal to its
  index and a `playerIDs` array of at most `teamSize` unique nonzero users.
- `rounds`: exactly 3 or 4 rows. Each `roundID` equals its index; the `matches`
  array has `numTeams >> (roundID + 1)` elements.
- Each match has `teamIDs` containing at most two valid team indices,
  `readyPlayerIDs` containing unique members of those teams, UInt64 `lobbyID`
  and Boolean `expired`. Optional `winningTeamID` is -1 or one of its teams;
  optional `matchResultPayload.scores` has at most two UInt16 values.
  An expired match also needs a signed integer `expireReason`.

No team may appear in two matches in the same round. The complete wire document
must fit the native 16 KiB string buffer, including its terminator. The catalog
is bounded to 128 publications and 2 MiB. Numeric fields are validated before
narrowing them for native indices; large UInt64 values cannot wrap into a valid
team, team-size or winner index.

Registration only enrolls the authenticated user when the named datacenter and
tournament are open and unexpired. A publication with an explicit `state` must
already assign that user to a team. Automatic `formation` publications accept
registration before assignment; the authenticated party search allocates its
real members as described below. A second enrollment cannot replace an active tournament.
Retries return the same registration response without rewriting enrollment.

`enrollments.json` stores up to 4,096 players for that title in a single atomic
replacement. Ready-up affects the first unfinished match for that player and
is visible to both participants. Accept and rejoin preserve readiness. Decline
and leave remove only the authenticated user's enrollment. Leaving is
idempotent and can succeed even if a catalog has become invalid or unavailable.
New ready-up records include the native round and match indices. They cannot
automatically ready a player for the next round after a result arrives. Legacy
records without these indices apply only to round zero.
After a backend restart, authenticated reconnects recover enrollment and
readiness. Expired or removed publications cannot produce a positive state.

Malformed client requests return 106 before mutation. Invalid persisted or
published JSON returns storage failure 102. Unpublished registration returns
108; unassigned users receive 101; absent enrollment or an expired bracket
returns Replay's player-not-in-tournament 14526.

## Host-authorized results and advancement

The exact request produced by Replay `0x141076A10` is:

```json
{
  "tournamentID": 173,
  "lobbyID": 174,
  "winningTeamID": 0,
  "matchResultPayload": {"scores": [6, 4]}
}
```

Both IDs are nonzero UInt64 values. The winning team is a global bracket index,
not a local score index; both scores are UInt16 values. The request contains
exactly these four keys, and the payload contains only the two scores. Duplicate
keys, trailing wire fields, floats, negative values and narrowing overflow are
rejected before mutation.

The signed player must accept enrollment, belong to the reported match and own
its actual title-scoped matchmaking lobby. Both assigned teams must have members
present in that lobby. The lobby must be live and undisbanded, and the match must
be published as PLAYING, unexpired and have both previous winners available for
later rounds. No request-supplied user ID can grant authority. The shared lobby
reader validates the persisted envelope, membership, host document and lobby ID
before authorization. Missing or inactive lobbies remain unavailable.

`results/<tournamentID>.json` stores a single atomic journal with `schema`,
`title`, `tournament` and `results`. Each accepted entry records `round`, `match`,
`lobby`, `reporter`, `teams`, `winner`, two `scores` and `recorded` UTC seconds.
There are at most fifteen unique matches, the maximum in a sixteen-team bracket.
The original reporting user can repeat the exact result without a write,
including after a server restart or lobby expiry. A different result for the
same completed match returns 14536, which the exact Replay completion
`0x141078610` recognizes as nonretryable. Invalid tournament IDs return its
other nonretryable error, 14529. A foreign reporting user receives 101.

Task 145/20 derives its document from the current publication and that journal.
It fills each destination match only once both preceding winners are known,
preserving left/right score and global-team order. Advancement alone never
allocates a next-round lobby; the scheduler below requires fresh readiness and
live party searches. Its complete output is validated against Replay's native fixed arrays
and 16 KiB capacity before returning it. Replay `0x141071680` checks these same
two-child prerequisites; `0x141074530` reads the winner, team IDs and scores.

Every journal entry must still match its published lobby and assigned teams.
Reusing an already completed match slot for different teams or a new lobby
returns storage failure 102 rather than applying an obsolete result. Publish a
new tournament ID for a different competition. Corrupt or inconsistent state
is preserved for diagnosis. Results do not rewrite the catalog or enrollment;
publication edits are observed on the next request without a server restart.

## Native update notifications

Accepted membership, readiness and newly committed results send an encrypted
async-matchmaker event to the tournament's accepted, assigned participants.
Replay's exact decoder `0x14213F1C0` reads event 2010 as one typed bracket string,
with no separate tournament ID or synthetic length. The game callback
`0x14103F3F0` forwards that string to `OnlineTournament_OnUpdateTournament`.
The bracket is the same validated document returned by task 145/20.

Notifications use the existing delayed, serialized endpoint writer. Before
writing each frame, the server rereads the current publication, result journal
and enrollment, checks that the user is still accepted, and compares the full
derived bracket SHA256. Leaving revokes queued updates; a newer readiness/result
snapshot suppresses older queued documents. Exact idempotent task retries do
not generate duplicate updates. Each current, authenticated connection for an
eligible account can receive the update; offline accounts recover through task
145/20. This event carries derived state; the capacity allocator described below
owns automatic formation.

## Native tournament search and join

Replay `OnlineMatchmakerOmniscient::StartMatchmaking` at `0x14104A450` emits
`"tournament":{"team_size":N}` in its ordinary task-145/18 search document.
The backend intercepts that exact search form after validating every party
member's matchmaking token and live issuing session. All members must have
registered for the same unexpired publication and fit its team size. Legacy
bracket publications require the same published team; automatic publications
reserve capacity for the whole authenticated party. Private-lobby/presence-join instructions cannot be
combined with a tournament formation search. Ordinary multiplayer searches
retain their existing map/rules/host assignment path.

A formation search returns the usual `{"mm_id":...}` string result and emits
event **2009** to its registered, unaccepted party members. The exact target
decoder at `0x14213F1C0` reads a typed UInt64 **matchmaking search ID**, followed
by one typed bracket string. There is no extra length or tournament-ID field.
Callback `0x14103F330` sets the matchmaker's tournament ID from the bracket and
calls `OnlineTournament_OnJoinTournament` at `0x141073FC0`, which queues the
game's native acknowledgement. The server does not seed accepted enrollment.
Task 145/23 remains the authenticated acceptance/decline operation.

The search and `matchmaking/<title>/tournament-searches.json` account index are
published together through the existing flushed, recoverable matchmaking
transaction. Formation searches use `lobby_id:0`, a tournament ID, owner
session fingerprint and exact member-session bindings. They do not create a
playable lobby or invent a native host address/DTLS key. Identical active
search retries reuse the search ID without rewriting the transaction. A new
search retires the prior indexed formation searches in that same transaction.

Pending joins use the existing idle publisher and serialized writer. Deduplication
includes event kind, search ID and derived bracket hash, so a join cannot hide
the subsequent accepted-member update with identical bracket content. Delivery
requires current enrollment, same published team, current index assignments,
unchanged member tokens, live issuing sessions and an unexpired active search.
Cancel/shutdown, leave, session replacement, expiration or publication changes
revoke stale queued frames. A reconnect under the same active issuing session
can recover a pending join; a fresh authentication session needs fresh party
tokens/search. Pending joins work without opting into idle bracket edits.

`tools/tournament_join_fixtures.py` checks the event with two independent
encrypted clients, exact returned search identity, registration before acceptance,
subsequent acknowledgement/readiness, idempotent retries, cancellation and
shutdown, replacement, malformed state and expiry. These protocol checks do
not establish that the native UI accepted a join or that a tournament is playable.
Automatic team allocation, completed bracket formation and round-to-lobby
scheduling are implemented by the capacity publication below. Native gameplay
and forfeits remain open.

## Automatic formation from authenticated parties

Publish `formation` instead of `state` to let the backend allocate the players
and generate all native teams/rounds. Its complete definition is
`{"team_size":2,"num_teams":8}`: team size is 1 through 4, team count is 8 or 16.
The surrounding row retains `id`, `name`, `data_center`, `expires`,
`registration_open` and `start_search_offset_seconds`. The name must match
Replay's scheduled tournament request. Do not include player IDs, teams, rounds
or a `state` object in this mode. `live_updates` defaults to true; specifying false
disables idle bracket edits but retains explicit lifecycle notifications.

Registration creates only the authenticated account's enrollment. A task-145/18
party search validates every live matchmaking token and every member's
registration before taking a team with enough capacity for the whole party.
Parties are never split. Searches append only their authenticated member IDs;
no filler opponents or automatic acceptance are created. Existing reservations
cannot be taken over by a different party. Native event-2009 documents describe
the actual partial allocation while its status remains `FORMING`.

The server moves the bracket to `PLAYING` only when every team is full and every
allocated user has acknowledged with an authenticated session which is still
live. The final acknowledgement commits that state and notifies all accepted
participants through event 2010. The idle publisher can also finish formation
when a temporarily disconnected issuing session returns. Automatic readiness
requires that user's accepted session and the completed bracket; formation does
not automatically ready a player or allocate a playable lobby.

`matchmaking/<title>/tournaments/<id>.json` stores the complete bounded formation
layout: schema/title/ID/expiry, immutable competition definition, party-to-team
reservations and derived native state. Its validators check every native bound,
party ownership, uniqueness and exact equality between reserved members and
bracket players. Changing name/datacenter/expiry/capacity under an existing ID
fails closed; use a new ID for a different competition. Publisher files are
never rewritten by registration or allocation.

Formation changes, search/index changes and enrollment use the existing flushed
matchmaking transaction. Its one cross-domain name `tournament-enrollments.json`
maps only to `tournaments/<title>/enrollments.json`; arbitrary parent paths are
not accepted. Complete snapshots are validated before any recovery write. A
failure after writing enrollment rolls forward the same formation snapshot
before any service reads it, and task retries retain their normal identity.

An owned leave or decline while `FORMING` releases the whole party reservation
and removes only the caller's registration. Other party members retain their
registrations but lose acceptance/readiness for the changed allocation. The
backend publishes exact native event **2011**, typed tournament ID, to those
members. A persisted disband marker permits idle/reconnect catch-up. New valid
party searches clear that marker in the allocation transaction; queued obsolete
disbands are suppressed when the user is assigned again. Once `PLAYING`, team
membership stays fixed; match forfeits remain unfinished work. Round scheduling
uses the publication described below.

`tools/tournament_formation_fixtures.py` uses eight separately authenticated
clients; six enter through signed machine registration without provisioning.
It checks partial/full formation, native array generation, acceptance gating,
readiness, immutable competition identity, interrupted cross-domain writes,
party withdrawal, event 2011, slot reuse and owned decline. These are protocol
fixtures, not native game bracket UI or playable tournament evidence.

## Ready rounds and native lobby allocation

An automatic `formation` publication may include `round_rules`: three query
objects for eight teams, or four for sixteen teams. Each query contains
`ruleset_payload` with the normal native playlist filter. Optional `performance`
and `acceptable_platforms: ["bnet"]` are supported. Client members, tokens,
capacity, listen addresses and teams are derived from authenticated searches;
they are not publisher overrides. Round rules are pinned with the competition
definition, so changing them under an allocated tournament ID fails closed.

For example, append this array to an eight-team formation publication, replacing
the playlist version with the current published catalog version:

```json
"round_rules": [
  {"ruleset_payload": {"filter": {"playlist_id": 1, "playlist_version": 13, "netcode_version": 1}}},
  {"ruleset_payload": {"filter": {"playlist_id": 1, "playlist_version": 13, "netcode_version": 1}}},
  {"ruleset_payload": {"filter": {"playlist_id": 1, "playlist_version": 13, "netcode_version": 1}}}
]
```

Round allocation also requires `native_map_pool_revision` on the publication.
It must match the canonical policy in `data/tournaments/5800/map-pools.json`:

```json
{
  "schema": 1,
  "title": 5800,
  "revision": 1,
  "rounds": [["mp_shipment"], ["mp_shipment"], ["mp_shipment"], ["mp_shipment"]]
}
```

This example uses Shipment only. No production tournament or player is seeded
by installing the backend. Four pools are required even for an eight-team
competition because Replay prepares four native round-map slots. Each pool
contains one through eight unique lowercase map identifiers of at most 23
bytes. Names use only letters, digits and underscores. Extra fields, duplicate
JSON keys, trailing data, invalid titles and revision values outside 1..65535
are rejected. Each chosen map must still exist with positive weight in that
round's published playlist and in the installation's available-map policy.

The same canonical policy supplies the four native map-name dvar strings in
the title-5800 `general` publisher namespace. Bindings come from the generated
Replay `native-dvar-names.json`, not another build's numeric addresses. Its
revision becomes the namespace's MinorVersion and cannot be older than the
configured publisher namespace version. A missing policy leaves ordinary
publisher variables unchanged; legacy formations without this opt-in do not
allocate new round lobbies. Refresh publisher variables on clients after a
new policy is published, using the existing `dw_restart` connection refresh
when needed. Backend files are read on demand; this does not require a game
executable rebuild.

The flushed atomic `map-pools.applied.json` receipt binds title, revision and
the SHA256 of the canonical JSON document. The server rejects a lower revision
or changed content under an already accepted revision, including after server
restart. Keep this receipt intact; increment the policy revision for changes.
An existing competition pins the complete policy snapshot as well as its round
rules. Publish a new competition ID for changed pools. A publication whose
requested revision is unavailable is suppressed rather than assigned a map
different from its declaration.

Map selection follows original Replay `0x141070840` / `0x141070950`. Round N
uses bits `16*N` through `16*N+15` of the full UInt64 tournament ID. Pools with
one map always select it. Larger pools first exclude every previously selected
map; when that exhausts the pool, they exclude only the immediately previous
map. Remaining candidates retain their published order, and the seed modulo
their count chooses the index. `tools/verify-tournament-native-map-selector.py`
executes the untouched PE instructions in Unicorn for 32 independent cases,
including chained unwind fragments; only the security-cookie checker is
stubbed. Build `tools/build-tournament-map-check.ps1`, then pass its executable
as `--compiled-selector` to compare against the exact selector/crypto objects
used by the backend. All 32 cases match. The Python tool needs the optional
Unicorn and Capstone packages. This is an isolated CPU check and does not
establish native tournament playability. A separate focused native startup
and reconnect pass verified application of the four strings and their revision;
see `validation/20261006-tournament-map-native-policy.json`.

A round requires two complete teams, both preceding winners when applicable,
all members' fresh round-scoped readiness and acceptance, and the actual live
sessions/tokens that authorized their party searches. Cancelled or expired
searches do not silently become valid again. Selection uses the same playlist
catalog and available-map policy as ordinary matchmaking. Unavailable maps or
missing native host information leave the lobby unallocated until a valid retry
or idle update can prepare it.

Allocation uses the shared lobby document builder and real registered native
listen address/DTLS fields. The backend document includes `tournament_id`,
UInt16-compatible `round_id` and `lobby_to_tournament_team_ids` mapping local
teams `"0"`/`"1"` to global bracket teams. Team rosters retain their actual user
IDs and party search IDs. Presence joins and user team changes are disabled;
the lobby is not a public matchmaking pool. The owned host receives native event
2005 (create), while opponents receive event 2001 (join), with the actual search
ID and ordinary host/backend document envelopes.

The formation record, lobby, affected searches, account assignment index and
enrollment snapshot share one flushed recoverable transaction. A failed write
rolls forward the same allocation, rather than creating a second lobby on retry.
Host-authorized results advance winners; the next round still requires new
readiness. Its searches retain their identity while receiving the new lobby,
round and match assignment.

The existing idle publisher recovers bracket and round delivery after a
temporary same-session disconnect. Once a round is allocated, its bracket is
delivered even if optional live publication updates were disabled, so the native
client sees the allocation before the create/join callback. Current enrollment,
host lease, token/session, search/account assignment and document snapshot are
revalidated before writing. Each connection receives a given round lobby/search
join once; ordinary host document updates continue on their existing path.

`tools/tournament_round_fixtures.py` exercises eight signed machine registrations,
map-policy waiting, interrupted coupled publication, all four first-round
allocations, temporary reconnect and all seven result-driven matches. These are
encrypted protocol checks. The pools and backend map choice share the recovered
native rule. Native tournament callbacks, host departure/forfeit rules and
playable two-game tournaments remain unverified; startup/reconnect evidence
does not establish those gates.

## Live publication changes and disband

Backend-managed competitions (formation plus pinned round rules) now cancel when
an authenticated participant who is still competing explicitly leaves (145/22)
or declines (145/23 false). The local realm deliberately publishes disband rather
than inventing a retail forfeit score or winner. Eliminated participants and the
champion after a completed final may leave without cancelling the competition.
Departure from a finished final retires its old matchmaking assignments; an
eliminated team's departure releases its completed lobbies and searches while
preserving winning-team searches needed for subsequent rounds.
Connection loss alone remains recoverable; no disconnect timeout is imposed.

The complete terminal record lives at
`matchmaking/<title>/tournament-terminations/<id>.json`. Its schema-1 fields are
`title`, `id`, `expires`, `actor`, `action` (`leave` or `decline`), `recorded`, and
the actual derived `state`, including its full native bracket. Actor membership
and continuing participation, every bracket index and the entire record are
validated. Cancellation, enrollment, lobby retirement, search deactivation and
both account assignment indexes share one flushed recoverable transaction.
A failed terminal publication must roll forward before further requests can
observe the store. Notification-source fallback cannot swallow a retirement
transaction failure. Completed match results remain intact; no result is
fabricated. Assignments to unrelated lobby/search IDs are retained.

Remaining accepted participants receive native event 2012 through the existing
idle publisher, including when live updates were disabled or a round had not
yet been allocated. Their registrations remain for authenticated leave and
diagnostics, with readiness cleared. Queued bracket/join deliveries revalidate
against the terminal snapshot; result, readiness, acceptance and registration
cannot reopen a cancelled ID. An operator must publish a new tournament ID.
Legacy explicitly supplied brackets retain their existing lifecycle behavior.

`tools/tournament_withdrawal_fixtures.py` adds encrypted signed-client checks for
both explicit tasks, pre-allocation and allocated-round cancellation, completed
participant departure, malformed-source rejection, a blocked terminal write and
owned retry, same-session reconnect, stale task rejection and complete terminal
schema rejection. `record-tournament-withdrawal-proof.py` binds those groups and
the records retained after fixture server restart to the exact backend image.
These checks do not establish native positive withdrawal callbacks, a playable
tournament or retail forfeit/disconnect policy.

Set `live_updates: true` on a publication before players register to opt those
enrollments into the idle watcher. It samples connected accepted accounts once
per second. Bracket edits produce event 2010 without a client state request or
either process restarting. The writer compares the complete derived document
and suppresses identical periodic snapshots per connection. Explicit lifecycle
task notifications still retain their normal semantics. Polling notifications
wait 500 ms and are revalidated immediately before writing; a newer document,
leave or disabled live publication suppresses an obsolete queued frame.

An expired/removed publication or removed assignment emits event 2012: typed
UInt64 tournament ID, typed UInt64 reason, and typed message string after the
event number. This local realm uses reason zero for unavailable publication.
Replay's decoder `0x14213F1C0` and callback `0x14103F470` define this envelope.
Corrupt publication data suppresses delivery and remains a task-level storage
error. It is never converted into a synthetic tournament disband. A removed
publication leaves enrollment available for diagnosis or an authenticated leave.
The same missing/expired snapshot is sent once per connection; a restored
publication can send a fresh bracket. Native join/formation and playable round
callback validation remain separate work.

Native validation changed a PLAYING publication from 16 players in teams of two
to eight players in teams of one. The same running game parsed the changed
counts without a tournament task or either process restarting. Expiring that
publication then delivered event 2012: Replay displayed "Tournament has been
disbanded" and cleared its tournament state/bracket while DW stayed connected.
The receiver fixture still explicitly seeds acceptance after actual native UI
registration; this does not establish native join-assignment completion.
`verify-native-tournament-publication.py` records the edit/log boundary and
requires the native before/after counts, unchanged process receipts, cleared
expiry state and exact data restoration. Its screenshot remains separate
visual evidence of the native error message. No match is scheduled by the tool.

Independent encrypted clients verify receipt by both reporting and opposing
accounts, the exact target event layout, stale snapshot suppression and recipient
revocation. The native receiver check completed actual UI registration, then
received FORMING and PLAYING event-2010 documents. Read-only observations found
the delivered tournament ID and the native arrays' 16 participants, team size 2,
8 teams, 3 rounds and local team 0. FORMING correctly leaves these counts unset;
the target parser fills them after formation. Recipient acceptance was explicitly
seeded in backend fixture data, so this verifies the decoder/parser without
claiming native join-assignment completion. No lobby or map was scheduled. Exact
pre-test publication and enrollment bytes were restored and both processes were
restarted. `verify-native-tournament-update.py` sends the bounded fixture;
`record-native-tournament-update.py` requires observed counts, image hashes and
restoration before writing its separate proof.

Independent encrypted-wire tests cover these methods, full bracket bounds,
ownership, retry, result conflict, advancement and process restart. Their passing receipt is distinct from
native positive tournament callback validation. The native menu test completed
registration, parsed the 600.25 search offset through the real callback, and
displayed the expected countdown. After restarting both game and server, native
145/20 read the persisted bracket and its completion parsed the exact tournament
ID into the rejoin candidate. `record-native-tournament-proof.py` requires those
two observations and their exact executable hashes. Ready/accept/decline/leave/
rejoin native callbacks, bracket UI rendering and playable tournaments remain
unverified. Positive event decoding and bracket parsing are verified as described
above. The native 145/21 positive result callback remains unobserved; its
protocol fixtures are not a substitute. No match was started. Menu/startup validation alone does not
establish that a tournament can be played.
