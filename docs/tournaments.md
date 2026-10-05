# Replay tournament publication and owned lifecycle

The server implements Replay tasks 145/19, 20, 21, 22, 23, 28 and 29. These are
backend handlers, without game executable changes or fabricated native fences.
The implementation uses an explicit published bracket. Automatic scheduling,
forming teams from matchmaking parties, match assignment and join/disband push
events remain separate work. Host-authorized result submissions persist
the scores and advance winners in the published bracket. Task 145/27 from another
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
tournament are open, unexpired, and the bracket actually assigns that user to a
team. Publication therefore grants membership explicitly; it never trusts a
request's player ID. A second enrollment cannot replace an active tournament.
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
preserving left/right score and global-team order. It never invents a next-round
lobby. Its complete output is validated against Replay's native fixed arrays
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
145/20. This is an update transport, not an automatic team-formation scheduler.

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
