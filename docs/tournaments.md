# Replay tournament publication and owned lifecycle

The server implements Replay tasks 145/19, 20, 22, 23, 28 and 29. These are
backend handlers, without game executable changes or fabricated native fences.
The implementation uses an explicit published bracket. Automatic scheduling,
forming teams from matchmaking parties, match assignment, tournament push
notifications and result advancement remain separate work. Legacy task 145/21
has a recovered string request but no reviewed domain contract, and remains
unavailable. Task 145/27 from another source build is not silently substituted.

The following evidence comes from the original Replay executable and its
SQLite export; display aliases in that export can be misleading:

| Original Replay VA | Task | Request/result |
| --- | --- | --- |
| `0x142136110` | 145/19 ready | UInt64 tournament ID, UInt64 `0xFFFFFFFF`; no result binding |
| existing 145/20 writer, game `0x141075F30` | 145/20 state | No parameters; one `bdStringResult`, native callback `0x141077F20` accepts not-enrolled error 14526 |
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
After a backend restart, authenticated reconnects recover enrollment and
readiness. Expired or removed publications cannot produce a positive state.

Malformed client requests return 106 before mutation. Invalid persisted or
published JSON returns storage failure 102. Unpublished registration returns
108; unassigned users receive 101; absent enrollment or an expired bracket
returns Replay's player-not-in-tournament 14526.

Independent encrypted-wire tests cover these methods, full bracket bounds,
ownership, retry and process restart. Their passing receipt is distinct from
native positive tournament callback validation. The native menu test completed
registration, parsed the 600.25 search offset through the real callback, and
displayed the expected countdown. After restarting both game and server, native
145/20 read the persisted bracket and its completion parsed the exact tournament
ID into the rejoin candidate. `record-native-tournament-proof.py` requires those
two observations and their exact executable hashes. Ready/accept/decline/leave/
rejoin native callbacks, bracket push rendering and playable tournaments remain
unverified. No match was started. Menu/startup validation alone does not
establish that a tournament can be played.
