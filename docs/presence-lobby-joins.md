# Replay presence lobby joins

Replay's `OnlineMatchmakerOmniscient::StartMatchmaking` at original VA
`0x14104A450` sends the ordinary `members` and `tokens` arrays, with either
`lobby_id_to_presence_join` or `player_id_to_presence_join` instead of a new
playlist filter. Service 145/task 18 recognizes this path before new-lobby
selection. The party must contain the authenticated requester, and each member
must have a valid issued matchmaking token.

The existing lobby must be unexpired, not disbanded, open for presence joins,
and have room for every distinct joining member. The request's `lobby_slots.max`
sets creation capacity, bounded to 200; legacy files without that field retain
the existing 200-member limit. SDK source oracle
`Playlist_WritePlaylistLobbySlotsJSON` supplies the slot-field interpretation.
Match selection is rechecked against the current published playlist and
installed-map policy. Joining cannot silently replace unavailable maps.
The host must have a live authenticated lobby connection. Presence-by-player
also requires the target member to be online; persisted lobby files cannot
revive disconnected sessions after a stop or restart.

The join preserves the lobby ID, native listen-server address, DTLS credentials,
and ruleset/map weights. It advances the host/backend revision, adds unique
members to the least-populated existing team, retains existing members' search
IDs, and assigns the joining party a new matchmaking search ID. Joining members
remain owner-restricted for host-document updates and disband.

Replay's async decoder at `0x14213F1C0` consumes event 2001 as typed UInt64
matchmaking ID, UInt64 lobby ID, host string, then backend string. Only the
joining party receives this event. Existing nonjoining members receive event
2006 with lobby ID, update ID and the same documents. Cancelling a joining
search before delivery suppresses its queued event; an already committed lobby
document update remains visible to existing members.
An assignment is also suppressed if the member's current matchmaking ID has
already been replaced by a newer search. Delivery uses the existing connection
and service-store locking; it does not infer connectivity from a presence file.

`data/matchmaking/<title>/current-lobbies.json` stores the most recent assignment
for each member. Presence-by-player uses this index rather than choosing an
arbitrary historical lobby. The index is bounded to 4096 accounts and validated
before committing new documents. Pre-upgrade lobbies remain accessible by
explicit lobby ID; successful joins index their members. Lobby, search and index
now publish through a flushed transaction with pre-read and startup recovery;
see [matchmaking-transactions.md](matchmaking-transactions.md) for the commit,
storage-error and notification semantics.

`tools/lobby_join_fixtures.py`, included by `tools/test-lobby.py`, uses independent
encrypted clients and two separately provisioned accounts. It covers valid
full-lobby rejection, malformed targets, invalid tokens, closed joins, both
native join fields, exact event layouts/recipients, shared document reads,
host-only updates, repeated unique membership, cancellation, map withdrawal
and disband. It launches no map and modifies only isolated fixture data.
Wire acceptance remains separate from two-game playability.

`tools/native-social-test.py lobby` provisions no new account and uses only the
existing `native-social` validation identity. It obtains its own matchmaking
token/lobby through real tasks, binds an unused loopback UDP endpoint, and
publishes its own presence. It answers only the running game's `INV:\0\0`
session-info request through service 6/task 14. Replay's actual consumer
`0x140F1E480` and join-info deserializer `0x14106E1E0` verify the header and full
129-byte layout: game mode/matchmaking/platform, lobby/tournament IDs, block flag,
session-present byte, 84-byte common address, 16-byte security key, 8-byte ID.
No game or DTLS server is emulated by this peer.

The native friend-menu path was exercised with this peer. Replay sent
`player_id_to_presence_join`; its live matchmaking instance then held the
assigned lobby ID and peer host ID in states 7/4, with all 27 startup fences
passing. `tools/record-native-presence-join.py` verifies the process/hash-bound
observation against the persisted signed request and lobby membership. The
sanitized receipt is `validation/20261005-native-presence-join.json`.
The expected final host-connection timeout is explicitly recorded: this proves
the native session-info exchange and backend lobby assignment, not two-game
network connectivity or a playable map. The test peer disbands its lobby at the
end; remove its temporary relationship with `native-social-test.py remove`.

Host migration, cross-lobby merging, automatic public matchmaking fill and
tournament match scheduling remain separate work.
