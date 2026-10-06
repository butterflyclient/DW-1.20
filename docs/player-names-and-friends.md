# Player names and native friends

The executable reads `game_dx12_ship_replay_dw.ini` beside itself, then
`replay-dw.ini` as a fallback. Set `player_name=YourName` and fully restart the
game. Names contain 1..35 printable ASCII characters, without `#`, `%`, or spaces
at either end. Names are unique on this backend, ignoring letter case. Omitting
the field keeps the account's last saved name.

On first launch, the game creates `%LOCALAPPDATA%\ReplayDW\player-identity.bin`
for the current Windows user. It contains a P-256 private key protected by user
DPAPI. Subsequent launches reuse it, so replacing the EXE or INI does not change
the player. Never distribute or delete this file. A corrupt or inaccessible file
fails sign-in rather than silently creating another account. A completed pending
first-launch save is recovered after an interrupted process.

The backend sends a 30-second, single-use challenge. The client signs that
challenge, its public key, a fresh nonce and the requested player name. After
verification, an unknown public-key fingerprint automatically creates an account;
a known fingerprint selects its persisted account. Universal/platform IDs remain
stable through renames. Account metadata lives in
`data/platform-client-profiles/<public-key-sha256>.bin`. Private keys stay local.
No host provisioning, selected profile or access key is needed for players.

Every person uses the same four-file `data/Replay-DW-Client-Test.zip`. Package it
with `new-guest.ps1` (no arguments); this no longer stops the server or creates
accounts. Packaging preserves the host INI and excludes identities, backend
signing keys, access keys, game assets and proxy DLLs. Blank `player_name` creates
a unique `ReplayPlayer-...` default on first registration; later blank names keep
the existing name. Legacy manually provisioned identities are retained only for
private protocol fixtures and are not selected by the new game login path.
Automatic accounts take precedence over matching legacy fixture names in native
name search. Legacy fixture names cannot block a new player's chosen name;
duplicate names between automatic player accounts are rejected.

New players start without friends. In Multiplayer, open Social, Add Friends,
select Activision Account, and enter the other player's name or `Name#0`.
The other player accepts it in Friend Requests. Requests, acceptances, removal,
presence and list refresh use the existing native game tasks and callbacks.
Accepted friendships persist on the server, so future launches retain them.

The native name search is `umbrella / UserResource / usernamesearch`, GET
`/v1.0/users/?client=...&searchType=username&username=...&provider=...`.
Replay's serializer is at original VA `0x1420FCBB0`; the response reader is
`0x1420FD110`. `0x1420FCF50` reads `users[].accounts[]`, and `0x14210B940`
requires provider, accountID, created and updated, with an optional username.
The backend returns UNO and Battle.net representations of its own registered
identities, exact or terminal-prefix name matches, and empty results for unknown
users/providers. It never manufactures third-party accounts.

The opt-in `dw_localTestAddFriend "Name#0"` command exists only when the local
development marker is present at startup. It calls the same
`Online_Friends::Crossplay_AddPlayerByName` entry point as
`Social.AddFriendCrossplay`. The native search callback resolves the UNO account
and submits the invitation; the test command does not edit friendship state.

New automatic accounts begin with empty native friend/request lists. Neither
client nor server clears friendships on startup. Existing accepted friends and
requests persist through game and server restarts.

Native settings remain in `Documents\Call of Duty Modern Warfare\players`, using
the stable game account ID for `settings.<id>.iw8`. The game selects its native
`CODPC_NOCLOUD_SYNC` opt-out before sign-in. Settings serialization stays inside
the original engine; progression, loadouts and friendships retain backend storage.

For development launches, `launch-game.ps1` creates the game through local WMI
with the root game folder as its working directory. This avoids packaged editors'
AppData virtualization, so developer and ordinary Explorer launches select the
same Windows user's identity. The distributed CMD starts the EXE normally.

The current compiled image was validated in the native game: stable automatic
account across three processes, all 27 startup fences passing, Online publication,
native setting save/reload/restore, and name-based invitation, acceptance,
friendship persistence and removal. The final friend/request lists are empty.
See `validation/20261005-machine-local-player-identity.json` for scoped evidence.
Two-network party gameplay still needs the host/guest retest.
