# Player names and native friends

The executable reads `game_dx12_ship_replay_dw.ini` beside itself, then
`replay-dw.ini` as a fallback. Set `player_name=YourName` and fully restart the
game. Names contain 1..35 printable ASCII characters, without `#`, `%`, or spaces
at either end. Names are unique on this backend, ignoring letter case. Omitting
the field keeps the account's last saved name.

The selected profile and its access key determine the account. Changing the
name retains the same universal ID, platform account ID, settings and friends.
The server authenticates the profile before persisting the new name and signing
its existing identity payload. No game binary patch or proxy is involved.

Every person needs a separate guest package. Do not share one guest INI between
simultaneous players: it selects the same account. To provision another player
from the backend directory, before anyone signs in:

```powershell
.\new-guest.ps1 -Profile remote-test-4 -PlayerName "MyFriend"
```

The script stops the backend, provisions a persistent identity and a random
private access key, restarts the backend, and creates a four-file ZIP under
`data`. Existing accounts are never overwritten. Repackage an existing account
with `python tools\package-remote-guest.py --profile remote-test-4`.
Packaging preserves the host INI. Guest packages contain no backend signing
keys, game assets, or proxy DLLs. Keep each package private.

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
The backend returns UNO and Battle.net representations of its own provisioned
identities, exact or terminal-prefix name matches, and empty results for unknown
users/providers. It never manufactures third-party accounts.

The opt-in `dw_localTestAddFriend "Name#0"` command exists only when the local
development marker is present at startup. It calls the same
`Online_Friends::Crossplay_AddPlayerByName` entry point as
`Social.AddFriendCrossplay`. The native search callback resolves the UNO account
and submits the invitation; the test command does not edit friendship state.

For an owner-requested fresh social test, stop the backend and run
`python tools\reset-test-friendships.py`, then start it again. This clears
relationships/requests involving the host and configured guests across social
contexts, retaining original stores privately under
`data/retained-test-friendships`. It is an explicit reset tool, never a startup
action.
