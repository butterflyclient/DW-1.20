# IW8 Replay local Demonware backend

Source-compiled C++ backend and private engine integration for
`E:\IW8\Builds\1.20-replay\game_dx12_ship_replay_dw.exe`.
Native login, publisher initialization, reconciliation, local datacenter QoS,
a catalog-driven Shipment session, clan activation, and friend
invitation/acceptance/removal have been verified in the game. Full service
coverage remains in development. Wire fixtures and game-side completion are
separate evidence gates.

## Repository and formatting

Development source is maintained in the private `IDARETW/IW8-Replay-DW`
repository. Commit new backend implementations after the relevant build,
independent fixtures and available native validation pass. `format-backend.ps1`
applies the checked-in C++ style; `format-backend.ps1 -Check` verifies it without
rewriting files. Keep functions, control flow and declarations in readable blocks.
Python tooling follows Black's formatting with a Python 3.12 target.

Runtime `data/`, signing and relay issuer keys, player profiles, credentials,
recordings, binaries and the frozen `replay-workstation/` compiler copy are
excluded from Git. The private compiler workflow still uses that local copy;
the repository does not redistribute the game image or its analysis database.
The original compiled engine crypto source remains byte-for-byte preserved so
backend-only rebuilds continue to validate against the existing game executable.

## Run and restart

Run `E:\IW8\Builds\1.20-replay\Run_Replay_DW.cmd`, or `launch-game.ps1` here.
The launcher verifies deployment and backend receipts, saves a counter/log
baseline, and uses the root game folder as its working directory.

Backend iterations use controlled restarts: close only the verified DW game,
run `stop-server.ps1`, build with `build-server.ps1`, validate, start with
`start-server.ps1`, refresh `update-server-deployment.ps1`, then launch.
The currently broken `dw_leave` command must not be used. Do not reissue the
default account's platform/auth credentials while the game runs; doing so
invalidates its session.

`refresh-game-connection.ps1` records dispatch of `dw_restart`; dispatch and
`DW_RESTART_CONNECTED` alone do not prove that native networking, permissions
and menu initialization recovered. The live cold-server-restart test reached
DW connected state but left native networking/permission fences failed. A
separate reconnect/menu-return experiment exited the game. Use controlled
game/server restarts for binary updates until the engine lifecycle is resolved.
Disk-backed publications, including marketing and scripted-loot catalogs, are
read per request and can already be updated without restarting either process.

The server binds loopback and provides a local realm. External account linking,
live Activision services and remote multiplayer deployment remain
unfinished. Ordinary Replay, shared compiler work, assets and proxy configuration
are preserved. Backend-only work does not rebuild or patch the game EXE.

## Native game evidence

Evidence lives under `data/`. Observations verify the live process/image hash,
ASLR base and linked symbols. Earlier receipts retain their original server hash;
they are not silently promoted to a newer build.

| Evidence | Native result |
|---|---|
| runtime-social-20261005.json / runtime-social-menu-20261005.json | Connected HSM state 33, sign-in 2, publisher application, reconciliation and datacenter QoS completion |
| runtime-catalog-lobby-native.json / runtime-catalog-match-return.json | Catalog lobby/host documents and Shipment match/return |
| native-catalog-shipment-match-20261005.jpg / native-catalog-shipment-result-20261005.jpg | Match/result screenshots |
| runtime-native-clan-activation.json / native-clan-test.json | Clan activation state 4; member/file/channel queries; temporary group removed |
| runtime-native-friends-accepted.json / runtime-native-friends-removed.json | Actual UI acceptance and game-cache insertion, then revocation push/cache removal |
| native-social-invite.json / native-social-remove.json | Hash-bound friend lifecycle receipts and temporary relationship cleanup |
| native-friends-accepted-20261005.jpg | Native Social screen after acceptance |
| runtime-scheduled-services-login.json | Fresh successful login after scheduled/performance integration |
| runtime-clan-role-accepted.json | Native invitation acceptance task completed after resolving the role-zero default; activation permission issue recorded separately |
| lobby-verification.json | Latest independent wire checks, backend/KDF hash and fixture directory |

`observe-game.ps1` or `tools/observe-game.py --output data/<name>.json` reads
native state without modifying it. `--pid` supports directly launched games and
distinguishes them from a correlated launcher receipt. Native commands and
`screenshotJpeg` use `invoke-game-command.ps1`. A backend ACK alone is not
native client completion.

## Implemented domains

Decimal IDs are recovered from Replay constructors, serializers and readers.
SQLite names are sometimes incorrect. SDK source supplies behavior context;
its build-specific addresses and task IDs are not blindly transferred.

| Service | Tasks | Behavior |
|---|---|---|
| Platform/auth | Signed provider, native auth/legacy/lobby | Persistent identity/resources, signed tickets, credential-bound encrypted protocol 210, connection lifecycle |
| 8 | 1â€“8 | Public/private profiles, ownership and deletion |
| 10 | 10, 11, 12, 17, 21 | Contextual files/backup and configured publisher files |
| 12 | 1, 6, 12, 13 | Local string policy, UTF-8/control sanitizer and seconds/milliseconds time |
| 3 | 46 | Explicit published legacy team catalog, complete DTO and paging |
| 6 | 14 | Signed sender-bound instant messages and encrypted push 21 |
| 23 | 1, 2 | Atomic signed global counter increments and totals |
| 27 | 2 | Complete DML geography DTO |
| 38 | 2, 6, 7, 8 | Complete challenge-response reports with signed/NAN values and bounded log, extended auth reports, session binding and receipts |
| 95 | 1, 3 | Publisher JSON/version DTOs; title 5800/build 967 defaults include autobuild and six standard namespaces |
| 193 | 6, 7, 8, 16 | User-object CRUD/read, publisher single/metadata batches, native missing indexes, checksums, immutable HTTP content |
| 29 | 4, 5, 7, 9, 10 | Durable mail send/header/body/delete, packed arrays, read state and expiration return |
| 4 | 1, 4, 11, 13, 14, 16, 17 | Atomic replace/add/max writes; rank/entity reads; included/excluded asset-column projections; trusted local server-validated stat batches with atomic retry receipts |
| 67 | 5, 6 | Durable telemetry archive/recent window and native filter initialization/push |
| 80 | 69, 106, 125, 132, 134, 243, 245 | Native inventory/balance reads, published SKU catalog, atomic owner purchases with full ResultV4/PlayerAssetsV3 or legacy coupon results, signed-credential reconciliation |
| 123 | 1, 2 | Published redeemable codes/payloads, atomic inventory/currency grants, owner binding and durable retry receipts |
| 151 | 1 | Explicit local esports-registration publication and native boolean DTO |
| 104 / 194 | 6, 7 / 1 | Full published marketing messages with native field/blob layouts and location/language/time selection, owned view receipts and signed empty AB enrollment |
| 195 | 1 | Full native scripted-loot proxy transport, explicitly published deterministic script responses and ordered owner-scoped task journals |
| 50 / 58 | 2, 3, 5, 6, 9, 10, 15, 16, 18, 19, 20 / 5, 6, 18, 20, 21 | Whole-file metadata/listing, real HTTP upload/download/COPY, persistent user/multipart stages, owner-bound upload/copy commits, tags/summaries and safe retry receipts |
| 125 | 1, 2, 3, 4, 5, 6, 9 | Published achievement definitions/states/activation, complete owner/batch event ingestion, binary/REST retry normalization, archived receipts and user-state JSON |
| 145 | 2, 3, 4, 8, 9, 10, 13, 15, 16, 18, 19, 20, 21, 22, 23, 24, 25, 26, 28, 29 | Player/token, real UDP QoS, relay discovery/authentication, playlist catalog, lobby/host CAS and lifecycle; published tournament lifecycle, host-authorized results, winner advancement, authenticated bracket updates and live publication/disband pushes |
| 197 | 10, 11 | Ordered provisioned-account aliases and explicit invalid slots |
| 197 | 20â€“32, 37 | Clan create/query/invite/consent/roles/removal, cooldowns, atomic membership replacement, native role-zero acceptance, active membership, paging, versioned files and pushes 77â€“84 |
| 198 | 1â€“7, 12 | Channel lifecycle/info/members, encrypted messages/whispers and disconnect cleanup |
| 150 | 1â€“4 | Published schedules, complete paired packed-array DTOs and member-bound event journaling |
| 152 | 1 | Owner-bound performance batches with signed Int64/NAN and persistent game-type history |
| 255 | 10 | Native REST; friend lifecycle/pushes, user-list CRUD/metadata/trim/paging, scoped presence/snapshots/subscriptions/offline pushes, achievement events and configured GET |

Friends use the game's evidenced **cod-shared** context. Presence and user lists
retain the context requested by the client. Known local friend rows include their
native presence snapshot. Names are supplied only for provisioned accounts.
Friendship requires reciprocal consent. Online status/subscriptions belong to
live connections, and old notifications are revision-checked before delivery.
Presence unsubscribe returns HTTP 200 with `errorUsers: []`: Replay binds the
complete native response even though its request is a DELETE. An empty HTTP 204
response left the native removal queue pending and caused retries every frame.
The native completion queue now clears after actual unsubscribe requests.

## Persistent data and configuration

Writes flush temporary files and publish atomically. Owners, contexts, wire
types and capacities are bounded. Opaque profile/stat payloads are preserved.
Credentials, request bodies, headers and retry tokens are excluded from logs.

- `data/platform-profile.bin`: stable default identity; never replace it to make a peer.
- `data/platform-profiles/<key>.bin`: additional stable identities. With the backend stopped, run `build/Release/iw8-dw-server.exe data --provision-profile <key> <name>`. Existing keys cannot be overwritten. Optional `/platform/login/<key>` issues independent credentials; the current game still selects the default profile.
- `data/profiles/<title>/<user>/{public,private}.bin`: opaque profiles.
- `data/storage/<title>/<context>/<user>/<name>.dwfile`: contextual files.
- `data/objectstore/users/<title>/<context>/uno-<user>/<name>.object.json`: native user-object content/metadata/tags. The bnet alias selects the same signed universal ID.
- `data/objectstore/publisher`: configured publisher metadata/content; use the supplied publication tools.
- `data/publisher-variables/<title>/<context-or-_default>/<namespace>.json`: string values; MajorVersion/MinorVersion match wire versions.
- `data/leaderboard-stats/<title>/<user>.json`: ratings/nullable columns; projection requires a matching published board definition.
- `data/marketplace/<title>/catalog.json`: complete native SKU fields and explicit prices/sale windows. `purchase-rules.json` separately publishes schema 1, a `rules` array with `sku`, `enabled`, `sources`, `maximum_quantity`, `allow_ignore_entitlements`, `items` and `currencies`. Each purchase debits all published SKU prices and applies its declared grants atomically; no product/price/grant is inferred from a bare SKU ID.
- `data/marketplace/<title>/<user>/inventory.json`: inventory, balances and owner/title-bound checksummed purchase/redemption receipts. A nonempty client transaction ID supports exact retry. Empty transaction IDs create distinct intents and return a generated 24-character ID that can subsequently be retried. Task 106 returns at most 255 coupons. Task 125 accepts 255 SKU orders, verifies supplied expected prices, preserves transaction metadata and uses a 32-bit source type. Its full asset snapshot inherits one owner and includes up to 10 UInt32 currency balances, 2048 InventoryV3 entries, 1000 entitlement/level pairs and 2048 held CouponV4 records. An incompatible snapshot is rejected before any debit is committed. Each retained exact response is bounded to 128 KiB; up to 4096 purchase receipts can be retained. Retries cannot change request content or switch between result formats. CouponOrderV2 redemption requests, discounts and cross-account purchases remain unavailable.
- `data/social/<title>/<SHA256(context)>/friends.json`: pending and consented relationships.
- `data/social/<title>/<SHA256(context)>/<user>/lists.json`: lists, scores and metadata.
- `data/presence/<title>/<SHA256(context)>/<user>.json`: scoped presence. Legacy unscoped files are readable only as iw8 data. Online state, subscriptions and revisions reset on restart.
- `data/mail/<title>/<context>/messages.json`: durable mail/IDs/expiration.
- `data/clans/<title>/groups.json`: clans, members, invitations and group files.
- `data/anti-cheat/<title>/<user>/<request-sha256>.json`: local challenge-response reports; signed values and NAN remain distinct, logs are bounded to 64 bytes, exact retries retain the receipt. These are report acknowledgements, not attestation or fabricated security verdicts.
- `data/counters/<title>.json`: shared signed counter totals.
- `data/teams/<title>/<context>/teams.json`: explicitly published legacy teams and member statuses.
- `data/content-streaming/<title>`: complete whole-file metadata and immutable payloads/capabilities. Upload completion verifies actual transferred bytes before publication.
- Whole-user uploads use persistent `user-uploads.json` staging and atomic `files.json` result receipts. See [the full contract and validation limits](docs/user-content-upload.md), including source-oracle preparation provenance and the unresolved optional checksum mode.
- `data/content-streaming/<title>/multipart.json`: signed-owner multipart staging and stable ten-URL pages. Parts are immutable, capabilities expire after ten inactive minutes, and a commit verifies every contiguous part and the byte total before publishing one file. Limits are 128 active sessions, 1024 parts per file and 16 MiB per file. A 64 MiB pending-data limit applies per title alongside whole-file uploads held in memory.
- `data/content-streaming/<title>/copies.json`: up to 128 source-snapshot copy stages with 600-second capabilities. `files.json` atomically commits the clone, source counter, owned slot replacement and durable `copy_receipts` journal. See [content-copy.md](docs/content-copy.md) for limits, ownership, retry behavior and target-versus-source-oracle provenance.
- `data/marketing/<title>/<context>/<user>.views.json`: owner-scoped viewed-message receipts.
- `data/marketing/<title>/<context>/catalog.json`: complete bounded message publications. See [marketing-messages.md](docs/marketing-messages.md) for the schema, native blob limits and consumer requirements.
- `data/loot-generation/<title>/<context>/catalog.json` and `receipts/<user>.json`: published exact scripted responses and durable owned task snapshots. See [scripted-loot.md](docs/scripted-loot.md) for native capacities, repeated opening semantics and remaining reward-rule/native-consumer gates.
- `data/esports/<title>/registered.json`: explicit registered-account catalog.
- `data/achievement-user-state` and `data/achievement-engine`: persistent state and explicitly published local rules.
- `data/achievements/<title>/<context>/<user>/events.json`: recent event journal and 256 hot retry receipts. Binary event UUIDs normalize to the same reversed-byte REST UUID. Batch first-party IDs are checked against signed identity claims; attribution is included in the retry digest.
- `data/achievements/<title>/<context>/<user>/receipts/<request-id-sha256>.json`: permanent title/context/owner-bound archived retry receipts. Archive publication precedes hot-receipt eviction and the next journal commit, so interruption cannot turn an accepted old request into a new event. Damaged or conflicting archives fail closed without being overwritten.

- `data/event-log/<title>/<user>/batches`: immutable accepted telemetry batches; the recent window is bounded separately.
- `data/scheduled-matches/<title>/matches.json`: schema 1 and matches array. Each row supplies id, start, end, status, affinity, base64 metadata and users with userID/accountType. Absent publication means no schedules. Member events persist in events.json.
- `data/performance/<title>/<context>/<user>.json`: game-type sample counts and bounded recent values; NAN is null.
- `data/qos/local-provider.json`: actual loopback UDP QoS provider and expiring issued security IDs.
- `data/relay/issuer-key.bin`: persistent local relay client credential issuer. Keep this private and preserve it across restarts; a damaged key is rejected rather than replaced. Task 145/26 returns Replay's exact 77-byte blob: version 1, 56 opaque bytes, 16-byte client secret and little-endian expiry delta, capped at one hour and the signed login expiry. The opaque payload encrypts owner/title/absolute expiry and authenticates the session digest and delta. `data/relay/<title>/clients/<user>.json` contains only the latest issued token hashes/expiry for native verification, without raw credentials. The local credential verifier is separate from active-login validation and UDP transport. `--inspect-relay-client-token <base64>` is an offline diagnostic; it deliberately reports `active_session_checked: false` and does not log secrets.
- `data/relay/local-provider.json`: `{"enabled":true}` starts the actual loopback UDP relay before task 145/24 advertises it. The native nested `server_info` string contains an 83-byte server credential, independently owner/title/expiry/current-relay-ID bound through AES-GCM. An unexpired client credential must also match a live signed lobby session. Server restart revokes old sessions and uses a fresh relay ID. BIND, JOIN, VERIFY, ESTABLISHED, client-origin ping echo, DATA forwarding, BIND_UPGRADE and DISCONNECT use Replay's exact headers, SHA256 HKDF labels including NUL, directional MAC keys and 32-packet replay window. DATA has a 5-byte MAC; control packets have 16. The ping byte is the ORIGIN (client=1/server=0), not a request/reply flag. Only authenticated loopback peers of the same title can forward traffic. Associations are bounded to 256 and expire on credential/session expiry, idle timeout or disconnect. `data/relay/transport-events.jsonl` records route/owner/time and verification hashes, without raw tokens or transport keys. If issuer state exists but its key is absent, initialization refuses to silently rotate the realm.
- `data/geography.json`: configured local geography, not real IP-derived location.
- `data/rest/<title>/<service>/<resource>/<operation>.json`: GET-only publication with status/body; mutations need domain handlers.

Pre-upgrade event receipts that used the raw binary retry token are still found
through their padded/unpadded URL-safe aliases. New receipts use the canonical
REST UUID; existing accepted events are preserved during upgrade.

The playlist catalog comes from unified_large_playlist_tu19.aggr and installed
map packages. Frontend/map conversion work is separate. Warzone transient
packages remain a deferred game-build concern.

## Remaining coverage

**Full emulation is not complete.** Remaining areas include:

- Playable multiuser lobby joining, host migration, automatic public matchmaking fill, tournament bracket scheduling/match assignment/join pushes and remote relay deployment/migration. Explicit presence joins by lobby/player, party-token/capacity checks, shared membership/documents and event-2001/2006 delivery have independent wire proof, plus a native friend-menu session-info exchange and lobby/host assignment; see [docs/presence-lobby-joins.md](docs/presence-lobby-joins.md) for remaining gates. The published tournament lifecycle, task-21 journal and event-2010/2012 transports are described in [docs/tournaments.md](docs/tournaments.md). Native registration, persisted-state, FORMING/PLAYING bracket parsing, idle publication changes and the disband callback were verified. The update test explicitly seeded accepted recipient enrollment; native join assignment, result/ready/accept/leave/rejoin callbacks and playable tournaments remain unverified. Local relay client/server authentication and UDP BIND/JOIN/forwarding are implemented. Native BIND/VERIFY/ESTABLISHED and decrypted SDK join-data fields are verified separately from the independent two-client JOIN/forwarding check; native two-game forwarding remains untested.
- Remaining streaming tasks 50/22 and 58/22 live/multipart download. Whole-user post and copy are implemented, but preparation IDs 50/5, 15 and 20 are source-oracle contracts without target writer proofs, and positive native upload/copy callbacks remain unobserved. Multipart download's exact bound result reader remains unresolved.
- Marketplace cross-account gifting, discount publication, inventory-token validation task 80/58, CouponOrderV2 redemption, quests and loot generation. Task 80/58 is Replay's `validateInventoryItemsToken`, with a filename and validation-token result; it is separate from a SKU purchase. Owner SKU purchases (80/106 and 80/125), full result layouts, explicit catalog grants and code redemption are implemented. Cross-account purchases remain unavailable until a multi-account transaction journal exists; a buyer is never debited before an uncommitted gift acknowledgement.
- Object-store category/list and large-upload completion families, including 193/3, 9, 10, 12 and 24. User metadata accompanies the implemented task-6 object read; source-oracle task 3 is a separate user-object listing route and remains unimplemented. Request writers for 9/10 are recovered; their exact response bindings still need resolution.
- Published achievement progression/reward rules. Replay requests achievement 1500 with no local publication, so it correctly returns unavailable. Changed-payload retry conflicts are rejected; event ingestion itself does not fabricate XP targets, quest definitions or rewards.
- Categorized mail/status and other service-family gaps require same-build constructor/reader confirmation. [Server-validated stats](docs/validated-stats.md) implement task 4/14 with trusted local authorization and atomic retries; retail token payload validation and its native positive callback remain unverified. The ordinary mail methods and esports registration result are implemented.
- Native positive completion for scheduled/performance and deeper inventory/achievement/content operations; current evidence for those is wire-level.
- Challenge reports and the full clan replacement/cooldown/push family have independent encrypted-wire and restart coverage; feature-specific native observations describe the game paths actually exercised.
- Remote multiplayer deployment and game-side additional-profile selection.

Native achievement REST ingestion and startup/menu fences were exercised in the
game. The binary 125/2 batch path has independent encrypted-wire and restart
coverage; the current game uses REST and has not produced a positive native
125/2 call. Keep those acceptance claims separate.
Multipart uploads (58/20â€“21) and owner purchases (80/106 and 80/125) have independent
encrypted-wire, real HTTP where applicable, and restart proof. A native positive
call for those deeper methods has not yet been observed.

Lobby/search/index persistence uses a recoverable flushed transaction. Creation,
joining, cancellation, host updates and disbanding recover before matchmaking
reads and server listeners. Real interrupted-write and restart checks are in
`tools/matchmaking_transaction_fixtures.py`; see
[docs/matchmaking-transactions.md](docs/matchmaking-transactions.md) for limits
and the distinction between durable recovery and callback acknowledgement.

`observe-game.py` records the live server process path/hash as well as the game
image and ASLR-resolved state. New launcher receipts bind the server process too,
so later evidence cannot silently attach old game observations to a new server.

`data/native-service-callgraph.json` inventories exact constructors/forwarders.
`tools/inventory-backend-coverage.py` joins that target evidence with reviewed
handler registrations, static fixture call sites and hash-bound native proofs.
It writes `data/backend-coverage-inventory.json` and a plain-text counterpart.
The current ledger has 140 known or explicitly reviewed task routes, 133
registered handlers and 7 known target tasks without handlers. The two copy
preparation routes are explicitly labeled as source-oracle contracts rather
than recovered target constructors. These counts do not include every indirect
SDK or REST operation; these gaps remain explicit. Fixture source references
are not presented as native completion.
Indirect/dynamic calls remain explicit audit gaps. Unsupported tasks return
native errors, without generic success replies or forced fences. Conservative
overall /health matchmaking/native_game_verified flags remain false; refer to
feature-specific evidence for the native results already validated.

`refresh-game-connection.ps1` dispatches `dw_restart` and saves a separate
connection receipt for the current server PID/hash/log offsets. It preserves the
original game launch receipt. `observe-game.py` validates either receipt and
attributes later requests to that connection; command dispatch is not assumed
to mean native completion. If a server stop has already put the game into the
network-disconnect error screen, use a controlled game restart instead.

`data/native-relay-client-verification.json` records Replay's actual token
deserialization and completion callback: native state 2, reconstructed 77-byte
token/expiry matching the issuer, all 27 fences passing and Multiplayer frontend
state 9. `tools/record-native-relay-client.py` checks these conditions explicitly.
This verifies the client credential service, not UDP relay transport.

`data/native-relay-transport-verification.json` separately records the actual
server credential consumer, native NetRelay state 6 and SDK bound-association
state 3. The decrypted SDK routing ID, relay ID, endpoint and verification hash
must match the server's authenticated UDP establishment event. Stability evidence
compares the same native route across at least 60 seconds and real ping echoes.
Packet rejection is separate from provider failure: socket-send, socket-wait or
durable event-write failure withdraws the provider and clears active routes.
The relay health object reports a bounded failure label without credentials.
`tools/relay_transport_fixtures.py` checks real two-client BIND/JOIN, 1288-byte
forwarding in both directions, control replies, malformed/foreign-session
rejection and sequence rollover with independent Python AES-GCM/SHA256 crypto.
These feature-specific proofs do not declare the full backend complete.

## Build and validation tools

`build-server.ps1` uses C++20 and MSVC /W4 /WX. Platform/auth tests use the actual
compiled game-side CNG verifier. `tools/test-lobby.py` uses independent crypto,
isolated credentials/data/ports, two-account pushes, ownership, malformed input,
DTOs and restart persistence. The latest check count and hash are in
lobby-verification.json. It does not launch maps or modify production player data.

`build-game.ps1` / `deploy-game.ps1` retain the private frozen compiler workflow
and relocation/VM/provenance gates. `data/deployment.json` connects the game
image and backend receipts. Backend-only iterations do not rebuild the EXE.

`tools/native-social-test.py` uses native-social for controlled invite/remove/
online checks without reauthenticating the game account.
`tools/record-native-social-proof.py` only records game acceptance/removal after
the native caches prove it. Remove temporary relationships through the task API.
