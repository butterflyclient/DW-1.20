"""Join target constructor evidence, explicit backend routes and validation receipts.

This is a coverage ledger, not a declaration that every SDK call was recovered.
Handler registration is curated from dispatch code; fixture call sites are static
references, not runtime/native completion. Unknown indirect calls remain open.
"""

import ast
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"

# Reviewed public dispatch routes. Variant restrictions remain explicit below.
ROUTES = [
    (3, "legacy teams", "team_services.cpp", [46]),
    (4, "leaderboards", "account_services.cpp", [1, 14]),
    (4, "leaderboards", "leaderboard_services.cpp", [4, 11, 13, 16, 17]),
    (6, "instant messaging", "channel_services.cpp", [14]),
    (8, "public/private profiles", "services.cpp", list(range(1, 9))),
    (10, "contextual storage", "services.cpp", [10, 11, 12, 17, 21]),
    (12, "utilities", "startup_services.cpp", [1, 13]),
    (12, "utilities", "services.cpp", [6, 12]),
    (23, "shared counters", "counter_services.cpp", [1, 2]),
    (27, "geography", "startup_services.cpp", [2]),
    (29, "mail", "mail_services.cpp", [4, 5, 7, 9, 10]),
    (38, "anti-cheat and auth reports", "anticheat_services.cpp", [2]),
    (38, "anti-cheat and auth reports", "services.cpp", [6, 7, 8]),
    (
        50,
        "content streaming",
        "content_services.cpp",
        [2, 3, 5, 6, 9, 10, 15, 16, 18, 19, 20],
    ),
    (58, "content streaming", "content_services.cpp", [5, 6, 18, 20, 21]),
    (67, "telemetry", "engagement_services.cpp", [5]),
    (67, "telemetry", "startup_services.cpp", [6]),
    (80, "marketplace", "marketplace_services.cpp", [69, 106, 125, 132, 134, 243, 245]),
    (80, "marketplace", "inventory_validation_services.cpp", [58]),
    (95, "publisher variables", "services.cpp", [1, 3]),
    (104, "marketing", "engagement_services.cpp", [6, 7]),
    (123, "redemption", "marketplace_services.cpp", [1, 2]),
    (125, "achievements", "achievement_services.cpp", [1, 2, 3, 4, 5, 6]),
    (125, "achievements", "account_services.cpp", [9]),
    (
        145,
        "matchmaking, QoS, relay and tournaments",
        "matchmaking_services.cpp",
        [2, 3, 8, 9, 10, 13, 15, 18],
    ),
    (
        145,
        "matchmaking, QoS, relay and tournaments",
        "qos_services.cpp",
        [4, 16, 24, 25],
    ),
    (145, "matchmaking, QoS, relay and tournaments", "relay_services.cpp", [26]),
    (
        145,
        "matchmaking, QoS, relay and tournaments",
        "tournament_services.cpp",
        [19, 20, 21, 22, 23, 28, 29],
    ),
    (150, "scheduled matches", "scheduled_services.cpp", [1, 2, 3, 4]),
    (151, "esports registration", "startup_services.cpp", [1]),
    (152, "performance samples", "scheduled_services.cpp", [1]),
    (193, "object store", "objectstore_services.cpp", [6, 7, 8, 16]),
    (194, "AB enrollment", "abtesting_services.cpp", [1]),
    (195, "scripted loot", "engagement_services.cpp", [1]),
    (197, "account aliases and clans", "identity_services.cpp", [10, 11]),
    (197, "account aliases and clans", "clan_services.cpp", list(range(20, 33)) + [37]),
    (198, "channels", "channel_services.cpp", list(range(1, 8)) + [12]),
    (255, "REST domain dispatch", "rest_services.cpp", [10]),
]
GAPS = {
    "3": "Only published legacy team data; broader clan/team SDK families require target evidence.",
    "4": "Task 14 applies explicitly trusted local token-hash/stat-batch authorizations with atomic retry receipts. Retail opaque token payload validation and a positive native callback remain unverified. Shipped column publication and packed projection support are implemented; native Total XP definitions now read accepted cumulative progression with unsigned physical-column bits and recover interrupted event transactions before ranking. Other virtual score aggregation and positive native row callbacks remain open.",
    "6": "Offline delivery is unavailable; no unsolicited invented recipient identity.",
    "8": "Full native positive CRUD roundtrip still needs observation.",
    "10": "Full native positive editing/deletion/backup roundtrip still needs observation.",
    "12": "Native utility methods outside the recovered request set remain unclassified.",
    "23": "Native signed positive/negative uploads and durable aggregate restoration have a scoped per-method receipt. Native counter download and a complete increment/read roundtrip remain unverified; current-binary upload credit requires that exact receipt below.",
    "27": "Configured geography is local metadata, not real IP geolocation.",
    "29": "Original sendMail 0x14212D970 forwards to sendMailWithDuration 0x14212D9D0, whose raw conditional-move/stack-save path selects task 7 for an explicit sender and task 9 otherwise; that forwarding method is not evidence for task 2. Categorized/status SDK variants not recovered in Replay remain unclassified. Native event 18 recipient notifications, bounded per-connection unread catch-up, durable idle expiration returns and queued-row revalidation are implemented and covered by encrypted two-client fixtures. The stock game callback, header/body decoder, deletion and idle return were verified with one inert diagnostic; application-specific mail handlers remain unverified.",
    "38": "Reports are durable acknowledgements, not a retail attestation/security verdict.",
    "50": "Task 22 live download; preparation IDs 5/15/20 are source-oracle contracts without target constructor proofs. Whole-user optional X-Checksum algorithm unresolved. Full positive native upload/copy lifecycle still unobserved.",
    "58": "Whole pooled-file preparation and HTTP staging persist across backend restarts in a validated per-title store. Immutable blobs are flushed before HTTP acknowledgement; catalog-before-staging-cleanup publication recovers the same file ID on retries. Pooled and multipart transfers share a bounded staging quota with expiry reclamation. Isolated Windows/Linux native-wire and HTTP fixtures cover interrupted writes, corrupt snapshots/blobs, ownership, expiry and user/multipart/copy regressions. Task 22 multipart/live download exact extended result binding remains unresolved: its consumer reads fields beyond the ordinary file-metadata DTO. Positive native upload/commit consumption remains unverified.",
    "67": "Positive native telemetry batch completion beyond startup filter initialization.",
    "80": "Task 58 validates trusted local issuer publications with the exact Int64/Int64/blob DTO; retail token issuance/semantics and positive native validation callback remain unverified. Task125 CouponOrderV2 request unavailable. Task106 recipient SKU orders support published gifting to existing local accounts with full owner/buyer coupon DTOs, flushed multi-account intents, conflicting-image preflight and disk/process recovery. CSV sale and smart prices preserve base ownership; smart prerequisites are checked against durable buyer inventory. Sale/smart self-purchases and durable retries deliver absolute item quantities through the exact event-67 UByte8 version and kind-18 completion envelope. A real zero-price sale has private-game native callback/cache evidence; paid/smart UI and gift callbacks remain unverified. Other discount and loot-generation rules remain open.",
    "95": "Additional title/build tuning documents need explicit publication; unknown namespaces remain unavailable.",
    "104": "Full bounded message publication and owned view receipts implemented. Native positive view callback and redemption-action consumers remain separate validation gates.",
    "123": "Positive native redemption callbacks and game reward consumers still need validation.",
    "125": (
        "Native mp_addxp deltas update career XP and Replay rank thresholds. Complete flushed "
        "event intents preflight every recipient journal/retry receipt; conflicts make no changes "
        "and interrupted writes recover before queries/local restoration. Positive-XP retries "
        "refresh the latest absolute total from hot or archived receipts; serialized delivery "
        "checks reject superseded snapshots. Windows/Linux fixtures cover recovery, restart and "
        "both transports; original consumer execution proves absolute assignment without rank-up "
        "UI on refresh. Pending XP waits for nonce-bound local persistence confirmation; stale "
        "local snapshots cannot erase accepted awards. The idle publisher coalesces successful "
        "unchanged writes. Published Total XP ranking shares accepted snapshots and registered "
        "account names. The REST envelope retains the full Reply, including cross-player pushes. "
        "All 232 shipped MP/BR/co-op mission descriptions and prior-string aliases are recovered "
        "from two matching English fastfiles. Original-parser-bound MP kill/healing and BR counter/action/location/purchase mission "
        "predicates commit stage progress, shipped XP/items, next-stage activation and retry "
        "identity together with player/weapon XP and Battle Pass writes. Native public in_game "
        "membership and activation timestamps gate earning; private/expired/stale assignments "
        "cannot earn credit. Exact earning proof and linked-image identity are retained in "
        "the matching-image mission_earning_evidence receipt below, including its supported/remaining counts. Unbound mission "
        "predicates, delayed-event match lifetime, exactly-once push acknowledgements and new "
        "native mission gameplay/completion/reward/successor callback validation remain open."
    ),
    "145": "Presence joins and public lobby filling have authenticated party tokens, live-host/capacity checks, shared documents and typed event-2001/2006 pushes. Public selection also binds playlist/map publication, native netcode/rules, privacy and native in_game join-in-progress policy; two authenticated clients are covered by encrypted-wire fixtures. Primary-player additional reservations are validated/published and counted in public/presence capacity, team occupancy and fullest-lobby selection. Replay bnet platform restrictions are validated without splitting equivalent cross-play pools. Legacy zero-reservation documents remain compatible; native split-screen consumption/gameplay remain unverified. Complete native host snapshots retire omitted/READY_TO_REMOVE members across teams/squads/optional metadata, preserve shared searches and newer assignments, and commit through recoverable transactions. Document clocks advance monotonically to prevent equal-second native update loss; native departure callbacks remain unverified. Party-elected task-145/15 host claims bind current membership/search tokens and registered native addresses after the original host lease ends; ownership, migration order and departed-member cleanup share the existing durable transaction while DTLS keys/map/rules remain intact. Six encrypted fixture groups cover stale/live-host denial, successor claims and interrupted publication. A native friend-menu session-info exchange and assigned lobby/host were verified on the recorded server hash; native public-search callbacks, playable two-game connections and native host-migration callbacks remain open. Native tournament task-18 searches now use authenticated party tokens, published same-team enrollment and recoverable formation-search/index transactions; exact event-2009 join pushes bind the returned search ID, with retry/deduplication/cancellation/expiry checks covered by two encrypted clients. Capacity-based tournament publications now accept unassigned registrations and allocate real authenticated parties without splitting them; native teams/rounds are generated and PLAYING requires every slot and live-session acknowledgement. Formation/enrollment/search/index changes share flushed recoverable transactions with an explicitly fixed cross-domain enrollment target. Forming-party withdrawal releases slots, resets peer acceptance while retaining registration and emits exact event-2011 with durable catch-up/revocation. Capacity publications with pinned round rules now allocate closed native round lobbies through the shared playlist/map policy and document builder after complete session-bound readiness. Exact create/join pushes retain actual party search IDs and native tournament/team/round metadata; formation, lobby, searches, account index and enrollment share one recoverable transaction. Eight signed machine accounts verify map-policy waiting, interrupted publication, four independent first-round lobbies, temporary same-session join catch-up and all seven result-driven matches. Canonical tournament map pools supply both native publisher dvar strings and backend round selection, with durable revision/hash protection and immutable competition snapshots. The compiled selector matches original Replay x64 instructions across 32 cases; four native strings and their revision survive same-process backend reconnect. Native join/formation/round callback validation, forfeits and native result/ready/accept/leave/rejoin callbacks remain open. Host-authorized task 21 results, durable journals, bracket advancement, exact event-2010 updates and opt-in idle publication/disband pushes with recipient/snapshot revalidation are implemented. Native registration/state callbacks, FORMING/PLAYING parsing, idle publication updates and event-2012 disband were verified with explicitly seeded enrollment; playable tournaments remain open. Remote relay deployment/migration and native two-game forwarding remain open.",
    "150": "Positive native scheduled match operations; local publication required.",
    "151": "Published local registration only; retail esports registration workflow is not emulated.",
    "152": "Positive native performance write completion.",
    "193": "Verified user-object PUT/read and publisher metadata/content retain native envelopes. Complete multi-object upload windows use flushed per-title/account intents, full namespace/content/tag preflight and blocked-read/process-restart recovery; native profile-window recovery still needs a targeted client failure run. Tasks 3/9/10/12/24 category/list/large-upload families remain open; response binding is unresolved for some recovered writers.",
    "194": "Published deterministic weighted cohorts and active treatments use the exact native eight-enrollment/one-treatment/1024-byte engine allocation. Full catalog/state validation, title/account/context ownership, revision rollback protection, schedule filtering, failed atomic publication and restart persistence are implemented. A positive native dvar treatment and same-process backend restart/refetch have a hash-bound receipt; current-image completion is evaluated separately. Automatic future native schedule polling, other modifier types and retail experiment rules remain separate unverified scopes.",
    "195": "Full task-1 proxy request/result and published deterministic script responses with ordered owned task journals. Constant native clientData is not used as retry identity. Retail script/reward rules and positive native callback/game consumers remain unverified; no fabricated inventory grants.",
    "197": "Current family implemented; deeper native callback coverage and distributed/multi-profile lifecycle remain open.",
    "198": "Complete persisted channel layouts, Replay's 200-member limit and native event-24/25 member/channel-info DTOs are implemented. Signed clients cover owned join/category unsubscribe, last-live-socket departure, rapid rejoin generation revocation, concurrent joins and failed atomic publication. Field 8 is native UInt32 dataVersion. The serialized endpoint publishes a real sender join before its first message and coalesces the delayed duplicate. Native private-party creation, real peer join/leave and first incoming-message history are recorded in hash-bound proofs. A second game's subscribe/unsubscribe/send task callbacks and multi-game chat remain open.",
    "255": "Friends/user lists/presence/event ingestion and exact-target regulation publication/preference CRUD are implemented. Regulation choices bind the signed owner, preserve retries and survive atomic-write failure/process restart; no preference is invented from an absent publication. Regulation response vtables were verified independently of misleading database aliases, but live native regulation task callbacks remain unverified. Online queries require a registered, valid issuer lease; revoked idle/partial reads and keepalives retire promptly, with last-valid-session scoped offline notifications and independent session preservation covered by native-wire fixtures. Four exact-target account upgrade/auth/link/Umbrella routes persist optional credentials on the existing signed owner; per-session UNO grants, credential-change revocation and recoverable account/profile publication are covered by encrypted fixtures. Native account-menu/crossplay-login callbacks and two-network lifecycle remain unverified; other account/objectstore REST mutations need explicit request/result/domain contracts.",
}

# Current rank/chat/BR source contracts. Deployment and native completion
# remain independently checked by the hash-bound evidence readers below.
GAPS["125"] += (
    " Native mp_addxp.Param4 now earns exact current-season Battle Pass XP through "
    "the recoverable event transaction, independently of player and weapon XP. "
    "Free/premium tier rewards, once-only COD Points, fractional XP on late premium "
    "activation, tier-100 saturation and non-completing retry refreshes share one "
    "tier advancement implementation. Original Replay FlushXPCache execution "
    "proves the independent 64-bit field and first-weapon-only emission. Sixteen "
    "focused encrypted fixture groups pass on the deployed Linux image. A fresh "
    "shipping-game login restores its tier/XP cache; the short Shipment runs "
    "emitted only zero-XP match events, so a positive native match-earned Battle "
    "Pass callback remains unverified."
)
GAPS["125"] += (
    " Native player and 51 canonical weapon XP snapshots now include uppercase "
    "ACHIEVEMENT routing. Shipped initial items, player-rank features and unconditional "
    "weapon-rank items receive absolute owned inventory through the same recoverable "
    "XP/retry transaction. Inventory delivery hashes track entitlement changes even "
    "without XP changes. Conditional camo/quest predicates and positive game UI "
    "completion remain separate requirements."
    " A hash-bound private-game test verifies event-67 XP/rank callback consumption, "
    "local save, game-restart restoration and no duplicate award from an authenticated "
    "self-report retry. That independent-wire submission is not a game-issued report "
    "task, match-earned XP or an after-action animation test."
    " The 232 native ALL/BR/CP mission stages now have real compiled definitions "
    "and persistent activation/deactivation with independent mode selections. "
    "All 447 table rows and all 32 initialized native mission groups were matched. "
    "A hash-bound shipping-game proof verifies 125/5 callbacks and 125/3 restoration "
    "of MP/co-op/BR selections across a new game process. Other platform/operator "
    "mission eligibility and unbound earning predicates remain open; "
    "compiled MP/BR predicates have separate original-parser and encrypted-wire "
    "earning/reward/recovery evidence, without native gameplay callback claims."
)
GAPS["198"] += (
    " The original outgoing text length excludes its NUL terminator. The backend "
    "normalizes text for the native 500-byte receiver and rejects empty, embedded-NUL "
    "and oversized messages. Current two-player in-game delivery remains unverified."
)
GAPS["145"] += (
    " BR publication takes squad size from native playlist teamSize, keeps each party "
    "together and disables MP partition splitting. Verdansk client selectors and a "
    "targeted missing-combined-collision-package fallback have linked-code evidence; "
    "BR load/traversal and full transient package readiness remain unverified."
)

GAPS["145"] += (
    " Globally unavailable managed publications now retire forming/playing searches and "
    "allocated lobbies, remove account assignments and clear readiness in one recoverable "
    "transaction. A validated system terminal record preserves actual results, prevents "
    "re-published IDs from resurrecting the old competition and enables native event-2012 "
    "catch-up for accepted and pending registrations. Cleanup runs on an enrolled client's "
    "idle update, authenticated tournament request or once-per-second service-store maintenance. "
    "Maintenance visits persisted enrollments independently of sockets, including server "
    "startup with no authenticated clients. A missing personal bracket slot does "
    "not cancel a globally live publication; other tournaments and newer assignments are "
    "preserved. Offline withdrawal, blocked-transaction recovery, reconnect notification "
    "and real-clock startup expiry with malformed-realm isolation have exact-binary fixture "
    "evidence. Native allocated-round retirement, orphan formations without enrollment and "
    "retail disconnect/forfeit policy remain separate gates."
)

GAPS["145"] += (
    " Managed unfinished tournament withdrawal now has a complete persistent cancellation layout "
    "and shared enrollment/lobby/search/account-index transaction. Native tasks 145/22 and "
    "145/23 false cancel a still-competing participant's tournament; idle event-2012 retires "
    "peer state. Eliminated and completed-final departures release old matchmaking assignments "
    "while preserving actual results and winning-team searches. Signed encrypted fixtures cover "
    "both tasks, allocation, reconnect, source validation, interrupted terminal publication, "
    "retry and stale-task denial. Native positive withdrawal callbacks, retail forfeits and "
    "disconnect timeouts remain unverified/unimplemented."
)

GAPS["255"] += (
    " Bulk username hydration has a target-bound 200-record reader, exact numeric-title "
    "query contract and registered UNO/Battle.net aliases; malformed/oversized requests "
    "and duplicate REST singleton fields are rejected. Repeated SDK fields remain valid. "
    "Native username-resolver task completion is still a separate unverified scope."
)

GAPS["194"] += (
    " Both transports preflight the original legacy reader's 8096-byte buffer "
    "including its terminator before publication. The explicit abtesting/enroll "
    "REST handler shares account-owned cohorts and token state with task 194/1; "
    "encrypted fixtures cover the exact 8095-byte boundary and overflow. Original "
    "Replay's REST writer leaves serviceName empty and its own validator rejects "
    "that request before transport; the explicit backend route does not fix or "
    "establish completion of that native REST path."
)


# Dedicated domain handlers only. A configured GET publication is not equivalent
# to an implemented authenticated account/objectstore mutation.
REST_HANDLERS = {
    (
        "ae.demonware.net",
        "user_events",
        "report_user_events_batch",
    ): "achievement_services.cpp",
    ("uno", "UserResource", "renameUsername"): "identity_rest_services.cpp",
    ("uno", "UnoRes", "updatesecuredfields"): "identity_rest_services.cpp",
    ("uno", "UserResource", "authenticateUser"): "identity_rest_services.cpp",
    ("umbrella", "UserResource", "linkUser"): "identity_rest_services.cpp",
    ("umbrella", "Umbrella", "updateUmbrellaAccount"): "identity_rest_services.cpp",
    ("abtesting", "abtesting", "enroll"): "abtesting_services.cpp",
    ("umbrella", "UserResource", "usernamesearch"): "social_services.cpp",
    ("presence", "UserPresence", "set_user_presence"): "social_services.cpp",
    ("social-service", "UsersPresence", "get_users_presence"): "social_services.cpp",
    ("presence", "UsersPresence", "subscribe_to_users"): "social_services.cpp",
    ("presence", "UsersPresence", "unsubscribe_from_users"): "social_services.cpp",
    ("friends", "Friends", "invite_friend"): "social_services.cpp",
    ("social-service", "Friends", "get_pending_friend_requests"): "social_services.cpp",
    ("friends", "Friends", "reject_friend_request"): "social_services.cpp",
    ("social-service", "Friends", "get_friends"): "social_services.cpp",
    ("userlists", "UserLists", "create_user_list"): "social_services.cpp",
    (
        "userlists",
        "UserLists",
        "add_or_update_users_in_user_list",
    ): "social_services.cpp",
    ("userlists", "UserLists", "remove_users_from_user_list"): "social_services.cpp",
    ("social-service", "UserLists", "get_user_list"): "social_services.cpp",
    ("umbrella", "Regulations", "fetchRegulations"): "regulation_services.cpp",
    ("umbrella", "Regulations", "setUserPreference"): "regulation_services.cpp",
    ("umbrella", "Regulations", "getUserPreference"): "regulation_services.cpp",
    ("social-service", "Users", "get_usernames"): "social_services.cpp",
}
for environment in ("dev", "cert", "prod"):
    for operation in ("get_objects", "put_objects"):
        REST_HANDLERS[
            (
                f"objectstore.{environment}.demonware.net",
                "ObjectsVectorizedResourceUsers",
                operation,
            )
        ] = "objectstore_services.cpp"

GAPS["4"] += (
    " Shipped regular/virtual asset schemas now generate 747 native column publications. "
    "Stored rows support 240 columns while each response retains its ten-column native "
    "bound. Included projections retain request order; excluded projections retain schema "
    "order. All 40 original virtual column builders/accessors and 80 encrypted entity/rank "
    "projections were verified on current Windows/Linux binaries. Positive native menu/row "
    "callbacks and automatic virtual score aggregation remain open; no statistics were seeded."
    " Schema-2 publications now resolve native read namespaces to base/tracked stored boards; "
    "unpublished client prefixes are never inferred. Shared row validation and partial native "
    "writes preserve up to 240 columns with replace/add/max/NAN semantics, atomic failure "
    "and restart persistence. Current deployment has exact-binary protocol evidence without "
    "a new game run, following the owner's test restriction."
)

GAPS["193"] += (
    " The same native REST vector GET/PUT routes now share the struct-buffer domain, "
    "complete account-owned storage and journal recovery. Matching cache version/checksum "
    "hints use the target NotModified reader; REST body windows retain their 256 KiB cap. "
    "Native REST method callbacks remain unverified. The alias at 0x1420F1890 is not an "
    "upload-completion reader; see validation/20261006-target-consumer-alias-correction.json."
)

GAPS["193"] += (
    " Publisher cache bytes now use flushed atomic publication and checksum-verified "
    "repair. Durable title/context/publisher/name references keep cache presence separate "
    "from current public ACL, expiry and exact content identity. Six encrypted-wire/HTTP "
    "fixture groups include real blocked writes, corrupt snapshots and process restart; "
    "a fresh root-folder game run passed all 27 startup fences and created eight verified "
    "publisher cache records on the recorded backend hash. See "
    "validation/20261009-publisher-cache-readiness.json. Category-list and large-upload "
    "response bindings remain open; this publication proof does not close those routes."
)

GAPS["193"] += (
    " Exact-name DIA lookup in the game-test oracle found class declarations but no "
    "emitted class-owned function symbols for the publisher/user category responses. "
    "The complete-single-upload response provides a positive emitted-method control. "
    "These are oracle availability results, not proof of Replay's wire layout or "
    "unused routes; see validation/20261009-storage-oracle-method-availability.json."
)


def friend_native_evidence(server_hash, game_hash):
    path = ROOT / "validation/20261006-friend-store-native-lifecycle.json"
    if not path.is_file():
        return None
    proof = json.loads(path.read_bytes())
    expected_sources = {
        "src/social_services.cpp",
        "src/rest_services.cpp",
        "tools/observe-game.py",
        "tools/record-native-friend-store-proof.py",
    }
    reconnect = proof.get("reconnect_proof", {})
    reconnect_path = ROOT / "validation/20261006-friend-store-native-reconnect.json"
    if not (
        proof.get("passed") is True
        and proof.get("server_sha256") == server_hash
        and proof.get("game_sha256") == game_hash
        and set(proof.get("source_sha256", {})) == expected_sources
        and all(
            proof["source_sha256"][source] == digest(ROOT / source)
            for source in expected_sources
        )
        and reconnect_path.is_file()
        and reconnect.get("path", "").replace("\\", "/")
        == reconnect_path.relative_to(ROOT).as_posix()
        and reconnect.get("sha256") == digest(reconnect_path)
    ):
        return None
    return path.relative_to(ROOT).as_posix(), proof


def abtesting_native_evidence(server_hash, game_hash):
    path = ROOT / "validation/20261006-abtesting-native.json"
    if not path.is_file():
        return None
    proof = json.loads(path.read_bytes())
    expected_sources = {
        "src/abtesting_services.cpp",
        "src/abtesting_services.h",
        "src/engagement_services.cpp",
        "tools/observe-game.py",
        "tools/record-native-abtesting-proof.py",
    }
    if not (
        proof.get("passed") is True
        and proof.get("server_sha256") == server_hash
        and proof.get("game_sha256") == game_hash
        and set(proof.get("sources", {})) == expected_sources
        and all(
            proof["sources"][source] == digest(ROOT / source)
            for source in expected_sources
        )
        and proof.get("native_ab_enrollment_completion_verified")
        and proof.get("native_populated_treatment_and_registered_dvar_verified")
        and proof.get("same_process_backend_restart_and_native_ab_refetch_verified")
        and proof.get("empty_default_enrollment_verified_after_cleanup")
    ):
        return None
    return path.relative_to(ROOT).as_posix(), proof


def native_pair_evidence(server_hash):
    path = ROOT / "validation/20261006-current-native-pair-readiness.json"
    if not path.is_file():
        return None
    proof = json.loads(path.read_bytes())
    expected_sources = {
        "src/social_services.cpp",
        "src/channel_services.cpp",
        "tools/observe-game.py",
    }
    if not (
        proof.get("passed")
        and proof.get("backend_sha256") == server_hash
        and proof.get("audit_tool_sha256")
        == digest(ROOT / "tools/record-native-pair-readiness.py")
        and proof.get("native_two_game_private_party_join_verified")
        and proof.get(
            "native_friend_removal_and_active_crossplay_mask_cleanup_verified"
        )
        and set(proof.get("source_sha256", {})) == expected_sources
        and all(
            digest(ROOT / source) == sha
            for source, sha in proof.get("source_sha256", {}).items()
        )
    ):
        return None
    references = [proof["backend_build"], proof["protocol"]]
    references.extend(
        item for peer in proof["evidence"].values() for item in peer.values()
    )
    for item in references:
        evidence = (ROOT / item["path"]).resolve()
        if not evidence.is_relative_to(ROOT / "data") or not evidence.is_file():
            return None
        if digest(evidence) != item["sha256"]:
            return None
    return path.relative_to(ROOT).as_posix(), proof


def rest_coverage(inventory, friend_evidence, server_hash):
    pair_evidence = native_pair_evidence(server_hash)
    event_receipt = ROOT / "validation/20261006-achievement-rest-layout.json"
    event_proof = (
        json.loads(event_receipt.read_bytes()) if event_receipt.exists() else None
    )
    if event_proof and (
        event_proof["target_image_sha256"] != inventory["target_image_sha256"]
        or event_proof["audit_tool_sha256"]
        != digest(ROOT / "tools/research-achievement-rest-target.py")
        or not event_proof["callback_vm"]["passed"]
    ):
        raise ValueError("Refresh the exact achievement REST callback proof")
    event_native_path = (
        ROOT / "validation/20261006-achievement-rest-native-readiness.json"
    )
    event_native = (
        json.loads(event_native_path.read_bytes())
        if event_native_path.exists()
        else None
    )
    if event_native:
        valid = bool(
            event_native.get("passed")
            and event_native.get("backend_sha256") == server_hash
            and event_native.get("achievement_rest", {}).get(
                "native_single_user_callback_verified"
            )
        )
        for item in event_native.get("achievement_rest", {}).get(
            "native_callback_evidence", []
        ):
            path = ROOT / item["path"]
            valid = valid and path.is_file() and digest(path) == item["sha256"]
        if not valid:
            event_native = None
    receipt_path = ROOT / "validation/20261006-objectstore-rest-target-layout.json"
    proof = json.loads(receipt_path.read_bytes())
    if proof["target_image_sha256"] != inventory["target_image_sha256"] or proof[
        "audit_tool_sha256"
    ] != digest(ROOT / "tools/research-objectstore-rest-target.py"):
        raise ValueError("Refresh the exact object-store REST target receipt")
    proven_requests = {row["va"]: row for row in proof["requests"]}
    category_path = ROOT / "validation/20261006-objectstore-category-target.json"
    category = json.loads(category_path.read_bytes())
    if (
        category["target_image_sha256"] != inventory["target_image_sha256"]
        or category["audit_tool_sha256"]
        != digest(ROOT / "tools/research-objectstore-category-target.py")
        or not category["getter_vm"]["passed"]
        or category["environment_services"] != proof["environment_services"]
    ):
        raise ValueError("Refresh the exact object-store category request proof")
    proven_requests[category["request"]["va"]] = category["request"]
    ab_receipt = ROOT / "validation/20261006-abtesting-rest-target-layout.json"
    ab_proof = json.loads(ab_receipt.read_bytes())
    if (
        ab_proof["target_image_sha256"] != inventory["target_image_sha256"]
        or ab_proof["audit_tool_sha256"]
        != digest(ROOT / "tools/research-abtesting-rest-target.py")
        or not ab_proof["original_rest_writer_requires_service_correction"]
        or not ab_proof["original_validator_vm"]["passed"]
    ):
        raise ValueError("Refresh the exact AB REST writer/validator target receipt")
    requests = []
    for original in inventory["requests"]:
        row = dict(original)
        environment_binding = proven_requests.get(row["function_address"])
        if environment_binding:
            if row["resource_operations"] != [
                [environment_binding["resource"], environment_binding["operation"]]
            ]:
                raise ValueError("Object-store REST target operation changed")
            row["services"] = proof["environment_services"]
            row["service_operation_binding_resolved"] = True
            binding_receipt = (
                category_path
                if row["function_address"] == category["request"]["va"]
                else receipt_path
            )
            row["target_binding_receipt"] = binding_receipt.relative_to(ROOT).as_posix()
            if binding_receipt == category_path:
                row["native_response_reader_verified"] = False
        bound = (
            row["service_operation_binding_resolved"]
            and (len(row["services"]) == 1 or bool(environment_binding))
            and len(row["resource_operations"]) == 1
        )
        handler = (
            REST_HANDLERS.get((row["services"][0], *row["resource_operations"][0]))
            if bound
            else None
        )
        native_scope = None
        if bound and handler and friend_evidence:
            _, native_proof = friend_evidence
            binding = (row["services"][0], *row["resource_operations"][0])
            if binding in (
                ("umbrella", "UserResource", "usernamesearch"),
                ("friends", "Friends", "invite_friend"),
            ) and native_proof.get(
                "native_game_owned_name_search_and_outgoing_invitation"
            ):
                native_scope = "The game's native name-search and invitation tasks produced the diagnostic peer in its completed outgoing list"
            elif binding == (
                "social-service",
                "Friends",
                "get_friends",
            ) and native_proof.get(
                "accepted_friendship_persisted_across_backend_and_dw_restart"
            ):
                native_scope = "The same game process refetched its accepted diagnostic peer after backend restart and dw_restart"
        row.update(
            dedicated_domain_handler=(bool(handler) if bound else None),
            handler_source=("src/" + handler if handler else None),
            current_native_method_completion_verified=bool(native_scope),
            native_completion_evidence=(friend_evidence[0] if native_scope else None),
            native_completion_scope=native_scope,
            coverage_scope=(
                "Dedicated handler registration; native callback evidence is separate"
                if bound
                else "Dynamic/helper service binding remains unresolved"
            ),
        )
        if bound and handler and pair_evidence:
            pair_path, pair_proof = pair_evidence
            binding = [row["services"][0], *row["resource_operations"][0]]
            if binding in pair_proof["native_rest_bindings"]:
                row.update(
                    current_native_method_completion_verified=True,
                    native_completion_evidence=pair_path,
                    native_completion_scope="Two private root-folder game processes completed native name search, friend/pending lists, reciprocal invitation, online presence and removal; shared private-party membership was verified",
                    native_completion_game_sha256=pair_proof["game_sha256"],
                    shipping_executable_native_completion_inherited=False,
                )
        if row.get("shared_service_helper_only"):
            row["coverage_scope"] = (
                "Shared service parameter helper; not an independent REST request"
            )
        if row["function_address"] in (0x142102A60, 0x14216A100) and event_proof:
            if (
                row["services"] != ["ae.demonware.net"]
                or not row["shared_service_paths"]
            ):
                raise ValueError("Shared achievement REST service binding changed")
            row["target_response_layout_receipt"] = event_receipt.relative_to(
                ROOT
            ).as_posix()
            row["original_callback_vm_verified"] = True
            if row["function_address"] == 0x142102A60 and event_native:
                row.update(
                    current_native_method_completion_verified=True,
                    native_completion_evidence=event_native_path.relative_to(
                        ROOT
                    ).as_posix(),
                    native_completion_scope="Private root-folder Replay process sent owned single-user event batches; the original success callback completed with native response status 2 and no error",
                    native_completion_game_sha256=event_native["native_startup"][
                        "game_sha256"
                    ],
                    shipping_executable_native_completion_inherited=False,
                )
        if row["function_address"] == 0x1420FFE50:
            if row["services"] or row["resource_operations"] != [
                ["abtesting", "enroll"]
            ]:
                raise ValueError("Original AB REST writer binding changed")
            row.update(
                native_pre_transport_blocked=True,
                native_pre_transport_blocker="Original writer leaves serviceName empty; original SDK validator rejects the request before sending",
                target_binding_receipt=ab_receipt.relative_to(ROOT).as_posix(),
                explicit_backend_service="abtesting",
                explicit_backend_handler_source="src/"
                + REST_HANDLERS[("abtesting", "abtesting", "enroll")],
                coverage_scope="Explicit backend route implemented; original native writer requires a service-name correction and live REST callback validation",
            )
        requests.append(row)
    return requests


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def native_byte_task_evidence(receipt):
    """Accept only a current, byte-bound audit; this establishes no callbacks."""
    receipt = receipt.resolve()
    if not receipt.is_relative_to(ROOT / "validation"):
        raise ValueError("Keep the native task receipt in repository validation")
    if not receipt.is_file():
        return None, []
    proof = json.loads(receipt.read_bytes())
    raw_path = (ROOT / proof["raw_inventory"]["path"]).resolve()
    image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
    if not (
        proof.get("passed") is True
        and proof.get("schema") == 1
        and proof.get("audit_tool_sha256")
        == digest(ROOT / "tools/inventory-native-task-bytes.py")
        and proof.get("test_tool_sha256")
        == digest(ROOT / "tools/test-native-task-bytes.py")
        and proof.get("independent_x64_trace_cases") == 52
        and proof.get("chained_unwind_ownership_resolved") is True
        and proof.get("target_image_sha256") == digest(image)
        and raw_path.is_relative_to(DATA)
        and raw_path.is_file()
        and proof["raw_inventory"]["sha256"] == digest(raw_path)
        and proof.get("original_assembly_text_used") is False
        and proof.get("database_aliases_used_for_call_resolution") is False
        and proof.get("full_method_audit_complete") is False
        and proof.get("native_completion_verified") is False
    ):
        raise ValueError("Regenerate the original-byte task audit and receipt")
    raw = json.loads(raw_path.read_bytes())
    if (
        raw["target_image_sha256"] != proof["target_image_sha256"]
        or raw["audit_tool_sha256"] != proof["audit_tool_sha256"]
        or len(raw["inspected_functions"]) != proof["inspected_functions"]
        or raw.get("database_changed_during_labels")
        or raw.get("register_preserving_stack_probe")
        != proof.get("register_preserving_stack_probe")
    ):
        raise ValueError("Original-byte task audit provenance is inconsistent")
    probe = proof["register_preserving_stack_probe"]
    probe_path = (ROOT / probe["evidence"]).resolve()
    if not probe_path.is_relative_to(ROOT / "validation") or not probe_path.is_file():
        raise ValueError("Native stack-probe receipt is missing")
    probe_proof = json.loads(probe_path.read_bytes())
    if not (
        probe_proof.get("passed") is True
        and probe_proof.get("target_image_sha256") == proof["target_image_sha256"]
        and probe_proof.get("tool_sha256")
        == digest(ROOT / "tools/research-stack-probe-target.py")
        and probe_proof.get("original_instructions_executed") is True
        and probe_proof.get("modeled_external_calls") is False
        and probe_proof.get("function")
        == {
            "va": probe["target"],
            "size": probe["size"],
            "bytes_sha256": probe["bytes_sha256"],
        }
        and len(probe_proof.get("cases", [])) == 9
        and all(
            case.get("passed") is True and case.get("preserved_gprs") == 15
            for case in probe_proof["cases"]
        )
    ):
        raise ValueError("Native register-preserving call contract is unverified")
    # Keep the ledger dependency-free. Recheck bounded function bytes and each
    # direct branch against the original PE, without using SQLite display names.
    with image.open("rb") as stream:
        header = stream.read(64)
        if header[:2] != b"MZ":
            raise ValueError("Original target is not a PE image")
        pe_offset = struct.unpack_from("<I", header, 60)[0]
        stream.seek(pe_offset)
        header = stream.read(24)
        if header[:4] != b"PE\0\0":
            raise ValueError("Original target PE signature is invalid")
        section_count, optional_size = (
            struct.unpack_from("<H", header, 6)[0],
            struct.unpack_from("<H", header, 20)[0],
        )
        optional = stream.read(optional_size)
        if struct.unpack_from("<H", optional)[0] != 0x20B:
            raise ValueError("Original target is not a PE32+ image")
        base = struct.unpack_from("<Q", optional, 24)[0]
        sections = []
        for _ in range(section_count):
            section = stream.read(40)
            rva, size, offset = struct.unpack_from("<III", section, 12)
            sections.append((base + rva, size, offset))

        def original_bytes(address, size):
            for start, raw_size, offset in sections:
                if start <= address and address + size <= start + raw_size:
                    stream.seek(offset + address - start)
                    data = stream.read(size)
                    if len(data) == size:
                        return data
            raise ValueError("Task evidence lies outside original file-backed sections")

        if (
            hashlib.sha256(original_bytes(probe["target"], probe["size"])).hexdigest()
            != probe["bytes_sha256"]
        ):
            raise ValueError("Native stack-probe bytes changed")

        pdata_rva, pdata_size = struct.unpack_from("<II", optional, 112 + 3 * 8)
        if not pdata_rva or pdata_size % 12:
            raise ValueError("Original exception directory is malformed")
        pdata = original_bytes(base + pdata_rva, pdata_size)
        entries = {
            begin: (end, unwind)
            for begin, end, unwind in struct.iter_unpack("<III", pdata)
        }

        def primary_unwind(begin):
            visited = set()
            while True:
                if begin in visited or begin not in entries:
                    raise ValueError("Original unwind chain is cyclic or missing")
                visited.add(begin)
                end, unwind = entries[begin]
                header = original_bytes(base + unwind, 4)
                if not (header[0] >> 3) & 4:
                    return begin
                offset = (4 + header[2] * 2 + 3) & ~3
                parent, parent_end, parent_unwind = struct.unpack(
                    "<III", original_bytes(base + unwind + offset, 12)
                )
                if entries.get(parent) != (parent_end, parent_unwind):
                    raise ValueError("Original chained unwind parent is inconsistent")
                begin = parent

        owned_chunks = {}
        for begin, (end, _) in entries.items():
            owner = base + primary_unwind(begin)
            owned_chunks.setdefault(owner, []).append((base + begin, base + end))
        for chunks in owned_chunks.values():
            chunks.sort()
        regions = {row["start"]: row for row in raw["inspected_functions"]}
        if len(regions) != len(raw["inspected_functions"]):
            raise ValueError("Duplicate original-byte function bounds")
        for row in regions.values():
            chunks = row.get("chunks", [])
            bounds = [(chunk["start"], chunk["end"]) for chunk in chunks]
            if not chunks or not 0 < sum(end - begin for begin, end in bounds) <= 65536:
                raise ValueError("Original-byte owned code size is invalid")
            if row["boundary"] == "pe-unwind":
                if bounds != owned_chunks.get(row["start"]):
                    raise ValueError("Original-byte unwind ownership changed")
            elif row["boundary"] != "sqlite-fallback" or bounds != [
                (row["start"], row["end"])
            ]:
                raise ValueError("Unknown original-byte boundary source")
            for chunk in chunks:
                size = chunk["end"] - chunk["start"]
                if (
                    size <= 0
                    or hashlib.sha256(original_bytes(chunk["start"], size)).hexdigest()
                    != chunk["bytes_sha256"]
                ):
                    raise ValueError("Original-byte chunk hash changed")
        for row in raw["calls"]:
            region = regions.get(row["function"])
            if (
                not region
                or not any(
                    chunk["start"] <= row["callsite"] <= chunk["end"] - 5
                    for chunk in region["chunks"]
                )
                or row["constructor"] not in (0x1421170B0, 0x142156330, 0x142117C10)
            ):
                raise ValueError("Original-byte task call ownership is invalid")
            branch = original_bytes(row["callsite"], 5)
            target = row["callsite"] + 5 + struct.unpack_from("<i", branch, 1)[0]
            if branch[0] not in (0xE8, 0xE9) or target != row["callee"]:
                raise ValueError("Original-byte task call target changed")
    calls = [
        row
        for row in raw["calls"]
        if isinstance(row["service"], int) and isinstance(row["task"], int)
    ]
    routes = {(row["service"], row["task"]) for row in calls}
    if (
        routes != {(row["service"], row["task"]) for row in raw["routes"]}
        or len(routes) != proof["route_count"]
    ):
        raise ValueError("Original-byte task route totals are inconsistent")
    summary = dict(proof)
    summary.update(
        receipt=receipt.relative_to(ROOT).as_posix(),
        receipt_sha256=digest(receipt),
        original_function_bytes_and_direct_call_targets_rechecked=True,
    )
    return summary, calls


def offline_tournament_maintenance_evidence(server_hash):
    candidates = (
        ROOT / "validation/20261009-clean-backend-linux-offline-startup.json",
        ROOT / "validation/20261009-clean-backend-windows-offline-startup.json",
        ROOT / "validation/20261006-offline-tournament-startup.json",
    )
    path = next(
        (path for path in candidates if path.is_file()
         and json.loads(path.read_bytes()).get("backend_sha256") == server_hash),
        None,
    )
    if path is None:
        return None
    proof = json.loads(path.read_bytes())
    expected_sources = {
        "src/server.cpp",
        "src/services.cpp",
        "src/services.h",
        "src/tournament_services.cpp",
        "src/tournament_services.h",
    }
    if not (
        proof.get("passed") is True
        and proof.get("backend_sha256") == server_hash
        and proof.get("test_tool_sha256")
        == digest(ROOT / "tools/test-offline-tournament-startup.py")
        and set(proof.get("source_sha256", {})) == expected_sources
        and all(
            digest(ROOT / name) == expected
            for name, expected in proof["source_sha256"].items()
        )
        and proof.get("authenticated_lobby_connections") == 0
        and proof.get("authentication_requests") == 0
        and proof.get("native_tasks") == 0
        and proof.get("real_clock_expiry")
        and proof.get("terminal_committed")
        and proof.get("readiness_cleared")
        and proof.get("malformed_realm_preserved")
        and proof.get("independent_realm_progressed")
        and proof.get("exact_source_restoration_verified")
        and proof.get("game_launched") is False
        and proof.get("receiver_membership_seeded") is True
    ):
        return None
    if "remote_export" in proof:
        exported = proof["remote_export"]
        raw_path = (ROOT / exported["path"]).resolve()
        if (not raw_path.is_relative_to(DATA) or not raw_path.is_file()
                or digest(raw_path) != exported["sha256"]):
            return None
        original = {key: value for key, value in proof.items()
                    if key not in ("remote_export", "local_protocol_evidence")}
        if json.loads(raw_path.read_bytes()) != original:
            return None
    reference = proof.get("local_protocol_evidence", proof["protocol_evidence"])
    if reference["sha256"] != proof["protocol_evidence"]["sha256"]:
        return None
    protocol_path = Path(reference["path"]).resolve()
    if (
        not protocol_path.is_relative_to(DATA)
        or not protocol_path.is_file()
        or digest(protocol_path) != reference["sha256"]
    ):
        return None
    protocol = json.loads(protocol_path.read_bytes())
    if not (
        protocol.get("passed")
        and protocol.get("server_sha256") == server_hash
        and len(protocol.get("checks", [])) == proof.get("protocol_groups")
        and any(
            item.startswith("Offline managed publication retirement")
            for item in protocol["checks"]
        )
    ):
        return None
    return dict(
        receipt=path.relative_to(ROOT).as_posix(),
        sha256=digest(path),
        offline_retirement_and_reconnect_fixture_verified=True,
        startup_real_clock_expiry_with_zero_authenticated_clients_verified=True,
        malformed_realm_isolation_verified=True,
        orphan_formation_discovery_verified=bool(
            proof.get("formation_discovered_without_tournament_realm")
            and proof.get("orphan_formation_terminal_committed")
            and proof.get("orphan_registration_and_readiness_not_fabricated")
        ),
        malformed_formation_isolation_verified=bool(
            proof.get("malformed_formation_isolated")
            and proof.get("noncanonical_formation_preserved")
            and proof.get("globally_live_orphan_formation_preserved")
        ),
        backend_fixture_membership_seeded=True,
        native_game_receiver_completion_verified=False,
        cross_network_gameplay_verified=False,
    )


def private_tournament_retirement_evidence(server_hash):
    path = ROOT / "validation/20261006-tournament-retirement-native-proof.json"
    if not path.is_file():
        return None
    proof = json.loads(path.read_bytes())
    if not (
        proof.get("passed") is True
        and proof.get("server_sha256") == server_hash
        and proof.get("tournament_source_sha256")
        == digest(ROOT / "src/tournament_services.cpp")
        and proof.get("observer_source_sha256")
        == digest(ROOT / "tools/observe-game.py")
        and proof.get("recorder_source_sha256")
        == digest(ROOT / "tools/record-native-tournament-retirement.py")
        and proof.get("native_update_parser_verified")
        and proof.get("native_disband_callback_verified")
        and proof.get("native_state_cleared")
        and proof.get("exact_fixture_restoration_verified")
        and proof.get("accepted_membership_seeded")
        and proof.get("bracket_membership_seeded")
        and proof.get("evidence")
    ):
        return None
    for item in proof["evidence"]:
        evidence = (ROOT / item["file"]).resolve()
        if (
            not evidence.is_relative_to(ROOT)
            or not evidence.is_file()
            or digest(evidence) != item["sha256"]
        ):
            return None
    return dict(
        receipt=path.relative_to(ROOT).as_posix(),
        sha256=digest(path),
        private_game_sha256=proof["game_sha256"],
        scope=proof["scope"],
        native_registration_response_callback_verified=True,
        native_update_and_disband_receivers_verified=True,
        native_registration_enrollment_was_seeded=True,
        accepted_membership_and_playing_bracket_seeded=True,
        native_allocated_round_retirement_verified=False,
        shipping_executable_native_completion_inherited=False,
        cross_network_gameplay_verified=False,
    )


def private_pair_evidence(server_hash):
    current = native_pair_evidence(server_hash)
    if current:
        path, proof = current
        return dict(
            receipt=path,
            sha256=digest(ROOT / path),
            private_game_sha256=proof["game_sha256"],
            scope=proof["scope"],
            native_social_and_private_party_verified=True,
            native_local_settings_persistence_tested_in_this_run=False,
            active_crossplay_masks_cleared_after_native_removal=True,
            shipping_executable_native_completion_inherited=False,
            relay_peer_data_forwarding_verified=False,
            cross_network_gameplay_verified=False,
        )
    path = ROOT / "validation/20261006-native-pair-party-profile.json"
    if not path.is_file():
        return None
    proof = json.loads(path.read_bytes())
    if not (
        proof.get("passed") is True
        and proof.get("server_sha256") == server_hash
        and proof.get("native_two_game_private_party_join_verified")
        and proof.get("native_shared_party_channel_member_and_host_callbacks_verified")
        and proof.get("native_local_settings_persistence_across_new_process_verified")
        and proof.get("native_startup_fences_passing_per_client") == 27
    ):
        return None
    return dict(
        receipt=path.relative_to(ROOT).as_posix(),
        sha256=digest(path),
        private_game_sha256=proof["game_sha256"],
        scope=proof["multiplayer_scope"],
        shipping_executable_native_completion_inherited=False,
        relay_peer_data_forwarding_verified=False,
        cross_network_gameplay_verified=False,
        observed_open_issues=proof["observed_open_issues"],
    )


def current_protocol_fixture(server_hash):
    fallback = DATA / "lobby-verification.json"
    fixture = json.loads(fallback.read_bytes())
    if fixture.get("passed") and fixture.get("server_sha256") == server_hash:
        return fixture, fallback.relative_to(ROOT).as_posix()
    latest = DATA / "backend-readiness-latest.json"
    if not latest.exists():
        return fixture, fallback.relative_to(ROOT).as_posix()

    def referenced(row):
        path = (ROOT / row["path"]).resolve()
        if not path.is_relative_to(ROOT) or digest(path) != row["sha256"]:
            raise ValueError(
                "Backend readiness evidence changed or escaped the project"
            )
        return path, json.loads(path.read_bytes())

    _, readiness = referenced(json.loads(latest.read_bytes()))
    if readiness.get("passed") and readiness.get("backend_sha256") == server_hash:
        full = readiness.get("full_protocol_evidence")
        if full:
            path, candidate = referenced(full)
            if (
                candidate.get("passed")
                and candidate.get("server_sha256") == server_hash
            ):
                return candidate, path.relative_to(ROOT).as_posix()
    return fixture, fallback.relative_to(ROOT).as_posix()


def objectstore_completion_evidence():
    path = ROOT / "validation/20261007-objectstore-completion-target.json"
    if not path.exists():
        return None
    proof = json.loads(path.read_bytes())
    tool = ROOT / "tools/research-objectstore-completion-target.py"
    assert proof["tool_sha256"] == digest(tool)
    assert (
        proof["target_image_sha256"]
        == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
    )
    assert all(row["passed"] for row in proof["completion_calls"])
    assert {
        (row["mode"], row["call"]["task"]) for row in proof["completion_calls"]
    } == {(2, 12), (4, 24)}
    return dict(
        receipt=path.relative_to(ROOT).as_posix(),
        sha256=digest(path),
        scope="Original conditional post-HTTP task-manager bindings; fixture initializes modes",
        task_semantics=proof["interpretation"],
        cached_serializer_binding_verified=False,
        rejected_analysis_aliases=proof["rejected_analysis_aliases"],
        native_method_completion_verified=False,
    )


def counter_upload_evidence(server_hash, game_hash):
    path = ROOT / "validation/20261008-native-counter-upload-readiness.json"
    if not path.is_file():
        return None
    proof = json.loads(path.read_bytes())
    if not (
        proof.get("passed")
        and proof.get("server_sha256") == server_hash
        and proof.get("game_sha256") == game_hash
        and proof.get("native_counter_upload_completion_verified")
        and proof.get("native_compensating_signed_upload_verified")
        and proof.get("temporary_increment_reversed")
        and proof.get("write_interval_restored_minutes") == 15
    ):
        return None
    for item in proof["evidence"]:
        evidence = (ROOT / item["path"]).resolve()
        if not evidence.is_relative_to(ROOT) or digest(evidence) != item["sha256"]:
            raise ValueError("Current native counter evidence changed")
    return path.relative_to(ROOT).as_posix(), proof


def private_counter_read_evidence(server_hash, shipping_hash):
    path = ROOT / "validation/20261008-native-counter-read-readiness.json"
    if not path.is_file():
        return None
    proof = json.loads(path.read_bytes())
    if not (
        proof.get("passed")
        and proof.get("server_sha256") == server_hash
        and proof.get("shipping_game_sha256") == shipping_hash
        and proof.get("native_counter_read_completion_verified")
        and proof.get("native_counter_cache_matches_durable_totals")
        and proof.get("native_counter_task_retired")
        and proof.get("private_diagnostic_command")
        and proof.get("counter_store_unchanged")
        and proof.get("shipping_executable_native_completion_inherited") is False
    ):
        return None
    for item in proof["evidence"]:
        evidence = (ROOT / item["path"]).resolve()
        if not evidence.is_relative_to(ROOT) or digest(evidence) != item["sha256"]:
            raise ValueError("Private native counter read evidence changed")
    return path.relative_to(ROOT).as_posix(), proof


def private_store_variants_evidence(server_hash):
    path = ROOT / "validation/20261008-native-store-variants-readiness.json"
    if not path.is_file():
        return None
    proof = json.loads(path.read_bytes())
    if not (
        proof.get("passed")
        and proof.get("server_sha256") == server_hash
        and proof.get("private_test_game")
        and proof.get("shipping_image_completion_inherited") is False
        and proof.get("native_sale_purchase_completion_verified")
        and proof.get("native_immediate_inventory_update_verified")
        and proof.get("native_inventory_override_applied") is False
        and proof.get("recorder_sha256")
        == digest(ROOT / "tools/record-native-store-variants-proof.py")
    ):
        return None
    for name, expected in proof["evidence"].items():
        evidence = (ROOT / name).resolve()
        if not evidence.is_relative_to(ROOT) or digest(evidence) != expected:
            raise ValueError("Private native sale purchase evidence changed")
    return path.relative_to(ROOT).as_posix(), proof


def native_progression_callback_evidence(server_hash):
    path = ROOT / "validation/20261008-native-progression-callback-readiness.json"
    if not path.is_file():
        return None
    proof = json.loads(path.read_bytes())
    if not (
        proof.get("passed") and proof.get("server_sha256") == server_hash
        and proof.get("native_player_xp_callback_verified")
        and proof.get("native_rank_callback_verified")
        and proof.get("native_progression_restored_after_game_restart")
        and proof.get("durable_retry_did_not_award_again")
        and proof.get("game_issued_report_task_completion_verified") is False
        and proof.get("shipping_image_completion_inherited") is False
        and proof.get("recorder_sha256")
        == digest(ROOT / "tools/record-native-progression-callback-proof.py")
    ):
        return None
    for name, expected in proof["evidence"].items():
        evidence = (ROOT / name).resolve()
        if not evidence.is_relative_to(ROOT) or digest(evidence) != expected:
            raise ValueError("Native progression callback evidence changed")
    return dict(receipt=path.relative_to(ROOT).as_posix(), sha256=digest(path),
                scope=proof["scope"], game_sha256=proof["game_sha256"],
                native_report_task_completion_verified=False,
                shipping_image_completion_inherited=False)


def native_quest_management_evidence(server_hash, game_hash):
    path = ROOT / "validation/20261008-native-quest-management-readiness.json"
    if not path.is_file():
        return None
    proof = json.loads(path.read_bytes())
    if not (
        proof.get("passed") and proof.get("server_sha256") == server_hash
        and proof.get("game_sha256") == game_hash
        and proof.get("native_activation_task_completion_verified")
        and proof.get("native_saved_state_query_completion_verified")
        and proof.get("native_state_restored_after_game_restart")
        and proof.get("game_and_ini_unchanged")
        and proof.get("native_mission_event_progression_verified") is False
        and proof.get("recorder_sha256")
        == digest(ROOT / "tools/record-native-quest-management-proof.py")
        and proof.get("observer_sha256") == digest(ROOT / "tools/observe-game.py")
        and proof.get("native_asset_receipt_sha256")
        == digest(ROOT / "validation/20261008-replay-quest-assets.json")
        and proof.get("original_target_research_sha256")
        == digest(ROOT / "validation/20261008-replay-quest-target.json")
    ):
        return None
    for name, expected in proof["evidence"].items():
        evidence = (ROOT / name).resolve()
        if not evidence.is_relative_to(ROOT) or digest(evidence) != expected:
            raise ValueError("Native mission callback evidence changed")
    reader = (ROOT / proof["native_quest_reader_source"]).resolve()
    if not reader.is_relative_to(ROOT) or digest(reader) != proof["native_quest_reader_sha256"]:
        raise ValueError("Native mission reader source changed")
    return path.relative_to(ROOT).as_posix(), proof


def live_streaming_layout_evidence():
    path = ROOT / "validation/20261008-live-streaming-target-layout.json"
    if not path.is_file():
        return None
    proof = json.loads(path.read_bytes())
    assert proof["passed"] and proof["target_consumer_layout_corroborated"]
    assert (
        proof["original_image_sha256"]
        == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
    )
    assert proof["tool_sha256"] == digest(
        ROOT / "tools/research-live-streaming-layout.py"
    )
    oracle = (ROOT / proof["oracle"]["path"]).resolve()
    assert oracle.is_relative_to(ROOT) and digest(oracle) == proof["oracle"]["sha256"]
    assert [row["part_index"] for row in proof["unchanged_original_vm_cases"]] == [
        0,
        1,
        9,
    ]
    assert all(
        row["passed"] and row["external_calls"] == 0
        for row in proof["unchanged_original_vm_cases"]
    )
    return dict(
        receipt=path.relative_to(ROOT).as_posix(),
        sha256=digest(path),
        target_consumer_layout_corroborated=True,
        extended_metadata_deserializer_verified=False,
        response_wire_order_verified=False,
        native_task_completion_verified=False,
        interpretation=proof["interpretation"],
    )


def mission_earning_evidence(server_hash):
    for filename, stages, cases in (
        ("20261011-emulation-finalization-readiness.json", 181, 534),
        ("20261011-replay-quest-modifier-readiness.json", 127, 379),
        ("20261010-replay-quest-kiosk-readiness.json", 110, 276),
        ("20261010-replay-quest-stim-readiness.json", 95, 221),
        ("20261010-replay-quest-kill-readiness.json", 93, 214),
        ("20261010-replay-quest-context-readiness.json", 83, 192),
        ("20261010-replay-quest-location-readiness.json", 67, 176),
        ("20261010-replay-quest-entry-readiness.json", 45, 108),
        ("20261009-replay-quest-action-readiness.json", 42, 104),
        ("20261009-replay-quest-counter-readiness.json", 37, 100),
    ):
        path = ROOT / "validation" / filename
        if not path.is_file():
            continue
        proof = json.loads(path.read_bytes())
        if not (proof.get("passed") and proof.get("linux_server_sha256") == server_hash
                and proof.get("native_game_callback_verified") is False
                and proof.get("supported_earning_stages") == stages
                and proof.get("original_parser_cases") == cases
                and proof.get("shipped_mission_descriptions") == 232):
            continue
        for reference in proof["evidence"]:
            evidence = (ROOT / reference["path"]).resolve()
            if not evidence.is_relative_to(ROOT) or digest(evidence) != reference["sha256"]:
                raise ValueError("Mission earning evidence changed")
        return dict(receipt=path.relative_to(ROOT).as_posix(), sha256=digest(path),
                    original_parser_cases=cases, supported_earning_stages=stages,
                    shipped_mission_descriptions=232, remaining_earning_stages=232-stages,
                    native_game_callback_verified=False,
                    scope="Original parameter/operator/cache decisions and original-bytecode-correlated shipped producers; encrypted earning, fractional timers, recovery and restart fixtures. Native gameplay completion and unbound predicates remain open.")
    return None


def category_constructor_evidence():
    path = ROOT / "validation/20261009-objectstore-category-constructors.json"
    if not path.is_file():
        return None
    proof = json.loads(path.read_bytes())
    assert proof["passed"] and len(proof["cases"]) == 8
    assert proof["target_image_sha256"] == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
    assert proof["tool_sha256"] == digest(ROOT / "tools/research-objectstore-category-constructors.py")
    assert all(row["passed"] and row["captured"]["service"] == 193 for row in proof["cases"])
    assert {(row["captured"]["task"], row["response_offset"]) for row in proof["cases"]} == {(9, 8), (10, 432)}
    assert proof["native_response_reader_verified"] is False
    return dict(receipt=path.relative_to(ROOT).as_posix(), sha256=digest(path),
                scope=proof["scope"], native_response_reader_verified=False,
                native_runtime_verified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--server", type=Path, default=ROOT / "build/Release/iw8-dw-server.exe"
    )
    parser.add_argument("--deployment", type=Path, default=DATA / "deployment.json")
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--source-receipt", type=Path)
    parser.add_argument(
        "--task-audit",
        type=Path,
        default=ROOT / "validation/20261009-native-task-arithmetic-inventory.json",
    )
    parser.add_argument(
        "--rest-audit", type=Path, default=DATA / "native-rest-callgraph.json"
    )
    parser.add_argument("--protocol", type=Path)
    parser.add_argument(
        "--output", type=Path, default=DATA / "backend-coverage-inventory.json"
    )
    parser.add_argument(
        "--text-output", type=Path, default=DATA / "backend-coverage-inventory.txt"
    )
    args = parser.parse_args()
    source_root = args.source_root.resolve()
    source_receipt = None
    if args.source_receipt:
        source_receipt = json.loads(args.source_receipt.read_bytes())
        for name, expected in source_receipt["inputs"].items():
            if name.startswith("src/"):
                path = (source_root / name).resolve()
                if not path.is_relative_to(source_root) or digest(path) != expected:
                    raise ValueError("Compiled source receipt changed: " + name)
    for output in (args.output, args.text_output):
        if not output.resolve().is_relative_to(ROOT):
            raise ValueError("Keep inventory output inside the backend project")
    graph = json.loads((DATA / "native-service-callgraph.json").read_bytes())
    byte_evidence, byte_calls = native_byte_task_evidence(args.task_audit)
    deployment = json.loads(args.deployment.read_bytes())
    executable = args.server
    current_hash = digest(executable)
    if args.protocol:
        fixture = json.loads(args.protocol.read_bytes())
        fixture_path = args.protocol.resolve().relative_to(ROOT).as_posix()
        if not fixture.get("passed") or fixture.get("server_sha256") != current_hash:
            raise ValueError("Selected protocol proof does not match the backend image")
    else:
        fixture, fixture_path = current_protocol_fixture(current_hash)
    valid_fixture = bool(fixture["passed"] and fixture["server_sha256"] == current_hash)
    routes = {}
    domains = {}
    sources = {}
    for service, domain, filename, tasks in ROUTES:
        path = source_root / "src" / filename
        sources["src/" + filename] = digest(path)
        domains[service] = domain
        for task in tasks:
            assert (service, task) not in routes, (service, task)
            routes[service, task] = "src/" + filename
    for name in ("src/quest_services.cpp", "src/quest_services.h", "src/replay_quest_data.h",
                 "src/battlepass_services.cpp", "src/achievement_store.cpp"):
        sources[name] = digest(source_root / name)
    # Source locations aid further review. These do not establish execution or
    # every optional/malformed path, even when the enclosing suite has passed.
    references = {}
    suite = [ROOT / "tools/test-lobby.py"]
    # Fixtures can import further local fixtures. Follow those imports once per
    # module so nested marketplace checks remain visible in the coverage ledger.
    seen = set(suite)
    for path in suite:
        tree = ast.parse(path.read_text())
        modules = {
            name.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for name in node.names
        }
        for name in sorted(modules):
            candidate = ROOT / "tools" / (name + ".py")
            if candidate.is_file() and candidate not in seen:
                if len(seen) >= 128:
                    raise ValueError("Unexpectedly large local fixture import graph")
                seen.add(candidate)
                suite.append(candidate)
    for path in suite:
        for node in ast.walk(ast.parse(path.read_text())):
            if (
                not isinstance(node, ast.Call)
                or not isinstance(node.func, ast.Attribute)
                or node.func.attr != "task"
                or len(node.args) < 2
            ):
                continue
            if not all(
                isinstance(arg, ast.Constant) and type(arg.value) is int
                for arg in node.args[:2]
            ):
                continue
            pair = tuple(arg.value for arg in node.args[:2])
            expected = next(
                (
                    keyword.value.value
                    for keyword in node.keywords
                    if keyword.arg == "error"
                    and isinstance(keyword.value, ast.Constant)
                ),
                0,
            )
            references.setdefault(pair, []).append(
                dict(
                    file=str(path.relative_to(ROOT)),
                    line=node.lineno,
                    expected_error=expected,
                    evidence="static fixture call site",
                )
            )
    tasks = []
    pairs = (
        set(routes)
        | {
            (int(service), task)
            for service, values in graph["families"].items()
            for task in values
        }
        | {(row["service"], row["task"]) for row in byte_calls}
    )
    relay_proofs = {}
    for task, filename in (
        (26, "native-relay-client-verification.json"),
        (24, "native-relay-transport-verification.json"),
    ):
        path = DATA / filename
        if path.exists():
            relay_proofs[task] = ("data/" + filename, json.loads(path.read_bytes()))
    tournament_path = DATA / "native-tournament-verification.json"
    if tournament_path.exists():
        tournament_proof = json.loads(tournament_path.read_bytes())
        for task in (20, 29):
            relay_proofs[task] = ("data/" + tournament_path.name, tournament_proof)
    presence_join_path = DATA / "native-presence-join-verification.json"
    if presence_join_path.exists():
        relay_proofs[18] = (
            "data/" + presence_join_path.name,
            json.loads(presence_join_path.read_bytes()),
        )
    # A newly linked backend must not inherit native proof from an older image.
    # Reconnect receipts prove only the auth/relay methods, not search or join UI.
    for path in sorted((ROOT / "validation").glob("*native-reconnect*.json")):
        proof = json.loads(path.read_bytes())
        if (
            proof.get("passed")
            and proof.get("server_sha256") == current_hash
            and proof.get("game_sha256") == deployment["sha256"]
            and proof.get("fresh_backend_native_auth_and_lobby_session_verified")
            and proof.get("native_relay_token_renewed_on_restart")
            and proof.get("native_relay_bind_verify_established_after_restart")
            and proof.get("native_relay_join_data_correlated_with_backend_event")
        ):
            for task in (24, 26):
                relay_proofs[task] = (path.relative_to(ROOT).as_posix(), proof)
    same_server_path = ROOT / "validation/20261006-same-server-native-reconnect.json"
    if same_server_path.is_file():
        proof = json.loads(same_server_path.read_bytes())
        expected_sources = {
            "integration/replay/DW_LocalPlatform.cpp",
            "tools/observe-game.py",
            "tools/record-native-same-server-reconnect.py",
        }
        if (
            proof.get("passed") is True
            and proof.get("server_sha256") == current_hash
            and proof.get("game_sha256") == deployment["sha256"]
            and proof.get("same_server_and_game_process_preserved")
            and proof.get("old_native_relay_authenticated_disconnect_verified")
            and proof.get("fresh_native_relay_token_and_udp_association_verified")
            and proof.get("native_relay_stability_verified")
            and proof.get("native_fences_passing") == 27
            and set(proof.get("sources", {})) == expected_sources
            and all(
                proof["sources"][source] == digest(ROOT / source)
                for source in expected_sources
            )
        ):
            # This pass proves client-auth completion (26), not that a newly
            # fetched server-info response (24) replaced the retained cache.
            relay_proofs[26] = (same_server_path.relative_to(ROOT).as_posix(), proof)
    for continuity_path in (
        ROOT / "validation/20261008-relay-session-continuity-readiness.json",
        ROOT / "validation/20261008-session-store-relay-native-readiness.json",
    ):
        if not continuity_path.is_file():
            continue
        proof = json.loads(continuity_path.read_bytes())
        if (
            proof.get("passed")
            and proof.get("backend_sha256") == current_hash
            and proof.get("game_sha256") == deployment["sha256"]
            and proof.get("native_relay_callback_and_server_event_correlated")
            and proof.get("native_udp_keepalives_verified")
        ):
            for item in proof["evidence"]:
                path = (ROOT / item["path"]).resolve()
                if not path.is_relative_to(ROOT) or digest(path) != item["sha256"]:
                    raise ValueError("Current native relay evidence changed")
            normalized = dict(proof, server_sha256=proof["backend_sha256"])
            for task in (24, 26):
                relay_proofs[task] = (
                    continuity_path.relative_to(ROOT).as_posix(),
                    normalized,
                )
    for filename in (
        "relay_provider.cpp",
        "crypto.cpp",
        "platform.cpp",
        "lobby.cpp",
        "lobby.h",
        "matchmaking_store.cpp",
        "matchmaking_store.h",
        "tournament_map_policy.cpp",
        "tournament_map_policy.h",
        "playlist_catalog.cpp",
        "playlist_catalog.h",
        "channel_store.cpp",
        "channel_store.h",
        "regulation_services.cpp",
        "regulation_services.h",
        "rest_services.h",
        "social_services.cpp",
        "social_services.h",
    ):
        sources["src/" + filename] = digest(source_root / "src" / filename)
    marketing_path = DATA / "native-marketing-verification.json"
    marketing_proof = (
        json.loads(marketing_path.read_bytes()) if marketing_path.exists() else None
    )
    mail_path = ROOT / "validation/20261006-mail-native-consumer.json"
    mail_proof = json.loads(mail_path.read_bytes()) if mail_path.exists() else None
    map_policy_path = ROOT / "validation/20261006-tournament-map-native-policy.json"
    map_policy_proof = (
        json.loads(map_policy_path.read_bytes()) if map_policy_path.exists() else None
    )
    channel_path, channel_proof = None, None
    for path in sorted((ROOT / "validation").glob("*channel-native-*.json")):
        proof = json.loads(path.read_bytes())
        if (
            proof.get("passed")
            and proof.get("server_sha256") == current_hash
            and proof.get("game_sha256") == deployment["sha256"]
            and proof.get("native_channel_create_completion_verified")
            and proof.get("positive_native_member_callback_verified")
        ):
            channel_path, channel_proof = path, proof
    rest_path = args.rest_audit.resolve()
    if not rest_path.is_relative_to(DATA):
        raise ValueError("Keep the native REST audit in repository data")
    rest_inventory = json.loads(rest_path.read_bytes()) if rest_path.exists() else None
    friend_evidence = friend_native_evidence(current_hash, deployment["sha256"])
    ab_evidence = abtesting_native_evidence(current_hash, deployment["sha256"])
    counter_evidence = counter_upload_evidence(current_hash, deployment["sha256"])
    private_counter_read = private_counter_read_evidence(
        current_hash, deployment["sha256"]
    )
    private_store = private_store_variants_evidence(current_hash)
    quest_evidence = native_quest_management_evidence(current_hash, deployment["sha256"])
    rest_requests = (
        rest_coverage(rest_inventory, friend_evidence, current_hash)
        if rest_inventory
        else []
    )
    if rest_inventory:
        if rest_inventory["inventory_tool_sha256"] != digest(
            ROOT / "tools/inventory-native-rest.py"
        ):
            raise ValueError("Regenerate the native REST inventory after tool changes")
        if rest_inventory.get("target_database_changed"):
            raise ValueError(
                "Regenerate the native REST inventory from a stable database"
            )
    for service, task in sorted(pairs):
        constructors = [
            proof
            for proof in graph["proven_calls"]
            if (proof["service"], proof["task"]) == (service, task)
        ]
        proof_filename, relay_proof = (
            relay_proofs.get(task, (None, None)) if service == 145 else (None, None)
        )
        if (service, task) == (104, 6) and marketing_proof:
            proof_filename, relay_proof = "data/" + marketing_path.name, marketing_proof
        if service == 29 and task in (4, 5, 10) and mail_proof:
            proof_filename = str(mail_path.relative_to(ROOT)).replace("\\", "/")
            relay_proof = mail_proof
        if (service, task) == (95, 1) and map_policy_proof:
            proof_filename = map_policy_path.relative_to(ROOT).as_posix()
            relay_proof = map_policy_proof
        if (service, task) == (198, 6) and channel_proof:
            proof_filename = channel_path.relative_to(ROOT).as_posix()
            relay_proof = channel_proof
        if (service, task) == (194, 1) and ab_evidence:
            proof_filename, relay_proof = ab_evidence
        if (service, task) == (23, 1) and counter_evidence:
            proof_filename, relay_proof = counter_evidence
        if service == 125 and task in (3, 5) and quest_evidence:
            proof_filename, relay_proof = quest_evidence
        completion = bool(relay_proof and relay_proof.get("passed"))
        scope = None
        if (service, task) == (23, 1) and counter_evidence:
            scope = counter_evidence[1]["scope"]
        if service == 125 and task in (3, 5) and quest_evidence:
            scope = (
                "Shipping game's native activation callbacks installed three MP/co-op/BR "
                "mission records; a fresh game process restored all three through the "
                "saved-state query without another activation. No earned mission "
                "counter, completion, reward or other achievement-family claim"
            )
        if (
            service == 145
            and task in (24, 26)
            and relay_proof
            and relay_proof.get("native_udp_keepalives_verified")
        ):
            scope = "Native SDK discovery/auth/association callbacks matched exact issuer token and backend UDP event; authenticated keepalives advanced with an unchanged route. In-match/two-network renewal remains unverified."
        if (service, task) == (194, 1) and ab_evidence:
            scope = "Native populated enrollment decoded exact test/cohort/modifier and applied its registered dvar before and after backend restart/dw_restart; cleanup restored the empty enrollment and value 16. Future native polling and other modifier types remain unverified"
        if (service, task) == (198, 6) and channel_proof:
            completion = bool(
                completion
                and channel_proof.get("native_channel_create_completion_verified")
                and channel_proof.get("positive_native_member_callback_verified")
            )
            scope = "Native private-party create response installed its real channel/host; peer event-24/25 callbacks updated its native member records. The peer's subscribe/unsubscribe task requests came from an independent wire client, not another game"
            if channel_proof.get("native_channel_message_verified"):
                scope += "; the first real peer message was consumed in native chat history. The peer send request came from the wire client"
        if (service, task) == (95, 1) and map_policy_proof:
            completion = bool(
                completion
                and map_policy_proof.get("native_publisher_map_strings_applied") == 4
                and map_policy_proof.get("native_publisher_values_stable_after_restart")
            )
            scope = "Native general publisher namespace applied four tournament map strings and its revision across backend restart; other publisher tuning and native tournament play remain unverified"
        if service == 29 and task in (4, 5, 10) and mail_proof:
            completion = bool(
                completion
                and mail_proof.get("native_game_mail_callback_verified")
                and mail_proof.get("native_mail_header_and_body_completion_verified")
                and mail_proof.get("native_mail_deletion_and_idle_return_verified")
            )
            scope = "Stock native onNewMail wakeup, header/body completion, deletion and idle return for one inert diagnostic; application mail handlers unverified"
        if (service, task) == (145, 18) and relay_proof:
            completion = bool(
                relay_proof.get("native_friend_menu_invitation_handshake_verified")
                and relay_proof.get("native_presence_join_request_verified")
                and relay_proof.get("native_assigned_lobby_and_host_verified")
                and relay_proof.get("native_matchmaking_state") == 7
                and relay_proof.get("native_lobby_state") == 4
            )
            scope = "Friend-menu presence-by-player session exchange and native assigned lobby/host; no playable two-game connection or map"
        native = bool(
            relay_proof
            and completion
            and relay_proof["server_sha256"] == current_hash
            and relay_proof["game_sha256"] == deployment["sha256"]
        )
        private_proof = (
            private_counter_read if (service, task) == (23, 2)
            else private_store if (service, task) == (80, 106)
            else None
        )
        tasks.append(
            dict(
                service=service,
                task=task,
                domain=domains.get(service, "unclassified target family"),
                handler_registered=(service, task) in routes,
                handler_source=routes.get((service, task)),
                exact_target_constructor_proofs=constructors,
                original_byte_callsite_proofs=[
                    proof
                    for proof in byte_calls
                    if (proof["service"], proof["task"]) == (service, task)
                ],
                target_constructor_audit_covered=bool(constructors)
                or any(
                    (proof["service"], proof["task"]) == (service, task)
                    for proof in byte_calls
                ),
                preparation_contract_provenance=(
                    "SDK source oracle only; not recovered as a Replay request writer"
                    if (service, task) in ((50, 5), (50, 15), (50, 20))
                    else None
                ),
                static_fixture_references=references.get((service, task), []),
                native_positive_completion_verified_current_binary=native,
                native_completion_evidence=proof_filename if native else None,
                native_completion_scope=scope if native else None,
                private_native_positive_completion_verified=bool(private_proof),
                private_native_completion_evidence=(
                    private_proof[0] if private_proof else None
                ),
                private_native_completion_scope=(
                    private_proof[1]["scope"] if private_proof else None
                ),
                private_native_completion_game_sha256=(
                    private_proof[1]["game_sha256"] if private_proof else None
                ),
                native_fence_completion_is_not_per_method_proof=True,
            )
        )
    inventory = dict(
        schema=1,
        generated_utc=datetime.now(timezone.utc).isoformat(),
        full_backend_complete=False,
        full_native_method_audit_complete=False,
        scope="Known target constructors plus explicitly reviewed local handler routes; indirect/virtual and unclassified REST call sites remain audit gaps",
        target_database=graph["database"],
        target_database_size=graph["database_size"],
        target_database_mtime_ns=graph["database_mtime_ns"],
        callgraph_sha256=digest(DATA / "native-service-callgraph.json"),
        native_byte_task_inventory=byte_evidence,
        objectstore_completion_target_evidence=objectstore_completion_evidence(),
        objectstore_category_constructor_evidence=category_constructor_evidence(),
        live_streaming_target_layout_evidence=live_streaming_layout_evidence(),
        private_native_counter_read_evidence=private_counter_read,
        native_progression_callback_evidence=native_progression_callback_evidence(current_hash),
        mission_earning_evidence=mission_earning_evidence(current_hash),
        selected_protocol_fixture=fixture_path,
        target_exported_function_count=graph.get("exported_function_count"),
        ambiguous_display_aliases=graph.get("ambiguous_display_aliases", []),
        target_database_changed_during_inventory=graph.get(
            "database_changed_during_inventory"
        ),
        server_sha256=current_hash,
        game_sha256=deployment["sha256"],
        source_sha256=sources,
        source_inventory_scope=(
            "Selected frozen source hashes checked against its compilation receipt"
            if source_receipt
            else "Selected source hashes without a compiled-backend source receipt"
        ),
        selected_source_root=str(source_root),
        compiled_source_receipt=(
            dict(
                path=args.source_receipt.resolve().relative_to(ROOT).as_posix(),
                sha256=digest(args.source_receipt),
            )
            if source_receipt
            else None
        ),
        private_native_pair_evidence=private_pair_evidence(current_hash),
        private_native_tournament_retirement_evidence=private_tournament_retirement_evidence(
            current_hash
        ),
        offline_tournament_maintenance_evidence=offline_tournament_maintenance_evidence(
            current_hash
        ),
        validation=dict(
            independent_suite_matches_binary=valid_fixture,
            grouped_checks=len(fixture["checks"]),
            receipt=fixture_path,
            scope=fixture.get("scope", "full fixture suite"),
            native_method_completion_is_separate=True,
        ),
        counts=dict(
            task_routes=len(tasks),
            registered_handlers=sum(t["handler_registered"] for t in tasks),
            known_target_tasks_without_handler=sum(
                not t["handler_registered"] for t in tasks
            ),
        ),
        tasks=tasks,
        native_rest_inventory=(
            dict(
                receipt=rest_path.relative_to(ROOT).as_posix(),
                sha256=digest(rest_path),
                target_image_sha256=rest_inventory["target_image_sha256"],
                exported_functions=rest_inventory["exported_functions"],
                requests=rest_requests,
                counts=dict(
                    containing_functions=len(rest_requests),
                    request_functions=sum(
                        not row.get("shared_service_helper_only")
                        for row in rest_requests
                    ),
                    shared_parameter_helpers=sum(
                        bool(row.get("shared_service_helper_only"))
                        for row in rest_requests
                    ),
                    dedicated_domain_handlers=sum(
                        row["dedicated_domain_handler"] is True for row in rest_requests
                    ),
                    known_literal_bindings_without_handler=sum(
                        row["dedicated_domain_handler"] is False
                        for row in rest_requests
                    ),
                    unresolved_dynamic_or_helper_bindings=sum(
                        row["dedicated_domain_handler"] is None
                        and not row.get("native_pre_transport_blocked")
                        and not row.get("shared_service_helper_only")
                        for row in rest_requests
                    ),
                    confirmed_native_pre_transport_blockers=sum(
                        bool(row.get("native_pre_transport_blocked"))
                        for row in rest_requests
                    ),
                    current_native_method_completions=sum(
                        row["current_native_method_completion_verified"]
                        for row in rest_requests
                    ),
                ),
                unresolved=rest_inventory["unresolved"],
                full_rest_audit_complete=False,
                native_response_verified=False,
            )
            if rest_inventory
            else None
        ),
        domain_gaps=GAPS,
        non_task_subsystems=[
            dict(
                domain="signed platform/provider and resources",
                sources=["src/platform.cpp", "src/platform_resources.cpp"],
                gaps="Remote deployment and game additional-profile selection",
            ),
            dict(
                domain="native auth and legacy account token",
                sources=["src/platform.cpp", "src/server.cpp"],
                gaps="Only local signed realm; no retail credentials",
            ),
            dict(
                domain="protocol 210 encrypted lobby/push lifetime",
                sources=["src/lobby.cpp", "src/services.cpp"],
                gaps="Distributed hosting, multi-game connection lifecycle and provider refresh validation",
            ),
            dict(
                domain="bandwidth measurement",
                sources=["src/bandwidth.cpp"],
                gaps="Remote endpoint deployment",
            ),
            dict(
                domain="UDP NAT introduction and QoS",
                sources=["src/qos_provider.cpp", "src/qos_services.cpp"],
                gaps="Configurable remote listener/endpoint publication is implemented; actual native peer traversal across two networks remains unverified",
            ),
            dict(
                domain="playlist/map/match catalog",
                sources=["src/playlist_catalog.cpp", "src/matchmaking_services.cpp"],
                gaps="Broader lobby join/migration/tournament management; no additional map tests requested",
            ),
            dict(
                domain="REST friends, presence and user lists",
                sources=["src/social_services.cpp", "src/rest_services.cpp"],
                gaps="Bulk username hydration now implements the exact Replay DTO, 200-user capacity, registered-provider aliases and signed title scope. Its response vtable was verified from native resolver allocation; per-method live username-resolver completion remains open. Other native REST resources must be recovered individually",
                native_friend_lifecycle_evidence=(
                    friend_evidence[0] if friend_evidence else None
                ),
                target_layout_receipt="validation/20261006-username-target-layout.json",
            ),
            dict(
                domain="REST account credentials and UNO/Umbrella grants",
                sources=[
                    "src/identity_rest_services.cpp",
                    "src/platform.cpp",
                    "src/platform_account_store.cpp",
                ],
                gaps="Four original request/response contracts and encrypted fixtures implemented; native account-menu/crossplay-login callbacks, cross-player migration and retail ownership remain separate scopes",
                target_layout_receipt="validation/20261006-native-account-auth-layout.json",
            ),
            dict(
                domain="REST regulation publications and owned preferences",
                sources=["src/regulation_services.cpp", "src/rest_services.cpp"],
                gaps="Exact target response layouts and durable owner semantics implemented; native regulation commands are absent from the current compiled game, and per-method runtime completion remains unverified",
                target_layout_receipt="validation/20261006-regulation-target-layout.json",
            ),
            dict(
                domain="authenticated relay UDP routing",
                sources=[
                    "src/relay_services.cpp",
                    "src/relay_provider.cpp",
                    "src/crypto.cpp",
                ],
                gaps="Local BIND/JOIN/VERIFY/ping/data/upgrade/disconnect and anti-replay implemented; remote deployment/migration and native two-game JOIN/forwarding remain open",
            ),
        ],
        unresolved_target_paths=graph["unresolved_paths"],
        dynamic_forwarders=graph["dynamic_forwarders"],
        unidentified_scope=[
            "Indirect virtual dispatch not captured by direct constructor audit",
            "Memory-derived service/task IDs",
            "REST/push consumer coverage outside binary task constructors",
        ],
    )
    args.output.write_text(json.dumps(inventory, indent=2) + "\n", newline="\n")
    text = [
        "REPLAY DW BACKEND COVERAGE INVENTORY",
        "",
        "Full backend and full native method audit remain incomplete.",
        "Handler registration, protocol fixtures and native method completion are separate gates.",
        "",
        f"Server SHA256: {current_hash}",
        f'Game SHA256: {deployment["sha256"]}',
        f'Known task routes: {len(tasks)}; registered: {inventory["counts"]["registered_handlers"]}; '
        f'known target tasks without handler: {inventory["counts"]["known_target_tasks_without_handler"]}',
        "",
    ]
    for service in sorted({row["service"] for row in tasks}):
        known = [row for row in tasks if row["service"] == service]
        implemented = (
            ",".join(str(row["task"]) for row in known if row["handler_registered"])
            or "none"
        )
        missing = (
            ",".join(str(row["task"]) for row in known if not row["handler_registered"])
            or "none in current constructor set"
        )
        text += [
            f'{service}: {domains.get(service, "unclassified target family")}',
            f"  Handlers: {implemented}",
            f"  Missing known handlers: {missing}",
            f'  Remaining: {GAPS.get(str(service), "Unclassified")}',
            "",
        ]
    text += [
        "Additional audit gaps: indirect/virtual task dispatch, memory-derived IDs and unclassified REST/push paths.",
        "The JSON ledger retains exact constructor call-site provenance and static fixture source references.",
        "No map tests performed. No generic success replies or native fence overrides.",
    ]
    if byte_evidence:
        text += [
            "",
            "Independent original-instruction task inventory:",
            "  Receipt: " + byte_evidence["receipt"],
            f'  {byte_evidence["route_count"]} routes; {byte_evidence["inspected_functions"]} inspected functions; '
            f'{byte_evidence["unwind_bounded_functions"]} PE unwind bounds; {byte_evidence["sqlite_fallback_functions"]} SQLite boundary hint.',
            f'  {byte_evidence["independent_x64_trace_cases"]} independent register/stack/branch fixtures passed; '
            f'{byte_evidence["state_limited_paths"]} state-limited paths and {byte_evidence["unresolved_paths"]} unresolved paths remain.',
            f'  Exported-text routes: {byte_evidence["text_inventory_routes"]}; text-only routes: '
            f'{byte_evidence["text_routes_not_recovered_from_bytes"]}; additional raw routes: '
            + ", ".join(
                f"{service}/{task}"
                for service, task in byte_evidence["additional_raw_routes"]
            ),
            "  Original function byte hashes and direct branch targets rechecked; aliases do not resolve calls.",
            "  Conditional moves retain both alternatives; branch feasibility, indirect dispatch and stack arguments remain open.",
            "  Potential routes and handler registration do not establish native callback completion.",
        ]
    retirement = inventory["private_native_tournament_retirement_evidence"]
    if retirement:
        text += [
            "",
            "Current-backend private native tournament receiver evidence:",
            "  Receipt: " + retirement["receipt"],
            "  Native registration response, PLAYING update and event-2012 disband consumed.",
            "  Enrollment, acceptance and bracket membership explicitly seeded using registered accounts.",
            "  Same native game/backend processes; complete state clearing and exact restoration verified.",
            "  No native join assignment, allocated-round retirement, map or WAN gameplay credit.",
            "  Shipping-executable completion is not inherited from this private image.",
        ]
    maintenance = inventory["offline_tournament_maintenance_evidence"]
    if maintenance:
        text += [
            "",
            "Current-backend offline tournament maintenance evidence:",
            "  Receipt: " + maintenance["receipt"],
            "  Offline retirement, interrupted transaction recovery and exact once-only reconnect notification.",
            "  Real-clock expiry from server startup with zero authenticated clients/tasks.",
            "  Malformed neighboring realm preserved; valid realm progressed; fixture files restored exactly.",
            "  Backend fixture memberships seeded; no native receiver, map or WAN gameplay credit.",
        ]
    if rest_inventory:
        text += [
            "",
            "Exact-target direct REST request inventory (response semantics remain separate):",
        ]
        for request in rest_requests:
            text.append(
                f'  0x{request["function_address"]:X} {request["function"]}: '
                f'services={request["services"]}; resource/operations={request["resource_operations"]}; '
                f'literal binding resolved={request["service_operation_binding_resolved"]}; '
                f'dedicated handler={request["dedicated_domain_handler"]}; '
                f'current native method completion={request["current_native_method_completion_verified"]}'
            )
            if request.get("native_pre_transport_blocked"):
                text.append("    Blocker: " + request["native_pre_transport_blocker"])
                text.append("    Backend scope: " + request["coverage_scope"])
    args.text_output.write_text("\n".join(text) + "\n", newline="\n")
    print(json.dumps(inventory["counts"]))


if __name__ == "__main__":
    main()
