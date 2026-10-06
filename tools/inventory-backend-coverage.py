"""Join target constructor evidence, explicit backend routes and validation receipts.

This is a coverage ledger, not a declaration that every SDK call was recovered.
Handler registration is curated from dispatch code; fixture call sites are static
references, not runtime/native completion. Unknown indirect calls remain open.
"""

import ast
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

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
    (194, "AB enrollment", "engagement_services.cpp", [1]),
    (195, "scripted loot", "engagement_services.cpp", [1]),
    (197, "account aliases and clans", "identity_services.cpp", [10, 11]),
    (197, "account aliases and clans", "clan_services.cpp", list(range(20, 33)) + [37]),
    (198, "channels", "channel_services.cpp", list(range(1, 8)) + [12]),
    (255, "REST domain dispatch", "rest_services.cpp", [10]),
]
GAPS = {
    "3": "Only published legacy team data; broader clan/team SDK families require target evidence.",
    "4": "Task 14 applies explicitly trusted local token-hash/stat-batch authorizations with atomic retry receipts. Retail opaque token payload validation and a positive native callback remain unverified. Verified game leaderboard asset column publication remains open.",
    "6": "Offline delivery is unavailable; no unsolicited invented recipient identity.",
    "8": "Full native positive CRUD roundtrip still needs observation.",
    "10": "Full native positive editing/deletion/backup roundtrip still needs observation.",
    "12": "Native utility methods outside the recovered request set remain unclassified.",
    "23": "Full native positive signed increment/read roundtrip still needs observation.",
    "27": "Configured geography is local metadata, not real IP geolocation.",
    "29": "Native task 2 and categorized/status variants remain open. Original sendMailWithDuration 0x14212D9D0 selects task 7 for an explicit sender and task 9 otherwise. Native event 18 recipient notifications, bounded per-connection unread catch-up, durable idle expiration returns and queued-row revalidation are implemented and covered by encrypted two-client fixtures. The stock game callback, header/body decoder, deletion and idle return were verified with one inert diagnostic; application-specific mail handlers remain unverified.",
    "38": "Reports are durable acknowledgements, not a retail attestation/security verdict.",
    "50": "Task 22 live download; preparation IDs 5/15/20 are source-oracle contracts without target constructor proofs. Whole-user optional X-Checksum algorithm unresolved. Full positive native upload/copy lifecycle still unobserved.",
    "58": "Task 22 multipart/live download exact result binding; positive native multipart upload/commit.",
    "67": "Positive native telemetry batch completion beyond startup filter initialization.",
    "80": "Task 58 validates trusted local issuer publications with the exact Int64/Int64/blob DTO; retail token issuance/semantics and positive native validation callback remain unverified. Task125 CouponOrderV2 request unavailable. Task106 recipient SKU orders support published gifting to existing local accounts with full owner/buyer coupon DTOs, flushed multi-account intents, conflicting-image preflight and disk/process recovery. Native gift/purchase callbacks, discount rules, other variants and loot generation remain open.",
    "95": "Additional title/build tuning documents need explicit publication; unknown namespaces remain unavailable.",
    "104": "Full bounded message publication and owned view receipts implemented. Native positive view callback and redemption-action consumers remain separate validation gates.",
    "123": "Positive native redemption callbacks and game reward consumers still need validation.",
    "125": "Publish progression/reward/quest rules; native positive binary event/activation paths. Ingestion alone does not fabricate rewards.",
    "145": "Presence joins and public lobby filling have authenticated party tokens, live-host/capacity checks, shared documents and typed event-2001/2006 pushes. Public selection also binds playlist/map publication, native netcode/rules, privacy and native in_game join-in-progress policy; two authenticated clients are covered by encrypted-wire fixtures. Primary-player additional reservations are validated/published and counted in public/presence capacity, team occupancy and fullest-lobby selection. Replay bnet platform restrictions are validated without splitting equivalent cross-play pools. Legacy zero-reservation documents remain compatible; native split-screen consumption/gameplay remain unverified. Complete native host snapshots retire omitted/READY_TO_REMOVE members across teams/squads/optional metadata, preserve shared searches and newer assignments, and commit through recoverable transactions. Document clocks advance monotonically to prevent equal-second native update loss; native departure callbacks remain unverified. Party-elected task-145/15 host claims bind current membership/search tokens and registered native addresses after the original host lease ends; ownership, migration order and departed-member cleanup share the existing durable transaction while DTLS keys/map/rules remain intact. Six encrypted fixture groups cover stale/live-host denial, successor claims and interrupted publication. A native friend-menu session-info exchange and assigned lobby/host were verified on the recorded server hash; native public-search callbacks, playable two-game connections and native host-migration callbacks remain open. Native tournament task-18 searches now use authenticated party tokens, published same-team enrollment and recoverable formation-search/index transactions; exact event-2009 join pushes bind the returned search ID, with retry/deduplication/cancellation/expiry checks covered by two encrypted clients. Capacity-based tournament publications now accept unassigned registrations and allocate real authenticated parties without splitting them; native teams/rounds are generated and PLAYING requires every slot and live-session acknowledgement. Formation/enrollment/search/index changes share flushed recoverable transactions with an explicitly fixed cross-domain enrollment target. Forming-party withdrawal releases slots, resets peer acceptance while retaining registration and emits exact event-2011 with durable catch-up/revocation. Capacity publications with pinned round rules now allocate closed native round lobbies through the shared playlist/map policy and document builder after complete session-bound readiness. Exact create/join pushes retain actual party search IDs and native tournament/team/round metadata; formation, lobby, searches, account index and enrollment share one recoverable transaction. Eight signed machine accounts verify map-policy waiting, interrupted publication, four independent first-round lobbies, temporary same-session join catch-up and all seven result-driven matches. Canonical tournament map pools supply both native publisher dvar strings and backend round selection, with durable revision/hash protection and immutable competition snapshots. The compiled selector matches original Replay x64 instructions across 32 cases; four native strings and their revision survive same-process backend reconnect. Native join/formation/round callback validation, forfeits and native result/ready/accept/leave/rejoin callbacks remain open. Host-authorized task 21 results, durable journals, bracket advancement, exact event-2010 updates and opt-in idle publication/disband pushes with recipient/snapshot revalidation are implemented. Native registration/state callbacks, FORMING/PLAYING parsing, idle publication updates and event-2012 disband were verified with explicitly seeded enrollment; playable tournaments remain open. Remote relay deployment/migration and native two-game forwarding remain open.",
    "150": "Positive native scheduled match operations; local publication required.",
    "151": "Published local registration only; retail esports registration workflow is not emulated.",
    "152": "Positive native performance write completion.",
    "193": "Verified user-object PUT/read and publisher metadata/content retain native envelopes. Complete multi-object upload windows use flushed per-title/account intents, full namespace/content/tag preflight and blocked-read/process-restart recovery; native profile-window recovery still needs a targeted client failure run. Tasks 3/9/10/12/24 category/list/large-upload families remain open; response binding is unresolved for some recovered writers.",
    "194": "Signed empty local enrollment; populated experiments need explicit treatment rules.",
    "195": "Full task-1 proxy request/result and published deterministic script responses with ordered owned task journals. Constant native clientData is not used as retry identity. Retail script/reward rules and positive native callback/game consumers remain unverified; no fabricated inventory grants.",
    "197": "Current family implemented; deeper native callback coverage and distributed/multi-profile lifecycle remain open.",
    "198": "Complete persisted channel layouts, Replay's 200-member limit and native event-24/25 member/channel-info DTOs are implemented. Signed clients cover owned join/category unsubscribe, last-live-socket departure, rapid rejoin generation revocation, concurrent joins and failed atomic publication. Field 8 is native UInt32 dataVersion. The serialized endpoint publishes a real sender join before its first message and coalesces the delayed duplicate. Native private-party creation, real peer join/leave and first incoming-message history are recorded in hash-bound proofs. A second game's subscribe/unsubscribe/send task callbacks and multi-game chat remain open.",
    "255": "Friends/user lists/presence/event ingestion and exact-target regulation publication/preference CRUD are implemented. Regulation choices bind the signed owner, preserve retries and survive atomic-write failure/process restart; no preference is invented from an absent publication. Regulation response vtables were verified independently of misleading database aliases, but live native regulation task callbacks remain unverified. Online queries require a registered, valid issuer lease; revoked idle/partial reads and keepalives retire promptly, with last-valid-session scoped offline notifications and independent session preservation covered by native-wire fixtures. Native expiry UI callbacks and two-network lifecycle remain unverified; remaining account/objectstore REST mutations need explicit request/result/domain contracts.",
}

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


# Dedicated domain handlers only. A configured GET publication is not equivalent
# to an implemented authenticated account/objectstore mutation.
REST_HANDLERS = {
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


def rest_coverage(inventory):
    requests = []
    for original in inventory["requests"]:
        row = dict(original)
        bound = (
            row["service_operation_binding_resolved"]
            and len(row["services"]) == 1
            and len(row["resource_operations"]) == 1
        )
        handler = (
            REST_HANDLERS.get((row["services"][0], *row["resource_operations"][0]))
            if bound
            else None
        )
        row.update(
            dedicated_domain_handler=(bool(handler) if bound else None),
            handler_source=("src/" + handler if handler else None),
            current_native_method_completion_verified=False,
            coverage_scope=(
                "Dedicated handler registration; native callback evidence is separate"
                if bound
                else "Dynamic/helper service binding remains unresolved"
            ),
        )
        requests.append(row)
    return requests


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    graph = json.loads((DATA / "native-service-callgraph.json").read_bytes())
    deployment = json.loads((DATA / "deployment.json").read_bytes())
    fixture = json.loads((DATA / "lobby-verification.json").read_bytes())
    executable = ROOT / "build/Release/iw8-dw-server.exe"
    current_hash = digest(executable)
    valid_fixture = bool(fixture["passed"] and fixture["server_sha256"] == current_hash)
    routes = {}
    domains = {}
    sources = {}
    for service, domain, filename, tasks in ROUTES:
        path = ROOT / "src" / filename
        sources[str(path.relative_to(ROOT))] = digest(path)
        domains[service] = domain
        for task in tasks:
            assert (service, task) not in routes, (service, task)
            routes[service, task] = str(path.relative_to(ROOT))
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
    pairs = set(routes) | {
        (int(service), task)
        for service, values in graph["families"].items()
        for task in values
    }
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
        sources["src/" + filename] = digest(ROOT / "src" / filename)
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
    rest_path = DATA / "native-rest-callgraph.json"
    rest_inventory = json.loads(rest_path.read_bytes()) if rest_path.exists() else None
    rest_requests = rest_coverage(rest_inventory) if rest_inventory else []
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
        completion = bool(relay_proof and relay_proof.get("passed"))
        scope = None
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
        tasks.append(
            dict(
                service=service,
                task=task,
                domain=domains.get(service, "unclassified target family"),
                handler_registered=(service, task) in routes,
                handler_source=routes.get((service, task)),
                exact_target_constructor_proofs=constructors,
                target_constructor_audit_covered=bool(constructors),
                preparation_contract_provenance=(
                    "SDK source oracle only; not recovered as a Replay request writer"
                    if (service, task) in ((50, 5), (50, 15), (50, 20))
                    else None
                ),
                static_fixture_references=references.get((service, task), []),
                native_positive_completion_verified_current_binary=native,
                native_completion_evidence=proof_filename if native else None,
                native_completion_scope=scope if native else None,
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
        target_exported_function_count=graph.get("exported_function_count"),
        ambiguous_display_aliases=graph.get("ambiguous_display_aliases", []),
        target_database_changed_during_inventory=graph.get(
            "database_changed_during_inventory"
        ),
        server_sha256=current_hash,
        game_sha256=deployment["sha256"],
        source_sha256=sources,
        validation=dict(
            independent_suite_matches_binary=valid_fixture,
            grouped_checks=len(fixture["checks"]),
            receipt="data/lobby-verification.json",
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
                receipt="data/native-rest-callgraph.json",
                sha256=digest(rest_path),
                target_image_sha256=rest_inventory["target_image_sha256"],
                exported_functions=rest_inventory["exported_functions"],
                requests=rest_requests,
                counts=dict(
                    containing_functions=len(rest_requests),
                    dedicated_domain_handlers=sum(
                        row["dedicated_domain_handler"] is True for row in rest_requests
                    ),
                    known_literal_bindings_without_handler=sum(
                        row["dedicated_domain_handler"] is False
                        for row in rest_requests
                    ),
                    unresolved_dynamic_or_helper_bindings=sum(
                        row["dedicated_domain_handler"] is None for row in rest_requests
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
                target_layout_receipt="validation/20261006-username-target-layout.json",
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
    (DATA / "backend-coverage-inventory.json").write_text(
        json.dumps(inventory, indent=2) + "\n"
    )
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
    (DATA / "backend-coverage-inventory.txt").write_text("\n".join(text) + "\n")
    print(json.dumps(inventory["counts"]))


if __name__ == "__main__":
    main()
