"""Map Replay DW domains, target routes, persistence and implementation gaps."""

from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import runpy
import subprocess

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"

# These are engine/backend domains, not inferred numerical task identities.
# Their task identities and caller addresses are joined from target inventories.
DOMAINS = [
    ("Player profiles", [8], "profiles", "Native public/private profile CRUD"),
    ("Contextual storage", [10], "storage", "User files, backups and publisher files"),
    ("String policy and server time", [12], "policy", "Native validation/sanitization and time"),
    ("Leaderboard and validated stats", [4], "leaderboards,validated-stats", "Owner/stat batch writes and ranked reads"),
    ("Instant messaging and invitations", [6], "channels", "Native INV session-info and party invitation transport"),
    ("Text channels and whispers", [198], "channels", "Party/match/private messages and membership pushes"),
    ("Friends, lists and presence", [255], "social,presence", "REST friendships, invitations, subscriptions and online status"),
    ("Accounts, names and regulations", [197, 255], "profiles,platform,regulations", "Signed local accounts, aliases, UNO/Umbrella and preferences"),
    ("Clans and groups", [3, 197], "teams,clans", "Membership, proposals, roles, replacement, cooldowns and notifications"),
    ("Shared counters", [23], "counters", "Signed increments and shared totals"),
    ("Geography", [27], "geography.json", "Configured local DML metadata"),
    ("Mail", [29], "mail", "Send, duration, headers/body, deletion, expiration and event 18"),
    ("Auth and anti-cheat reports", [38], "auth-reports,anticheat", "Durable native reports; not a retail attestation verdict"),
    ("Content streaming", [50, 58], "content", "Whole file, copy, summary and multipart HTTP lifecycles"),
    ("Telemetry", [67], "event-log", "Native event filter and durable batches"),
    ("Marketplace and inventory", [80], "marketplace,inventory-validation", "Tokens, balances, orders, gifting and native result layouts"),
    ("Code redemption", [123], "redemption", "Owned, retry-safe published reward grants"),
    ("Publisher configuration", [95], "publisher", "Replay title 5800/build namespaces, revisions and native dvars"),
    ("Marketing", [104], "marketing", "Localized scheduled messages and owned view receipts"),
    ("Progression, achievements and quests", [125], "achievements", "Event ingestion, career XP/rank; deeper definitions remain publication-dependent"),
    ("Lobby and public matchmaking", [145], "matchmaking", "Party tokens, matching, membership, admission and host documents"),
    ("Host migration", [145], "matchmaking", "Session-bound successor claims and recoverable shared state"),
    ("Tournaments", [145], "tournaments", "Registration, formation, native bracket/round publication and results"),
    ("Scheduled matches", [150], "scheduled-matches", "Explicit schedules, members and events"),
    ("Esports registration", [151], "esports", "Published local registration"),
    ("Performance samples", [152], "performance", "Game-type samples attributed to each player"),
    ("Object store", [193], "objectstore", "Owned profile blobs, publisher metadata/content and REST envelopes"),
    ("Experiments and treatments", [194], "ab-testing", "Deterministic cohorts, native allocations and active treatments"),
    ("Scripted loot", [195], "scripted-loot", "Native proxy requests and explicitly published response rules"),
]

NON_TASK_DOMAINS = [
    ("Local platform and Battle.net boundary", ["src/platform.cpp", "integration/replay/DW_LocalPlatform.cpp"],
     "Signed machine identity/session, local names, licenses, account policy and native completion"),
    ("Authentication and encrypted lobby", ["src/lobby.cpp", "src/crypto.cpp", "src/traffic_kdf.h"],
     "Native auth/legacy tickets, protocol-210 challenge, directional crypto and session expiry"),
    ("Local profile and XP persistence", ["integration/replay/DW_LocalProgression.cpp", "integration/replay/DW_LocalConfig.cpp"],
     "Player-owned local XP/INI and native settings; server-side SDK state remains a mirror"),
    ("UDP NAT and QoS", ["src/qos_provider.cpp", "src/qos_services.cpp"],
     "Real bounded native NAT introductions and security-ID-bound QoS packets"),
    ("Authenticated UDP relay", ["src/relay_provider.cpp", "src/relay_services.cpp"],
     "Native credentials, BIND/JOIN/VERIFY/ESTABLISHED, DATA forwarding and replay windows"),
    ("Bandwidth probe", ["src/bandwidth.cpp"], "Native bounded probe transport"),
    ("Voice permission and transport integration", ["integration/replay/DW_LocalPlatform.cpp", "src/relay_provider.cpp"],
     "Signed account permissions; codec, capture, mute and native game voice remain engine consumers"),
    ("Playlist and installed-map contracts", ["src/playlist_catalog.cpp", "tools/prepare-playlist-catalog.py", "tools/playlist_packages.py"],
     "Owner publication, native weights/rules, package inventory and matchmaking eligibility"),
    ("Signed update manifests", ["tools/prepare-replay-publisher-content.py", "src/objectstore_services.cpp"],
     "Exact Replay no-update manifest/signature and immutable publisher-object download"),
]

# REST uses one gateway task, but the resource/operation owns the domain.
# Keep those actual bindings visible instead of crediting every 255/10 call
# to both friends and accounts merely because they share a transport.
REST_DOMAINS = {
    "Friends, lists and presence": (
        {"Friends", "UserLists", "UserPresence", "UsersPresence"},
        ["src/social_services.cpp"],
    ),
    "Accounts, names and regulations": (
        {"UserResource", "Users", "UnoRes", "Umbrella", "Regulations"},
        ["src/identity_rest_services.cpp", "src/identity_services.cpp",
         "src/regulation_services.cpp", "src/platform_resources.cpp"],
    ),
    "Progression, achievements and quests": (
        {"user_events"}, ["src/achievement_services.cpp", "src/achievement_store.cpp",
                          "src/rest_services.cpp"],
    ),
    "Experiments and treatments": ({"abtesting"}, ["src/abtesting_services.cpp"]),
    "Object store": (
        {"ObjectsResourcePublishers", "ObjectsVectorizedResourceUsers"},
        ["src/objectstore_services.cpp"],
    ),
}


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


definitions = runpy.run_path(str(ROOT / "tools/inventory-backend-coverage.py"))
graph = load(DATA / "native-service-callgraph.json")
rest = load(DATA / "native-rest-callgraph.json")
coverage = load(DATA / "backend-coverage-inventory.json")
routes = defaultdict(dict)
for service, domain, source, tasks in definitions["ROUTES"]:
    for task in tasks:
        routes[service][task] = "src/" + source
calls = defaultdict(list)
for row in graph["proven_calls"]:
    calls[row["service"]].append({
        "address": row["address"], "analysis_label": row["name"],
        "service": row["service"], "task": row["task"],
        "constructor": row["constructor"],
    })

dirty = set(subprocess.check_output(
    ["git", "diff", "--name-only"], cwd=ROOT, text=True
).splitlines())
build = load(DATA / "backend-build-latest.json")
rows = []
for name, services, persistence, contract in DOMAINS:
    tasks = sorted({(service, task) for service in services for task in routes[service]})
    native_tasks = sorted({
        (service, task) for service in services
        for task in graph["families"].get(str(service), [])
    })
    sources = sorted({routes[service][task] for service, task in tasks})
    resources, rest_sources = REST_DOMAINS.get(name, (set(), []))
    requests = [request for request in rest["requests"] if any(
        resource in resources for resource, operation in request["resource_operations"]
    )]
    sources = sorted(set(sources + rest_sources))
    rows.append({
        "name": name, "services": services, "contract": contract,
        "persistence": persistence.split(","), "handler_sources": sources,
        "registered_task_routes": [list(pair) for pair in tasks],
        "target_known_missing_routes": [list(pair) for pair in native_tasks if pair not in tasks],
        "target_constructor_entries": [entry for service in services for entry in calls[service]],
        "rest_request_routes": requests,
        "implementation_limits": {str(service): definitions["GAPS"].get(str(service), "Unclassified") for service in services},
        "working_sources_differ_from_recorded_build": [
            path for path in sources if build["inputs"].get(path) != digest(ROOT / path)
        ],
        "uncommitted_sources": [path for path in sources if path in dirty],
        "full_native_completion_verified": False,
    })

represented = {service for row in rows for service in row["services"]}
unclassified = sorted(set(map(int, graph["families"])) - represented)
packages_path = DATA / "playlists/5800/packages.json"
packages = load(packages_path) if packages_path.exists() else None
catalog = load(DATA / "playlists/5800/catalog.json")
report = {
    "schema": 1,
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "full_backend_complete": False,
    "subsystems": rows,
    "non_task_subsystems": [
        {"name": name, "sources": sources, "contract": contract}
        for name, sources, contract in NON_TASK_DOMAINS
    ],
    "target_inventory": {
        "path": "data/native-service-callgraph.json", "sha256": digest(DATA / "native-service-callgraph.json"),
        "database": graph["database"], "exported_functions": graph["exported_function_count"],
        "changed_during_inventory": graph["database_changed_during_inventory"],
        "unclassified_known_service_ids": unclassified,
        "dynamic_forwarders": graph["dynamic_forwarders"],
        "unresolved_paths": graph["unresolved_paths"],
        "labels_are_not_address_or_response_layout_proof": True,
    },
    "rest_request_inventory": {
        "path": "data/native-rest-callgraph.json", "sha256": digest(DATA / "native-rest-callgraph.json"),
        "request_functions": len(rest["requests"]), "unresolved": rest["unresolved"],
        "resource_operation_writers": sum(bool(row["resource_operations"]) for row in rest["requests"]),
        "full_audit_complete": rest["full_rest_audit_complete"],
    },
    "coverage_ledger": {"path": "data/backend-coverage-inventory.json", "sha256": digest(DATA / "backend-coverage-inventory.json"), "counts": coverage["counts"]},
    "objectstore_completion_target_evidence": coverage.get("objectstore_completion_target_evidence"),
    "playlist_contract": {
        "playlists": len(catalog["playlists"]), "game_types": len(catalog["gametypes"]),
        "declared_maps": len({e["map"] for p in catalog["playlists"] for e in p["maps"]}),
        "match_entries": sum(len(p["maps"]) for p in catalog["playlists"]),
        "installed_main_packages": sum(row["available"] for row in packages["maps"]) if packages else None,
        "native_weighted_entry_limit": 20,
        "native_weight_reader_slot_limit": 20,
        "primary_package_presence_is_not_transient_or_gameplay_validation": True,
    },
    "game_runs_performed": False,
}
assert not unclassified, "Assign recovered service families to a subsystem before publishing"
(DATA / "replay-dw-subsystems.json").write_text(json.dumps(report, indent=2) + "\n")
text = ["REPLAY DEMONWARE SUBSYSTEM MAP", "", "Target constructor, handler, protocol and native completion are separate evidence.", "Full backend implementation remains in progress. No game runs in this inventory phase.", ""]
for row in rows:
    text.extend([
        row["name"], "  Services: " + ", ".join(map(str, row["services"])),
        "  Contract: " + row["contract"], "  Persistence: " + ", ".join(row["persistence"]),
        "  Backend: " + ", ".join(row["handler_sources"]),
        "  Registered routes: " + ", ".join(f"{s}/{t}" for s, t in row["registered_task_routes"]),
        "  REST resources: " + (", ".join(sorted({
            resource + "/" + operation for request in row["rest_request_routes"]
            for resource, operation in request["resource_operations"]
        })) or "none in recovered writer set"),
        "  Known missing routes: " + (", ".join(f"{s}/{t}" for s, t in row["target_known_missing_routes"]) or "none in recovered constructor set"),
        "  Open contracts: " + " ".join(row["implementation_limits"].values()), "",
    ])
text.append("NON-TASK DOMAINS")
for row in report["non_task_subsystems"]:
    text.extend([row["name"], "  " + row["contract"], "  " + ", ".join(row["sources"]), ""])
text.extend([
    "PLAYLIST CONTRACT", json.dumps(report["playlist_contract"], indent=2), "",
    "The JSON companion retains target caller addresses, ambiguous labels, unresolved paths,",
    "REST inventory, source/build drift and each recovered task route. Direct constructor",
    "coverage does not imply all virtual/inlined SDK methods or positive native completion.",
])
(ROOT / "docs/replay-dw-subsystems.txt").write_text("\n".join(text) + "\n")
print(f"Mapped {len(rows)} service domains and {len(NON_TASK_DOMAINS)} non-task domains; full implementation remains open.")
