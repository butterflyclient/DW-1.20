"""Record current-backend two-game social/party callbacks from owned observations.

Private game evidence is kept separate from the shipping image, WAN gameplay,
relay peer data and the earlier profile-persistence test.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--state-root", required=True, type=Path)
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()
state, output = args.state_root.resolve(), args.output.resolve()
assert state.is_relative_to(ROOT / "data")
assert output.is_relative_to(ROOT / "validation") and output.suffix == ".json"


def load(path):
    return json.loads(path.read_bytes().decode("utf-8-sig"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reference(path):
    return dict(path=path.relative_to(ROOT).as_posix(), sha256=digest(path))


build = load(ROOT / "data/backend-build-latest.json")
assert build["compile_passed"]
backend = ROOT / "build/Release/iw8-dw-server.exe"
assert digest(backend) == build["sha256"]
protocol = load(ROOT / "data/lobby-verification.json")
assert protocol["server_sha256"] == build["sha256"]
assert protocol["passed"]
rows, evidence, deployments = {}, {}, {}
for peer in ("alpha", "bravo"):
    directory = state / peer
    deployment = deployments[peer] = load(directory / "deployment.json")
    assert deployment["private_test_build"]
    assert deployment["server_sha256"] == build["sha256"]
    rows[peer], evidence[peer] = {}, {}
    for label in ("online", "friends", "joined-party", "cleanup"):
        path = directory / (label + ".json")
        observation = rows[peer][label] = load(path)
        assert observation["sha256"] == deployment["sha256"]
        assert observation["native_dw_hsm_connected_state_33"]
        assert observation["native_social_online_status"] == 2
        assert observation["native_local_player_settings"]["profile_logged_in"]
        fences = observation["native_fences_controller_0"]
        assert len(fences) == 27 and all(
            r["passing"] and not r["failed"] for r in fences
        )
        assert observation["native_network"]["error"] == 0
        assert observation["native_relay_association"]["state"] == 3
        server = observation["server_process_verified"]
        assert server["sha256"] == build["sha256"]
        assert server["verified_live_process"] and server["connection_receipt_matches"]
        lists = observation["native_crossplay_friend_lists"]
        assert len(lists) == 3 and all(r["fetch_state"] == 2 for r in lists)
        assert [r["count"] for r in lists] == (
            [1, 0, 0] if label in ("friends", "joined-party") else [0, 0, 0]
        )
        presence = observation["native_presence_subscriptions"]
        assert presence["records_stable"]
        assert presence["pending_subscribe"] == presence["pending_unsubscribe"] == 0
        assert presence["start_failures"] == presence["unsubscribe_error_count"] == 0
        assert presence["active_crossplay_records"] == (
            1 if label in ("friends", "joined-party") else 0
        )
        evidence[peer][label] = reference(path)
    for label in ("party-roster", "friends"):
        evidence[peer][label + "_image"] = reference(directory / (label + ".jpg"))
    sessions = {r["pid"] for r in rows[peer].values()}
    assert len(sessions) == 1
    for key in ("native_user_xuid", "native_user_platform_id"):
        assert len({r[key] for r in rows[peer].values()}) == 1
    for leaf in ("executable", "test_enabled_file", "test_command_file"):
        path = (
            Path(deployment[leaf])
            if leaf == "executable"
            else Path(deployment["executable"]).parent / deployment[leaf]
        )
        assert not path.exists(), "Remove the stopped owned root test artifacts first"
    assert not Path(deployment["executable"]).with_suffix(".ini").exists()

joined = {peer: row["joined-party"] for peer, row in rows.items()}
assert joined["alpha"]["pid"] != joined["bravo"]["pid"]
for key in ("native_user_xuid", "native_user_platform_id"):
    assert joined["alpha"][key] != joined["bravo"][key]
users = {r["native_user_xuid"] for r in joined.values()}
channels = []
for peer, row in joined.items():
    party = [r for r in row["native_channels"]["chats"] if r["type"] == 3]
    assert len(party) == 1 and party[0]["member_count"] == 2
    assert {r["user"] for r in party[0]["members"]} == users
    assert [r["user"] for r in party[0]["members"] if r["host"]] == [
        joined["bravo"]["native_user_xuid"]
    ]
    channels.append(party[0]["channel"])
    friend = row["native_crossplay_friend_lists"][0]["entries"][0]
    assert friend["user"] in users - {row["native_user_xuid"]}
assert channels[0] == channels[1]
log = rows["alpha"]["cleanup"]["server_log_since_launch"]
assert (
    sum("operation=global-instant-message-routed error=0" in line for line in log) >= 2
)
assert any("operation=friend-relationship-removed error=0" in line for line in log)
# Each of these methods has both a successful native request and the specific
# consumer effect above. Merely observing another REST request earns no credit.
bindings = [
    ("umbrella", "UserResource", "usernamesearch"),
    ("friends", "Friends", "invite_friend"),
    ("social-service", "Friends", "get_friends"),
    ("social-service", "Friends", "get_pending_friend_requests"),
    ("friends", "Friends", "reject_friend_request"),
    ("presence", "UsersPresence", "subscribe_to_users"),
    ("presence", "UserPresence", "set_user_presence"),
]
for service, resource, operation in bindings:
    assert any(
        f"rest_service={service} " in line
        and f"resource={resource} " in line
        and f"operation_name={operation} " in line
        and "error=0 " in line
        for line in log
    ), ("Missing successful original native request for " + operation)
assert deployments["alpha"]["sha256"] == deployments["bravo"]["sha256"]
game_build = Path(deployments["alpha"]["build_directory"])
for name in ("build-report.json", "verification-report.json", "relocation-audit.json"):
    assert load(game_build / name)["sha256"] == deployments["alpha"]["sha256"]
verification = load(game_build / "verification-report.json")
assert verification["unresolved_symbols"] == 0
assert load(game_build / "relocation-audit.json")["passed"]
assert len(verification["dw_private_test_paths"]) == 28
assert all(row["passed"] for row in verification["dw_private_test_paths"])
source_paths = (
    "src/social_services.cpp",
    "src/channel_services.cpp",
    "tools/observe-game.py",
)
for path in source_paths[:2]:
    assert build["inputs"][path] == digest(ROOT / path)
shipping = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay_dw.exe")
assert (
    digest(shipping)
    == "bdc091d35dc57f29c10ce14a4552467a5ce0d8c0d881d287ec31f09fc7ee9e18"
)
assert (
    digest(shipping.with_suffix(".ini"))
    == "7aaa432650fd5ba032f19be8de551cb6281dae704f7e9d55d9f0ebde2f9fbb7a"
)
proof = dict(
    schema=1,
    recorded_utc=datetime.now(timezone.utc).isoformat(),
    passed=True,
    backend_sha256=build["sha256"],
    game_sha256=deployments["alpha"]["sha256"],
    private_build_job=deployments["alpha"]["job_id"],
    audit_tool_sha256=digest(Path(__file__)),
    source_sha256={path: digest(ROOT / path) for path in source_paths},
    backend_build=reference(ROOT / "data/backend-build-latest.json"),
    protocol=reference(ROOT / "data/lobby-verification.json"),
    native_rest_bindings=[list(b) for b in bindings],
    native_two_game_private_party_join_verified=True,
    native_two_game_party_channel_member_and_host_callbacks_verified=True,
    native_friend_removal_and_active_crossplay_mask_cleanup_verified=True,
    retained_inactive_presence_cache_is_not_a_failed_unsubscribe=True,
    native_transport_unsubscribe_callback_verified=False,
    temporary_friendship_added_through_native_name_search=True,
    initial_friendships=0,
    final_friendships=0,
    native_fences_passing_per_client=27,
    evidence=evidence,
    observed_open_issues=[
        "Remove Friend confirmation displays nil while the friend/action panels display the correct name"
    ],
    scope="Two owned root-folder native Replay processes with separate persisted profiles/cache. Local social and private-party callbacks only; no map launched.",
    game_recompiled_for_this_test=False,
    shipping_executable_native_completion_inherited=False,
    cross_network_gameplay_verified=False,
    relay_peer_data_forwarding_verified=False,
    full_backend_verified=False,
    owned_root_test_artifacts_removed=True,
)
output.write_text(json.dumps(proof, indent=2) + "\n")
print(
    "Verified current-backend native two-game social, local party and inactive presence-mask cleanup; WAN/relay DATA remain unverified."
)
