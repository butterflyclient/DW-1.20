"""Validate retained native two-game observations without exposing identity files.

This records local private-party membership and profile persistence. It does not
certify WAN traversal, relay peer forwarding, a map, or the shipping executable.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "data/native-pair-20261006"


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reference(path):
    return dict(path=path.relative_to(ROOT).as_posix(), sha256=digest(path))


def healthy(observation):
    assert observation["native_dw_hsm_connected_state_33"]
    assert observation["native_social_online_status"] == 2
    assert observation["native_local_player_settings"]["profile_logged_in"]
    assert len(observation["native_fences_controller_0"]) == 27
    assert all(
        row["passing"] and not row["failed"]
        for row in observation["native_fences_controller_0"]
    )
    assert observation["native_network"]["error"] == 0
    assert observation["native_relay_association"]["state"] == 3
    assert observation["server_process_verified"]["verified_live_process"]
    assert observation["server_process_verified"]["connection_receipt_matches"]


deployments, joined, startup, cleanup = {}, {}, {}, {}
evidence, cache = {}, {}
for peer in ("alpha", "bravo"):
    directory = STATE / peer
    deployments[peer] = load(directory / "deployment.json")
    assert deployments[peer]["private_test_build"]
    observations = {}
    for label in ("after-cache-fix", "joined-party", "cleanup"):
        path = directory / (label + ".json")
        observations[label] = load(path)
        healthy(observations[label])
        assert observations[label]["sha256"] == deployments[peer]["sha256"]
        assert (
            observations[label]["server_process_verified"]["sha256"]
            == deployments[peer]["server_sha256"]
        )
    startup[peer] = observations["after-cache-fix"]
    joined[peer] = observations["joined-party"]
    cleanup[peer] = observations["cleanup"]
    assert all(
        row["count"] == 0 for row in startup[peer]["native_crossplay_friend_lists"]
    )
    assert all(
        row["count"] == 0 for row in cleanup[peer]["native_crossplay_friend_lists"]
    )
    native_paths = startup[peer]["native_selected_dvars"]
    assert native_paths["LNLQSTKSLL"]["value"] == str(
        Path(deployments[peer]["executable"]).parent
    )
    assert native_paths["LOOQOTRNTN"]["value"] == deployments[peer]["home"]
    cache[peer] = []
    for leaf in ("toc0.dcache", "toc1.dcache", "data0.dcache", "data1.dcache"):
        path = Path(deployments[peer]["home"]) / "main" / leaf
        assert path.is_file()
        cache[peer].append(dict(filename=leaf, bytes=path.stat().st_size))
    evidence[peer] = {
        label: reference(directory / (label + ".json")) for label in observations
    }
    evidence[peer]["native_party_roster_image"] = reference(
        directory / "party-roster.jpg"
    )

assert deployments["alpha"]["sha256"] == deployments["bravo"]["sha256"]
assert joined["alpha"]["pid"] != joined["bravo"]["pid"]
for key in ("native_user_xuid", "native_user_platform_id"):
    assert startup["alpha"][key] != startup["bravo"][key]
    for peer in joined:
        assert startup[peer][key] == joined[peer][key] == cleanup[peer][key]
users = {row["native_user_xuid"] for row in joined.values()}
channels = {}
for peer, observation in joined.items():
    rows = [row for row in observation["native_channels"]["chats"] if row["type"] == 3]
    assert len(rows) == 1
    channels[peer] = rows[0]
    assert rows[0]["member_count"] == 2
    assert {member["user"] for member in rows[0]["members"]} == users
    assert [member["user"] for member in rows[0]["members"] if member["host"]] == [
        joined["bravo"]["native_user_xuid"]
    ]
    lists = observation["native_crossplay_friend_lists"]
    assert all(row["fetch_state"] == 2 for row in lists)
    assert [row["count"] for row in lists] == [1, 0, 0]
    assert lists[0]["entries"][0]["user"] in users - {observation["native_user_xuid"]}
    assert observation["native_presence_subscriptions"]["subscribed_count"] == 1
    assert observation["native_presence_subscriptions"]["start_failures"] == 0
assert channels["alpha"]["channel"] == channels["bravo"]["channel"]
assert (
    sum(
        "operation=global-instant-message-routed error=0" in line
        for line in joined["alpha"]["server_log_since_launch"]
    )
    >= 2
)
assert any(
    "operation=friend-relationship-removed error=0" in line
    for line in cleanup["alpha"]["server_log_since_launch"]
)

bravo = STATE / "bravo"
written = load(bravo / "setting-written.json")
restarted = load(bravo / "setting-after-restart.json")
healthy(restarted)
assert written["pid"] != restarted["pid"]
assert written["native_local_player_settings"]["keyboard_toggle_ads"]
assert restarted["native_local_player_settings"]["keyboard_toggle_ads"]
assert not cleanup["bravo"]["native_local_player_settings"]["keyboard_toggle_ads"]
for key in ("native_user_xuid", "native_user_platform_id"):
    assert restarted[key] == written[key] == startup["bravo"][key]
identity = [
    row
    for row in load(bravo / "persistence-before-restart.json")
    if row["path"].endswith("player-identity.bin")
]
assert len(identity) == 1 and digest(Path(identity[0]["path"])) == identity[0]["sha256"]
for label in ("setting-written", "setting-after-restart", "after-onboarding-restart"):
    evidence["bravo"][label] = reference(bravo / (label + ".json"))

build = Path(deployments["alpha"]["build_directory"])
report = load(build / "build-report.json")
verification = load(build / "verification-report.json")
audit = load(build / "relocation-audit.json")
assert (
    report["sha256"]
    == verification["sha256"]
    == audit["sha256"]
    == deployments["alpha"]["sha256"]
)
assert audit["passed"] and verification["unresolved_symbols"] == 0
assert len(verification["dw_private_test_paths"]) == 28
assert all(row["passed"] for row in verification["dw_private_test_paths"])
helper_hash = digest(ROOT / "integration/testing/DW_TestHomePath.cpp")
assert any(
    row["source"] == "src/DW_TestHomePath.cpp" and row["source_sha256"] == helper_hash
    for row in report["cpp"]
)

proof = dict(
    schema=1,
    recorded_utc=datetime.now(timezone.utc).isoformat(),
    passed=True,
    private_build_job=deployments["alpha"]["job_id"],
    game_sha256=report["sha256"],
    server_sha256=deployments["alpha"]["server_sha256"],
    private_test_home_source_sha256=helper_hash,
    compilation_gates=dict(
        unresolved_symbols=0,
        relocation_audit_passed=True,
        private_linked_body_checks=28,
        vm_os_boundaries_simulated=True,
    ),
    root_game_working_directory=str(Path(deployments["alpha"]["executable"]).parent),
    separate_native_profile_and_cache_paths_verified=True,
    cache_files=cache,
    distinct_automatically_created_native_identities_verified=True,
    seeded_friendships_used=False,
    native_name_search_invitation_acceptance_and_online_presence_verified=True,
    native_two_game_private_party_join_verified=True,
    native_shared_party_channel_member_and_host_callbacks_verified=True,
    native_party_channel=channels["alpha"]["channel"],
    native_local_settings_persistence_across_new_process_verified=True,
    native_profile_setting_restored=True,
    native_friend_removal_completion_and_two_client_list_cleanup_verified=True,
    native_startup_fences_passing_per_client=27,
    evidence=evidence,
    multiplayer_scope="Two real native game processes on one Windows machine, private-party membership through Social/Join Game. No map launched.",
    observed_open_issues=[
        "Remove Friend confirmation displayed nil for the selected peer name",
        "Immediate post-removal native presence subscription count remained one",
    ],
    relay_peer_data_forwarding_verified=False,
    cross_network_gameplay_verified=False,
    full_backend_verified=False,
    shipping_executable_replaced=False,
    owned_root_test_artifacts_removed=all(
        not path.exists()
        for deployment in deployments.values()
        for path in (
            Path(deployment["executable"]),
            Path(deployment["executable"]).with_suffix(".ini"),
            Path(deployment["executable"]).parent / deployment["test_enabled_file"],
            Path(deployment["executable"]).parent / deployment["test_command_file"],
        )
    ),
)
path = ROOT / "validation/20261006-native-pair-party-profile.json"
path.write_text(json.dumps(proof, indent=2) + "\n")
print(
    "Verified native two-game local party, independent identities, profile persistence and friend cleanup; WAN/map/relay DATA remain unverified."
)
