"""Record backend rename fixtures and native two-client reconnect separately."""

import ast
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "data/native-pair-rename-20261006"


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reference(path):
    return dict(path=path.relative_to(ROOT).as_posix(), sha256=digest(path))


build = load(ROOT / "data/backend-build-latest.json")
server = load(ROOT / "data/server-process.json")
protocol = load(ROOT / "data/lobby-verification.json")
assert build["compile_passed"] and protocol["passed"]
assert server["sha256"] == build["sha256"] == protocol["server_sha256"]
assert digest(Path(server["executable"])) == server["sha256"]
for name, expected in build["inputs"].items():
    assert digest(Path(build["source_directory"]) / name) == expected
for row in build["explicit_overlays"]:
    assert digest(ROOT / row["path"]) == row["sha256"]
rename_checks = [
    value
    for value in protocol["checks"]
    if "rename" in value.lower() or "renamed identity" in value.lower()
]
assert len(rename_checks) == 3
captured_observer = STATE / "observe-game-captured.py"
startup_observer = STATE / "observe-game-startup-captured.py"
current_observer = ROOT / "tools/observe-game.py"
assert ast.dump(ast.parse(captured_observer.read_bytes())) == ast.dump(
    ast.parse(current_observer.read_bytes())
)
# Startup predates the per-instance restart-receipt selector. Its native readers
# are unchanged. Verify the two known source differences rather than attributing
# every observation to the final harness revision.
selector_argument = """parser.add_argument(
    "--connection-receipt",
    type=Path,
    default=root / "data/current-runtime-connection.json",
    help="Owned per-instance dw_restart receipt, separate from the original launch",
)
"""
startup_equivalent = current_observer.read_text().replace(selector_argument, "")
startup_equivalent = startup_equivalent.replace(
    "    connection_path = args.connection_receipt",
    '    connection_path = root / "data/current-runtime-connection.json"',
)
assert ast.dump(ast.parse(startup_equivalent)) == ast.dump(
    ast.parse(startup_observer.read_bytes())
)
target_path = ROOT / "validation/20261006-native-identity-rename-layout.json"
target = load(target_path)
assert target["audit_tool_sha256"] == digest(
    ROOT / "tools/research-identity-rename-target.py"
)
assert not target["native_callback_verified"]
native = {}
for peer in ("alpha", "bravo"):
    directory = STATE / peer
    observations = {
        label: load(directory / (label + ".json"))
        for label in ("startup", "reconnected", "stable")
    }
    startup, renewed, stable = (
        observations[label] for label in ("startup", "reconnected", "stable")
    )
    for label, value in observations.items():
        source = startup_observer if label == "startup" else captured_observer
        assert value["observer_source_sha256"] == digest(source)
        assert value["native_dw_hsm_connected_state_33"]
        assert value["native_social_online_status"] == 2
        assert value["native_local_player_settings"]["profile_logged_in"]
        assert len(value["native_fences_controller_0"]) == 27
        assert all(
            row["passing"] and not row["failed"]
            for row in value["native_fences_controller_0"]
        )
        assert value["native_network"]["error"] == 0
        assert value["native_relay_association"]["state"] == 3
        assert value["server_process_verified"]["connection_receipt_matches"]
        assert value["server_process_verified"]["sha256"] == build["sha256"]
        assert all(row["count"] == 0 for row in value["native_crossplay_friend_lists"])
        assert value["native_presence_subscriptions"]["records_stable"]
        assert value["native_presence_subscriptions"]["active_crossplay_records"] == 0
    assert (
        startup["server_process_verified"]["pid"]
        != renewed["server_process_verified"]["pid"]
    )
    assert renewed["server_process_verified"] == stable["server_process_verified"]
    assert renewed["native_relay_association"] == stable["native_relay_association"]
    for key in ("pid", "sha256", "native_user_xuid", "native_user_platform_id"):
        assert startup[key] == renewed[key] == stable[key]
    elapsed = (
        datetime.fromisoformat(stable["observed_utc"])
        - datetime.fromisoformat(renewed["observed_utc"])
    ).total_seconds()
    assert elapsed > 0
    native[peer] = dict(
        game_sha256=stable["sha256"],
        same_game_process_after_backend_restart=True,
        stable_seconds=elapsed,
        native_fences_passing=27,
        native_online_status=2,
        stable_established_relay=True,
        native_friend_lists_empty=True,
        evidence={
            label: reference(directory / (label + ".json")) for label in observations
        },
    )
    deployment = load(directory / "deployment.json")
    game = Path(deployment["executable"]).parent
    for path in (
        Path(deployment["executable"]),
        Path(deployment["executable"]).with_suffix(".ini"),
        game / deployment["test_command_file"],
        game / deployment["test_enabled_file"],
    ):
        assert not path.exists()

old = ROOT / "data/native-pair-20261006"
before = load(old / "alpha/presence-friends-active.json")
assert before["native_presence_subscriptions"]["records_stable"]
assert before["native_presence_subscriptions"]["active_crossplay_records"] == 1
for peer in ("alpha", "bravo"):
    after = load(old / peer / "presence-after-revocation.json")
    presence = after["native_presence_subscriptions"]
    assert after["sha256"] == before["sha256"]
    assert (
        after["server_process_verified"]["sha256"]
        == before["server_process_verified"]["sha256"]
    )
    assert all(row["count"] == 0 for row in after["native_crossplay_friend_lists"])
    assert presence["records_stable"] and presence["subscribed_count"] == 1
    assert presence["active_crossplay_records"] == 0
    assert presence["records"][0]["subscription_mask"] == 0
    assert presence["pending_subscribe"] == presence["pending_unsubscribe"] == 0

main_image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay_dw.exe")
preserved = {
    main_image: "bdc091d35dc57f29c10ce14a4552467a5ce0d8c0d881d287ec31f09fc7ee9e18",
    main_image.with_suffix(
        ".ini"
    ): "7aaa432650fd5ba032f19be8de551cb6281dae704f7e9d55d9f0ebde2f9fbb7a",
    Path(
        r"C:\Users\achar\AppData\Local\ReplayDW\player-identity.bin"
    ): "49478c21b3a1bde343e0385e6e2a76b014c4fc1aad38dd60d5f4feee6e4633b2",
}
assert all(digest(path) == expected for path, expected in preserved.items())
receipt = dict(
    schema=1,
    generated_utc=datetime.now(timezone.utc).isoformat(),
    passed=True,
    backend_sha256=build["sha256"],
    unchanged_shipping_game_sha256=digest(main_image),
    build_receipt=reference(
        Path(build["build_directory"]).parent / "build-receipt.json"
    ),
    protocol_evidence=reference(ROOT / "data/lobby-verification.json"),
    protocol_groups=len(protocol["checks"]),
    target_contract_evidence=reference(target_path),
    native_observer=dict(
        startup_source=reference(startup_observer),
        captured_source=reference(captured_observer),
        current_source=reference(current_observer),
        reconnect_source_python_ast_identical=True,
        startup_native_readers_identical=True,
        startup_differences="No per-instance connection-receipt selector before reconnect tooling was added",
    ),
    rename_protocol_checks=rename_checks,
    rename_native_callback_verified=False,
    native_two_client_reconnect=native,
    friend_cache_revocation=dict(
        native_verified=True,
        backend_sha256=before["server_process_verified"]["sha256"],
        game_sha256=before["sha256"],
        cache_record_retained=True,
        active_crossplay_bits_cleared=True,
        before=reference(old / "alpha/presence-friends-active.json"),
        after=[
            reference(old / peer / "presence-after-revocation.json")
            for peer in ("alpha", "bravo")
        ],
    ),
    main_exe_ini_identity_preserved=True,
    owned_root_test_artifacts_removed=True,
    map_test_performed=False,
    cross_network_gameplay_verified=False,
    full_backend_complete=False,
)
destination = ROOT / "validation/20261006-identity-rename-native-readiness.json"
destination.write_text(json.dumps(receipt, indent=2) + "\n")
print(
    f"Verified {len(protocol['checks'])} protocol groups, two native reconnects and friend-cache semantics; live rename/WAN remain separate."
)
