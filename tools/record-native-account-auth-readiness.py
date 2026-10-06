"""Bind account protocol tests and a separate native startup to the final build."""

from datetime import datetime, timezone
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "--state-root", type=Path, default=ROOT / "data/native-pair-accounts-20261006"
)
parser.add_argument(
    "--output",
    type=Path,
    default=ROOT / "validation/20261006-account-auth-native-readiness.json",
)
parser.add_argument("--achievement-contract", action="store_true")
args = parser.parse_args()
STATE = args.state_root.resolve()
destination = args.output.resolve()
assert STATE.is_relative_to(ROOT / "data") and destination.is_relative_to(
    ROOT / "validation"
)


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reference(path):
    return dict(path=path.relative_to(ROOT).as_posix(), sha256=digest(path))


build = load(ROOT / "data/backend-build-latest.json")
server = load(ROOT / "data/server-process.json")
protocol_path = ROOT / "data/lobby-verification.json"
protocol = load(protocol_path)
assert build["compile_passed"] and protocol["passed"]
assert build["sha256"] == server["sha256"] == protocol["server_sha256"]
assert digest(Path(server["executable"])) == build["sha256"]
for name, expected in build["inputs"].items():
    assert digest(Path(build["source_directory"]) / name) == expected
for row in build["explicit_overlays"]:
    assert digest(ROOT / row["path"]) == row["sha256"]

fixture = load(ROOT / "data/backend-validation-latest.json")
assert fixture["build_receipt"]["sha256"] == build["sha256"]
for name, expected in fixture["frozen_input_hashes"].items():
    assert digest(Path(fixture["root"]) / name) == expected
account_checks = [
    value
    for value in protocol["checks"]
    if any(
        word in value
        for word in (
            "Four native account routes",
            "Optional email credentials",
            "Native UNO ID/access/refresh",
            "Failed intent publication",
            "Same-process publication recovery",
            "real account-document/profile",
        )
    )
]
assert len(account_checks) == 6
target_path = ROOT / "validation/20261006-native-account-auth-layout.json"
target = load(target_path)
assert target["audit_tool_sha256"] == digest(
    ROOT / "tools/research-account-auth-target.py"
)
assert (
    len(target["routes"]) == 4 and not target["native_account_menu_callbacks_verified"]
)

startup_path, stable_path = STATE / "alpha/startup.json", STATE / "alpha/stable.json"
startup, stable = load(startup_path), load(stable_path)
assert startup["pid"] == stable["pid"] and startup["sha256"] == stable["sha256"]
assert stable["server_process_verified"]["sha256"] == build["sha256"]
assert stable["server_process_verified"]["connection_receipt_matches"]
assert stable["observer_source_sha256"] == digest(ROOT / "tools/observe-game.py")
assert (
    stable["native_dw_hsm_connected_state_33"]
    and stable["native_social_online_status"] == 2
)
assert stable["native_local_player_settings"]["profile_logged_in"]
assert len(stable["native_fences_controller_0"]) == 27
assert all(
    row["passing"] and not row["failed"] for row in stable["native_fences_controller_0"]
)
assert (
    stable["native_network"]["error"] == 0
    and stable["native_relay_association"]["state"] == 3
)
assert all(row["count"] == 0 for row in stable["native_crossplay_friend_lists"])
assert stable["native_presence_subscriptions"]["records_stable"]
assert stable["native_presence_subscriptions"]["active_crossplay_records"] == 0

main = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay_dw.exe")
preserved = {
    main: "bdc091d35dc57f29c10ce14a4552467a5ce0d8c0d881d287ec31f09fc7ee9e18",
    main.with_suffix(
        ".ini"
    ): "7aaa432650fd5ba032f19be8de551cb6281dae704f7e9d55d9f0ebde2f9fbb7a",
    Path(
        r"C:\Users\achar\AppData\Local\ReplayDW\player-identity.bin"
    ): "49478c21b3a1bde343e0385e6e2a76b014c4fc1aad38dd60d5f4feee6e4633b2",
}
assert all(digest(path) == expected for path, expected in preserved.items())
for peer in ("alpha", "bravo"):
    deployment = load(STATE / peer / "deployment.json")
    image = Path(deployment["executable"])
    assert all(
        not path.exists()
        for path in (
            image,
            image.with_suffix(".ini"),
            image.parent / deployment["test_command_file"],
            image.parent / deployment["test_enabled_file"],
        )
    )

receipt = dict(
    schema=1,
    generated_utc=datetime.now(timezone.utc).isoformat(),
    passed=True,
    backend_sha256=build["sha256"],
    unchanged_shipping_game_sha256=preserved[main],
    build_receipt=reference(
        Path(build["build_directory"]).parent / "build-receipt.json"
    ),
    protocol_evidence=reference(protocol_path),
    protocol_groups=len(protocol["checks"]),
    account_protocol_checks=account_checks,
    target_contract_evidence=reference(target_path),
    native_startup=dict(
        game_sha256=stable["sha256"],
        native_online_status=2,
        native_fences_passing=27,
        native_logged_in=True,
        network_error=0,
        relay_state=3,
        friends_empty=True,
        same_game_process=True,
        evidence=[reference(startup_path), reference(stable_path)],
    ),
    account_menu_callbacks_verified=False,
    native_crossplay_login_selected=False,
    main_exe_ini_identity_preserved=True,
    game_recompile_performed=False,
    owned_root_test_artifacts_removed=True,
    map_test_performed=False,
    cross_network_gameplay_verified=False,
    full_backend_complete=False,
)
if args.achievement_contract:
    achievement_path = ROOT / "validation/20261006-achievement-rest-layout.json"
    achievement = load(achievement_path)
    assert achievement["audit_tool_sha256"] == digest(
        ROOT / "tools/research-achievement-rest-target.py"
    )
    assert (
        achievement["callback_vm"]["passed"]
        and len(achievement["callback_vm"]["cases"]) == 10
    )
    assert achievement["response"] == {"status": 200, "body": {"allSucceeded": True}}
    event_checks = [
        value
        for value in protocol["checks"]
        if value.startswith(
            ("Shared Replay achievement REST envelope", "Achievement REST root")
        )
    ]
    assert len(event_checks) == 2
    completion_path = STATE / "alpha/event-completion.json"
    completion = load(completion_path)
    assert completion["observer_sha256"] == digest(
        ROOT / "tools/observe-native-achievement.py"
    )
    assert (
        completion["pid"] == stable["pid"]
        and completion["game_sha256"] == stable["sha256"]
    )
    assert completion["backend_sha256"] == build["sha256"]
    assert completion["original_image_sha256"] == achievement["target_image_sha256"]
    assert completion["native_single_callback_success"]
    event_observation_path = STATE / "alpha/after-event.json"
    event_observation = load(event_observation_path)
    assert event_observation["pid"] == stable["pid"]
    assert event_observation["server_process_verified"]["sha256"] == build["sha256"]
    assert event_observation["server_process_verified"]["connection_receipt_matches"]
    event_requests = sum(
        "operation=achievement-events-recorded error=0" in line
        and "operation_name=report_user_events_batch" in line
        for line in event_observation["server_log_since_launch"]
    )
    assert event_requests >= 1
    receipt["achievement_rest"] = dict(
        target_contract_evidence=reference(achievement_path),
        protocol_checks=event_checks,
        original_callbacks_vm_passed=True,
        native_game_event_callback_verified=True,
        native_single_user_callback_verified=True,
        native_multi_user_callback_verified=False,
        native_event_requests=event_requests,
        native_callback_evidence=[
            reference(completion_path),
            reference(event_observation_path),
        ],
    )
destination.write_text(json.dumps(receipt, indent=2) + "\n")
(ROOT / "data/backend-readiness-latest.json").write_text(
    json.dumps(reference(destination), indent=2) + "\n"
)
print(
    f"Verified {len(protocol['checks'])} protocol groups and native startup; account-menu/WAN callbacks remain separate."
)
