"""Verify the stock native mail callback, body decoder and delete lifecycle."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
for name in ("before", "notified", "consumed", "diagnostic", "output"):
    parser.add_argument("--" + name, required=True, type=Path)
args = parser.parse_args()


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


paths = {
    name: getattr(args, name).resolve()
    for name in ("before", "notified", "consumed", "diagnostic")
}
assert all(path.is_relative_to((ROOT / "data").resolve()) for path in paths.values())
output = args.output.resolve()
assert output.is_relative_to((ROOT / "validation").resolve())
before, notified, consumed, diagnostic = (load(paths[name]) for name in paths)
deployment = load(ROOT / "data/deployment.json")
fixture = load(ROOT / "data/lobby-verification.json")
assert fixture["passed"] and fixture["server_sha256"] == deployment["server_sha256"]
assert digest(ROOT / "build/Release/iw8-dw-server.exe") == deployment["server_sha256"]
assert digest(Path(deployment["executable"])) == deployment["sha256"]
for observation in (before, notified, consumed):
    assert observation["pid"] == diagnostic["pid"]
    assert observation["sha256"] == diagnostic["game_sha256"] == deployment["sha256"]
    assert observation["server_process_verified"] == before["server_process_verified"]
    assert observation["server_process_verified"]["verified_live_process"]
    assert (
        observation["server_process_verified"]["sha256"]
        == diagnostic["server_sha256"]
        == deployment["server_sha256"]
    )
    assert observation["native_user_xuid"] == diagnostic["recipient"]
    assert observation["native_profile_sign_in_state"] == 2
    assert observation["native_dw_hsm_connected_state_33"]
    assert len(observation["native_fences_controller_0"]) == 27
    assert all(
        row["passing"] and not row["failed"]
        for row in observation["native_fences_controller_0"]
    )
    manager = observation["native_mail_manager"]
    assert manager["enabled"] == manager["controller_0_initialized"] == 1
    assert manager["context"] == diagnostic["context"] == ""
assert diagnostic["sender"] != diagnostic["recipient"]
assert diagnostic["observation_sha256"] == digest(paths["before"])
start, wake, finish = (
    value["native_mail_manager"] for value in (before, notified, consumed)
)
assert start["state"] == 0 and start["controller_0_pending"] == 0
assert wake["state"] == 1 and wake["controller_0_pending"] == 1
assert (
    finish["state"] == 0
    and finish["controller_0_pending"] == 0
    and not finish["task_active"]
)
assert finish["body_mail_id"] == diagnostic["mail_id"]
assert finish["body_length"] == diagnostic["body_length"]
assert (
    finish["body_sha256"]
    == hashlib.sha256(bytes(diagnostic["body_length"])).hexdigest()
)
sent = datetime.fromisoformat(diagnostic["sent_utc"])
ended = datetime.fromisoformat(consumed["observed_utc"])
assert (
    datetime.fromisoformat(before["observed_utc"])
    < sent
    < datetime.fromisoformat(notified["observed_utc"])
    < ended
)
assert 0 < (ended - sent).total_seconds() < diagnostic["duration"] == 300
lines = consumed["server_log_since_launch"]
ordered = (
    "service=29 task=9 operation=mail-sent error=0 results=0",
    "service=29 task=10 operation=mail-headers-read error=0 results=1",
    "service=29 task=4 operation=mail-bodies-read error=0 results=1",
    "service=29 task=5 operation=mail-deleted error=0 results=0",
)
position = 0
for marker in ordered:
    position = next(
        index + 1 for index in range(position, len(lines)) if marker in lines[index]
    )
mailbox = Path(diagnostic["mailbox"]).resolve()
assert mailbox == (ROOT / "data/mail/5800/_default/messages.json").resolve()
assert not any(row["id"] == diagnostic["mail_id"] for row in load(mailbox)["messages"])
receipt = {
    "schema": 1,
    "created_utc": datetime.now(timezone.utc).isoformat(),
    "passed": True,
    "game_sha256": deployment["sha256"],
    "server_sha256": deployment["server_sha256"],
    "compiler_job": deployment["job_id"],
    "engine_recompiled": False,
    "suite_grouped_checks": len(fixture["checks"]),
    "native_game_mail_callback_verified": True,
    "native_mail_header_and_body_completion_verified": True,
    "native_mail_deletion_and_idle_return_verified": True,
    "native_processing_done_buffer_clear_verified": True,
    "payload_hash_captured_before_processing_clear": False,
    "application_mail_handlers_verified": False,
    "native_startup_fences_passed": 27,
    "separate_fixture_identity_used": True,
    "friendship_created": False,
    "map_or_match_test_performed": False,
    "two_network_gameplay_verified": False,
    "complete_backend_verified": False,
    "native_ui_limit": "Terms of Agreement screen remained unaccepted",
    "observations": {
        str(path.relative_to(ROOT)): digest(path) for path in paths.values()
    },
    "source_sha256": {
        name: digest(ROOT / name)
        for name in ("tools/observe-game.py", "tools/native-mail-test.py")
    },
    "original_target_evidence_sha256": {
        name: digest(ROOT / name)
        for name in (
            "data/native-engine-mail-manager-20261006.json",
            "data/native-game-mail-headers-wrapper-20261006.json",
        )
    },
}
output.write_text(json.dumps(receipt, indent=2) + "\n")
print(
    "PASS: native new-mail wakeup, header/body completion, deletion and idle return; application handlers remain outside this diagnostic"
)
