"""Bind recipient purchase recovery and focused native checks to exact images."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--native-proof", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


native_path = args.native_proof.resolve()
output = args.output.resolve()
assert native_path.is_relative_to((ROOT / "validation").resolve())
assert output.is_relative_to((ROOT / "validation").resolve())
native = load(native_path)
fixture = load(ROOT / "data/lobby-verification.json")
deployment = load(ROOT / "data/deployment.json")
server_hash = digest(ROOT / "build/Release/iw8-dw-server.exe")
assert server_hash == fixture["server_sha256"] == deployment["server_sha256"]
assert server_hash == native["server_sha256"]
assert (
    digest(Path(deployment["executable"]))
    == deployment["sha256"]
    == native["game_sha256"]
)
assert fixture["passed"] and native["passed"]
assert native["native_relay_stability_after_restart_verified"]
covered = [
    check
    for check in fixture["checks"]
    if check.startswith(
        (
            "gift ",
            "mixed self/gift",
            "recipient overflow",
            "complete journal",
            "multi-account recovery",
            "fresh server process rolls forward an interrupted gift",
        )
    )
]
assert len(covered) == 7
receipt = {
    "schema": 1,
    "created_utc": datetime.now(timezone.utc).isoformat(),
    "server_sha256": server_hash,
    "game_sha256": deployment["sha256"],
    "engine_recompiled": False,
    "suite_grouped_checks": len(fixture["checks"]),
    "covered_checks": covered,
    "native_startup_reconnect_receipt": str(native_path.relative_to(ROOT)),
    "native_startup_reconnect_receipt_sha256": digest(native_path),
    "lobby_verification_sha256": digest(ROOT / "data/lobby-verification.json"),
    "source_sha256": {
        name: digest(ROOT / name)
        for name in (
            "src/marketplace_services.cpp",
            "tools/gift_fixtures.py",
            "tools/purchase_fixtures.py",
            "tools/test-lobby.py",
        )
    },
    "native_positive_gift_callback_verified": False,
    "native_gift_menu_verified": False,
    "two_network_gameplay_verified": False,
    "map_or_match_test_performed": False,
    "complete_backend_verified": False,
    "native_ui_limit": "Terms of Agreement screen remained unaccepted",
}
output.write_text(json.dumps(receipt, indent=2) + "\n")
print("PASS: current-image recipient purchase/recovery and scoped native reconnect")
