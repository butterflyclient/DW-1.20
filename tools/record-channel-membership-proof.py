"""Bind channel lifecycle fixtures to their exact compiled backend and sources."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


suite = json.loads((ROOT / "data/lobby-verification.json").read_bytes())
server_hash = digest(ROOT / "build/Release/iw8-dw-server.exe")
assert suite["passed"] and suite["server_sha256"] == server_hash
prefixes = (
    "Native channel event-24 contains full typed member/channel-info DTO",
    "Channel membership survives another valid socket closing",
    "Generation revalidation suppresses obsolete queued leave",
    "Independent simultaneous channel joins retain both member deltas",
    "Complete channel title/category/key/member/name/revision/generation layouts",
)
checks = [item for item in suite["checks"] if item.startswith(prefixes)]
assert len(checks) == len(prefixes)
fixture = Path(suite["fixture_directory"]).resolve()
assert fixture.parent == (ROOT / "data").resolve()
assert fixture.name.startswith("protocol-fixture-")
sources = (
    "src/channel_store.cpp",
    "src/channel_store.h",
    "src/channel_services.cpp",
    "src/channel_services.h",
    "src/services.cpp",
    "src/services.h",
    "tools/channel_membership_fixtures.py",
    "tools/record-channel-membership-proof.py",
)
receipt = {
    "schema": 1,
    "verified_at": datetime.now(timezone.utc).isoformat(),
    "passed": True,
    "server_sha256": server_hash,
    "scope": "Authenticated native channel join/leave push lifecycle and complete persistent layout",
    "checks": checks,
    "suite_checks": len(suite["checks"]),
    "source_sha256": {name: digest(ROOT / name) for name in sources},
    "target_build": "Replay 1.20",
    "native_reference_addresses": {
        "push_dispatch": "0x142122970",
        "member_subscription_v2": "0x142120A80",
        "channel_info_with_category": "0x1420FE9A0",
        "event_handler": "0x1414F4A50",
        "chat_channel_update": "0x140F3D690",
    },
    "positive_native_member_callback_verified": False,
    "two_network_multiplayer_verified": False,
}
output = ROOT / "validation/20261006-channel-membership.json"
output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
print(f"PASS: {len(checks)} channel groups; {len(suite['checks'])} suite groups")
