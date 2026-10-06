"""Bind original-selector, compiled-object and native publisher-variable evidence."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("before", type=Path)
parser.add_argument("after", type=Path)
parser.add_argument("stability", type=Path)
parser.add_argument(
    "--reference",
    type=Path,
    default=ROOT / "data/native-tournament-map-reference-20261006.json",
)
parser.add_argument(
    "--output",
    type=Path,
    default=ROOT / "validation/20261006-tournament-map-native-policy.json",
)
args = parser.parse_args()


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


deployment = load(ROOT / "data/deployment.json")
policy_path = ROOT / "data/tournaments/5800/map-pools.json"
policy = load(policy_path)
revision = load(policy_path.with_name("map-pools.applied.json"))
canonical = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
assert revision["sha256"] == hashlib.sha256(canonical).hexdigest()
assert revision["title"] == policy["title"] == 5800
assert revision["revision"] == policy["revision"]
bindings = load(ROOT / "data/playlists/5800/native-dvar-names.json")
reference = load(args.reference)
comparison = reference["compiled_backend_comparison"]
assert comparison["passed"] and comparison["cases"] == len(reference["cases"]) == 32
assert reference["sha256"] == digest(Path(reference["image"]))
for path, expected in comparison["sha256"].items():
    assert digest(Path(path)) == expected, path
assert (
    comparison["sha256"][str(ROOT / "build/Release/iw8-dw-server.exe")]
    == deployment["server_sha256"]
)
observations = [load(path) for path in (args.before, args.after, args.stability)]
assert len({item["pid"] for item in observations}) == 1
for item in observations:
    assert item["sha256"] == deployment["sha256"]
    assert item["server_process_verified"]["verified_live_process"]
    assert item["server_process_verified"]["sha256"] == deployment["server_sha256"]
    assert len(item["native_fences_controller_0"]) == 27
    assert all(
        row["passing"] and not row["failed"]
        for row in item["native_fences_controller_0"]
    )
    namespace = next(
        row
        for row in item["native_publisher_namespaces"]
        if row["namespace"] == "general"
    )
    assert namespace["applied"] and namespace["minor"] == policy["revision"]
    for round_index, pool in enumerate(policy["rounds"]):
        name = bindings[f"online_tournament_round_{round_index}_mapnames"]
        record = item["native_selected_dvars"][name]
        assert record["type"] == 9 and record["value"] == ",".join(pool)
assert (
    observations[0]["server_process_verified"]["pid"]
    != observations[1]["server_process_verified"]["pid"]
)
assert (
    observations[1]["server_process_verified"]
    == observations[2]["server_process_verified"]
)
assert (
    datetime.fromisoformat(observations[2]["observed_utc"])
    - datetime.fromisoformat(observations[1]["observed_utc"])
).total_seconds() >= 60
output = args.output.resolve()
assert output.is_relative_to((ROOT / "validation").resolve())
receipt = {
    "schema": 1,
    "passed": True,
    "observed_utc": datetime.now(timezone.utc).isoformat(),
    "server_sha256": deployment["server_sha256"],
    "game_sha256": deployment["sha256"],
    "original_replay_sha256": reference["sha256"],
    "compiled_backend_matches_original_x64_selector_cases": 32,
    "native_publisher_map_strings_applied": 4,
    "publisher_minor_revision": policy["revision"],
    "policy_sha256": revision["sha256"],
    "pools": policy["rounds"],
    "same_game_process_backend_restart_and_dw_restart_verified": True,
    "native_publisher_values_stable_after_restart": True,
    "native_memory_writes_used": False,
    "native_tournament_round_callbacks_verified": False,
    "playable_tournament_verified": False,
    "map_or_match_test_performed": False,
    "two_network_gameplay_verified": False,
    "complete_backend_verified": False,
    "reference": {
        str(args.reference.resolve().relative_to(ROOT)): digest(args.reference)
    },
    "observations": {
        str(path.resolve().relative_to(ROOT)): digest(path)
        for path in (args.before, args.after, args.stability)
    },
    "scope": "Original x64 selector and actual backend objects agree; unchanged Replay applied native publisher map strings before and after same-process reconnect. No native round gameplay claim.",
}
output.write_text(json.dumps(receipt, indent=2) + "\n")
print(
    "PASS: compiled backend / original selector agreement and four native map variables across backend restart"
)
