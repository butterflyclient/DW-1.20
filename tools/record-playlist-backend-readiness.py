"""Record backend/playlist readiness without inheriting prior native game tests."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--fixture-root", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
fixture = args.fixture_root.resolve(strict=True)
output = args.output.resolve()
assert fixture.is_relative_to(ROOT / "data")
assert output.is_relative_to(ROOT / "validation") and output.suffix == ".json"


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reference(path):
    return {"path": path.relative_to(ROOT).as_posix(), "sha256": digest(path)}


build = load(ROOT / "data/backend-build-latest.json")
assert build["compile_passed"]
state = ROOT / "data/subsystem-integration-20261007" / build["sha256"][:12]
state.mkdir(parents=True, exist_ok=True)
backend = ROOT / "build/Release/iw8-dw-server.exe"
assert digest(backend) == build["sha256"]
for name, expected in build["inputs"].items():
    assert digest(Path(build["source_directory"]) / name) == expected
shipping = load(ROOT / "data/deployment.json")
assert digest(Path(shipping["executable"])) == shipping["sha256"]
build_path = state / "backend-build.json"
build_path.write_text(json.dumps(build, indent=2) + "\n")
wire_path = fixture / "data/playlist-wire-verification.json"
focused_path = fixture / "data/team-policy-verification.json"
wire, focused = load(wire_path), load(focused_path)
for proof in (wire, focused):
    assert proof["passed"] and proof["server_sha256"] == build["sha256"]
assert not wire["game_runs_performed"]
contract_path = ROOT / "data/playlist-contract-verification.json"
contract = load(contract_path)
assert contract["passed"] and not contract["game_runs_performed"]
selector = Path(build["build_directory"]) / "Release/iw8-playlist-contract-test.exe"
assert digest(selector) == contract["executable_sha256"]
for name, expected in contract["source_sha256"].items():
    assert build["inputs"][Path(name).as_posix()] == expected
packages_path = ROOT / "data/playlists/5800/packages.json"
packages = load(packages_path)
assert wire["package_revision"] == packages["revision"]
assert len(wire["results"]) == contract["playlists"]
assert sum(row["eligible"] for row in wire["results"]) == contract["eligible_playlists"]
full_path = fixture / "data/lobby-verification.json"
full = load(full_path) if full_path.exists() else None
if full is not None:
    assert full["passed"] and full["server_sha256"] == build["sha256"]
# Latest-pointer tools can refresh their output later. Bind readiness to
# immutable copies for this specific backend instead of those moving paths.
def preserve(source, name):
    target = state / name
    contents = source.read_bytes()
    if target.exists():
        assert target.read_bytes() == contents, "Readiness evidence changed for this backend"
    else:
        target.write_bytes(contents)
    return target


contract_path = preserve(contract_path, "compiled-selector.json")
wire_path = preserve(wire_path, "playlist-wire.json")
focused_path = preserve(focused_path, "multiplayer-progression-wire.json")
packages_path = preserve(packages_path, "installed-packages.json")
if full is not None:
    full_path = preserve(full_path, "full-protocol.json")

proof = {
    "schema": 1,
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "passed": True,
    "passed_scope": "Fresh backend compilation and bounded playlist/native-wire contracts",
    "backend_sha256": build["sha256"],
    "unchanged_shipping_game_sha256": shipping["sha256"],
    "build_receipt": reference(build_path),
    "protocol_evidence": reference(focused_path),
    "playlist_protocol_evidence": reference(wire_path),
    "compiled_selector_evidence": reference(contract_path),
    "package_inventory": reference(packages_path),
    "protocol_checks": len(focused["checks"]),
    "full_protocol_evidence": reference(full_path) if full is not None else None,
    "full_protocol_checks": len(full["checks"]) if full is not None else None,
    "playlists_checked": len(wire["results"]),
    "eligible_playlists": contract["eligible_playlists"],
    "installed_main_packages": contract["installed_main_packages"],
    "native_startup": {"passed": False, "pending": True, "evidence": []},
    "game_runs_performed": False,
    "native_map_load_verified": False,
    "transient_completeness_verified": False,
    "full_backend_complete": False,
    "source_scope": "Committed snapshot; unrelated dirty sources excluded",
}
output.write_text(json.dumps(proof, indent=2) + "\n")
(ROOT / "data/backend-readiness-latest.json").write_text(
    json.dumps(reference(output), indent=2) + "\n"
)
print(f"Recorded backend/playlist readiness: {output}; native game validation pending")
