"""Bind a verified server revision to the unchanged, previously deployed game.

Initial game deployment retains the full source/compiler gates. This separate
operation does not copy an executable or claim to reverify deleted source trees.
"""

import hashlib
import json
import os
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


record_path = ROOT / "data" / "deployment.json"
record = load(record_path)
build = Path(record["build_directory"]).resolve()
if not build.is_relative_to((ROOT / "data" / "workstation-builds").resolve()):
    raise RuntimeError("Game build evidence is outside the private build root")
game_hash = record["sha256"]
if (
    digest(record["executable"]) != game_hash
    or digest(record["workstation_artifact"]) != game_hash
):
    raise RuntimeError("Game image differs from the last fully verified deployment")
report = load(build / "build-report.json")
verification = load(build / "verification-report.json")
audit = load(build / "relocation-audit.json")
if (
    any(item["sha256"] != game_hash for item in (report, verification, audit))
    or verification["unresolved_symbols"] != 0
    or not audit.get("passed")
):
    raise RuntimeError(
        "Retained compiler/linker/relocation evidence does not match the deployed game"
    )
compiled = {item["source_sha256"]: item for item in report["cpp"]}
source_status = []
for item in record["platform_sources"] + [record["startup_compatibility"]]:
    if (
        item["source_sha256"] not in compiled
        or compiled[item["source_sha256"]]["object_sha256"] != item["object_sha256"]
    ):
        raise RuntimeError(
            "Retained compiled game integration differs from its deployment evidence"
        )
    object_path = build / (Path(item["source"]).stem + ".obj")
    if digest(object_path) != item["object_sha256"]:
        raise RuntimeError(
            "Retained game integration object changed: " + str(object_path)
        )
    current = digest(item["source"]) if Path(item["source"]).is_file() else None
    source_status.append(
        {
            "source": item["source"],
            "compiled_sha256": item["source_sha256"],
            "current_sha256": current,
            "matches_deployed_object": current == item["source_sha256"],
        }
    )
server_hash = digest(ROOT / "build" / "Release" / "iw8-dw-server.exe")
proofs = {
    name: load(ROOT / "data" / name)
    for name in (
        "platform-verification.json",
        "auth-verification.json",
        "lobby-verification.json",
        "platform-resource-verification.json",
    )
}
for name, proof in proofs.items():
    if not proof.get("passed") or proof.get("server_sha256") != server_hash:
        raise RuntimeError("Run current server verification before rebinding: " + name)
platform = proofs["platform-verification.json"]
crypto_source = next(
    item["source_sha256"]
    for item in record["platform_sources"]
    if Path(item["source"]).name == "DW_LocalPlatformCrypto.cpp"
)
if (
    platform["crypto_source_sha256"] != crypto_source
    or platform["public_key_sha256"] != digest(ROOT / "data/platform-public.blob")
    or proofs["platform-resource-verification.json"]["crypto_source_sha256"]
    != crypto_source
    or proofs["auth-verification.json"]["public_der_sha256"]
    != digest(ROOT / "data/platform-public.der")
    or proofs["lobby-verification.json"]["kdf_sha256"]
    != digest(ROOT / "data/replay-traffic-kdf.bin")
):
    raise RuntimeError(
        "Server trust/crypto verification does not match the compiled game integration"
    )
previous_server_hash = record["server_sha256"]
readiness_path = ROOT / "data/auth-profile-readiness.json"
readiness = load(readiness_path)
if readiness["executable_sha256"] != game_hash:
    raise RuntimeError("Readiness evidence belongs to another compiled game image")
if readiness["server_sha256"] != server_hash:
    # A backend-only build must invalidate the companion readiness receipt too.
    # Retain historical proof paths, but never carry their native flags forward.
    readiness["native_game_verified"] = False
    readiness["native_startup_reconnect_verified"] = False
    readiness["native_relay_restart_verified"] = False
    readiness["native_verified_scopes"] = []
readiness["server_sha256"] = server_hash
readiness["checks"] = proofs["lobby-verification.json"]["checks"]
readiness["backend_rebound_utc"] = datetime.now(timezone.utc).isoformat()
for path in sorted((ROOT / "src").iterdir()):
    if path.is_file() and path.suffix in (".cpp", ".h"):
        readiness["source_hashes"][str(path.relative_to(ROOT))] = digest(path)
if previous_server_hash != server_hash:
    # Wire/crypto gates do not promote an earlier server's native observation
    # to this revision. Retain the historical proof path but clear current status.
    record["native_game_verified"] = False
    if "local_player_identity" in record:
        record["local_player_identity"]["native_runtime_verified"] = False
    record["runtime_test"] = (
        "Backend revision changed; fresh native observation pending. "
        "Historical native receipts retain their original server hashes."
    )
record["server_sha256"] = server_hash
record["server_rebinding"] = {
    "verified_utc": datetime.now(timezone.utc).isoformat(),
    "unchanged_game_sha256": game_hash,
    "server_sha256": server_hash,
    "previous_server_sha256": previous_server_hash,
    "method": "retained successful game deployment, matching build/object/relocation evidence and fresh server wire/crypto fixtures",
    "game_source_snapshot_present": Path(record["compiler_source_root"]).is_dir(),
    "current_integration_source_status": source_status,
    "game_was_recompiled": False,
    "game_was_copied": False,
}
pending = record_path.with_suffix(".pending")
pending.write_text(json.dumps(record, indent=2) + "\n")
os.replace(pending, record_path)
pending = readiness_path.with_suffix(".pending")
pending.write_text(json.dumps(readiness, indent=2) + "\n")
os.replace(pending, readiness_path)
print("Verified server " + server_hash + " for unchanged game " + game_hash)
