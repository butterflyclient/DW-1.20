"""Verify a successful workstation job and install its freshly linked EXE beside Replay."""

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import os
import sys
import struct
import argparse
from datetime import datetime, timezone
import pefile

ROOT = Path(__file__).resolve().parents[1]
COMPILER = Path(r"E:\replay-compiler")
sys.path[:0] = [str(COMPILER / "tools"), str(COMPILER)]
from workstation.config import load_paths

paths = load_paths(COMPILER)
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--job-receipt", type=Path, default=ROOT / "data/workstation-job.json")
parser.add_argument("--snapshot-receipt", type=Path,
                    default=ROOT / "data/compiler-snapshot-receipt.json")
parser.add_argument("--startup-receipt", type=Path,
                    help="Explicit focused encrypted startup gate; does not claim full backend coverage")
args = parser.parse_args()
for receipt_path in (args.job_receipt, args.snapshot_receipt):
    if not receipt_path.resolve().is_relative_to((ROOT / "data").resolve()):
        raise RuntimeError("Use an owned private build receipt inside data")
dispatch = json.loads(args.job_receipt.read_text())
job_path = paths["cache"] / "jobs" / dispatch["id"] / "job.json"
job = json.loads(job_path.read_text())
if job.get("status") != "succeeded" or job.get("profile") != "engine":
    raise RuntimeError(
        "DW deployment requires the successful recorded workstation engine job"
    )
artifacts = [
    item
    for item in job["artifacts"]
    if str(item.get("path", "")).lower().endswith(".exe")
]
if len(artifacts) != 1:
    raise RuntimeError("Workstation job does not expose one executable artifact")
artifact = Path(artifacts[0]["path"]).resolve()
actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
if actual != artifacts[0]["sha256"]:
    raise RuntimeError("Published workstation executable hash changed")
build = Path(job["build_directory"]).resolve()
allowed_roots = (
    paths["build_root"].resolve(),
    (ROOT / "data" / "workstation-builds").resolve(),
)
if (
    not any(build.is_relative_to(folder) for folder in allowed_roots)
    or build.name != "build-workstation-" + job["id"]
):
    raise RuntimeError("Job build directory is outside its expected build root")
report = json.loads((build / "build-report.json").read_text())
if any(item["source"].endswith("DW_TestHomePath.cpp") for item in report["cpp"]):
    raise RuntimeError(
        "Private native-pair test build: do not replace the normal DW executable"
    )
source_root = Path(report["source_root"]).resolve()
snapshot_receipt = None
if source_root != COMPILER.resolve():
    snapshot_receipt = json.loads(
        args.snapshot_receipt.read_text()
    )
    if source_root != Path(snapshot_receipt["snapshot"]).resolve():
        raise RuntimeError(
            "Build report does not identify the recorded source snapshot"
        )
    for item in snapshot_receipt["files"]:
        source = Path(item["snapshot"]).resolve()
        if not source.is_relative_to(source_root):
            raise RuntimeError("Snapshot receipt contains an unrelated source path")
        # Only the preparation manifest changes: absolute input paths are
        # rebound to byte-identical evidence inside the frozen compiler root.
        if source == source_root / "generated" / "manifest.json":
            manifest = json.loads(source.read_text())
            for preparation in manifest["preparation_inputs"]:
                preparation["path"] = str(
                    COMPILER / Path(preparation["path"]).relative_to(source_root)
                )
            original_bytes = (
                (json.dumps(manifest, indent=2) + "\n").replace("\n", "\r\n").encode()
            )
            if hashlib.sha256(original_bytes).hexdigest() != item["sha256"]:
                raise RuntimeError(
                    "Recovery manifest changed beyond its preparation input paths"
                )
            continue
        if hashlib.sha256(source.read_bytes()).hexdigest() != item["sha256"]:
            raise RuntimeError("Frozen workstation input changed: " + str(source))
spec = importlib.util.spec_from_file_location(
    "dw_build_provenance", source_root / "tools" / "source_provenance.py"
)
provenance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provenance)
provenance.validate_report(report)
verification = json.loads((build / "verification-report.json").read_text())
relocations = json.loads((build / "relocation-audit.json").read_text())
if (
    report["sha256"] != actual
    or verification["sha256"] != actual
    or verification["unresolved_symbols"] != 0
):
    raise RuntimeError("Linked image has no matching successful verification")
if not relocations.get("passed") or relocations["sha256"] != actual:
    raise RuntimeError("Linked image has no matching successful relocation audit")
saved = json.loads((ROOT / "data" / "workstation-source-receipt.json").read_text())
records = {item["source_sha256"]: item for item in report["cpp"]}
for source in saved["sources"]:
    for override in (snapshot_receipt or {}).get("dw_private_revision_overrides", []):
        if source["id"] == override["id"]:
            source["content_sha256"] = source["revision"] = override["content_sha256"]
    if source["content_sha256"] not in records:
        raise RuntimeError("DW source revision was not compiled: " + source["name"])
    source["compiled_source"] = records[source["content_sha256"]]["source"]
    source["object_sha256"] = records[source["content_sha256"]]["object_sha256"]
startup_source = ROOT / "integration" / "replay" / "DW_GdiCloneBootstrap.cpp"
startup_sha256 = hashlib.sha256(startup_source.read_bytes()).hexdigest()
startup_object = records.get(startup_sha256)
if not startup_object or "func_1403061A0" not in report["symbols"]:
    raise RuntimeError("DW startup compatibility source was not compiled")
probe_source = ROOT / "integration/replay/DW_WindowsStartupProbe.cpp"
probe_digest = hashlib.sha256(probe_source.read_bytes()).hexdigest()
probe_object = records.get(probe_digest)
if not probe_object or "func_141489DA0" not in report["symbols"]:
    raise RuntimeError("Proxy-free startup source was not compiled")
endpoint_cases = verification.get("dw_local_endpoints", [])
if (
    len(endpoint_cases) != 4
    or not any(
        item.get("enabled")
        and item.get("ini_utf8_bom")
        and item.get("configured_host") == "203.0.113.12"
        for item in endpoint_cases
    )
    or not all(
        item.get("compiled_startup_constructor_returns")
        and item.get("compiled_startup_probe_returns")
        and item.get("compiled_public_address_serialization")
        for item in endpoint_cases
    )
):
    raise RuntimeError(
        "DW startup constructor and filename selection were not verified"
    )
platform_proof = json.loads((ROOT / "data" / "platform-verification.json").read_text())
if (
    not platform_proof.get("passed")
    or platform_proof["public_key_sha256"]
    != hashlib.sha256((ROOT / "data" / "platform-public.blob").read_bytes()).hexdigest()
):
    raise RuntimeError(
        "Local platform signing/validation proof is unavailable or stale"
    )
private_objects = []
private_sources = sorted((ROOT / "integration" / "replay").glob("DW_Local*.cpp"))
private_sources.append(ROOT / "integration/replay/DW_Multiplayer.cpp")
private_sources.append(ROOT / "integration/replay/DW_MapAvailability.cpp")
for path in private_sources:
    if path.name == "DW_LocalBackend_Frame.cpp":
        continue
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    record = records.get(digest)
    if not record:
        raise RuntimeError("Private platform C++ was not compiled: " + path.name)
    if (
        path.name == "DW_LocalPlatformCrypto.cpp"
        and digest != platform_proof["crypto_source_sha256"]
    ):
        raise RuntimeError("Compiled client crypto changed after protocol verification")
    private_objects.append(
        {
            "source": str(path),
            "source_sha256": digest,
            "compiled_source": record["source"],
            "object_sha256": record["object_sha256"],
        }
    )
required_private_sources = {
    "DW_LocalAuthTransport.cpp",
    "DW_LocalPlatform.cpp",
    "DW_LocalPlatformCrypto.cpp",
    "DW_LocalCachedContentCrypto.cpp",
    "DW_LocalResources.cpp",
    "DW_LocalConfig.cpp",
    "DW_LocalIdentity.cpp",
    "DW_LocalProgression.cpp",
    "DW_Multiplayer.cpp",
    "DW_MapAvailability.cpp",
}
client_integration = json.loads((ROOT / "validation/20261007-playtest-client.json").read_bytes())
if not client_integration.get("passed") or client_integration["executable_sha256"] != actual:
    raise RuntimeError("Linked unlock/Verdansk integration proof is unavailable or stale")
if {
    Path(item["source"]).name for item in private_objects
} != required_private_sources or not all(
    item.get("compiled_platform_payload_validation")
    and item.get("compiled_auth_url_and_key_selection")
    and item.get("compiled_legacy_url_selection")
    and item.get("compiled_publisher_key_selection_and_verification_lifetime")
    and item.get("compiled_connection_disconnect_lifecycle")
    and item.get("compiled_platform_online_status_persistence")
    and item.get("compiled_ini_player_name_header")
    for item in endpoint_cases
):
    raise RuntimeError(
        "Linked local platform integration has no complete validation receipt"
    )
local_cases = [
    item
    for item in endpoint_cases
    if item.get("enabled") and item.get("configured_host") == "127.0.0.1"
]
if len(local_cases) != 1 or not local_cases[0].get(
    "compiled_profile_license_and_account_metadata"
):
    raise RuntimeError(
        "Native profile/license/account metadata transition was not verified in linked code"
    )
if not local_cases[0].get("compiled_web_credential_queue_and_callback"):
    raise RuntimeError(
        "Native web credential request/callback was not verified in linked code"
    )
if not local_cases[0].get("compiled_dw_restart_lifecycle"):
    raise RuntimeError(
        "Native dw_restart command lifecycle was not verified in linked code"
    )
if not local_cases[0].get("compiled_dw_restart_preserves_platform_identity"):
    raise RuntimeError(
        "DW restart platform-identity preservation was not verified in linked code"
    )
if not local_cases[0].get("compiled_native_local_profile_selection"):
    raise RuntimeError(
        "Native local profile storage was not selected before compiled sign-in"
    )
resource_proof = json.loads(
    (ROOT / "data/platform-resource-verification.json").read_text()
)
if (
    not resource_proof.get("passed")
    or resource_proof["crypto_source_sha256"] != platform_proof["crypto_source_sha256"]
    or resource_proof["server_sha256"]
    != hashlib.sha256(
        (ROOT / "build/Release/iw8-dw-server.exe").read_bytes()
    ).hexdigest()
):
    raise RuntimeError(
        "Signed native resource protocol verification is unavailable or stale"
    )
if not all(
    symbol in report["symbols"]
    for symbol in ("func_140469380", "DW_LocalResource_Fetch")
):
    raise RuntimeError("SDK resource boundary is absent from the linked image")
image = pefile.PE(str(artifact), fast_load=True)
try:
    table = report["symbols"]["gl_142506750"]
    for slot, symbol in ((2, "func_14165E230"), (4, "func_14165DD20")):
        target = struct.unpack("<Q", image.get_data(table + 8 * slot, 8))[0]
        if target != image.OPTIONAL_HEADER.ImageBase + report["symbols"][symbol]:
            raise RuntimeError(
                "Native ACCOUNT vtable did not resolve to its compiled provider: "
                + symbol
            )
    wrapper = report["symbols"]["func_14165DF20"]
    code = image.get_data(wrapper, 5)
    if (
        code[0] != 0xE9
        or wrapper + 5 + struct.unpack_from("<i", code, 1)[0]
        != report["symbols"]["func_14165DF30"]
    ):
        raise RuntimeError(
            "Native ACCOUNT sign-in wrapper did not relink to its compiled provider"
        )
finally:
    image.close()
auth_proof = json.loads((ROOT / "data" / "auth-verification.json").read_text())
if (
    not auth_proof.get("passed")
    or auth_proof["server_sha256"] != platform_proof["server_sha256"]
    or auth_proof["public_der_sha256"]
    != hashlib.sha256((ROOT / "data" / "platform-public.der").read_bytes()).hexdigest()
):
    raise RuntimeError("Signed auth ticket/signature proof is unavailable or stale")
if (
    auth_proof["server_sha256"]
    != hashlib.sha256(
        (ROOT / "build" / "Release" / "iw8-dw-server.exe").read_bytes()
    ).hexdigest()
):
    raise RuntimeError("Server changed after signed-session/auth protocol verification")
lobby_proof = json.loads((args.startup_receipt or ROOT / "data/lobby-verification.json").read_text())
if args.startup_receipt and lobby_proof.get("scope") != "startup":
    raise RuntimeError("Expected an explicitly scoped startup verification receipt")
if (
    not lobby_proof.get("passed")
    or lobby_proof["server_sha256"] != auth_proof["server_sha256"]
    or lobby_proof["kdf_sha256"]
    != hashlib.sha256(
        (ROOT / "data" / "replay-traffic-kdf.bin").read_bytes()
    ).hexdigest()
):
    raise RuntimeError("Encrypted lobby/profile/storage proof is unavailable or stale")
required_profile_check = "native user-object read/upload, metadata/content/checksum/tags, missing indexes and caller ownership"
if required_profile_check not in lobby_proof.get("checks", []):
    raise RuntimeError(
        "Native user-object profile storage has not passed its protocol checks"
    )
if (
    "live-Replay platform-6 universal-ID owner upload/read and cross-account rejection"
    not in lobby_proof["checks"]
):
    raise RuntimeError(
        "Actual Replay profile owner representation has not passed its protocol checks"
    )
required_startup_checks = [
    "contextual storage universal-ID ownership and matching native account-type metadata",
    "Replay publisher namespace defaults, matched version fields and native string-value validation",
    "native empty mail-header queries, request bounds and account ownership",
    "native achievement user-state JSON, persistent per-account defaults and bounded context",
    "native clan group-identifier schema, empty result arrays and malformed-field rejection",
    "native leaderboard row persistence, replace/add/max/NAN semantics and atomic batch rejection",
    "native Friends and pending-invitation REST response schema and bounded requested context",
]
if any(check not in lobby_proof["checks"] for check in required_startup_checks):
    raise RuntimeError(
        "Observed startup service gaps have not passed their protocol checks"
    )
endpoint_record = (
    next(
        (
            item
            for item in snapshot_receipt["files"]
            if Path(item["original"]) == ROOT / "tools" / "verify-dw-endpoints.py"
        ),
        None,
    )
    if snapshot_receipt
    else None
)
if (
    not endpoint_record
    or endpoint_record["sha256"]
    != hashlib.sha256(
        (ROOT / "tools" / "verify-dw-endpoints.py").read_bytes()
    ).hexdigest()
):
    raise RuntimeError(
        "Compiled native account getter verification source is stale or unavailable"
    )
local_identity_proof = json.loads(
    (ROOT / "data/local-player-verification.json").read_text()
)
identity_source = ROOT / "integration/replay/DW_LocalIdentity.cpp"
if not all(
    local_identity_proof.get(field)
    for field in (
        "passed",
        "new_process_persistence",
        "distinct_players",
        "rename_preserves_identity",
        "interrupted_write_recovered",
        "corrupt_identity_preserved_and_rejected",
        "precise_identity_failure_stages",
        "lock_contention_preserves_identity",
        "damaged_dpapi_preserved_and_rejected",
        "invalid_names_preserve_identity",
        "backend_restart_persistence",
    )
) or (
    local_identity_proof["server_sha256"] != auth_proof["server_sha256"]
    or local_identity_proof["identity_source_sha256"]
    != hashlib.sha256(identity_source.read_bytes()).hexdigest()
    or local_identity_proof["client_dll_sha256"]
    != hashlib.sha256(
        (ROOT / "build/Release/iw8-dw-platform-client.dll").read_bytes()
    ).hexdigest()
):
    raise RuntimeError("Automatic local identity verification is absent or stale")
destination = paths["game"] / "game_dx12_ship_replay_dw.exe"
if (
    not destination.exists()
    or hashlib.sha256(destination.read_bytes()).hexdigest() != actual
):
    staged = destination.with_suffix(".exe.dw-installing")
    shutil.copyfile(artifact, staged)
    if hashlib.sha256(staged.read_bytes()).hexdigest() != actual:
        raise RuntimeError("Staged deployment hash mismatch")
    os.replace(staged, destination)
# Server-only iterations retain an already verified identical game image.
# This also permits refreshing its server proof binding while that image runs.
if hashlib.sha256(destination.read_bytes()).hexdigest() != actual:
    raise RuntimeError("Installed executable hash mismatch")
receipt = {
    "schema": 1,
    "job_id": job["id"],
    "workstation_artifact": str(artifact),
    "build_directory": str(build),
    "compiler_source_root": str(source_root),
    "source_snapshot_receipt": (
        str(args.snapshot_receipt.resolve())
        if snapshot_receipt
        else None
    ),
    "executable": str(destination),
    "sha256": actual,
    "profile": "engine",
    "stage": "encrypted-lobby-profiles",
    "native_auth": True,
    "platform_auth": True,
    "local_player_identity": {
        "automatic_registration": True,
        "player_provisioning_required": False,
        "local_path": "%LOCALAPPDATA%/ReplayDW/player-identity.bin",
        "protection": "Windows user DPAPI; P-256 challenge proof of possession",
        "protocol_verification": str(ROOT / "data/local-player-verification.json"),
        "native_runtime_verified": False,
    },
    "platform_sources": private_objects,
    "platform_protocol_verification": str(ROOT / "data" / "platform-verification.json"),
    "auth_protocol_verification": str(ROOT / "data" / "auth-verification.json"),
    "lobby_protocol_verification": str(ROOT / "data" / "lobby-verification.json"),
    "server_sha256": auth_proof["server_sha256"],
    "native_tasks": True,
    "profiles": True,
    "storage": True,
    "matchmaking": False,
    "native_game_verified": False,
    "runtime_test": "owner pending",
    "sources": saved["sources"],
    "disconnect_lifecycle": "compiled local provider disconnect, verified null-native-client lobby-loss path",
    "platform_presence": {
        "compiled_status_selection_verified": True,
        "native_social_update_and_menu_event_retained": True,
        "native_runtime_verified": False,
    },
    "local_player_settings": {
        "native_cloud_sync_opt_out": "CODPC_NOCLOUD_SYNC=1",
        "compiled_selection_before_signin_verified": True,
        "serializer": "native GamerProfile and config.cfg writers",
        "directory": "Documents/Call of Duty Modern Warfare/players",
        "native_runtime_verified": False,
    },
    "dw_restart": {
        "command": "dw_restart",
        "compiled_lifecycle_verified": True,
        "platform_identity_preservation_verified": True,
        "native_runtime_verified": False,
        "status_command": "dw_localPlatformStatus",
    },
    "native_account_metadata": {
        "platform_protocol_version": 2,
        "signed_country": "US",
        "signed_age": 21,
        "compiled_layout_verified": True,
        "native_policy_pump_retained": True,
        "native_vtable_and_signin_wrapper_relinked": True,
        "original_platform_id_getter_executed": True,
        "account_id_numeric_offset": 192,
        "game_account_id_numeric_offset": 224,
        "native_license_code": 51636,
        "native_license_notification_retained": True,
        "platform_id_and_license_before_tokens": True,
        "native_runtime_acceptance": "owner pending",
    },
    "profile_storage": {
        "legacy_profiles": True,
        "contextual_files": True,
        "native_user_objects": True,
        "read_upload_update_restart_verified": True,
        "native_runtime_acceptance": "owner pending",
    },
    "objectstore_task_map": {
        "6": "user vector download",
        "7": "user vector upload",
        "16": "publisher metadata",
    },
    "startup_domains": {
        "mail_headers": True,
        "friends_and_invitations": True,
        "achievement_user_state": True,
        "clan_group_infos": True,
        "leaderboard_replace_add_max": True,
        "Replay_publisher_defaults": True,
        "contextual_UNO_storage": True,
    },
    "startup_compatibility": {
        "source": str(startup_source),
        "source_sha256": startup_sha256,
        "compiled_source": startup_object["source"],
        "object_sha256": startup_object["object_sha256"],
        "symbol": "func_1403061A0",
        "placement_rva": report["symbols"]["func_1403061A0"],
        "method": "C++ constructor replacement linked from native PE unwind ownership",
    },
    "windows_import_probe": {
        "source": str(probe_source),
        "source_sha256": probe_digest,
        "object_sha256": probe_object["object_sha256"],
        "symbol": "func_141489DA0",
        "placement_rva": report["symbols"]["func_141489DA0"],
        "native_bootstrap_retained": True,
        "native_crt_allocation_and_parent_cleanup_verified": True,
        "native_runtime_verified": False,
    },
}
(ROOT / "data" / "deployment.json").write_text(json.dumps(receipt, indent=2) + "\n")
readiness = {
    "schema": 3,
    "created_utc": datetime.now(timezone.utc).isoformat(),
    "executable": str(destination),
    "executable_sha256": actual,
    "server_sha256": auth_proof["server_sha256"],
    "build_job": job["id"],
    "checks": lobby_proof["checks"],
    "game_launched_during_preparation": False,
    "native_game_verified": False,
    "owner_launcher": str(paths["game"] / "Run_Replay_DW.cmd"),
    "auth_flow": [
        "signed local platform identity and account policy",
        "native profile ID and license initialized before token completion",
        "native 84/85 PC tickets and RSA-PSS reply",
        "ticket-bound legacy account login",
        "protocol-210 mutual lobby authentication",
        "extended auth and session-token reporting",
    ],
    "profile_flow": [
        "native per-player local config and GamerProfile settings with cloud settings sync disabled",
        "public/private profile CRUD",
        "contextual opaque file storage CRUD",
        "native user-object vector read/upload/update with content and metadata",
        "Replay platform-6 uno owner namespace and caller isolation",
        "server-restart persistence",
    ],
    "native_account_metadata": receipt["native_account_metadata"],
    "startup_domains": receipt["startup_domains"],
    "compiled_image_checks": {
        "unresolved_symbols": verification["unresolved_symbols"],
        "windows_virtual_unwind_cases": verification["windows_virtual_unwind_cases"],
        "windows_sec_image_mapping": verification["windows_sec_image_mapping"],
        "relocation_audit_passed": relocations["passed"],
        "compiled_profile_license_and_account_metadata": True,
        "compiled_platform_online_status_persistence": True,
        "compiled_native_local_profile_selection": True,
        "compiled_payload_rejections": local_cases[0][
            "compiled_platform_payload_validation"
        ]["rejected"],
    },
    "previous_game_observation": str(
        ROOT / "data" / "connecting-stall-live-observation-20261004-second.json"
    ),
    "startup_freeze": {
        "cause_confirmed": False,
        "timed_client_stage_markers_added": True,
    },
    "remaining_scope": [
        "proxy-free native-game acceptance and two-network gameplay are separate pending gates",
        "full backend implementation continues; two-network party gameplay remains unverified",
        "see backend-coverage-inventory.json for reviewed routes and unresolved DTO methods",
        "public lobby fill has encrypted-client coverage; native public-search callbacks, host migration and tournament scheduling remain open",
        "marketplace gifts/discounts and validation-token semantics remain open",
        "object-store listing and large-upload variants remain open",
        "crossplay/Uno account linking and broader native progression/reward validation remain open",
    ],
    "source_hashes": {
        str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for folder in (ROOT / "src", ROOT / "integration" / "replay")
        for path in sorted(folder.iterdir())
        if path.is_file() and path.suffix in (".cpp", ".h")
    },
}
(ROOT / "data" / "auth-profile-readiness.json").write_text(
    json.dumps(readiness, indent=2) + "\n"
)
print("Installed:", destination)
print("SHA256:", actual)
print("Source revisions verified:", len(saved["sources"]))
