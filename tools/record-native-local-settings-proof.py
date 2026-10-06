"""Record local settings proof from a native save and a full game restart.

Run only after the controlled test has captured before.json, changed.json,
reloaded.json, restored.json and files-after-save.json in
data/native-settings-presence-20261005.
These are observations of the real game, not a profile-format reimplementation.
"""

import hashlib
import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--directory", type=Path, default=ROOT / "data/native-settings-presence-20261005")
TEST = parser.parse_args().directory.resolve()
if not TEST.is_relative_to(ROOT / "data"):
    raise ValueError("Native observations must be inside the private DW data directory")


def read(name):
    return json.loads((TEST / name).read_text(encoding="utf-8-sig"))


deployment = read("deployment.json")
before, changed, reloaded, restored = [
    read(name + ".json") for name in ("before", "changed", "reloaded", "restored")
]
for observation in (before, changed, reloaded, restored):
    assert observation["sha256"] == deployment["sha256"]
    assert observation["native_profile_sign_in_state"] == 2
    assert observation["native_dw_hsm_connected_state_33"]
    assert observation["native_local_player_settings"]["profile_logged_in"]
    assert not observation["native_local_player_settings"]["profile_reading"]
assert before["pid"] == changed["pid"] != reloaded["pid"]
initial = before["native_local_player_settings"]["keyboard_toggle_ads"]
edited = changed["native_local_player_settings"]["keyboard_toggle_ads"]
assert edited != initial
assert reloaded["native_local_player_settings"]["keyboard_toggle_ads"] == edited
assert restored["native_local_player_settings"]["keyboard_toggle_ads"] == initial
assert restored["pid"] == reloaded["pid"]

initial_files = {Path(row["path"]).name: row for row in read("files-before.json")["files"]}
saved_files = read("files-after-save.json")["files"]
settings = next(row for row in saved_files if Path(row["path"]).suffix == ".iw8")
assert settings["size"] > 0
assert settings["sha256"] != initial_files[Path(settings["path"]).name]["sha256"]
assert Path(settings["path"]).parent == Path(initial_files["config.cfg"]["path"]).parent
restored_settings = next(
    row for row in read("files-after-restore.json")["files"]
    if Path(row["path"]).name == Path(settings["path"]).name
)
assert restored_settings["sha256"] != settings["sha256"]

presence = read("published-presence.json")
assert presence["online"] is True
assert presence["platform"] == "bnet"
assert presence["userID"] == before["native_user_xuid"]
assert before["native_social_online_status"] == reloaded["native_social_online_status"] == 2
fences = restored["native_fences_controller_0"]
assert len(fences) == 27 and all(row["passing"] and not row["failed"] for row in fences)

proof = {
    "schema": 1,
    "game_sha256": deployment["sha256"],
    "server_sha256": deployment["server_sha256"],
    "compiler_job": deployment["job_id"],
    "native_game_verified": True,
    "native_online_presence_published": True,
    "native_local_profile_save_and_reload_verified": True,
    "different_process_after_reload": True,
    "native_startup_fences_passed": len(fences),
    "settings_option": "keyboard toggle ADS",
    "initial_value": initial,
    "edited_and_reloaded_value": edited,
    "native_settings_file": settings,
    "cloud_sync": "native CODPC_NOCLOUD_SYNC opt-out selected before sign-in",
    "observations": ["before.json", "changed.json", "reloaded.json", "restored.json"],
    "observation_sha256": {
        name: hashlib.sha256((TEST / name).read_bytes()).hexdigest()
        for name in ("before.json", "changed.json", "reloaded.json", "restored.json",
                     "published-presence.json")
    },
    "two_network_party_join_verified": False,
    "test_setting_restored_via_native_command": True,
    "restored_settings_file": restored_settings,
}
(TEST / "proof.json").write_text(json.dumps(proof, indent=2) + "\n")

# Update only the currently installed image's scoped runtime gates. This proof
# does not certify a second network's party join or broader backend behavior.
deployment_path = ROOT / "data/deployment.json"
current = json.loads(deployment_path.read_text())
if current["sha256"] != deployment["sha256"]:
    raise RuntimeError("Installed deployment changed during native validation")
current["platform_presence"]["native_runtime_verified"] = True
current["local_player_settings"]["native_runtime_verified"] = True
current["native_game_verified"] = True
current["runtime_test"] = (
    "Native host startup, Online publication and local profile save/full-restart reload passed; "
    "two-network party join remains pending"
)
current["native_presence_local_settings_proof"] = str(TEST / "proof.json")
deployment_path.write_text(json.dumps(current, indent=2) + "\n")
print("Native Online publication and local profile save/full-restart reload verified")
