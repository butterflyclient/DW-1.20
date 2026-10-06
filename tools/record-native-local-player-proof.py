"""Bind the machine-local identity handoff to recorded native game observations.

This records scoped evidence; it does not certify remote party gameplay.
Private observations and identities remain in data/. Only the sanitized result
is written to validation/.
"""

import hashlib
import json
import struct
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEST = ROOT / "data/native-machine-profile-20261005"


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    deployment = read(ROOT / "data/deployment.json")
    protocol = read(ROOT / "data/local-player-verification.json")
    package = read(ROOT / "data/remote-package-receipt.json")
    identity = read(TEST / "normal-identity-file.json")
    settings = read(TEST / "proof.json")
    names = ("before", "outgoing", "changed", "reloaded", "restored", "final")
    observations = {name: read(TEST / (name + ".json")) for name in names}
    before, final = observations["before"], observations["final"]
    for observation in observations.values():
        require(observation["sha256"] == deployment["sha256"], "Game image changed")
        require(observation["server_process_verified"]["sha256"] ==
                deployment["server_sha256"], "Backend image changed")
        require(observation["native_user_xuid"] == before["native_user_xuid"] and
                observation["native_user_platform_id"] == before["native_user_platform_id"] and
                observation["native_user_name"] == before["native_user_name"],
                "Native account changed between launches")
        require(observation["native_profile_sign_in_state"] == 2 and
                observation["native_dw_hsm_connected_state_33"] and
                observation["native_social_online_status"] == 2, "Native sign-in incomplete")
        fences = observation["native_fences_controller_0"]
        require(len(fences) == 27 and all(row["passing"] and not row["failed"]
                                        for row in fences), "Native fence failed")
        lists = observation["native_crossplay_friend_lists"]
        require(len(lists) == 3 and all(row["fetch_state"] == 2 for row in lists),
                "Native friend lists incomplete")

    def counts(name):
        return [row["count"] for row in observations[name]["native_crossplay_friend_lists"]]

    for name in ("before", "restored", "final"):
        require(counts(name) == [0, 0, 0], "Test relationship remains")
    require(counts("outgoing") == [0, 0, 1], "Native invitation missing")
    require(counts("changed") == counts("reloaded") == [1, 0, 0],
            "Accepted native friendship did not persist")
    require(before["pid"] != observations["reloaded"]["pid"] != final["pid"],
            "Full restart not observed")
    require(settings["native_local_profile_save_and_reload_verified"] and
            settings["test_setting_restored_via_native_command"] and
            settings["game_sha256"] == deployment["sha256"], "Settings proof mismatch")
    require(final["native_local_player_settings"]["keyboard_toggle_ads"] ==
            before["native_local_player_settings"]["keyboard_toggle_ads"],
            "Restored option did not survive final launch")

    fingerprint = identity["public_key_fingerprint"]
    registry = ROOT / "data/platform-client-profiles" / (fingerprint + ".bin")
    record = registry.read_bytes()
    require(len(record) == 56, "Account metadata size mismatch")
    _, _, user, game_id = struct.unpack_from("<IIQI", record)
    name = record[20:56].split(b"\0", 1)[0].decode("ascii")
    require((user, game_id, name) == (final["native_user_xuid"],
                                    final["native_user_platform_id"],
                                    final["native_user_name"]), "Local key account mismatch")
    require("LocalCache" not in identity["physical_path"] and
            "\\ReplayDW\\player-identity.bin" in identity["physical_path"],
            "Identity observation is in a virtualized development profile")
    require(protocol["passed"] and protocol["server_sha256"] ==
            deployment["server_sha256"], "Protocol proof mismatch")
    source = next(row for row in deployment["platform_sources"]
                  if Path(row["source"]).name == "DW_LocalIdentity.cpp")
    require(protocol["identity_source_sha256"] == source["source_sha256"] ==
            digest(Path(source["source"])), "Compiled identity source mismatch")
    require(digest(Path(deployment["executable"])) == deployment["sha256"],
            "Deployed executable changed")
    archive = Path(package["archive"])
    require(digest(archive) == package["archive_sha256"], "Archive changed")
    with zipfile.ZipFile(archive) as contents:
        require(set(contents.namelist()) == {
            "game_dx12_ship_replay_dw.exe", "game_dx12_ship_replay_dw.ini",
            "Run_Replay_DW_Client.cmd", "READ_ME.txt"}, "Unexpected package member")
        require(hashlib.sha256(contents.read("game_dx12_ship_replay_dw.exe")).hexdigest() ==
                deployment["sha256"], "Packaged executable mismatch")
        ini = contents.read("game_dx12_ship_replay_dw.ini").decode("utf-8")
        require("player_name=\n" in ini.replace("\r\n", "\n") and
                "access_key" not in ini and "profile=" not in ini, "Personalized client INI")

    proof = {
        "schema": 1,
        "game_sha256": deployment["sha256"],
        "server_sha256": deployment["server_sha256"],
        "compiler_job": deployment["job_id"],
        "automatic_registration": True,
        "player_provisioning_required": False,
        "normal_windows_profile_verified": True,
        "local_key_selects_native_account": True,
        "native_account_stable_across_processes": True,
        "native_processes": [before["pid"], observations["reloaded"]["pid"], final["pid"]],
        "native_startup_fences_passed": 27,
        "native_online_presence_published": settings["native_online_presence_published"],
        "native_setting_saved_reloaded_restored": True,
        "native_friend_name_search_and_invitation": True,
        "native_accepted_friendship_persisted": True,
        "native_friend_lists_empty_after_cleanup": True,
        "universal_package_has_no_identity_or_credentials": True,
        "archive_sha256": package["archive_sha256"],
        "two_network_party_join_verified": False,
        "complete_backend_verified": False,
        "protocol_checks": {key: protocol[key] for key in (
            "distinct_players", "new_process_persistence", "rename_preserves_identity",
            "backend_restart_persistence", "interrupted_write_recovered",
            "corrupt_identity_preserved_and_rejected", "duplicate_machine_names_rejected",
            "legacy_names_do_not_block_machine_players")},
        "observation_sha256": {name + ".json": digest(TEST / (name + ".json"))
                               for name in names},
    }
    require(all(proof["protocol_checks"].values()), "Identity protocol check failed")
    output = ROOT / "validation/20261005-machine-local-player-identity.json"
    output.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
    deployment["local_player_identity"]["native_runtime_verified"] = True
    deployment["local_player_identity"]["native_proof"] = str(output)
    deployment["runtime_test"] = (
        "Automatic machine-local identity, Online presence, native friend invitation/acceptance/"
        "restart persistence and local settings save/reload/restore passed; "
        "two-network party gameplay remains pending"
    )
    (ROOT / "data/deployment.json").write_text(json.dumps(deployment, indent=2) + "\n",
                                             encoding="utf-8")
    print("Native local identity and universal package evidence verified")


if __name__ == "__main__":
    main()
