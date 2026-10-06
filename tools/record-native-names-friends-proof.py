"""Record only name/friend behavior observed in the freshly compiled native game."""

import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
TEST = ROOT / "data/native-names-friends-20261005"
deployment = json.loads((ROOT / "data/deployment.json").read_text())
labels = ("before", "outgoing", "accepted", "incoming", "accepted-native",
          "removed", "reloaded", "restored")
observations = {
    label: json.loads((TEST / (label + ".json")).read_text()) for label in labels
}
peer = json.loads((ROOT / "data/native-social-invite.json").read_text())["peer"]


def users(observation, index):
    rows = [row for row in observation["native_crossplay_friend_lists"]
            if row["local_client"] == 0 and row["list_index"] == index]
    assert len(rows) == 1 and rows[0]["fetch_state"] == 2
    return {entry["user"] for entry in rows[0]["entries"]}


for item in observations.values():
    assert item["sha256"] == deployment["sha256"]
    assert item["native_profile_sign_in_state"] == 2
    assert item["native_dw_hsm_connected_state_33"]
before, reloaded = observations["before"], observations["reloaded"]
assert before["pid"] != reloaded["pid"]
assert before["native_user_name"] == "ReplayHostTest"
assert reloaded["native_user_name"] == "DWPlayer"
assert before["native_user_xuid"] == reloaded["native_user_xuid"]
assert before["native_user_platform_id"] == reloaded["native_user_platform_id"]
assert all(not users(before, index) for index in range(3))
assert users(observations["outgoing"], 2) == {peer}
assert users(observations["accepted"], 0) == {peer}
assert users(observations["incoming"], 1) == {peer}
assert users(observations["accepted-native"], 0) == {peer}
assert all(not users(observations["accepted-native"], index) for index in (1, 2))
assert all(not users(observations[label], index)
           for label in ("removed", "reloaded", "restored") for index in range(3))

identities = [ROOT / "data/platform-profile.bin"] + [
    ROOT / f"data/platform-profiles/remote-test-{index}.bin" for index in (1, 2, 3)
]
accounts = [struct.unpack_from("<QI", path.read_bytes(), 8) for path in identities]
assert len({uid for uid, _ in accounts}) == len({pid for _, pid in accounts}) == 4
owned = {uid for uid, _ in accounts}
settings = json.loads((TEST / "proof.json").read_text())
assert settings["game_sha256"] == deployment["sha256"]
assert settings["native_local_profile_save_and_reload_verified"]
for path in (ROOT / "data/social").glob("*/*/friends.json"):
    store = json.loads(path.read_text())
    assert not any(row[field]["userID"] in owned for key, fields in
                   (("friends", ("a", "b")), ("pending", ("from", "to")))
                   for row in store[key] for field in fields)

proof = {
    "schema": 1,
    "game_sha256": deployment["sha256"],
    "server_sha256": deployment["server_sha256"],
    "compiler_job": deployment["job_id"],
    "native_game_verified": True,
    "ini_name_applied_in_native_user_record": True,
    "name_changed_back_after_full_game_restart": True,
    "universal_and_platform_account_ids_preserved": True,
    "native_name_search_and_outgoing_request_completed": True,
    "peer_acceptance_refreshed_native_friend_list": True,
    "native_incoming_request_and_acceptance_completed": True,
    "native_removal_push_cleared_friend_and_request_lists": True,
    "host_and_three_guests_have_distinct_persistent_ids": True,
    "host_and_guest_friendships_and_requests_empty_for_handoff": True,
    "native_local_settings_save_and_reload_verified": True,
    "native_startup_fences_passed": settings["native_startup_fences_passed"],
    "second_network_party_join_verified": False,
    "observations": {
        label: hashlib.sha256((TEST / (label + ".json")).read_bytes()).hexdigest()
        for label in labels
    },
    "method": "Native engine-thread Social entry point, real backend tasks and read-only linked-symbol game observations",
}
(TEST / "names-friends-proof.json").write_text(json.dumps(proof, indent=2) + "\n")
(ROOT / "validation/20261005-player-names-friends.json").write_text(
    json.dumps(proof, indent=2) + "\n"
)
deployment["native_player_names_and_friends"] = proof
(ROOT / "data/deployment.json").write_text(json.dumps(deployment, indent=2) + "\n")
print("Native INI rename, outgoing/incoming friend lifecycle and empty handoff lists verified.")
