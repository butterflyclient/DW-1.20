"""Save this run's native Social evidence, preserving earlier game/server hashes."""

import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
data = root / "data"
receipt = json.loads((data / "native-social-online.json").read_text())
removal = json.loads((data / "native-social-remove.json").read_text())
names = [
    "runtime-native-presence-peer-online.json",
    "runtime-native-presence-peer-offline.json",
    "runtime-native-presence-peer-removed.json",
]
observations = [json.loads((data / name).read_text()) for name in names]
peer = receipt["peer"]
for observation in observations:
    assert observation["sha256"] == receipt["game_sha256"]
    assert (
        observation["native_dw_hsm_connected_state_33"]
        and observation["native_profile_sign_in_state"] == 2
    )
for observation in observations[:2]:
    assert any(
        row["list_index"] == 0
        and any(entry["user"] == peer for entry in row["entries"])
        for row in observation["native_crossplay_friend_lists"]
    )
assert all(
    entry["user"] != peer
    for row in observations[2]["native_crossplay_friend_lists"]
    for entry in row["entries"]
)
assert (
    receipt["game_sha256"] == removal["game_sha256"]
    and receipt["server_sha256"] == removal["server_sha256"]
)
screens = []
for name in [
    "native-social-peer-online-20261005.jpg",
    "native-social-peer-offline-20261005.jpg",
]:
    capture = json.loads((data / (name + ".json")).read_text(encoding="utf-8-sig"))
    screens.append(
        {
            "file": name,
            "sha256": hashlib.sha256((data / name).read_bytes()).hexdigest(),
            "capture": capture,
        }
    )
receipt.update(
    native_game_verified=True,
    temporary_relationship_removed=True,
    observations=names,
    screenshots=screens,
    native_evidence="Native Social visually inspected: Online 1/1 while peer connected, then Online 0/1 without closing Social; cache retained the friend until revocation removed it",
)
removal.update(native_game_verified=True, removal_observation=names[2])
for name, value in [
    ("native-presence-proof.json", receipt),
    ("native-social-remove.json", removal),
]:
    (data / name).write_text(json.dumps(value, indent=2) + "\n")
print(
    "Native online/offline Social and temporary friendship removal recorded with original hashes"
)
