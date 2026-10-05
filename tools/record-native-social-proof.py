"""Record native friend lifecycle proof only after verified engine observations."""

import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
invite = json.loads((root / "data/native-social-invite.json").read_text())
removal = json.loads((root / "data/native-social-remove.json").read_text())
accepted = json.loads((root / "data/runtime-native-friends-accepted.json").read_text())
removed = json.loads((root / "data/runtime-native-friends-removed.json").read_text())
peer = invite["peer"]
assert invite["context"] == removal["context"] == "cod-shared"
lists = accepted["native_crossplay_friend_lists"]
assert any(
    row["list_index"] == 0 and any(entry["user"] == peer for entry in row["entries"])
    for row in lists
)
assert all(
    entry["user"] != peer
    for row in removed["native_crossplay_friend_lists"]
    for entry in row["entries"]
)
assert accepted["sha256"] == removed["sha256"] == invite["game_sha256"]
invite.update(
    native_game_verified=True,
    acceptance_observation="runtime-native-friends-accepted.json",
    screenshot="native-friends-accepted-20261005.jpg",
    temporary_relationship_removed=True,
)
removal.update(
    native_game_verified=True, removal_observation="runtime-native-friends-removed.json"
)
for action, receipt in [("invite", invite), ("remove", removal)]:
    (root / "data" / f"native-social-{action}.json").write_text(
        json.dumps(receipt, indent=2) + "\n"
    )
print(
    "Native acceptance, friendship-revocation push and temporary relationship cleanup verified"
)
