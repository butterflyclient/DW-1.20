"""Record exact native clan cache results after removing the receipted test group."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

root = Path(__file__).resolve().parents[1]
data = root / "data"
receipt = json.loads((data / "native-clan-push-test.json").read_text())
assert receipt["temporary_test_clan"] and receipt["removed"]
group, target = receipt["clan_id"], receipt["target"]
names = [
    "runtime-clan-member-read-active.json",
    "runtime-clan-member-renamed.json",
    "runtime-clan-member-promoted-complete.json",
    "runtime-clan-member-demoted.json",
    "runtime-clan-member-removed.json",
    "runtime-clan-current-withdraw-invited.json",
    "runtime-clan-current-withdrawn.json",
    "runtime-clan-current-cleaned.json",
]
observations = [json.loads((data / name).read_text()) for name in names]
for observation in observations:
    assert observation["sha256"] == receipt["game_sha256"]
    assert observation["native_dw_hsm_connected_state_33"]
    assert observation["native_profile_sign_in_state"] == 2
for observation in observations[:4]:
    (clan,) = observation["native_active_clans"]
    assert clan["clan_id"] == group and clan["native_activation_complete"]
    if "member_count" in clan:
        assert clan["member_count"] == 2
        assert {member["user"] for member in clan["members"]} == {
            target,
            receipt["user"],
        }
assert observations[1]["native_active_clans"][0]["name"] == "DW Clan Push Updated"
for observation, expected in zip(observations[2:4], (2, 1)):
    assert (
        next(
            member["role"]
            for member in observation["native_active_clans"][0]["members"]
            if member["user"] == target
        )
        == expected
    )
for observation in (observations[4], observations[6], observations[7]):
    assert not observation["native_active_clans"]
    assert all(row["channel_id"] != group for row in observation["native_joined_chats"])
assert observations[5]["native_clan_invitations"][0]["entries"][0]["clan_id"] == group
assert not observations[6]["native_clan_invitations"][0]["entries"]
assert not observations[7]["native_clan_invitations"][0]["entries"]
screens = []
for name in (
    "native-clan-member-read-active.jpg",
    "native-clan-member-promoted.jpg",
    "native-clan-member-removed.jpg",
):
    capture = json.loads((data / (name + ".json")).read_text(encoding="utf-8-sig"))
    screens.append(
        dict(
            file=name,
            sha256=hashlib.sha256((data / name).read_bytes()).hexdigest(),
            capture=capture,
        )
    )
proof = dict(
    schema=1,
    recorded_utc=datetime.now(timezone.utc).isoformat(),
    game_sha256=receipt["game_sha256"],
    server_sha256=receipt["server_sha256"],
    temporary_clan=receipt,
    native_game_verified=True,
    full_backend_verified=False,
    observations=[
        dict(file=name, sha256=hashlib.sha256((data / name).read_bytes()).hexdigest())
        for name in names
    ],
    screenshots=screens,
    verified=[
        "Native UI invitation acceptance followed by state-4 activation and roster",
        "Group-update push changes native cached name",
        "Role pushes change native member role from 1 to 2 and back to 1",
        "Removal clears native active clan and its joined data/chat channel",
        "Invitation creation/withdrawal change native cache from one entry to zero",
        "Authenticated exact-group cleanup leaves no test membership/invitation",
    ],
    scope="Clan feature acceptance only; no map tests or forced game states",
)
(data / "native-clan-lifecycle-verification.json").write_text(
    json.dumps(proof, indent=2) + "\n"
)
print(
    "Native clan lifecycle verified and cleanup recorded under the original backend/game hashes"
)
