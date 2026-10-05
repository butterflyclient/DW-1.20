"""Provision the requested host/guest friendship through their native DW tasks.

Run before either game signs in. Login replaces each account's prior session.
No relationship database is edited directly and no identity is impersonated.
"""

import json
from pathlib import Path
import struct
import urllib.error
import urllib.request

from native_wire_client import NativeClient, binary, integer, text, u32

ROOT = Path(__file__).resolve().parents[1]
network = json.loads((ROOT / "data/network.json").read_text())
profile = "remote-test-1"
key = network["clients"][profile]


def request(owner, target):
    params = (
        integer(1, 1)
        + integer(2, 0)
        + integer(3, 1)
        + integer(100, 10000)
        + binary(200, bytes(256))
        + text(300, "Friends")
        + text(301, "invite_friend")
    )
    message = (
        binary(1, params)
        + integer(2, 1)
        + integer(10, 0x504F5354)
        + text(11, f"/v1/friends/uno-{owner}/invitation/?context=cod-shared")
        + text(101, "friends")
        + integer(102, 1)
        + integer(302, 1)
    )
    body = json.dumps({"users": [{"userID": target, "accountType": "uno"}]}).encode()
    blob = lambda value: b"\x13" + u32(len(value)) + value
    return u32(713) + blob(message) + b"\x01\x01" + blob(body)


# Deliberately supplied invalid credentials must fail even on loopback.
try:
    urllib.request.urlopen(
        urllib.request.Request(
            f"http://127.0.0.1:8085/platform/login/{profile}",
            bytes(32),
            headers={"X-Replay-Access": "0" * 64},
        ),
        timeout=5,
    )
    raise RuntimeError("Invalid guest access key was accepted")
except urllib.error.HTTPError as error:
    assert error.code == 403

with NativeClient(ROOT) as host, NativeClient(
    ROOT, profile=profile, access_key=key
) as guest:
    assert host.user != guest.user
    for sender, receiver in ((host, guest), (guest, host)):
        result = sender.task(
            255, 10, request(sender.user, receiver.user), structured=False
        )
        assert result.startswith(u32(713))
    receipt = {
        "schema": 1,
        "host_user": host.user,
        "guest_user": guest.user,
        "profile": profile,
        "native_tasks_completed": True,
        "actual_remote_gameplay_verified": False,
    }
    (ROOT / "data/remote-friend-preparation.json").write_text(
        json.dumps(receipt, indent=2) + "\n"
    )
    print(
        "Native host/guest reciprocal invitations completed; distinct identities verified."
    )
