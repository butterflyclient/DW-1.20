"""Controlled peer invitation for the verified native game, via real DW tasks.

Uses the separately provisioned 'native-social' identity; never signs in as the
running game's account. 'remove' retires only that peer's relationship.
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import struct
import time
from datetime import datetime, timezone
from native_wire_client import NativeClient, binary, integer, text, u32

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("action", choices=("invite", "remove", "online"))
parser.add_argument("--hold-seconds", type=int, default=120)
args = parser.parse_args()
context = "cod-shared"  # Actual Replay Friends calls use this shared-game scope.
deployment = json.loads((root / "data/deployment.json").read_text())
image = Path(deployment["executable"])
if hashlib.sha256(image.read_bytes()).hexdigest() != deployment["sha256"]:
    raise RuntimeError("Native game deployment changed")
target = struct.unpack_from("<Q", (root / "data/platform-profile.bin").read_bytes(), 8)[
    0
]
profile = root / "data/platform-profiles/native-social.bin"
peer_bytes = profile.read_bytes()
if len(peer_bytes) != 56 or peer_bytes[20:56].split(b"\0")[0] != b"DWBackendValidation":
    raise RuntimeError("Validation peer profile does not match its label")
peer = struct.unpack_from("<Q", peer_bytes, 8)[0]
if peer == target:
    raise RuntimeError("Validation identity must differ from game account")


def blob(value):
    return b"\x13" + u32(len(value)) + value


def request(service, operation, method, uri, body=None):
    resource = "UserPresence" if service == "presence" else "Friends"
    params = (
        integer(1, 1)
        + integer(2, 0)
        + integer(3, 1)
        + integer(100, 10000)
        + binary(200, bytes(256))
        + text(300, resource)
        + text(301, operation)
    )
    message = (
        binary(1, params)
        + integer(2, 1)
        + integer(10, method)
        + text(11, uri)
        + text(101, service)
        + integer(102, 1)
        + integer(302, 1)
    )
    value = b"" if body is None else json.dumps(body).encode()
    return u32(713) + blob(message) + b"\x01" + bytes([body is not None]) + blob(value)


with NativeClient(root, profile="native-social") as client:
    if client.user != peer:
        raise RuntimeError("Issuer selected an unexpected identity")
    base = f"/v1/friends/uno-{peer}/"
    if args.action in ("invite", "online"):
        raw = client.task(
            255,
            10,
            request(
                "friends",
                "invite_friend",
                0x504F5354,
                base + "invitation/?context=" + context,
                {"users": [{"userID": target, "accountType": "uno"}]},
            ),
            structured=False,
        )
    else:
        raw = client.task(
            255,
            10,
            request(
                "friends",
                "reject_friend_request",
                0x44454C45,
                base + f"uno-{target}/?context=" + context,
            ),
            structured=False,
        )
    if not raw.startswith(u32(713)):
        raise RuntimeError("Native REST result version mismatch")
    if args.action == "online":
        if not 1 <= args.hold_seconds <= 300:
            raise ValueError("Hold duration must be 1..300 seconds")
        # Same-Replay native frontend presence schema, observed from the game.
        # Use this signed peer's own platform ID and no joinable session flags.
        presence_data = {
            "clanTag": "",
            "context": 4,
            "flags": 0,
            "gametype": 0,
            "inputType": 2,
            "mapindex": 0,
            "platformId": base64.b64encode(
                struct.pack("<Q", struct.unpack_from("<I", peer_bytes, 16)[0])
            ).decode(),
            "sessionFlags": 0,
            "version": 8,
        }
        for scope in ("iw8", "cod-shared"):
            client.task(
                255,
                10,
                request(
                    "presence",
                    "set_user_presence",
                    0x505554,
                    f"/v2/users/uno-{peer}/presence/?context=" + scope,
                    {"online": True, "platform": "bnet", "data": presence_data},
                ),
                structured=False,
            )
        print(
            f"Validation peer is online for {args.hold_seconds} seconds; default game session is untouched",
            flush=True,
        )
        deadline = time.monotonic() + args.hold_seconds
        while time.monotonic() < deadline:
            client.socket.settimeout(1)
            try:
                client.receive()
            except TimeoutError:
                pass
receipt = {
    "schema": 1,
    "action": args.action,
    "context": context,
    "target": target,
    "peer": peer,
    "peer_profile": "native-social",
    "name": "DWBackendValidation",
    "game_sha256": deployment["sha256"],
    "server_sha256": deployment["server_sha256"],
    "utc": datetime.now(timezone.utc).isoformat(),
    "method": "Separately issued signed local identity and encrypted Replay task 255/10; native acceptance requires game observation",
    "native_game_verified": False,
    "temporary_relationship_removed": args.action == "remove",
}
history = root / "data/native-social-history"
history.mkdir(exist_ok=True)
latest = root / "data" / f"native-social-{args.action}.json"
if latest.exists():
    old = latest.read_bytes()
    (history / f"{time.time_ns()}-previous-{args.action}.json").write_bytes(old)
encoded = json.dumps(receipt, indent=2) + "\n"
(history / f"{time.time_ns()}-{args.action}.json").write_text(encoded)
latest.write_text(encoded)
print(
    "Validation peer "
    + {
        "invite": "invited the running game account",
        "remove": "removed its temporary invitation/relationship",
        "online": "completed its controlled online session",
    }[args.action]
    + " through the native task API"
)
