"""Controlled peer invitation for the verified native game, via real DW tasks.

Uses the separately provisioned 'native-social' identity; never signs in as the
running game's account. 'remove' retires only that peer's relationship. 'lobby'
supports the native invitation handshake without supplying a game/DTLS server.
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import struct
import socket
import os
import time
from datetime import datetime, timezone
from native_wire_client import NativeClient, binary, integer, text, u32, u64

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("action", choices=("invite", "remove", "online", "lobby"))
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


test_lobby = None
with NativeClient(root, profile="native-social") as client:
    if client.user != peer:
        raise RuntimeError("Issuer selected an unexpected identity")
    base = f"/v1/friends/uno-{peer}/"
    if args.action in ("invite", "online", "lobby"):
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
    if args.action in ("online", "lobby"):
        if not 1 <= args.hold_seconds <= 300:
            raise ValueError("Hold duration must be 1..300 seconds")
        if args.action == "lobby":
            # This peer exercises native lobby documents, not a game host.
            # Bind a real unused loopback endpoint; deliberately do not emulate
            # the game/DTLS protocol or claim playable two-game validation.
            endpoint = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            endpoint.bind(("127.0.0.1", 0))
            port = endpoint.getsockname()[1]
            # Same serializer as the verified local QoS provider: six IPv4/LE
            # port pairs, NAT/platform, then versioned empty relay join data.
            address = (bytes([127, 0, 0, 1]) + struct.pack("<H", port)) * 6
            address += b"\x01" + struct.pack("<I", 101) + b"\x01" + bytes(42)
            assert len(address) == 84
            info = {
                "dedicated_server": {"build_name": "replay-native-join-validation"},
                "listen_server": {
                    "local_address": base64.b64encode(address).decode(),
                    "security_id": base64.b64encode(os.urandom(8)).decode(),
                    "security_key": base64.b64encode(os.urandom(16)).decode(),
                },
                "game_state": {"map_packs": ["MP_ORIGINAL_MAPS"]},
                "hardware": "pc",
            }
            # Exact Replay consumer 14106E1E0: 21-byte join header, 84-byte
            # address, then security key before security ID (not struct order).
            join_session = (
                address
                + base64.b64decode(info["listen_server"]["security_key"])
                + base64.b64decode(info["listen_server"]["security_id"])
            )
            client.task(
                145, 2, b"\x10" + json.dumps(info).encode() + b"\0", structured=False
            )
            token = struct.unpack_from(
                "<Q", client.task(145, 3, b"", structured=False), 1
            )[0]
            catalog = json.loads(
                (root / "data/playlists/5800/catalog.json").read_bytes()
            )
            playlist = next(
                row
                for row in catalog["playlists"]
                if any(entry["map"] == "mp_shipment" for entry in row["maps"][:20])
            )
            query = {
                "members": [peer],
                "tokens": [token],
                "lobby_slots": {"min": 1, "max": 2},
                "ruleset_payload": {
                    "filter": {
                        "playlist_id": playlist["playlist"],
                        "netcode_version": 1,
                        "playlist_version": catalog["system"]["version"],
                    }
                },
            }
            client.task(
                145, 18, b"\x10" + json.dumps(query).encode() + b"\0", structured=False
            )
            kind, created = client.receive()
            if kind != 2 or not created.startswith(u32(2005)):
                raise RuntimeError(
                    "Validation peer did not receive its native lobby assignment"
                )
            lobby = struct.unpack_from("<Q", created, 15)[0]
            test_lobby = {
                "id": lobby,
                "peer": peer,
                "port": port,
                "game_host": False,
                "map_launched": False,
                "join_info_responses": 0,
            }
            (root / "data/native-presence-join-peer.json").write_text(
                json.dumps(test_lobby, indent=2) + "\n"
            )
            print(
                "Validation peer lobby assigned; it is a document/handshake test, not a game host",
                flush=True,
            )
        # Same-Replay presence schema, using this signed peer's own platform ID.
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
        try:
            deadline = time.monotonic() + args.hold_seconds
            while time.monotonic() < deadline:
                client.socket.settimeout(1)
                try:
                    kind, packet = client.receive()
                    if test_lobby and kind == 2 and packet.startswith(u32(21)):
                        assert packet[5] == 10 and packet[14] == 16
                        sender = struct.unpack_from("<Q", packet, 6)[0]
                        end = packet.index(0, 15)
                        offset = end + 1
                        assert packet[offset : offset + 2] == b"\x13\x08"
                        size = struct.unpack_from("<I", packet, offset + 2)[0]
                        message = packet[offset + 6 :]
                        assert len(message) == size
                        if sender == target and message == b"INV:\0\0":
                            join_info = (
                                bytes([2, 1, 4])
                                + struct.pack("<QQ", test_lobby["id"], 0)
                                + bytes([0, 1])
                                + join_session
                            )
                            assert len(join_info) == 129
                            # Same target 140F1E480: INV:\0, response type 1,
                            # success byte, UInt16 length, full session payload.
                            response = (
                                b"INV:\0\x01\x01"
                                + struct.pack("<H", len(join_info))
                                + join_info
                            )
                            client.task(
                                6, 14, u64(target) + blob(response), structured=False
                            )
                            test_lobby["join_info_responses"] += 1
                            (root / "data/native-presence-join-peer.json").write_text(
                                json.dumps(test_lobby, indent=2) + "\n"
                            )
                            print(
                                "Answered the native game session-info request with this peer's own assigned lobby",
                                flush=True,
                            )
                except TimeoutError:
                    pass
        finally:
            if test_lobby:
                client.socket.settimeout(5)
                try:
                    client.task(145, 10, u64(test_lobby["id"]), structured=False)
                    test_lobby["disband_requested"] = True
                    (root / "data/native-presence-join-peer.json").write_text(
                        json.dumps(test_lobby, indent=2) + "\n"
                    )
                finally:
                    endpoint.close()
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
    "method": "Separately issued signed local identity and encrypted Replay social/matchmaking/instant-message tasks; native acceptance requires game observation",
    "native_game_verified": False,
    "temporary_relationship_removed": args.action == "remove",
    "test_lobby": test_lobby,
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
        "lobby": "completed its controlled lobby-document session",
    }[args.action]
    + " through the native task API"
)
