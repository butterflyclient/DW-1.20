"""Read the complete native event-67 player progression notification."""

import json

from native_wire_client import u32, u64


def reward(client, xp, context="5800", reason="inProgress"):
    kind, packet = (2, client.pushes.pop(0)) if client.pushes else client.receive()
    prefix = u32(67) + u64(1) + u64(client.user)
    prefix += b"\x10uno\0\x10" + context.encode() + b"\0"
    prefix += b"\x07\x01\0\0\0" + u32(1) + b"\x07\x01\0\0\0\x10"
    assert kind == 2 and packet.startswith(prefix) and packet[-1] == 0
    event = json.loads(packet[len(prefix):-1])
    assert event["type"] == "achievement" and event["name"] == "player_xp"
    assert event["id_"] == 1000000 and event["reason"] == reason
    assert event["multiProgress"]["xp"]["value"] == xp
    return event
