"""Read the complete native event-67 player progression notification."""

import json
import struct

from native_wire_client import u32, u64


def decode_reward(packet, user=None):
    position = 0
    def number(tag, fmt):
        nonlocal position
        assert packet[position] == tag
        position += 1
        value = struct.unpack_from(fmt, packet, position)[0]
        position += struct.calcsize(fmt)
        return value
    def text():
        nonlocal position
        assert packet[position] == 16
        end = packet.index(0, position + 1)
        value = packet[position + 1:end].decode()
        position = end + 1
        return value
    assert number(8, "<I") == 67 and number(10, "<Q") == 1
    owner = number(10, "<Q")
    assert owner and (user is None or owner == user)
    assert text() == "uno"
    context = text()
    assert context in ("5800", "iw8")
    assert number(7, "<i") == 1 and number(8, "<I") == 1 and number(7, "<i") == 1
    event = json.loads(text())
    assert position == len(packet)
    assert event["type"] == "achievement" and event["name"] == "player_xp"
    assert event["id_"] == 1000000 and event["kind"] == 0
    assert event["reason"] in ("inProgress", "completed")
    for name in ("xp", "rank"):
        value = event["multiProgress"][name]["value"]
        assert type(value) is int and 0 <= value < 2**64
    return owner, context, event


def reward(client, xp, context="5800", reason="inProgress"):
    kind, packet = (2, client.pushes.pop(0)) if client.pushes else client.receive()
    assert kind == 2
    _, actual_context, event = decode_reward(packet, client.user)
    assert actual_context == context and event["reason"] == reason
    assert event["multiProgress"]["xp"]["value"] == xp
    return event
