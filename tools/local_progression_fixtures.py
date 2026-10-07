"""Nonce-signed local XP restore, INI rank selection and legacy login checks."""

import os
import struct
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from native_wire_client import NativeClient, fields, integer, structure, text


def exercise(root, data, offset, checks):
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_numbers()
    blob = struct.pack("<II", 0x31534345, 32)
    blob += public.x.to_bytes(32, "big") + public.y.to_bytes(32, "big")
    name = b"Local XP Signature Fixture".ljust(36, b"\0")
    url = f"http://127.0.0.1:{8085 + offset}"

    def post(path, body):
        with urllib.request.urlopen(urllib.request.Request(url + path, body), timeout=5) as response:
            return response.read()

    def login(version=2, user=0, xp=0, rank=0, restore=False):
        nonce = os.urandom(32)
        challenge = post("/platform/client/challenge", blob + nonce)
        prefix = struct.pack("<II", 0x31494452, version) + nonce + challenge + blob + name
        if version == 2:
            prefix += struct.pack("<IQQII", int(restore), user, xp, rank, 0)
        r, s = utils.decode_dss_signature(key.sign(prefix, ec.ECDSA(hashes.SHA256())))
        return post("/platform/client/login", prefix + r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    def total(reply):
        with NativeClient(root, port_offset=offset, platform_reply=reply) as client:
            result = fields(client.task(125, 3, structure(
                text(1, "5800") + integer(3, 100) + text(4, "") + integer(8, 0))))
            row = next(fields(row) for row in result[1] if fields(row)[11] == [1000000])
            progress = {fields(p)[1][0].decode(): fields(p)[2][0] for p in row[10]}
            return client.user, progress

    user, value = total(login(rank=5))
    assert value == {"xp": 15000, "rank": 4}
    _, value = total(login(user=user, xp=17500, restore=True))
    assert value == {"xp": 17500, "rank": 4}
    _, value = total(login(version=1))
    assert value == {"xp": 17500, "rank": 4}
    path = data / "achievements/5800/5800" / str(user) / "events.json"
    before = path.read_bytes()
    try:
        login(user=user + 1, xp=999999, restore=True)
        raise AssertionError("Foreign local progression accepted")
    except urllib.error.HTTPError as error:
        assert error.code in (400, 401)
    assert path.read_bytes() == before
    checks.append("signed machine login restores locally owned XP and selects Replay rank, retains legacy login compatibility, and rejects another identity's progression")
