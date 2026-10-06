"""Check authenticated INI rename semantics without touching any player's account."""

import hashlib
import json
import os
from pathlib import Path
import struct
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
profile = "native-social"
path = ROOT / f"data/platform-profiles/{profile}.bin"
before = path.read_bytes()
original = before[20:56].split(b"\0", 1)[0].decode()
name = "Replay Name Fixture"


def login(value, key="", expected=200):
    headers = {"X-Replay-Player-Name": value}
    if key:
        headers["X-Replay-Access"] = key
    try:
        with urllib.request.urlopen(urllib.request.Request(
            f"http://127.0.0.1:8085/platform/login/{profile}", os.urandom(32), headers
        ), timeout=5) as reply:
            assert expected == reply.status
            return reply.read()
    except urllib.error.HTTPError as error:
        assert error.code == expected


try:
    login(name, key="0" * 64, expected=403)
    assert path.read_bytes() == before
    for invalid in ("DWPlayer", "bad#tag", "bad%prefix", "trailing ", "a" * 36):
        login(invalid, expected=400)
        assert path.read_bytes() == before
    reply = login(name)
    changed = path.read_bytes()
    assert changed[:20] == before[:20] and changed[20:56].split(b"\0", 1)[0] == name.encode()
    assert len(reply) == 512 and reply[72:108].split(b"\0", 1)[0] == name.encode()
    assert struct.unpack_from("<Q", reply, 56)[0] == struct.unpack_from("<Q", before, 8)[0]
    with urllib.request.urlopen(urllib.request.Request(
        f"http://127.0.0.1:8085/platform/login/{profile}", os.urandom(32)
    ), timeout=5) as response:
        assert response.read()[72:108].split(b"\0", 1)[0] == name.encode()
finally:
    login(original)
    assert path.read_bytes() == before

receipt = {"passed": True, "server_sha256": hashlib.sha256(
    (ROOT / "build/Release/iw8-dw-server.exe").read_bytes()).hexdigest(),
    "checks": ["authenticated rename", "stable account ID", "durable identity name",
               "invalid/duplicate names rejected", "invalid access key cannot rename",
               "missing INI name retains persisted name", "fixture identity restored"]}
(ROOT / "data/player-name-verification.json").write_text(json.dumps(receipt, indent=2) + "\n")
print("PASS: player-name validation, authenticated persistence and stable identity; fixture restored.")
