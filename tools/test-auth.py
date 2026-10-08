"""Signed native auth response, credential rejection and exact ticket offsets."""

import base64
import hashlib
import json
import os
from pathlib import Path
import struct
import time
import urllib.error
import urllib.request
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

root = Path(__file__).resolve().parents[1]
base = os.environ.get("IW8_DW_TEST_BASE", "http://127.0.0.1:8085")
server = Path(os.environ.get("IW8_DW_TEST_SERVER", str(root / "build/Release/iw8-dw-server.exe")))
proof_directory = Path(os.environ.get("IW8_DW_TEST_PROOF_DIRECTORY", str(root / "data")))
nonce = os.urandom(32)
with urllib.request.urlopen(
    urllib.request.Request(base + "/platform/login", nonce), timeout=5
) as response:
    platform = response.read()
extra = {
    "session_token": platform[112:176].decode(),
    "account_token": platform[177:241].decode(),
    "extended_data": True,
}
request = {
    "auth_task": 84,
    "iv_seed": 123456,
    "title_id": 5311,
    "identity": "356c4bc3",
    "extra_data": json.dumps(extra),
}


def post(value):
    return urllib.request.urlopen(
        urllib.request.Request(
            base + "/auth/",
            json.dumps(value).encode(),
            {"Content-Type": "application/json"},
        ),
        timeout=5,
    )


with post(request) as response:
    raw = response.read()
    signature = base64.b64decode(response.headers["X-Signature"], validate=True)
public = load_der_public_key((root / "data" / "platform-public.der").read_bytes())
public.verify(
    signature,
    raw,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=0),
    hashes.SHA256(),
)
try:
    public.verify(
        signature,
        raw + b" ",
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=0),
        hashes.SHA256(),
    )
except InvalidSignature:
    pass
else:
    raise AssertionError("Modified auth bytes accepted")
reply = json.loads(raw)
assert reply["auth_task"] == 85 and reply["code"] == 700 and reply["iv_seed"] == 123456
assert reply["loginqueue_enabled"] is False
ticket = base64.b64decode(reply["client_ticket"], validate=True)
server_ticket = base64.b64decode(reply["server_ticket"], validate=True)
assert len(ticket) == len(server_ticket) == 128 and len(raw) < 5120
assert struct.unpack_from("<I", ticket, 0)[0] == 0xEFBDADDE
assert struct.unpack_from("<I", ticket, 5)[0] == 5311
assert (
    struct.unpack_from("<Q", ticket, 25)[0] == struct.unpack_from("<Q", platform, 56)[0]
)
assert ticket[33:97].split(b"\0")[0] == platform[72:108].split(b"\0")[0]
assert any(ticket[97:121])
assert json.loads(reply["extra_data"])["extended_data"]
native_strings = {**request, "auth_task": "84", "iv_seed": "123456", "title_id": "5311"}
with post(native_strings) as response:
    assert json.load(response)["code"] == 700
bad = dict(request)
bad["extra_data"] = json.dumps({**extra, "session_token": "0" * 64})
for invalid in (bad, {**request, "auth_task": 46}, {**request, "extra_data": "{}"}):
    try:
        post(invalid)
    except urllib.error.HTTPError as error:
        assert error.code == 400
    else:
        raise AssertionError("Invalid auth request accepted")
receipt = {
    "schema": 1,
    "passed": True,
    "native_game_acceptance": "separate live runtime gate",
    "checks": [
        "RSA-PSS-SHA256 zero-salt signature",
        "changed bytes rejected",
        "request/reply task IDs",
        "exact 128-byte native PC ticket",
        "identity binding",
        "random 24-byte session key",
        "bounded native auth reply",
        "native decimal-string numeric fields",
        "invalid credentials rejected",
        "unsupported platform rejected",
    ],
    "server_sha256": hashlib.sha256(
        server.read_bytes()
    ).hexdigest(),
    "public_der_sha256": hashlib.sha256(
        (root / "data" / "platform-public.der").read_bytes()
    ).hexdigest(),
}
(proof_directory / "auth-verification.json").write_text(
    json.dumps(receipt, indent=2) + "\n"
)
print(
    "PASS: signed auth response, native ticket layout and credential rejection; credentials not logged"
)
