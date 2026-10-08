"""Exercise the actual game crypto source against issued server responses."""

import ctypes
import hashlib
import json
import os
import os
from pathlib import Path
import struct
import time
import urllib.request

root = Path(__file__).resolve().parents[1]
base = os.environ.get("IW8_DW_TEST_BASE", "http://127.0.0.1:8085")
server = Path(os.environ.get("IW8_DW_TEST_SERVER", str(root / "build/Release/iw8-dw-server.exe")))
client_dll = Path(os.environ.get("IW8_DW_TEST_CLIENT_DLL", str(root / "build/Release/iw8-dw-platform-client.dll")))
proof_directory = Path(os.environ.get("IW8_DW_TEST_PROOF_DIRECTORY", str(root / "data")))
library = ctypes.CDLL(str(client_dll))
verify = library.DW_LocalPlatform_VerifyReply
verify.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64)
verify.restype = ctypes.c_bool
validate = library.DW_LocalPlatform_ValidatePayload
validate.argtypes = verify.argtypes
validate.restype = ctypes.c_bool
nonce = os.urandom(32)
request = urllib.request.Request(
    base + "/platform/login",
    nonce,
    {"Content-Type": "application/octet-stream"},
)
with urllib.request.urlopen(request, timeout=5) as response:
    data = response.read()
assert len(data) == 512
now = int(time.time())
assert verify(data, nonce, now), "Game crypto rejected an issued server session"
assert (
    struct.unpack_from("<I", data, 4)[0] == 2
    and data[242] == 21
    and data[243] == 0
    and struct.unpack_from("<I", data, 244)[0] == 1
)
assert not verify(data, os.urandom(32), now), "Wrong nonce was accepted"
assert not verify(data, nonce, now + 3601), "Expired session was accepted"
damaged = bytearray(data)
damaged[64] ^= 1
assert not verify(bytes(damaged), nonce, now), "Changed identity was accepted"
damaged = bytearray(data)
damaged[400] ^= 1
assert not verify(bytes(damaged), nonce, now), "Changed signature was accepted"
damaged = bytearray(data)
damaged[255] = 1
assert not validate(bytes(damaged), nonce, now), "Nonzero reserved data was accepted"
for offset in (242, 243, 244):
    damaged = bytearray(data)
    damaged[offset] = 255
    assert not validate(
        bytes(damaged), nonce, now
    ), "Invalid account policy was accepted"
damaged = bytearray(data)
damaged[112] = ord("!")
assert not validate(bytes(damaged), nonce, now), "Malformed token was accepted"
damaged = bytearray(data)
struct.pack_into("<Q", damaged, 48, now - 1)
assert not validate(bytes(damaged), nonce, now), "Expired payload was accepted"
nonce2 = os.urandom(32)
with urllib.request.urlopen(
    urllib.request.Request(base + "/platform/login", nonce2), timeout=5
) as response:
    second = response.read()
assert verify(second, nonce2, now)
assert data[56:108] == second[56:108], "Persistent player identity changed"
assert data[112:242] != second[112:242], "Session credentials were reused"
evidence = {
    "schema": 1,
    "passed": True,
    "method": "actual game-side crypto C++ compiled as a Windows DLL, real server signatures and CNG verification",
    "checks": [
        "valid signature",
        "wrong nonce rejected",
        "expiry rejected",
        "changed identity rejected",
        "changed signature rejected",
        "reserved data rejected",
        "token format rejected",
        "stable identity",
        "unique credentials",
        "signed account age/region/capability policy",
    ],
    "server_sha256": hashlib.sha256(
        server.read_bytes()
    ).hexdigest(),
    "crypto_source_sha256": hashlib.sha256(
        (root / "integration" / "replay" / "DW_LocalPlatformCrypto.cpp").read_bytes()
    ).hexdigest(),
    "public_key_sha256": hashlib.sha256(
        (root / "data" / "platform-public.blob").read_bytes()
    ).hexdigest(),
}
(proof_directory / "platform-verification.json").write_text(
    json.dumps(evidence, indent=2) + "\n"
)
print(
    "PASS: issued-session crypto, rejection paths and persistent identity; credentials not logged"
)
