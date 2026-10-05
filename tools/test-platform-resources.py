"""Real signed provider response, native-handle wire fields and resource codec."""

import ctypes
import hashlib
import json
import os
from pathlib import Path
import struct
import time
import urllib.error
import urllib.request
import zlib

root = Path(__file__).resolve().parents[1]
verify = ctypes.CDLL(
    str(root / "build/Release/iw8-dw-platform-client.dll")
).DW_LocalPlatform_VerifyResourceReply
verify.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64)
verify.restype = ctypes.c_bool
request = os.urandom(32) + struct.pack("<IIII", 16974, 0x61706674, 0, 1)


def exchange(body):
    return urllib.request.urlopen(
        urllib.request.Request("http://127.0.0.1:8085/platform/resource", body),
        timeout=5,
    )


with exchange(request) as response:
    data = response.read()
now = int(time.time())
assert len(data) == 4688 and verify(data, request, now)
assert not verify(data, os.urandom(32) + request[32:], now)
assert not verify(data, request, now + 3601)
for offset in (56, 80, 336, 4432):
    changed = bytearray(data)
    changed[offset] ^= 1
    assert not verify(
        bytes(changed), request, now
    ), f"Changed signed resource accepted at {offset}"
for body in (
    request[:-1],
    bytes(48),
    request[:32] + struct.pack("<IIII", 1, 0x61706674, 0, 1),
    request[:32] + struct.pack("<IIII", 16974, 1, 0, 1),
):
    try:
        with exchange(body):
            raise AssertionError("Malformed/unsupported resource key accepted")
    except urllib.error.HTTPError as error:
        assert error.code == 400
handle_length, content_length = struct.unpack_from("<II", data, 72)
handle, content = data[80 : 80 + handle_length], data[336 : 336 + content_length]
assert handle[:10] == b"\x0d\x01\0\0\0\x15tfpa"
assert (
    handle[10:12] == b"\x1a\x20" and handle[12:44] == hashlib.sha256(content).digest()
)
assert handle[44] == 0x22 and handle[45] < 128 and len(handle) == 46 + handle[45]
url = handle[46:].decode("ascii")
assert url.startswith("http://127.0.0.1:8085/platform/resources/")
assert content[:8] == b"ZpmC\0\0\0\0"
decoded = zlib.decompress(content[16:])
assert len(decoded) == struct.unpack_from("<Q", content, 8)[0]
with urllib.request.urlopen(url, timeout=5) as response:
    assert response.read() == content
try:
    urllib.request.urlopen(url + "?wrong", timeout=5)
    raise AssertionError("Unknown immutable resource accepted")
except urllib.error.HTTPError as error:
    assert error.code == 404
receipt = {
    "schema": 1,
    "passed": True,
    "server_sha256": hashlib.sha256(
        (root / "build/Release/iw8-dw-server.exe").read_bytes()
    ).hexdigest(),
    "crypto_source_sha256": hashlib.sha256(
        (root / "integration/replay/DW_LocalPlatformCrypto.cpp").read_bytes()
    ).hexdigest(),
    "method": "actual game-side CNG verifier DLL; real resource provider; zlib decode and SHA256 native DTO checks",
    "checks": [
        "nonce and signature",
        "expiry",
        "modified metadata/content/signature rejected",
        "unsupported/malformed key rejected",
        "native ResourceHandle fixed32 region/usage and SHA256 fields",
        "immutable content URL",
        "ZpmC/zlib decoded length",
    ],
    "native_filter_compilation_verified": False,
    "resource_sha256": hashlib.sha256(content).hexdigest(),
    "decoded_bytes": len(decoded),
}
(root / "data/platform-resource-verification.json").write_text(
    json.dumps(receipt, indent=2) + "\n"
)
print(
    "PASS: signed platform resource, native handle wire layout, hash, codec and rejection paths"
)
