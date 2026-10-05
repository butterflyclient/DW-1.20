"""Pin the provisioned local RSA key in the private DW compilation source."""

import hashlib
import json
from pathlib import Path
import struct

root = Path(__file__).resolve().parents[1]
blob = (root / "data" / "platform-public.blob").read_bytes()
magic, bits, exponent_length, modulus_length, p, q = struct.unpack_from("<6I", blob)
if (magic, bits, exponent_length, modulus_length, p, q) != (
    0x31415352,
    2048,
    3,
    256,
    0,
    0,
):
    raise RuntimeError(
        "Platform key is not a 2048-bit RSA public key with exponent 65537"
    )
if len(blob) != 283 or blob[24:27] != b"\x01\x00\x01":
    raise RuntimeError("Platform public blob is malformed")
header = root / "integration" / "replay" / "dw_local_trust.h"
body = ", ".join("0x%02x" % b for b in blob)


def tlv(tag, data):
    length = len(data)
    encoded = (
        bytes([length])
        if length < 128
        else (
            b"\x81" + bytes([length])
            if length < 256
            else b"\x82" + length.to_bytes(2, "big")
        )
    )
    return bytes([tag]) + encoded + data


modulus = blob[27:]
if modulus[0] & 128:
    modulus = b"\0" + modulus
der = tlv(
    0x30,
    bytes.fromhex("300d06092a864886f70d0101010500")
    + tlv(3, b"\0" + tlv(0x30, tlv(2, modulus) + tlv(2, blob[24:27]))),
)
assert len(der) == 294
(root / "data" / "platform-public.der").write_bytes(der)
header.write_text(
    "#pragma once\n// Provisioned local public key; private key remains in server data.\n"
    "[[maybe_unused]] static const unsigned char s_dwLocalPlatformPublicKey[] = {"
    + body
    + "};\n"
    "[[maybe_unused]] static const unsigned char s_dwLocalAuthDer[] = {"
    + ", ".join("0x%02x" % b for b in der)
    + "};\n"
)
(root / "data" / "platform-trust.json").write_text(
    json.dumps(
        {
            "schema": 1,
            "algorithm": "RSA-PSS/SHA256",
            "bits": bits,
            "salt_bytes": 32,
            "public_blob_sha256": hashlib.sha256(blob).hexdigest(),
            "header": str(header),
            "header_sha256": hashlib.sha256(header.read_bytes()).hexdigest(),
        },
        indent=2,
    )
    + "\n"
)
print("Compiled platform trust pinned:", hashlib.sha256(blob).hexdigest())
