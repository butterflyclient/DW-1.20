"""Read only signed session-store metadata; never export credentials or keys."""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import remote_backend

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--user", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    assert output.is_relative_to(ROOT)
    before = remote_backend.verify()
    with remote_backend.connect() as client:
        with client.open_sftp() as sftp:
            path = "/var/lib/replay-dw/platform-sessions.bin"
            size = sftp.stat(path)
            assert 272 <= size.st_size <= 2 * 1024 * 1024
            assert size.st_mode & 0o077 == 0
            raw = sftp.open(path, "rb").read()
            public = sftp.open("/var/lib/replay-dw/platform-public.blob", "rb").read()
    after = remote_backend.verify()
    assert before == after, "Server process changed during this read"
    magic, version, count = struct.unpack_from("<8sII", raw)
    assert magic == b"RPSES001" and version == 1 and len(raw) == 16 + count + 256
    key_magic, bits, es, ns, _, _ = struct.unpack_from("<6I", public)
    assert key_magic == 0x31415352 and bits == 2048
    e = int.from_bytes(public[24 : 24 + es], "big")
    n = int.from_bytes(public[24 + es : 24 + es + ns], "big")
    rsa.RSAPublicNumbers(e, n).public_key().verify(
        raw[-256:],
        raw[:-256],
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    rows = json.loads(raw[16:-256])
    entries = []
    for row in rows:
        payload = base64.b64decode(row["payload"], validate=True)
        assert len(payload) == 256
        user = struct.unpack_from("<Q", payload, 56)[0]
        if user != args.user:
            continue
        entries.append(
            dict(
                user=user,
                issued=struct.unpack_from("<Q", payload, 40)[0],
                expires=struct.unpack_from("<Q", payload, 48)[0],
                title=row["title"],
                seed=row["seed"],
                native_key_sha256=hashlib.sha256(
                    base64.b64decode(row["key"], validate=True)
                ).hexdigest(),
                native_ticket_sha256=hashlib.sha256(
                    base64.b64decode(row["ticket"], validate=True)
                ).hexdigest(),
                platform_session_token_sha256=hashlib.sha256(
                    payload[112:176]
                ).hexdigest(),
                legacy_token_sha256=hashlib.sha256(
                    row["umbrella"].encode()
                ).hexdigest(),
                legacy_grant_present=bool(row["umbrella"]),
                uno_grants_present=all(
                    bool(row[field])
                    for field in ("uno_id", "uno_access", "uno_refresh")
                ),
            )
        )
    assert entries, "Native owner's session was not persisted"
    proof = dict(
        schema=1,
        observed_utc=datetime.now(timezone.utc).isoformat(),
        server=after,
        signature_verified=True,
        private_file_permissions_verified=True,
        store_sha256=hashlib.sha256(raw).hexdigest(),
        store_size=len(raw),
        owner=args.user,
        sessions=entries,
        audit_tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    )
    output.write_text(json.dumps(proof, indent=2) + "\n", newline="\n")
    print(
        f"Verified signed private store for {len(entries)} owner session(s); credentials remain on the server"
    )


if __name__ == "__main__":
    main()
