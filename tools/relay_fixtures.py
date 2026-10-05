"""Independent Replay 145/26 reader and local issuer/verifier tests; no UDP claim."""

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import struct
import subprocess
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _expand(key, info, size):
    out = previous = b""
    for i in range(1, 256):
        previous = hmac.digest(key, previous + info + bytes([i]), "sha1")
        out += previous
        if len(out) >= size:
            return out[:size]
    raise AssertionError("HKDF bound")


def _native_blob(raw):
    assert len(raw) == 83 and raw[:2] == b"\x13\x08"
    assert struct.unpack_from("<I", raw, 2)[0] == 77
    token = raw[6:]
    assert token[0] == 1 and 0 < struct.unpack_from("<I", token, 73)[0] <= 3600
    return token


def _inspect(exe, directory, token, success=True):
    result = subprocess.run(
        [
            str(exe),
            str(directory),
            "--inspect-relay-client-token",
            base64.b64encode(token).decode(),
        ],
        capture_output=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
        timeout=5,
    )
    assert result.returncode == (0 if success else 2), (
        result.returncode,
        result.stderr,
    )
    if success:
        claims = json.loads(result.stdout)
        assert claims["valid"] and claims["active_session_checked"] is False
        assert claims["udp_transport_verified"] is False
        return claims
    if token:
        assert (
            token.hex().encode() not in result.stderr
            and base64.b64encode(token) not in result.stderr
        )


def exercise(client, peer, directory, exe, user, peer_user, checks):
    directory, exe = Path(directory), Path(exe)
    token = _native_blob(client.task(145, 26))
    key_file = directory / "relay/issuer-key.bin"
    key_bytes = key_file.read_bytes()
    assert len(key_bytes) == 72 and key_bytes[:8] == b"RPLYRLY\x01"
    assert hashlib.sha256(key_bytes[:40]).digest() == key_bytes[40:]
    key = key_bytes[8:40]
    opaque, delta = token[1:57], struct.unpack_from("<I", token, 73)[0]
    expected_mac = hmac.digest(
        _expand(key, b"replay-relay-client-mac-v1", 20),
        opaque[:40] + token[73:],
        "sha1",
    )[:16]
    assert hmac.compare_digest(opaque[40:], expected_mac)
    expected_secret = hmac.digest(
        _expand(key, b"replay-relay-client-secret-v1", 20), opaque, "sha1"
    )[:16]
    assert hmac.compare_digest(token[57:73], expected_secret)
    decrypt = Cipher(
        algorithms.AES(_expand(key, b"replay-relay-client-aes-v1", 16)),
        modes.CBC(opaque[:16]),
    ).decryptor()
    decoded = decrypt.update(opaque[16:32]) + decrypt.finalize()
    owner, title, expires = struct.unpack("<QII", decoded)
    assert (
        owner == user
        and title == 5800
        and time.time() < expires <= time.time() + delta + 1
    )
    proof = json.loads((directory / f"relay/{title}/clients/{user}.json").read_text())
    assert (
        proof["user"] == user
        and proof["title"] == title
        and proof["expires"] == expires
    )
    assert proof["native_wire_sha256"] == hashlib.sha256(token).hexdigest()
    assert proof["opaque_sha256"] == hashlib.sha256(opaque).hexdigest()
    assert proof["udp_transport_advertised"] is False
    assert "secret" not in proof and "token" not in proof
    assert _inspect(exe, directory, token)["user"] == user
    peer_token = _native_blob(peer.task(145, 26))
    assert (
        _inspect(exe, directory, peer_token)["user"] == peer_user
        and peer_token != token
    )
    checks.append(
        "Replay 145/26 exact 77-byte native blob, independent AES/HMAC, authenticated owner/title/expiry and peer separation"
    )

    audit_before = (directory / f"relay/{title}/clients/{user}.json").read_bytes()
    client.task(145, 26, b"\x08\x01\x00\x00\x00", error=106)
    assert (
        audit_before == (directory / f"relay/{title}/clients/{user}.json").read_bytes()
    )
    for index in (0, 1, 16, 17, 32, 33, 40, 41, 56, 57, 72, 73, 76):
        damaged = bytearray(token)
        damaged[index] ^= 1
        _inspect(exe, directory, damaged, success=False)
    for malformed in (token[:-1], token + b"\0", b"", b"\1" + os.urandom(76)):
        _inspect(exe, directory, malformed, success=False)

    # Own-realm expiry boundaries: even a correctly signed/encrypted expired
    # credential and zero/oversized deltas must fail the C++ verifier.
    def owned_credential(expiry, lifetime):
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(_expand(key, b"replay-relay-client-aes-v1", 16)),
            modes.CBC(iv),
        ).encryptor()
        opaque = (
            iv
            + cipher.update(struct.pack("<QII", user, 5800, expiry))
            + cipher.finalize()
            + os.urandom(8)
        )
        opaque += hmac.digest(
            _expand(key, b"replay-relay-client-mac-v1", 20),
            opaque + struct.pack("<I", lifetime),
            "sha1",
        )[:16]
        secret = hmac.digest(
            _expand(key, b"replay-relay-client-secret-v1", 20), opaque, "sha1"
        )[:16]
        return b"\1" + opaque + secret + struct.pack("<I", lifetime)

    for expired, lifetime in (
        (int(time.time()) - 1, 3600),
        (int(time.time()) + 100, 0),
        (int(time.time()) + 100, 3601),
        (int(time.time()) + 4000, 3600),
    ):
        _inspect(exe, directory, owned_credential(expired, lifetime), success=False)
    # Corruption must not silently replace issuer state. Use a separate owned
    # fixture directory so live and main fixture issuer keys are untouched.
    corrupt = directory / "damaged-relay-issuer"
    (corrupt / "relay").mkdir(parents=True)
    bad_key = bytearray(key_bytes)
    bad_key[8] ^= 1
    (corrupt / "relay/issuer-key.bin").write_bytes(bad_key)
    _inspect(exe, corrupt, token, success=False)
    assert (corrupt / "relay/issuer-key.bin").read_bytes() == bad_key
    checks.append(
        "relay malformed request without mutation, full credential tamper rejection, expiry bounds and damaged issuer preservation"
    )
    return dict(token=token, key=key_bytes, directory=directory, exe=exe, user=user)


def check_restart(client, fixture, checks):
    directory, exe = fixture["directory"], fixture["exe"]
    assert (directory / "relay/issuer-key.bin").read_bytes() == fixture["key"]
    assert _inspect(exe, directory, fixture["token"])["user"] == fixture["user"]
    renewed = _native_blob(client.task(145, 26))
    assert (
        renewed != fixture["token"]
        and _inspect(exe, directory, renewed)["user"] == fixture["user"]
    )
    checks.append(
        "relay issuer survives backend restart; old unexpired credentials decrypt and fresh login gets a new session-bound credential"
    )
