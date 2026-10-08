"""Exercise admission expiry, signed renewal and session revocation over real UDP.

Disposable accounts and a private issuer shorten a valid admission token to four
seconds. Production clocks, credentials and server configuration are untouched.
The original UDP protocol, authenticated platform routes and verifiers execute.
"""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import time
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from native_wire_client import NativeClient
from relay_fixtures import _expand, _native_blob
from relay_transport_fixtures import Relay

ROOT = Path(__file__).resolve().parents[1]


def shorten(token, issuer, expires, lifetime):
    cipher_key = _expand(issuer, b"replay-relay-client-aes-v1", 16)
    decrypt = Cipher(algorithms.AES(cipher_key), modes.CBC(token[1:17])).decryptor()
    claims = bytearray(decrypt.update(token[17:33]) + decrypt.finalize())
    struct.pack_into("<I", claims, 12, expires)
    iv = os.urandom(16)
    encrypt = Cipher(algorithms.AES(cipher_key), modes.CBC(iv)).encryptor()
    opaque = iv + encrypt.update(bytes(claims)) + encrypt.finalize() + token[33:41]
    delta = struct.pack("<I", lifetime)
    opaque += hmac.digest(
        _expand(issuer, b"replay-relay-client-mac-v1", 20), opaque + delta, "sha1"
    )[:16]
    secret = hmac.digest(
        _expand(issuer, b"replay-relay-client-secret-v1", 20), opaque, "sha1"
    )[:16]
    return b"\1" + opaque + secret + delta


class IssuerClient:
    def __init__(self, base, public_blob):
        self.base = base
        self.key = ec.generate_private_key(ec.SECP256R1())
        point = self.key.public_key().public_numbers()
        self.public = (
            struct.pack("<II", 0x31534345, 32)
            + point.x.to_bytes(32, "big")
            + point.y.to_bytes(32, "big")
        )
        _, _, exponent_size, modulus_size, _, _ = struct.unpack_from("<6I", public_blob)
        self.issuer = rsa.RSAPublicNumbers(
            int.from_bytes(public_blob[24 : 24 + exponent_size], "big"),
            int.from_bytes(
                public_blob[24 + exponent_size : 24 + exponent_size + modulus_size],
                "big",
            ),
        ).public_key()

    def post(self, path, body, expected=200):
        try:
            with urllib.request.urlopen(
                urllib.request.Request(self.base + path, body), timeout=5
            ) as response:
                assert response.status == expected
                return response.read()
        except urllib.error.HTTPError as error:
            assert error.code == expected, (path, error.code, expected)
            return error.read()

    def request(self, token=None, corrupt=False):
        nonce = os.urandom(32)
        challenge = self.post("/platform/client/challenge", self.public + nonce)
        prefix = (
            struct.pack("<II", 0x31494452, 1 if token is None else 3)
            + nonce
            + challenge
            + self.public
            + (b"Relay Lease Fixture".ljust(36, b"\0") if token is None else token)
        )
        r, s = utils.decode_dss_signature(
            self.key.sign(prefix, ec.ECDSA(hashes.SHA256()))
        )
        body = prefix + r.to_bytes(32, "big") + s.to_bytes(32, "big")
        if corrupt:
            body = body[:-1] + bytes([body[-1] ^ 1])
        reply = self.post(
            "/platform/client/login" if token is None else "/platform/client/renew",
            body,
            400 if corrupt else 200,
        )
        if corrupt:
            return reply
        assert len(reply) == 512 and reply[8:40] == nonce
        self.issuer.verify(
            reply[256:],
            reply[:256],
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        return reply


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True, type=Path)
    parser.add_argument("--trust-data", type=Path, default=ROOT / "data")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    fixture = ROOT / "data" / ("relay-continuity-fixture-" + str(time.time_ns()))
    fixture.mkdir(mode=0o700)
    data = fixture / "data"
    (data / "relay").mkdir(parents=True)
    (data / "qos").mkdir()
    (data / "relay/local-provider.json").write_text('{"enabled":true}\n')
    (data / "qos/local-provider.json").write_text('{"enabled":true}\n')
    for name in (
        "platform-private.blob",
        "platform-public.blob",
        "replay-traffic-kdf.bin",
    ):
        shutil.copyfile(args.trust_data / name, data / name)
    for offset in range(13500, 13600):
        probes = []
        try:
            for port, kind in (
                (8085, socket.SOCK_STREAM),
                (8443, socket.SOCK_STREAM),
                (3075, socket.SOCK_STREAM),
                (3077, socket.SOCK_DGRAM),
            ):
                probe = socket.socket(socket.AF_INET, kind)
                probes.append(probe)
                probe.bind(("127.0.0.1", port + offset))
            break
        except OSError:
            continue
        finally:
            for probe in probes:
                probe.close()
    else:
        raise RuntimeError("No private relay fixture ports available")
    base = f"http://127.0.0.1:{8085 + offset}"
    log = (fixture / "server.log").open("wb")
    process = subprocess.Popen(
        [str(args.server.resolve()), str(data), "--port-offset", str(offset)],
        stdout=log,
        stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    checks, clients, relays = [], [], []
    stage = "server startup"
    failure = None
    try:
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError("Private relay backend exited")
            try:
                urllib.request.urlopen(base + "/health", timeout=0.5).close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("Private relay backend did not start")
        machine = IssuerClient(base, (data / "platform-public.blob").read_bytes())
        initial = machine.request()
        owner = NativeClient(fixture, port_offset=offset, platform_reply=initial)
        clients.append(owner)
        peer = NativeClient(fixture, port_offset=offset, player_name="Relay Peer")
        clients.append(peer)
        token = _native_blob(owner.task(145, 26, b"", structured=False))
        key_bytes = (data / "relay/issuer-key.bin").read_bytes()
        assert (
            len(key_bytes) == 72
            and hashlib.sha256(key_bytes[:40]).digest() == key_bytes[40:]
        )
        expires = int(time.time()) + 4
        short = shorten(token, key_bytes[8:40], expires, 4)
        stage = "short-lived authenticated handshakes"
        host = Relay(owner, owner.user, token=short)
        relays.append(host)
        host.establish()
        joined = Relay(peer, peer.user, host)
        relays.append(joined)
        joined.establish()
        pending = Relay(owner, owner.user, token=short)
        relays.append(pending)
        checks.append(
            "Valid four-second admission token binds a verified route and a pending handshake"
        )
        while int(time.time()) <= expires - 2:
            time.sleep(0.05)
        renewed = machine.request(initial[112:176])
        assert renewed[56:256] == initial[56:256]
        assert (
            struct.unpack_from("<Q", renewed, 48)[0]
            > struct.unpack_from("<Q", initial, 48)[0]
        )
        checks.append(
            "Pinned signed machine renewal preserves the native session key and account tokens"
        )
        while int(time.time()) <= expires:
            time.sleep(0.05)
        stage = "established route after admission expiry"
        ping = struct.pack("<QB", 123456789, 1)
        host.send(6, ping)
        assert host.reply(6) == ping
        joined.send(6, ping)
        assert joined.reply(6) == ping
        for sender, destination in ((host, joined), (joined, host)):
            payload = (
                struct.pack("<I", destination.route) + b"continued-session-payload"
            )
            sender.send(5, payload)
            assert destination.reply(5, source=sender.route) == payload
        checks.append(
            "Existing route IDs/MACs/counters and bidirectional UDP data survive admission expiry"
        )
        stage = "expired admission and pending handshake rejection"
        host.silent(host.init)
        pending.send(3, pending.verification)
        pending.silent()
        # The failed INIT/VERIFY must not destroy or rotate the established route.
        host.send(6, ping)
        assert host.reply(6) == ping
        with urllib.request.urlopen(base + "/health", timeout=5) as response:
            status = json.load(response)["relay"]
        assert (
            status["active_associations"] == 2 and status["verified_associations"] == 2
        )
        checks.append(
            "Expired INIT and unverified handshake rejected; established route remains unchanged"
        )
        stage = "invalid renewal isolation"
        machine.request(initial[112:176], corrupt=True)
        host.send(6, ping)
        assert host.reply(6) == ping
        checks.append(
            "An invalid renewal proof cannot replace or disrupt the valid association"
        )
        stage = "native reauthentication revokes the old association"
        replacement = NativeClient(fixture, port_offset=offset, platform_reply=renewed)
        clients.append(replacement)
        host.send(6, ping)
        host.silent()
        joined.send(6, ping)
        assert joined.reply(6) == ping
        with urllib.request.urlopen(base + "/health", timeout=5) as response:
            status = json.load(response)["relay"]
        assert status["active_associations"] == 1
        checks.append(
            "Native reauthentication revokes the old session route; unrelated peer remains live"
        )
    except Exception as error:
        failure = f"{type(error).__name__}: {error}"
    finally:
        for relay in relays:
            relay.close()
        for client in clients:
            client.close()
        process.terminate()
        process.wait(timeout=10)
        log.close()
        proof = {
            "schema": 1,
            "passed": failure is None,
            "recorded_utc": datetime.now(timezone.utc).isoformat(),
            "server_sha256": hashlib.sha256(args.server.read_bytes()).hexdigest(),
            "fixture": str(fixture),
            "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "checks": checks,
            "last_stage": stage,
            "failure": failure,
            "native_game_verified": False,
            "production_clock_or_account_modified": False,
        }
        args.output.write_text(json.dumps(proof, indent=2) + "\n")
    if failure:
        raise RuntimeError(f"{stage}: {failure}")
    print(f"PASS: {len(checks)} signed-session/real-UDP continuity groups")


if __name__ == "__main__":
    main()
