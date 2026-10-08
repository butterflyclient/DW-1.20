"""Real process restarts with cached native credentials on disposable backends."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import socket
import struct
import subprocess
import time
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from native_wire_client import NativeClient, binary, integer, text, u32

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True, type=Path)
    parser.add_argument("--trust-data", type=Path, default=ROOT / "data")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    fixture = ROOT / "data" / f"platform-session-persistence-{time.time_ns()}"
    data = fixture / "data"
    data.mkdir(parents=True)
    for leaf in (
        "platform-private.blob",
        "platform-public.blob",
        "replay-traffic-kdf.bin",
    ):
        shutil.copyfile(args.trust_data / leaf, data / leaf)
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    for offset in range(12900, 13000):
        probes = []
        try:
            for port in (8085, 8443, 3075):
                probe = socket.socket()
                probes.append(probe)
                probe.bind(("127.0.0.1", port + offset))
            break
        except OSError:
            pass
        finally:
            for probe in probes:
                probe.close()
    else:
        raise RuntimeError("No private fixture ports available")
    base = f"http://127.0.0.1:{8085 + offset}"
    log = (fixture / "server.log").open("wb")
    process = None
    checks = []
    rest_response = runpy.run_path(str(ROOT / "tools/test-progression-retry.py"))[
        "rest_response"
    ]

    def start(valid=True):
        nonlocal process
        assert process is None
        process = subprocess.Popen(
            [str(args.server.resolve()), str(data), "--port-offset", str(offset)],
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=flags,
        )
        for _ in range(100):
            if process.poll() is not None:
                assert not valid and process.returncode != 0
                process = None
                return
            try:
                with urllib.request.urlopen(base + "/health", timeout=0.5) as reply:
                    assert valid, "Malformed session image started a healthy issuer"
                    assert json.load(reply)["native_auth"]
                    return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("Fixture startup did not reach its expected state")

    def stop():
        nonlocal process
        if process is not None:
            process.terminate()
            process.wait(timeout=15)
            process = None

    def post(path, body, expected=200):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        try:
            with urllib.request.urlopen(
                urllib.request.Request(base + path, body), timeout=10
            ) as reply:
                assert reply.status == expected
                return reply.read()
        except urllib.error.HTTPError as error:
            assert error.code == expected, (path, error.code, expected)
            return error.read()

    private = (data / "platform-private.blob").read_bytes()
    magic, bits, es, ns, ps, qs = struct.unpack_from("<6I", private)
    assert magic == 0x32415352 and bits == 2048
    values, position = [], 24
    for size in (es, ns, ps, qs):
        values.append(int.from_bytes(private[position : position + size], "big"))
        position += size
    e, n, p, q = values
    d = pow(e, -1, (p - 1) * (q - 1))
    issuer = rsa.RSAPrivateNumbers(
        p, q, d, d % (p - 1), d % (q - 1), pow(q, -1, p), rsa.RSAPublicNumbers(e, n)
    ).private_key()
    machine = ec.generate_private_key(ec.SECP256R1())
    public = machine.public_key().public_numbers()
    key_blob = (
        struct.pack("<II", 0x31534345, 32)
        + public.x.to_bytes(32, "big")
        + public.y.to_bytes(32, "big")
    )

    def signed(prefix):
        r, s = utils.decode_dss_signature(
            machine.sign(prefix, ec.ECDSA(hashes.SHA256()))
        )
        return prefix + r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def verified(reply, nonce):
        assert len(reply) == 512 and reply[8:40] == nonce
        issuer.public_key().verify(
            reply[256:],
            reply[:256],
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        return reply

    def renew(token, expected=200):
        nonce = os.urandom(32)
        challenge = post("/platform/client/challenge", key_blob + nonce)
        request = signed(
            struct.pack("<II", 0x31494452, 3) + nonce + challenge + key_blob + token
        )
        reply = post("/platform/client/renew", request, expected)
        return (verified(reply, nonce) if expected == 200 else reply), request

    def legacy(identity, expected=200):
        raw = post(
            "/v1.0/tokens/lsg/?client=replaylocal",
            dict(
                ticket=base64.b64encode(identity["ticket"]).decode(),
                initialVectorSeed=base64.b64encode(
                    str(identity["seed"]).encode()
                ).decode(),
                titleID=5800,
            ),
            expected,
        )
        return json.loads(raw)

    def account(client, operation, body, access):
        resource = "UnoRes" if operation == "updatesecuredfields" else "UserResource"
        method = 0x505554 if operation == "updatesecuredfields" else 0x504F5354
        uri = (
            f"/v1.0/users/{client.user}/securedfields/?client=replaylocal"
            if operation == "updatesecuredfields"
            else "/v1.0/auth/?client=replaylocal"
        )
        params = integer(1, 1) + integer(2, 0) + integer(3, 1) + integer(100, 10000)
        params += binary(200, bytes(256)) + text(300, resource) + text(301, operation)
        header = text(1, "Authorization") + text(2, "Bearer  " + access)
        message = (
            binary(1, params) + integer(2, 1) + integer(10, method) + text(11, uri)
        )
        message += (
            binary(14, header) + text(101, "uno") + integer(102, 1) + integer(302, 1)
        )
        blob = lambda raw: b"\x13" + u32(len(raw)) + raw
        request = (
            u32(713) + blob(message) + b"\x01\x01" + blob(json.dumps(body).encode())
        )
        return rest_response(client.task(255, 10, request, structured=False))

    store = data / "platform-sessions.bin"

    def snapshot():
        raw = store.read_bytes()
        magic, version, size = struct.unpack_from("<8sII", raw)
        assert magic == b"RPSES001" and version == 1 and len(raw) == 16 + size + 256
        issuer.public_key().verify(
            raw[-256:],
            raw[:-256],
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        return json.loads(raw[16:-256])

    def publish(rows):
        # Negative fixtures use only this private issuer and its disposable profiles.
        body = json.dumps(rows, separators=(",", ":")).encode()
        raw = struct.pack("<8sII", b"RPSES001", 1, len(body)) + body
        signature = issuer.sign(
            raw,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        store.write_bytes(raw + signature)

    try:
        start()
        nonce = os.urandom(32)
        challenge = post("/platform/client/challenge", key_blob + nonce)
        initial = verified(
            post(
                "/platform/client/login",
                signed(
                    struct.pack("<II", 0x31494452, 1)
                    + nonce
                    + challenge
                    + key_blob
                    + b"Persistence Owner".ljust(36, b"\0")
                ),
            ),
            nonce,
        )
        with NativeClient(
            fixture, port_offset=offset, platform_reply=initial
        ) as client:
            identity = client.fixture_auth_identity
            access = legacy(identity)["accessToken"]
            fields = dict(
                email="session-owner@example.invalid",
                password="Fixture-password-1!",
                accountType="full",
                subscriptionOptIn=False,
            )
            assert account(client, "updatesecuredfields", fields, access)[0] == 200
            status, original_grants = account(
                client,
                "authenticateUser",
                dict(
                    email=fields["email"],
                    password=fields["password"],
                    grantType="password",
                ),
                access,
            )
            assert status == 200
            assert client.task(12, 6, b"", structured=False)
        assert snapshot()
        stop()
        start()
        with NativeClient(
            fixture, port_offset=offset, auth_identity=identity
        ) as client:
            assert client.task(12, 6, b"", structured=False)
            assert legacy(identity)["accessToken"] == access
            assert (
                account(
                    client,
                    "authenticateUser",
                    dict(
                        email=fields["email"],
                        password=fields["password"],
                        grantType="password",
                    ),
                    access,
                )[1]
                == original_grants
            )
            checks.append(
                "Real process restart preserves native ticket/key, encrypted task completion, legacy access and UNO grants without another auth request"
            )
            time.sleep(1.1)
            renewed, replay = renew(initial[112:176])
            assert renewed[56:256] == initial[56:256]
            assert (
                struct.unpack_from("<Q", renewed, 48)[0]
                > struct.unpack_from("<Q", initial, 48)[0]
            )
            assert client.task(12, 6, b"", structured=False)
            before = store.read_bytes()
            pending = data / "platform-sessions.bin.creating"
            assert not pending.exists()
            pending.mkdir()
            try:
                renew(initial[112:176], expected=400)
                assert store.read_bytes() == before and client.task(
                    12, 6, b"", structured=False
                )
            finally:
                pending.rmdir()
            checks.append(
                "Blocked atomic publication rejects renewal, preserves the previous disk image and keeps the cached native session usable"
            )
        stop()
        start()
        with NativeClient(
            fixture, port_offset=offset, auth_identity=identity
        ) as client:
            assert client.task(12, 6, b"", structured=False)
            post("/platform/client/renew", replay, 400)
            later, _ = renew(initial[112:176])
            assert later[56:256] == initial[56:256]
            assert client.task(12, 6, b"", structured=False)
            checks.append(
                "Renewed lease persists across another process restart; consumed old challenges stay invalid while fresh machine proof renews the same native key"
            )
        with NativeClient(
            fixture, port_offset=offset, platform_reply=initial
        ) as client:
            replacement = client.fixture_auth_identity
            assert replacement["key"] != identity["key"]
            legacy(identity, expected=400)
        stop()
        start()
        legacy(identity, expected=400)
        with NativeClient(
            fixture, port_offset=offset, auth_identity=replacement
        ) as client:
            assert client.task(12, 6, b"", structured=False)
        checks.append(
            "Reauthentication key/ticket rotation remains durable; restart cannot revive the superseded native ticket"
        )
        stop()
        healthy = store.read_bytes()
        damaged = bytearray(healthy)
        damaged[40] ^= 1
        store.write_bytes(damaged)
        start(valid=False)
        assert store.read_bytes() == damaged
        store.write_bytes(healthy[:-1])
        start(valid=False)
        rows = json.loads(healthy[16:-256])
        bad = json.loads(json.dumps(rows))
        bad[0]["uno_access"] = "g" * 64
        publish(bad)
        start(valid=False)
        checks.append(
            "Unsigned mutation, truncated signed image and malformed authenticated credential layout fail startup without replacing the evidence"
        )
        expired = json.loads(json.dumps(rows))
        for row in expired:
            payload = bytearray(base64.b64decode(row["payload"]))
            struct.pack_into(
                "<QQ", payload, 40, int(time.time()) - 100, int(time.time()) - 1
            )
            row["payload"] = base64.b64encode(payload).decode()
        publish(expired)
        start()
        renew(initial[112:176], expected=400)
        legacy(replacement, expected=400)
        with urllib.request.urlopen(base + "/health") as reply:
            assert json.load(reply)["platform_sessions"] == 0
        checks.append(
            "Expired signed fixture records are not restored or renewed; no production clock or player account is modified"
        )
        args.output.write_text(
            json.dumps(
                dict(
                    schema=1,
                    passed=True,
                    server_sha256=hashlib.sha256(args.server.read_bytes()).hexdigest(),
                    tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    checks=checks,
                    fixture_directory=str(fixture),
                    native_game_verified=False,
                    primary_server_or_game_modified=False,
                ),
                indent=2,
            )
            + "\n",
            newline="\n",
        )
        print(
            f"PASS: {len(checks)} durable native session groups with real process restarts"
        )
    finally:
        stop()
        log.close()


if __name__ == "__main__":
    main()
