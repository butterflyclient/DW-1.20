"""Verify machine/session-bound renewal on isolated ports and disposable profiles.

The optional Windows DLL executes the real DPAPI identity signer and pinned
reply verifier. Native lobby tasks use independent Python wire/crypto code.
No game is launched and no primary-server account is used.
"""

import argparse
import base64
import ctypes
import hashlib
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

from native_wire_client import NativeClient, integer, structure, text

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--client-dll", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--trust-data", type=Path, default=ROOT / "data")
    args = parser.parse_args()
    fixture = ROOT / "data" / ("platform-renewal-fixture-" + str(time.time_ns()))
    data = fixture / "data"
    data.mkdir(parents=True)
    for leaf in (
        "platform-private.blob",
        "platform-public.blob",
        "replay-traffic-kdf.bin",
    ):
        shutil.copyfile(args.trust_data / leaf, data / leaf)
    for offset in range(12700, 12800):
        sockets = []
        try:
            for port in (8085, 8443, 3075):
                probe = socket.socket()
                sockets.append(probe)
                probe.bind(("127.0.0.1", port + offset))
            break
        except OSError:
            continue
        finally:
            for probe in sockets:
                probe.close()
    else:
        raise RuntimeError("No isolated renewal fixture ports available")
    base = f"http://127.0.0.1:{8085 + offset}"
    output = (fixture / "server.log").open("wb")
    process = subprocess.Popen(
        [str(args.server.resolve()), str(data), "--port-offset", str(offset)],
        stdout=output,
        stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    checks = []

    def post(path, body, expected=200):
        try:
            with urllib.request.urlopen(
                urllib.request.Request(base + path, body), timeout=10
            ) as response:
                assert response.status == expected
                return response.read(), response.headers
        except urllib.error.HTTPError as error:
            assert error.code == expected, (path, error.code, expected)
            return error.read(), error.headers

    blob = (data / "platform-public.blob").read_bytes()
    _, _, exponent_size, modulus_size, _, _ = struct.unpack_from("<6I", blob)
    public = rsa.RSAPublicNumbers(
        int.from_bytes(blob[24 : 24 + exponent_size], "big"),
        int.from_bytes(
            blob[24 + exponent_size : 24 + exponent_size + modulus_size], "big"
        ),
    ).public_key()

    def verified(reply, nonce):
        assert len(reply) == 512 and reply[8:40] == nonce
        public.verify(
            reply[256:],
            reply[:256],
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        issued, expires = struct.unpack_from("<QQ", reply, 40)
        assert issued <= int(time.time()) + 30 < expires and expires - issued <= 3600
        return reply

    def machine():
        key = ec.generate_private_key(ec.SECP256R1())
        numbers = key.public_key().public_numbers()
        return key, struct.pack("<II", 0x31534345, 32) + numbers.x.to_bytes(
            32, "big"
        ) + numbers.y.to_bytes(32, "big")

    def signed(key, prefix):
        r, s = utils.decode_dss_signature(key.sign(prefix, ec.ECDSA(hashes.SHA256())))
        return prefix + r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def login(key, key_blob, name):
        nonce = os.urandom(32)
        challenge, _ = post("/platform/client/challenge", key_blob + nonce)
        prefix = (
            struct.pack("<II", 0x31494452, 1)
            + nonce
            + challenge
            + key_blob
            + name.encode().ljust(36, b"\0")
        )
        reply, _ = post("/platform/client/login", signed(key, prefix))
        return verified(reply, nonce)

    def renewal(key, key_blob, token, expected=200, corrupt=False, version=3):
        nonce = os.urandom(32)
        challenge, _ = post("/platform/client/challenge", key_blob + nonce)
        prefix = (
            struct.pack("<II", 0x31494452, version)
            + nonce
            + challenge
            + key_blob
            + token
        )
        request = signed(key, prefix)
        if corrupt:
            request = request[:-1] + bytes([request[-1] ^ 1])
        reply, _ = post("/platform/client/renew", request, expected)
        return (verified(reply, nonce) if expected == 200 else reply), request

    def authenticate(reply):
        user = struct.unpack_from("<Q", reply, 56)[0]
        platform_id = struct.unpack_from("<I", reply, 64)[0]
        seed = int.from_bytes(os.urandom(4), "little")
        credentials = {
            "session_token": reply[112:176].decode(),
            "account_token": reply[177:241].decode(),
        }
        raw, headers = post(
            "/auth/",
            json.dumps(
                {
                    "auth_task": "84",
                    "iv_seed": str(seed),
                    "title_id": "5800",
                    "extra_data": json.dumps(credentials),
                }
            ).encode(),
        )
        public.verify(
            base64.b64decode(headers["X-Signature"]),
            raw,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=0),
            hashes.SHA256(),
        )
        auth = json.loads(raw)
        return dict(
            user=user,
            platform_account_id=platform_id,
            seed=seed,
            ticket=base64.b64decode(auth["server_ticket"]),
            key=base64.b64decode(auth["client_ticket"])[97:121],
        )

    try:
        for attempt in range(100):
            try:
                with urllib.request.urlopen(base + "/health", timeout=1):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("Isolated backend did not start")
        owner, owner_blob = machine()
        other, other_blob = machine()
        initial = login(owner, owner_blob, "Renewal Owner")
        peer = login(other, other_blob, "Renewal Peer")
        identity = authenticate(initial)
        with NativeClient(
            fixture, port_offset=offset, auth_identity=identity
        ) as client:
            before_connection = client.connection
            assert client.task(12, 6, b"", structured=False)
            time.sleep(1.1)
            renewed, request = renewal(owner, owner_blob, initial[112:176])
            assert (
                struct.unpack_from("<Q", renewed, 48)[0]
                > struct.unpack_from("<Q", initial, 48)[0]
            )
            assert renewed[:8] == initial[:8] and renewed[56:256] == initial[56:256]
            assert (
                client.task(12, 6, b"", structured=False)
                and client.connection == before_connection
            )
            checks.append(
                "signed renewal preserves complete identity/token layout and an established encrypted native lobby connection"
            )
            channel = 817260108
            client.task(
                198,
                6,
                structure(
                    text(1, "chat") + integer(2, channel) + integer(3, identity["user"])
                ),
            )
            channels = json.loads((data / "channels/5800.json").read_bytes())
            member = channels["channels"][f"chat:{channel}"]["members"][
                str(identity["user"])
            ]
            assert member["expires"] == struct.unpack_from("<Q", renewed, 48)[0]
            token = client.task(145, 26, b"", structured=False)
            assert token
            relay = json.loads(
                (data / "relay/5800/clients" / f"{identity['user']}.json").read_bytes()
            )
            assert relay["expires"] == member["expires"]
            checks.append(
                "new native channel membership and relay credentials use the renewed issuer lease on the original connection"
            )
            post("/platform/client/renew", request, 400)
            checks.append("consumed challenge replay rejected")
            renewal(other, other_blob, initial[112:176], expected=400)
            checks.append("different machine cannot renew another player session")
            renewal(owner, owner_blob, peer[112:176], expected=400)
            checks.append("owner cannot renew a foreign session token")
            renewal(owner, owner_blob, initial[112:176], expected=400, corrupt=True)
            renewal(owner, owner_blob, initial[112:176], expected=400, version=2)
            post("/platform/client/renew", b"bad", 400)
            checks.append(
                "damaged signature, wrong protocol version and malformed size rejected"
            )
            assert client.task(12, 6, b"", structured=False)
            checks.append(
                "denied renewal attempts leave the existing native session usable"
            )
        if args.client_dll:
            appdata = fixture / "appdata"
            appdata.mkdir()
            os.environ["LOCALAPPDATA"] = str(appdata)
            dll = ctypes.CDLL(str(args.client_dll.resolve()))
            callback_type = ctypes.CFUNCTYPE(
                ctypes.c_bool,
                ctypes.c_wchar_p,
                ctypes.c_void_p,
                ctypes.c_uint,
                ctypes.c_void_p,
                ctypes.c_uint,
            )

            def exchange(path, pointer, length, target, capacity):
                try:
                    reply, _ = post(path, ctypes.string_at(pointer, length))
                    if len(reply) != capacity:
                        return False
                    ctypes.memmove(target, reply, capacity)
                    return True
                except (OSError, AssertionError):
                    return False

            callback = callback_type(exchange)
            logon = dll.DW_LocalIdentity_Login
            logon.argtypes = (
                ctypes.c_char_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
                callback_type,
            )
            logon.restype = ctypes.c_bool
            identity_error = dll.DW_LocalIdentity_Error
            identity_error.restype = ctypes.c_char_p
            renew = dll.DW_LocalIdentity_Renew
            renew.argtypes = (
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
                callback_type,
            )
            renew.restype = ctypes.c_bool
            verify = dll.DW_LocalPlatform_VerifyReply
            verify.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64)
            verify.restype = ctypes.c_bool
            nonce = os.urandom(32)
            first = ctypes.create_string_buffer(512)
            assert logon(
                b"Renewal Native Signer", nonce, first, callback
            ), identity_error().decode()
            assert verify(first, nonce, int(time.time()))
            nonce = os.urandom(32)
            result = ctypes.create_string_buffer(512)
            assert renew(
                nonce, first.raw[112:176], result, callback
            ), identity_error().decode()
            assert verify(result, nonce, int(time.time()))
            assert first.raw[56:256] == result.raw[56:256]
            checks.append(
                "real Windows DPAPI identity signer and pinned RSA reply verifier execute the renewal exchange"
            )
        args.output.write_text(
            json.dumps(
                dict(
                    schema=1,
                    passed=True,
                    server_sha256=hashlib.sha256(args.server.read_bytes()).hexdigest(),
                    client_dll_sha256=(
                        hashlib.sha256(args.client_dll.read_bytes()).hexdigest()
                        if args.client_dll
                        else None
                    ),
                    checks=checks,
                    tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    fixture_directory=str(fixture),
                    native_game_verified=False,
                ),
                indent=2,
            )
            + "\n"
        )
        print(
            f"PASS: {len(checks)} machine/session renewal groups; no live server or game changed"
        )
    finally:
        process.terminate()
        process.wait(timeout=15)
        output.close()


if __name__ == "__main__":
    main()
