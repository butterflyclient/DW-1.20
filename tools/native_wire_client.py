"""Independent authenticated Replay 210 client for controlled local checks.

Calling login/auth supersedes that identity's earlier session. Default-account
callers MUST stop the game first; a separate provisioned profile is independent.
No credentials or transport keys are written to disk or printed.
"""

import base64
import hashlib
import hmac
import json
import os
import socket
import struct
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def u32(value):
    return b"\x08" + struct.pack("<I", value)


def u64(value):
    return b"\x0a" + struct.pack("<Q", value)


def varint(value):
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def integer(tag, value):
    return varint(tag << 3) + varint(value)


def binary(tag, value):
    return varint((tag << 3) | 2) + varint(len(value)) + value


def text(tag, value):
    return binary(tag, value.encode())


def structure(value):
    return b"\x17" + u32(len(value)) + value


def fields(raw):
    position = 0

    def number():
        nonlocal position
        value = 0
        for shift in range(0, 64, 7):
            if position >= len(raw):
                raise ValueError("Truncated structured integer")
            byte = raw[position]
            position += 1
            if shift == 63 and byte > 1:
                raise ValueError("Structured integer overflow")
            value |= (byte & 127) << shift
            if not byte & 128:
                return value
        raise ValueError("Structured integer overflow")

    out = {}
    while position < len(raw):
        key = number()
        tag, kind = key >> 3, key & 7
        if not tag:
            raise ValueError("Invalid structured tag")
        if kind == 0:
            value = number()
        elif kind == 2:
            size = number()
            if size > len(raw) - position:
                raise ValueError("Truncated structured object")
            value = raw[position : position + size]
            position += size
        else:
            raise ValueError("Unexpected structured wire type")
        out.setdefault(tag, []).append(value)
    return out


def expand(key, info, size):
    out = previous = b""
    for index in range(1, 256):
        previous = hmac.digest(key, previous + info + bytes([index]), "sha1")
        out += previous
        if len(out) >= size:
            return out[:size]
    raise ValueError("HKDF size")


class NativeClient:
    def __init__(
        self, root: Path, title=5800, profile="", host="127.0.0.1", access_key="",
        player_name=""
    ):
        self.socket = None
        self.title = title
        self.pushes = []
        base = f"http://{host}:8085"

        def post(path, value):
            data = value if isinstance(value, bytes) else json.dumps(value).encode()
            headers = {"X-Replay-Access": access_key} if access_key else {}
            if player_name and path.startswith("/platform/login"):
                headers["X-Replay-Player-Name"] = player_name
            return urllib.request.urlopen(
                urllib.request.Request(
                    base + path,
                    data,
                    headers=headers,
                ),
                timeout=5,
            )

        if profile and (
            len(profile) > 32
            or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in profile)
        ):
            raise ValueError("Invalid local profile key")
        with post(
            "/platform/login" + ("/" + profile if profile else ""), os.urandom(32)
        ) as reply:
            platform = reply.read()
        if len(platform) != 512:
            raise ValueError("Platform reply size")
        self.user = struct.unpack_from("<Q", platform, 56)[0]
        credentials = {
            "session_token": platform[112:176].decode(),
            "account_token": platform[177:241].decode(),
        }
        seed = struct.unpack("<I", os.urandom(4))[0]
        with post(
            "/auth/",
            {
                "auth_task": "84",
                "iv_seed": str(seed),
                "title_id": str(title),
                "extra_data": json.dumps(credentials),
            },
        ) as reply:
            raw = reply.read()
            signature = base64.b64decode(reply.headers["X-Signature"], validate=True)
        public = (root / "data/platform-public.blob").read_bytes()
        magic, bits, exponent_size, modulus_size, _, _ = struct.unpack_from(
            "<6I", public
        )
        if magic != 0x31415352 or bits != 2048:
            raise ValueError("Platform public-key format")
        exponent = int.from_bytes(public[24 : 24 + exponent_size], "big")
        modulus = int.from_bytes(
            public[24 + exponent_size : 24 + exponent_size + modulus_size], "big"
        )
        rsa.RSAPublicNumbers(exponent, modulus).public_key().verify(
            signature,
            raw,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=0),
            hashes.SHA256(),
        )
        auth = json.loads(raw)
        ticket = base64.b64decode(auth["server_ticket"], validate=True)
        key = base64.b64decode(auth["client_ticket"], validate=True)[97:121]
        self.session_fingerprint = base64.b64encode(
            hashlib.sha256(key).digest()
        ).decode()
        with post(
            "/v1.0/tokens/lsg/?client=replaylocal",
            {
                "ticket": auth["server_ticket"],
                "initialVectorSeed": base64.b64encode(str(seed).encode()).decode(),
                "titleID": title,
            },
        ) as reply:
            if json.load(reply)["umbrellaID"] != self.user:
                raise ValueError("Legacy identity binding")
        self.socket = socket.create_connection((host, 3075), timeout=5)
        self.incoming = self.outgoing = 1
        try:
            hello = struct.pack("<5I", 200, 200, 210, 220, 1024 * 1024) + os.urandom(8)
            self.socket.sendall(hello)
            ack = self.frame()
            if (
                len(ack) != 26
                or ack[4:6] != b"\xab\x81"
                or struct.unpack_from("<I", ack, 6)[0] != 210
            ):
                raise ValueError("Native hello acknowledgement")
            self.connection = struct.unpack_from("<Q", ack, 10)[0]
            values = []

            def bits(value, count):
                values.extend((value >> i) & 1 for i in range(count))

            bits(7, 8)
            bits(1, 1)
            bits(8, 5)
            bits(title, 32)
            bits(8, 5)
            bits(seed, 32)
            for value in ticket:
                bits(value, 8)
            while len(values) % 8:
                values.append(0)
            bitbuffer = bytes(
                sum(values[j + i] << i for i in range(8))
                for j in range(0, len(values), 8)
            )
            prefix = struct.pack("<I", len(bitbuffer) + 10) + b"\xab\x82" + bitbuffer
            traffic = expand(
                key, (root / "data/replay-traffic-kdf.bin").read_bytes(), 24
            )
            prk = hmac.digest(
                hashlib.sha1(hello[8:] + ack + prefix).digest(), traffic, "sha1"
            )
            challenge = expand(prk, b"CLIENTCHAL", 16)
            self.socket.sendall(prefix + challenge[:8])
            if self.frame()[4:] != b"\xab\x83" + challenge[8:]:
                raise ValueError("Native server challenge")
            self.material = expand(prk, b"BDDATA", 72)
            kind, data = self.receive()
            if kind != 4 or data != u64(self.connection):
                raise ValueError("Native connection ID")
        except BaseException:
            self.close()
            raise

    def exact(self, size):
        out = bytearray()
        while len(out) < size:
            chunk = self.socket.recv(size - len(out))
            if not chunk:
                raise EOFError("Native lobby closed")
            out.extend(chunk)
        return bytes(out)

    def frame(self):
        header = self.exact(4)
        size = struct.unpack("<I", header)[0]
        if size > 1024 * 1024:
            raise ValueError("Native frame bounds")
        return header + self.exact(size)

    def receive(self):
        packet = self.frame()
        if (
            packet[4:6] != b"\xab\x85"
            or struct.unpack_from("<I", packet, 6)[0] != self.incoming
        ):
            raise ValueError("Native record sequence")
        if not hmac.compare_digest(
            packet[-8:], hmac.digest(self.material[20:40], packet[:-8], "sha1")[:8]
        ):
            raise ValueError("Native record MAC")
        cipher = Cipher(
            algorithms.AES(self.material[56:72]), modes.CBC(packet[10:26])
        ).decryptor()
        plain = cipher.update(packet[26:-8]) + cipher.finalize()
        size = struct.unpack_from("<I", plain)[0]
        if size > len(plain) - 5 or plain[5 + size :] != bytes(len(plain) - 5 - size):
            raise ValueError("Native record bounds/padding")
        self.incoming += 1
        return plain[4], plain[5 : 5 + size]

    def task(self, service, task, params, structured=True):
        payload = bytes([service, 3, task]) + params + b"\0"
        plain = struct.pack("<I", len(payload)) + b"\x86" + payload
        plain += bytes((-len(plain)) % 16)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.material[40:56]), modes.CBC(iv)).encryptor()
        encrypted = cipher.update(plain) + cipher.finalize()
        packet = (
            struct.pack("<I", len(encrypted) + 30)
            + b"\xab\x85"
            + struct.pack("<I", self.outgoing)
            + iv
            + encrypted
        )
        self.outgoing += 1
        self.socket.sendall(
            packet + hmac.digest(self.material[:20], packet, "sha1")[:8]
        )
        for _ in range(64):
            kind, data = self.receive()
            if kind == 2:
                self.pushes.append(data)
                continue
            if kind != 1 or data[0] != 10 or data[9] != 8:
                raise ValueError("Native task result header")
            error = struct.unpack_from("<I", data, 10)[0]
            if error:
                raise RuntimeError(f"Native task {service}/{task} returned {error}")
            if not structured:
                if data[14:17] != bytes([3, task, 8]):
                    raise ValueError("Native ordinary result header")
                count = struct.unpack_from("<I", data, 17)[0]
                if not count:
                    if len(data) != 21:
                        raise ValueError("Native empty result size")
                    return b""
                if data[21] != 8 or struct.unpack_from("<I", data, 22)[0] != count:
                    raise ValueError("Native result count")
                return data[26:]
            if data[14:18] != bytes([3, task, 23, 8]):
                raise ValueError("Native structured result header")
            size = struct.unpack_from("<I", data, 18)[0]
            if len(data) != size + 22:
                raise ValueError("Native structured result size")
            return data[22:]
        raise ValueError("Excessive unsolicited notifications")

    def close(self):
        if self.socket:
            self.socket.close()
            self.socket = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
