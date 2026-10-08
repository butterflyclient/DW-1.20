"""Independent Replay relay wire client against real UDP sockets; no game/maps."""

import base64
import hashlib
import hmac
import json
import os
import socket
import struct
import time
import urllib.request
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import relay_fixtures


def expand256(key, info, size):
    out = previous = b""
    for i in range(1, 256):
        previous = hmac.digest(key, previous + info + bytes([i]), "sha256")
        out += previous
        if len(out) >= size:
            return out[:size]
    raise AssertionError("HKDF bound")


def hkdf(seed, label, size):
    return expand256(hmac.digest(bytes(32), seed, "sha256"), label + b"\0", size)


def packet(kind, route, counter, payload, key):
    data = struct.pack("<BIH", kind, route, counter & 65535) + payload
    return (
        data
        + hmac.digest(key, data + struct.pack("<I", counter), "sha256")[
            : 5 if kind == 5 else 16
        ]
    )


class Relay:
    def __init__(self, client, user, remote=None, *, token=None):
        self.user = user
        document = json.loads(
            client.task(145, 24, b"\x10replay\0\x10pc\0", structured=False)[1:-1]
        )
        assert document["datacenter"] == "local" and isinstance(
            document["server_info"], str
        )
        self.server = base64.b64decode(
            json.loads(document["server_info"])["relay_auth_token"], validate=True
        )
        assert len(self.server) == 83 and self.server[0] == 1
        self.relay_id = struct.unpack_from("<Q", self.server, 75)[0]
        self.address_bytes = self.server[69:75]
        self.address = (
            socket.inet_ntoa(self.address_bytes[:4]),
            struct.unpack_from("<H", self.address_bytes, 4)[0],
        )
        assert self.address[0] == "127.0.0.1" and self.address[1] and self.relay_id
        self.token = (
            relay_fixtures._native_blob(client.task(145, 26, b"", structured=False))
            if token is None
            else token
        )
        assert len(self.token) == 77 and self.token[0] == 1
        self.secret = self.token[57:73]
        credential = self.server[:53] if remote is None else remote.join_init()
        self.remote_secret = (
            self.server[53:69] if remote is None else remote.join_secret
        )
        self.random = os.urandom(16)
        init_key = hkdf(
            self.secret + self.remote_secret + self.random, b"GceTGCsU2PYWfEYWJ0wA", 16
        )
        payload = (
            b"\2"
            + self.token[:57]
            + self.token[73:]
            + credential
            + self.random
            + struct.pack("<I", 101)
            + bytes(100)
        )
        self.init = packet(0 if remote is None else 1, 0, 0, payload, init_key)
        assert len(self.init) == (258 if remote is None else 232)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(1)
        self.socket.sendto(self.init, self.address)
        ack, peer = self.socket.recvfrom(1290)
        assert peer == self.address and len(ack) == 142 and ack[0] == 2
        assert ack[7:23] == self.random and ack[39] == 1
        self.route = struct.unpack_from("<I", ack, 1)[0]
        self.ack = ack
        keys = hkdf(
            struct.pack("<IQ", 5800, user)
            + self.secret
            + self.remote_secret
            + self.random
            + ack[23:39],
            b"atOnU0BTUtmM0ju414F7",
            48,
        )
        self.send_key, self.cipher, self.receive_key = keys[:16], keys[16:32], keys[32:]
        assert self.read(ack, 2, 0) == ack[7:-16]
        plain = AESGCM(self.cipher).decrypt(ack[40:52], ack[52:126], None)
        assert len(plain) == 58
        self.join_secret, self.verification = plain[:16], plain[16:32]
        relay_id, self.route, self.join = struct.unpack_from("<QIQ", plain, 32)
        assert (
            relay_id == self.relay_id
            and self.route
            and self.route == struct.unpack_from("<I", ack, 1)[0]
        )
        assert plain[52:] == self.address_bytes and bool(self.join) == (remote is None)
        self.counter = 1
        self.received_counter = 0

    def join_init(self):
        return (
            b"\1"
            + struct.pack("<QIQ", self.relay_id, self.route, self.join)
            + self.address_bytes
        )

    def read(self, data, kind, counter=None, source=None):
        assert data[0] == kind and struct.unpack_from("<I", data, 1)[0] == (
            self.route if source is None else source
        )
        low = struct.unpack_from("<H", data, 5)[0]
        full = low if counter is not None else (self.received_counter & ~65535) | low
        if counter is None and full < self.received_counter - 32768:
            full += 65536
        if counter is not None:
            assert low == counter & 65535
            full = counter
        size = 5 if kind == 5 else 16
        assert hmac.compare_digest(
            data[-size:],
            hmac.digest(
                self.send_key, data[:-size] + struct.pack("<I", full), "sha256"
            )[:size],
        )
        self.received_counter = max(getattr(self, "received_counter", 0), full)
        return data[7:-size]

    def send(self, kind, payload=b"", counter=None):
        if counter is None:
            counter = self.counter
            self.counter += 1
        data = packet(kind, self.route, counter, payload, self.receive_key)
        self.socket.sendto(data, self.address)
        return data

    def reply(self, kind, source=None):
        data, peer = self.socket.recvfrom(1290)
        assert peer == self.address
        return self.read(data, kind, source=source)

    def silent(self, data=None, target=None):
        self.socket.settimeout(0.1)
        if data is not None:
            self.socket.sendto(data, self.address if target is None else target)
        try:
            self.socket.recvfrom(1290)
            raise AssertionError("Rejected relay packet got a response")
        except socket.timeout:
            pass
        finally:
            self.socket.settimeout(1)

    def establish(self):
        self.send(3, self.verification)
        assert self.reply(4) == b""

    def close(self):
        self.socket.close()


def exercise(client, peer, user, peer_user, directory, base, checks, old_token):
    opened = []
    try:
        host = Relay(client, user)
        opened.append(host)
        issuer = (directory / "relay/issuer-key.bin").read_bytes()[8:40]
        opaque = host.server[1:53]
        claims = AESGCM(
            relay_fixtures._expand(issuer, b"replay-relay-server-aes-v1", 16)
        ).decrypt(opaque[:12], opaque[12:], None)
        owner, title, expires, relay_id = struct.unpack("<QIIQ", claims)
        assert (
            owner == user
            and title == 5800
            and time.time() < expires <= time.time() + 3601
            and relay_id == host.relay_id
        )
        expected = hmac.digest(
            relay_fixtures._expand(issuer, b"replay-relay-server-secret-v1", 32),
            opaque,
            "sha256",
        )[:16]
        assert hmac.compare_digest(expected, host.server[53:69])
        # Exact retransmission preserves the encrypted ACK, routing ID and keys.
        host.socket.sendto(host.init, host.address)
        assert host.socket.recvfrom(1290)[0] == host.ack
        host.silent(packet(3, host.route, 1, bytes(16), host.receive_key))
        # Bad MAC with an advanced counter must not advance the replay window.
        bad = bytearray(
            packet(3, host.route, 20000, host.verification, host.receive_key)
        )
        bad[-1] ^= 1
        host.silent(bad)
        host.establish()
        checks.append(
            "Replay real UDP BIND/VERIFY/ESTABLISHED, native AES-GCM join payload and SHA256 HKDF/MAC directions, idempotent INIT and bad-MAC window preservation"
        )

        joined = Relay(peer, peer_user, host)
        opened.append(joined)
        joined.establish()
        assert joined.route != host.route
        for sender, destination in ((host, joined), (joined, host)):
            payload = os.urandom(1272)
            frame = sender.send(5, struct.pack("<I", destination.route) + payload)
            assert len(frame) == 1288
            assert (
                destination.reply(5, source=sender.route)
                == struct.pack("<I", destination.route) + payload
            )
            sender.socket.sendto(frame, sender.address)
            destination.silent()
        checks.append(
            "Replay JOIN route/secret lookup and bidirectional 1288-byte relay data forwarding with destination MACs and source routing IDs; duplicates rejected"
        )

        ping = struct.pack("<QB", 123456789, 1)
        for counter in (10, 12, 11, 32770, 65530, 65536, 65537):
            host.send(6, ping, counter=counter)
            assert host.reply(6) == ping[:8] + b"\1"
        host.silent(packet(6, host.route, 11, ping, host.receive_key))
        host.silent(packet(6, host.route, 65536, ping, host.receive_key))
        host.counter = 65538
        # Wrong UDP endpoint cannot take over an authenticated route.
        joined.silent(
            packet(6, host.route, 65538, ping, host.receive_key), target=host.address
        )
        # Server token bound to one signed user cannot upgrade another user.
        joined.silent(
            packet(
                8, joined.route, joined.counter, host.server[:53], joined.receive_key
            )
        )
        joined.send(8, joined.server[:53])
        new_join = struct.unpack("<Q", joined.reply(9))[0]
        assert new_join
        joined.join = new_join
        checks.append(
            "relay ping echo, 32-packet reordering window/16-bit rollover, wrong endpoint and foreign-owner rejection, native BIND_UPGRADE_ACK"
        )

        # Authenticated opaque token with a fake session digest is still denied.
        forged = bytearray(host.token)
        forged[33:41] = os.urandom(8)
        forged[41:57] = hmac.digest(
            relay_fixtures._expand(issuer, b"replay-relay-client-mac-v1", 20),
            forged[1:41] + forged[73:],
            "sha1",
        )[:16]
        forged[57:73] = hmac.digest(
            relay_fixtures._expand(issuer, b"replay-relay-client-secret-v1", 20),
            forged[1:57],
            "sha1",
        )[:16]
        random = os.urandom(16)
        payload = (
            b"\2"
            + forged[:57]
            + forged[73:]
            + host.server[:53]
            + random
            + struct.pack("<I", 101)
            + bytes(100)
        )
        init_key = hkdf(
            bytes(forged[57:73]) + host.server[53:69] + random,
            b"GceTGCsU2PYWfEYWJ0wA",
            16,
        )
        host.silent(packet(0, 0, 0, payload, init_key))
        # An unexpired token from the previous server process decrypts offline,
        # but its lobby session was revoked by that process restart.
        payload = (
            b"\2"
            + old_token[:57]
            + old_token[73:]
            + host.server[:53]
            + random
            + struct.pack("<I", 101)
            + bytes(100)
        )
        host.silent(
            packet(
                0,
                0,
                0,
                payload,
                hkdf(
                    old_token[57:73] + host.server[53:69] + random,
                    b"GceTGCsU2PYWfEYWJ0wA",
                    16,
                ),
            )
        )
        damaged = bytearray(host.server[:53])
        damaged[52] ^= 1
        payload = (
            b"\2"
            + host.token[:57]
            + host.token[73:]
            + damaged
            + random
            + struct.pack("<I", 101)
            + bytes(100)
        )
        host.silent(
            packet(
                0,
                0,
                0,
                payload,
                hkdf(
                    host.secret + host.server[53:69] + random,
                    b"GceTGCsU2PYWfEYWJ0wA",
                    16,
                ),
            )
        )
        # Native platform value is 101, not the reference source's 107.
        payload = (
            b"\2"
            + host.token[:57]
            + host.token[73:]
            + host.server[:53]
            + random
            + struct.pack("<I", 107)
            + bytes(100)
        )
        host.silent(
            packet(
                0,
                0,
                0,
                payload,
                hkdf(
                    host.secret + host.server[53:69] + random,
                    b"GceTGCsU2PYWfEYWJ0wA",
                    16,
                ),
            )
        )
        host.send(10)
        assert host.reply(11) == b""
        host.silent(packet(6, host.route, host.counter, ping, host.receive_key))
        joined.send(10)
        assert joined.reply(11) == b""
        with urllib.request.urlopen(base + "/health") as response:
            status = json.load(response)["relay"]
        assert (
            status["enabled"]
            and status["verified_associations"] == 2
            and status["active_associations"] == 0
        )
        assert (
            status["forwarded_packets"] == 2
            and status["ping_replies"] == 7
            and status["rejected_packets"] >= 10
        )
        rejected = [
            json.loads(line)
            for line in (directory / "relay/transport-events.jsonl")
            .read_text()
            .splitlines()
            if json.loads(line)["action"] == "rejected"
            and json.loads(line)["relay_id"] == status["relay_id"]
        ]
        assert len(rejected) == status["rejected_packets"] == status["rejection_events"]
        assert status["suppressed_rejection_events"] == 0
        assert all(
            set(row)
            == {
                "schema",
                "time",
                "action",
                "relay_id",
                "port",
                "reason",
                "bytes",
                "route",
                "packet_type",
            }
            for row in rejected
        )
        checks.append(
            "rejected relay packets retain bounded header-only diagnostics matching transport counters without credentials, packet bodies or peer addresses"
        )
        checks.append(
            "relay live signed-session binding, Replay platform enforcement, authenticated DISCONNECT_ACK and closed-route rejection; real transport counters"
        )
    finally:
        for item in opened:
            item.close()
