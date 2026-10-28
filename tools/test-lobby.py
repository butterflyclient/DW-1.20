"""Independent native-wire client, isolated credentials/data, no game launch.

Uses cryptography instead of the server's CNG functions to detect mismatched
transcript hashing, HKDF, AES record offsets, MAC direction and serializers.
"""

import base64, hashlib, hmac, json, os, socket, struct, subprocess, time
import argparse
from pathlib import Path
import urllib.request, urllib.error
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--startup-only", action="store_true",
                    help="Stop after encrypted startup, social, publisher and user-profile storage contracts")
parser.add_argument("--host-controls-only", action="store_true")
parser.add_argument("--matchmaking-transaction-only", action="store_true")
args = parser.parse_args()
exe = Path(os.environ.get("IW8_DW_TEST_SERVER", str(root / "build" / "Release" / "iw8-dw-server.exe")))
# Imported fixture modules share this subprocess module. The Windows window
# suppression flag has no purpose on Linux; zero retains normal POSIX launch.
if os.name != "nt":
    subprocess.CREATE_NO_WINDOW = 0
directory = root / "data" / ("protocol-fixture-" + str(time.time_ns()))
directory.mkdir()
# Provision a real second identity with the server's issuer. This is not a
# forged auth ticket or a direct write into the relationship store.
subprocess.run(
    [str(exe), str(directory), "--provision-profile", "peer", "Fixture Peer"],
    check=True,
    stdout=subprocess.DEVNULL,
    creationflags=subprocess.CREATE_NO_WINDOW,
)
subprocess.run(
    [
        str(exe),
        str(directory),
        "--provision-profile",
        "rename",
        "Rename Original",
    ],
    check=True,
    stdout=subprocess.DEVNULL,
    creationflags=subprocess.CREATE_NO_WINDOW,
)
subprocess.run(
    [str(exe), str(directory), "--provision-profile", "account", "Account Original"],
    check=True,
    stdout=subprocess.DEVNULL,
    creationflags=subprocess.CREATE_NO_WINDOW,
)


def choose_offset():
    for offset in range(10000, 10200):
        sockets = []
        try:
            for port in (8085, 8443, 3075):
                s = socket.socket()
                sockets.append(s)
                s.bind(("127.0.0.1", port + offset))
            return offset
        except OSError:
            pass
        finally:
            for s in sockets:
                s.close()
    raise RuntimeError("No isolated fixture ports available")


offset = choose_offset()
base = f"http://127.0.0.1:{8085 + offset}"
output = (directory / "stdout.log").open("wb")
process = subprocess.Popen(
    [str(exe), str(directory), "--port-offset", str(offset)],
    stdout=output,
    stderr=subprocess.STDOUT,
    creationflags=subprocess.CREATE_NO_WINDOW,
)
checks = []


def post(path, value):
    data = value if isinstance(value, bytes) else json.dumps(value).encode()
    return urllib.request.urlopen(
        urllib.request.Request(base + path, data, {"Content-Type": "application/json"}),
        timeout=5,
    )


def u32(x):
    return b"\x08" + struct.pack("<I", x)


def u64(x):
    return b"\x0a" + struct.pack("<Q", x)


def text(x):
    return b"\x10" + x.encode() + b"\0"


def blob(x):
    return b"\x13" + u32(len(x)) + x


def boolean(x):
    return b"\x01" + bytes([int(x)])


def expand(key, info, size):
    out = previous = b""
    for index in range(1, 256):
        previous = hmac.digest(key, previous + info + bytes([index]), "sha1")
        out += previous
        if len(out) >= size:
            return out[:size]
    raise AssertionError("HKDF size")


def exact(s, size):
    result = b""
    while len(result) < size:
        part = s.recv(size - len(result))
        if not part:
            raise EOFError("fixture connection closed")
        result += part
    return result


def read_frame(s):
    size = exact(s, 4)
    return size + exact(s, struct.unpack("<I", size)[0])


def send_fragments(s, message):
    for start in range(0, len(message), 17):
        s.sendall(message[start : start + 17])


try:
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError("Fixture server exited; inspect its log")
        try:
            with urllib.request.urlopen(base + "/health", timeout=0.3) as response:
                status = json.load(response)
            break
        except (OSError, urllib.error.URLError):
            time.sleep(0.05)
    else:
        raise RuntimeError("Fixture server did not become ready")
    assert (
        status["native_tasks"]
        and status["profiles"]
        and status["native_game_verified"] is False
    )
    with post("/platform/login", os.urandom(32)) as response:
        platform = response.read()
    user = struct.unpack_from("<Q", platform, 56)[0]
    credentials = {
        "session_token": platform[112:176].decode(),
        "account_token": platform[177:241].decode(),
    }
    # Actual Replay native auth metadata, not an unrelated title fixture.
    seed, title = 197892, 5800
    request = {
        "auth_task": "84",
        "iv_seed": str(seed),
        "title_id": str(title),
        "extra_data": json.dumps(credentials),
    }
    with post("/auth/", request) as response:
        raw = response.read()
        signature = base64.b64decode(response.headers["X-Signature"], validate=True)
    public = (directory / "platform-public.blob").read_bytes()
    magic, bits, exponent_size, modulus_size, _, _ = struct.unpack_from("<6I", public)
    assert bits == 2048 and magic == 0x31415352
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
    checks.append("native decimal-string auth and zero-salt RSA signature")
    legacy = {
        "ticket": auth["server_ticket"],
        "initialVectorSeed": base64.b64encode(str(seed).encode()).decode(),
        "titleID": title,
    }
    with post("/v1.0/tokens/lsg/?client=replaylocal", legacy) as response:
        account = json.load(response)
        rename_access_token = account["accessToken"]
        assert (
            account["umbrellaID"] == user
            and account["expires"] > time.time()
            and len(account["accessToken"]) == 64
        )
    for bad in (
        {**legacy, "initialVectorSeed": "bad"},
        {**legacy, "titleID": title + 1},
    ):
        try:
            post("/v1.0/tokens/lsg/?client=replaylocal", bad)
        except urllib.error.HTTPError as e:
            assert e.code == 400
        else:
            raise AssertionError("Legacy ticket binding failed")
    checks.append("legacy account ticket/title/IV binding")

    class Client:
        def __init__(self, bad_ticket=False, bad_verify=False, auth_identity=None):
            session_ticket, session_key = (
                (ticket, key) if auth_identity is None else auth_identity
            )
            self.fixture_auth_identity = (session_ticket, session_key)
            self.s = socket.create_connection(("127.0.0.1", 3075 + offset), timeout=5)
            self.outgoing = self.incoming = 1
            self.mail_notifications = []
            self.progression_notifications = []
            self.instant_notifications = []
            hello = struct.pack("<5I", 200, 200, 210, 220, 1024 * 1024) + os.urandom(8)
            send_fragments(self.s, hello)
            ack = read_frame(self.s)
            assert (
                len(ack) == 26
                and ack[4:6] == b"\xab\x81"
                and struct.unpack_from("<I", ack, 6)[0] == 210
            )
            self.connection = struct.unpack_from("<Q", ack, 10)[0]
            auth_bits = []

            def bits(value, count):
                auth_bits.extend((value >> i) & 1 for i in range(count))

            bits(7, 8)
            bits(1, 1)
            bits(8, 5)
            bits(title, 32)
            bits(8, 5)
            bits(seed, 32)
            current_ticket = bytearray(session_ticket)
            if bad_ticket:
                current_ticket[30] ^= 1
            for value in current_ticket:
                bits(value, 8)
            while len(auth_bits) % 8:
                auth_bits.append(0)
            bitbuffer = bytes(
                sum(auth_bits[j + i] << i for i in range(8))
                for j in range(0, len(auth_bits), 8)
            )
            prefix = struct.pack("<I", len(bitbuffer) + 10) + b"\xab\x82" + bitbuffer
            transcript = hello[8:] + ack + prefix
            traffic_session = expand(
                session_key, (root / "data" / "replay-traffic-kdf.bin").read_bytes(), 24
            )
            prk = hmac.digest(
                hashlib.sha1(transcript).digest(), traffic_session, "sha1"
            )
            challenge = expand(prk, b"CLIENTCHAL", 16)
            verify = bytearray(challenge[:8])
            if bad_verify:
                verify[0] ^= 1
            send_fragments(self.s, prefix + verify)
            if bad_ticket or bad_verify:
                assert self.s.recv(1) == b""
                self.s.close()
                return
            done = read_frame(self.s)
            assert done[4:] == b"\xab\x83" + challenge[8:]
            self.material = expand(prk, b"BDDATA", 72)
            connection_type, connection_data = self.receive()
            assert connection_type == 4 and connection_data == u64(self.connection)

        def close(self):
            self.s.close()

        def record(self, payload, sequence=None):
            if sequence is None:
                sequence = self.outgoing
                self.outgoing += 1
            plain = struct.pack("<I", len(payload)) + b"\x86" + payload
            plain += bytes((-len(plain)) % 16)
            iv = os.urandom(16)
            encryptor = Cipher(
                algorithms.AES(self.material[40:56]), modes.CBC(iv)
            ).encryptor()
            ciphertext = encryptor.update(plain) + encryptor.finalize()
            record = (
                struct.pack("<I", len(ciphertext) + 30)
                + b"\xab\x85"
                + struct.pack("<I", sequence)
                + iv
                + ciphertext
            )
            return record + hmac.digest(self.material[:20], record, "sha1")[:8]

        def receive_record(self):
            packet = read_frame(self.s)
            assert packet[4:6] == b"\xab\x85"
            assert struct.unpack_from("<I", packet, 6)[0] == self.incoming
            self.incoming += 1
            assert hmac.compare_digest(
                packet[-8:], hmac.digest(self.material[20:40], packet[:-8], "sha1")[:8]
            )
            decryptor = Cipher(
                algorithms.AES(self.material[56:72]), modes.CBC(packet[10:26])
            ).decryptor()
            plain = decryptor.update(packet[26:-8]) + decryptor.finalize()
            size = struct.unpack_from("<I", plain)[0]
            assert plain[5 + size :] == bytes(len(plain) - 5 - size)
            return plain[4], plain[5 : 5 + size]

        def receive(self, take_instant=True):
            if take_instant and self.instant_notifications:
                return self.instant_notifications.pop(0)
            # Native onNewMail is asynchronous and may precede a later task's
            # result. Keep its exact bare event for the dedicated mail checks;
            # all other unsolicited records retain their existing strict order.
            for _ in range(64):
                record = self.receive_record()
                if record == (2, u32(18)):
                    self.mail_notifications.append(record)
                    continue
                if record[0] == 2 and record[1].startswith(u32(67)):
                    from progression_delivery_fixtures import decode_reward
                    decode_reward(record[1])
                    self.progression_notifications.append(record)
                    continue
                return record
            raise AssertionError("Unexpected native notification flood")

        def receive_mail(self):
            if self.mail_notifications:
                return self.mail_notifications.pop(0)
            record = self.receive_record()
            assert record == (2, u32(18))
            return record

        def task(
            self, service, task, params=b"", error=0, structured=False, terminator=True
        ):
            send_fragments(
                self.s,
                self.record(
                    bytes([service, 3, task]) + params + (b"\0" if terminator else b"")
                ),
            )
            kind, data = self.receive()
            # A native self-instant message can arrive before its own task
            # acknowledgement now that recipient writes determine success.
            # Retain this exact Push21 for the dedicated message assertion;
            # other service/push ordering contracts stay strict.
            instant_count = 0
            while service == 6 and task == 14 and kind == 2 and data.startswith(u32(21)):
                instant_count += 1
                assert instant_count <= 64, "Unexpected native instant-message flood"
                self.instant_notifications.append((kind, data))
                kind, data = self.receive(take_instant=False)
            assert kind == 1
            assert (
                data[0] == 10
                and data[9] == 8
                and struct.unpack_from("<I", data, 10)[0] == error
            )
            if error:
                assert len(data) == 14
                return []
            assert data[14:16] == bytes([3, task])
            if structured:
                assert data[16:18] == bytes([23, 8])
                size = struct.unpack_from("<I", data, 18)[0]
                assert len(data) == 22 + size
                return data[22:]
            assert data[16] == 8
            count = struct.unpack_from("<I", data, 17)[0]
            if not count:
                assert len(data) == 21
                return []
            assert data[21] == 8 and struct.unpack_from("<I", data, 22)[0] == count
            return data[26:]

        def lsg_bandwidth(self, request, error=0):
            send_fragments(self.s, self.record(bytes([18, 1]) + request))
            kind, data = self.receive()
            assert kind == 5 and len(data) >= 9
            assert struct.unpack_from("<Q", data)[0] > 0
            if error:
                assert data[8:] == bytes([1]) + struct.pack("<H", error)
                return b""
            assert data[8] == 0
            return data[9:]

    Client(bad_ticket=True)
    Client(bad_verify=True)
    client = Client()
    checks.append(
        "fragmented native 210 hello, typed bit auth, KDF and mutual challenge"
    )

    def i64(value):
        return b"\x09" + struct.pack("<q", value)

    def counters(items):
        return b"".join(u32(number) + i64(value) for number, value in items)

    assert client.task(23, 2, u32(71) + u32(72)) == counters([(71, 0), (72, 0)])
    assert client.task(23, 1, counters([(71, 5), (72, -9), (71, 3)])) == []
    assert client.task(23, 2, u32(72) + u32(71) + u32(71)) == counters(
        [(72, -9), (71, 8), (71, 8)]
    )
    assert client.task(23, 1, counters([(74, (1 << 63) - 2), (75, -(1 << 63))])) == []
    counterpath = directory / "counters" / f"{title}.json"
    counter_before = counterpath.read_bytes()
    for parameters in (
        counters([(73, 1), (74, 1)]),
        counters([(75, -1)]),
        u32(71) + b"\x14",
        counters([(73, 2)]) + u32(72) + b"\x09\x01",
        u32(0xFFFFFFFF) + i64(1),
    ):
        client.task(23, 1, parameters, error=106)
        assert counterpath.read_bytes() == counter_before
    assert client.task(23, 1) == [] and client.task(23, 2) == []
    client.task(23, 2, u64(71), error=106)
    checks.append(
        "complete native UInt32/Int64 global counters, duplicate ordering, signed limits, NAN rejection and atomic malformed/overflow rollback"
    )
    client.lsg_bandwidth(bytes([1]) + bytes(20), error=106)
    client.lsg_bandwidth(bytes([0, 2]) + bytes(14), error=106)
    client.lsg_bandwidth(bytes([0, 1]), error=106)
    config = client.lsg_bandwidth(bytes([0, 1]) + os.urandom(14))
    assert len(config) == 42
    (
        packet_size,
        packet_count,
        wait_ms,
        upload_ms,
        first_timeout,
        download_ms,
        idle_ms,
        udp_port,
    ) = struct.unpack_from("<7IH", config)
    host = socket.inet_ntoa(config[30:34])
    nonce = config[34:42]
    assert (
        host == "127.0.0.1"
        and 12 <= packet_size <= 1400
        and 32 <= packet_count <= 1024
        and udp_port
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind(("127.0.0.1", 0))
        udp.settimeout(3)

        def packet(sequence, token=nonce):
            return struct.pack("<I", sequence) + token + bytes(packet_size - 12)

        udp.sendto(packet(0, bytes(8)), (host, udp_port))
        # Offer 32 real packets, plus a duplicate and invalid sequence. Server
        # counts each authenticated packet once and derives upload from receive.
        started = time.monotonic()
        for sequence in range(32):
            target = started + sequence * (upload_ms / 1000) / 32
            time.sleep(max(0, target - time.monotonic()))
            udp.sendto(packet(sequence), (host, udp_port))
        udp.sendto(packet(31), (host, udp_port))
        udp.sendto(packet(packet_count), (host, udp_port))
        received = []
        began = None
        elapsed = 0
        for _ in range(packet_count):
            datagram, sender = udp.recvfrom(2048)
            assert (
                sender == (host, udp_port)
                and len(datagram) == packet_size
                and datagram[4:12] == nonce
            )
            sequence = struct.unpack_from("<I", datagram)[0]
            assert sequence < packet_count and sequence not in received
            current = time.monotonic()
            if began is None:
                began = current
            received.append(sequence)
            elapsed = int((current - began) * 1000)
        download_bytes = len(received) * (packet_size + 8)
        report = struct.pack(
            "<5I",
            download_bytes,
            elapsed,
            sum(received) // len(received),
            min(received),
            max(received),
        )
        client.lsg_bandwidth(
            bytes([1]) + struct.pack("<5I", download_bytes + 1, elapsed, 0, 0, 0),
            error=106,
        )
        measured = client.lsg_bandwidth(bytes([1]) + report)
        assert len(measured) == 20
        upload_bytes, measured_ms, average, minimum, maximum = struct.unpack(
            "<5I", measured
        )
        assert (
            upload_bytes == 32 * (packet_size + 8)
            and 150 <= measured_ms <= upload_ms + 100
        )
        assert (average, minimum, maximum) == (15, 0, 31)
    client.lsg_bandwidth(bytes([1]) + report, error=106)
    checks.append(
        "raw LSG message-5 bandwidth completion, actual UDP transfer, nonce/counter validation and report bounds"
    )
    seconds = client.task(12, 6)
    assert (
        seconds[0] == 8
        and abs(struct.unpack_from("<I", seconds, 1)[0] - time.time()) < 5
    )
    milliseconds = client.task(12, 12)
    assert (
        milliseconds[0] == 10
        and abs(struct.unpack_from("<Q", milliseconds, 1)[0] - time.time() * 1000)
        < 5000
    )
    checks.append("native encrypted server-time task replies and result headers")
    assert client.task(151, 1) == boolean(False)
    esports_path = directory / "esports" / str(title) / "registered.json"
    esports_path.parent.mkdir(parents=True)
    esports_path.write_text(json.dumps({"schema": 1, "registered": [user]}))
    assert client.task(151, 1) == boolean(True)
    esports_path.write_text(json.dumps({"schema": 1, "registered": [user + 1]}))
    assert client.task(151, 1) == boolean(False)
    esports_path.write_text(json.dumps({"schema": 1, "registered": [-1]}))
    client.task(151, 1, error=102)
    esports_path.unlink()
    client.task(151, 1, u32(1), error=106)
    checks.append(
        "native esports registration boolean, explicit local publication, account selection and malformed-store rejection"
    )
    info = (
        u32(4)
        + u32(967)
        + u64(0)
        + u64(0)
        + u64(0)
        + blob(bytes(6))
        + text("replay-local-platform-v1")
    )
    assert client.task(38, 6, info) == []
    assert client.task(38, 6, b"broken", error=106) == []
    assert client.task(250, 9, error=108) == []
    assert client.task(250, 9, error=108, terminator=False) == []
    checks.append(
        "extended auth reporting and explicit malformed/unimplemented task errors"
    )
    from challenge_response_fixtures import (
        exercise as exercise_challenge_responses,
        check_peer as check_peer_challenge_responses,
    )

    challenge_fixture = exercise_challenge_responses(
        client, directory, title, user, blob, checks
    )
    profile = os.urandom(256)
    assert client.task(8, 3, blob(profile)) == []
    assert client.task(8, 1, u64(user)) == u64(user) + blob(profile)
    private = os.urandom(512)
    assert client.task(8, 4, blob(private)) == []
    assert client.task(8, 2) == u64(user) + blob(private)
    assert client.task(8, 7, u64(user + 1), error=101) == []
    checks.append("public/private profile write/read and owner isolation")
    owner = u64(user) + text("bnet")
    stats = os.urandom(1024)
    path = text("iw8") + text("fixture_stats.bin")
    meta = client.task(10, 10, path + boolean(True) + blob(stats) + owner + u32(1))
    assert meta.startswith(u32(len(stats))) and meta.endswith(
        owner + text("fixture_stats.bin")
    )
    assert client.task(10, 12, path + owner) == blob(stats)
    assert (
        client.task(10, 12, text("iw8") + text("not-present.bin") + owner, error=1000)
        == []
    )
    assert (
        client.task(
            10,
            10,
            text("iw8") + text("../escape") + boolean(True) + blob(stats) + owner,
            error=106,
        )
        == []
    )
    checks.append(
        "opaque stats storage, native file metadata, no-file error and traversal rejection"
    )
    universal = u64(user) + text("uno")
    meta = client.task(
        10,
        10,
        text("iw8")
        + text("fixture_universal.bin")
        + boolean(True)
        + blob(stats)
        + universal,
    )
    assert meta.endswith(universal + text("fixture_universal.bin"))
    assert client.task(
        10, 12, text("iw8") + text("fixture_universal.bin") + universal
    ) == blob(stats)
    client.task(
        10,
        12,
        text("iw8") + text("fixture_universal.bin") + u64(user + 1) + text("uno"),
        error=1000,
    )
    client.task(
        10,
        10,
        text("iw8")
        + text("fixture_universal.bin")
        + boolean(True)
        + blob(stats)
        + u64(user + 1)
        + text("uno"),
        error=101,
    )
    checks.append(
        "contextual storage universal-ID ownership and matching native account-type metadata"
    )
    varpath = directory / "publisher-variables" / str(title) / "iw8"
    varpath.mkdir(parents=True)
    (varpath / "fixture.json").write_text(json.dumps({"fixture_value": "1"}))
    variables = client.task(95, 1, text("iw8") + text("fixture"))
    assert variables.startswith(b"\x06\x01\x00\x06\x00\x00" + text("fixture"))

    def vint(value):
        result = b""
        while value >= 128:
            result += bytes([(value & 127) | 128])
            value >>= 7
        return result + bytes([value])

    def pb_text(tag, value):
        raw = value.encode()
        return vint((tag << 3) | 2) + vint(len(raw)) + raw

    def pb_integer(tag, value):
        return vint(tag << 3) + vint(value)

    def pb_bytes(tag, raw):
        return vint((tag << 3) | 2) + vint(len(raw)) + raw

    def pb_fields(data):
        position = 0
        fields = []

        def varint():
            nonlocal position
            value = 0
            for shift in range(0, 70, 7):
                assert position < len(data)
                byte = data[position]
                position += 1
                value |= (byte & 127) << shift
                if not byte & 128:
                    return value
            raise AssertionError("protobuf varint overflow")

        while position < len(data):
            key = varint()
            tag, kind = key >> 3, key & 7
            if kind == 0:
                value = varint()
            elif kind == 2:
                size = varint()
                value = data[position : position + size]
                assert len(value) == size
                position += size
            elif kind in (1, 5):
                size = 8 if kind == 1 else 4
                value = data[position : position + size]
                assert len(value) == size
                position += size
            else:
                raise AssertionError("protobuf wire type")
            fields.append((tag, kind, value))
        return fields

    def pb_map(data):
        result = {}
        for tag, kind, value in pb_fields(data):
            result.setdefault(tag, []).append(value)
        return result

    def structure(raw):
        return b"\x17" + u32(len(raw)) + raw

    from content_domain_fixtures import exercise

    content_fixture = exercise(
        client,
        directory,
        title,
        user,
        base,
        (u32, u64, text, blob, structure, pb_text, pb_bytes),
        checks,
    )
    import multipart_content_fixtures

    multipart_fixture = multipart_content_fixtures.exercise(
        client, directory, title, user, base, (u32, u64, text), checks
    )
    import full_coverage_fixtures

    full_coverage_fixtures.exercise(
        client,
        directory,
        title,
        user,
        base,
        (u32, u64, text, structure, pb_text, pb_bytes, pb_fields),
        content_fixture,
        multipart_fixture,
        checks,
    )
    request_structure = pb_text(1, "iw8") + pb_text(2, "fixture")
    bulk = client.task(
        95,
        3,
        b"\x17" + u32(len(request_structure)) + request_structure,
        structured=True,
    )
    assert (
        bulk.startswith(b"\x0a")
        and pb_text(3, "fixture") in bulk
        and b"fixture_value" in bulk
    )
    assert client.task(95, 1, text("iw8") + text("missing"), error=108) == []
    checks.append(
        "configured publisher JSON, native protobuf bulk responses and absent-namespace error"
    )
    for namespace in (
        "general",
        "pc",
        "f2p",
        "general_8_19",
        "pc_8_19",
        "f2p_8_19",
        "autobuild",
    ):
        result = client.task(95, 1, text("iw8") + text(namespace))
        assert result == b"\x06\x01\x00\x06\x00\x00" + text(namespace) + text(
            json.dumps(
                {"MajorVersion": "1", "MinorVersion": "0"}, separators=(",", ":")
            )
        )
        assert client.task(95, 1, text("") + text(namespace)) == result
    client.task(95, 1, text("") + text("unknown_build"), error=108)
    client.task(95, 1, text("other") + text("autobuild"), error=108)
    native_bulk = client.task(
        95, 3, structure(pb_text(1, "") + pb_text(2, "autobuild")), structured=True
    )
    objects = pb_fields(native_bulk)
    assert len(objects) == 1 and objects[0][:2] == (1, 2)
    assert pb_fields(objects[0][2]) == [
        (1, 0, 1),
        (2, 0, 0),
        (3, 2, b"autobuild"),
        (
            4,
            2,
            json.dumps(
                {"MajorVersion": "1", "MinorVersion": "0"}, separators=(",", ":")
            ).encode(),
        ),
    ]
    (varpath / "versioned.json").write_text(
        json.dumps({"MajorVersion": "2", "MinorVersion": "7", "fixture_value": "1"})
    )
    assert client.task(95, 1, text("iw8") + text("versioned")).startswith(
        b"\x06\x02\x00\x06\x07\x00"
    )
    (varpath / "invalid.json").write_text(json.dumps({"MajorVersion": "65536"}))
    client.task(95, 1, text("iw8") + text("invalid"), error=106)
    (varpath / "invalid.json").write_text(json.dumps({"fixture_value": True}))
    client.task(95, 1, text("iw8") + text("invalid"), error=106)
    checks.append(
        "Replay publisher namespace defaults, matched version fields and native string-value validation"
    )
    marketing = structure(
        pb_text(1, "iw8")
        + pb_text(2, "en")
        + pb_bytes(3, pb_integer(1, 1) + pb_integer(2, 5))
    )
    assert client.task(104, 6, marketing, structured=True) == b""
    client.task(104, 6, structure(pb_text(1, "iw8")), error=106)
    client.task(
        104,
        6,
        structure(
            pb_text(1, "iw8")
            + pb_text(2, "en")
            + pb_bytes(3, pb_integer(1, 1) + pb_integer(2, 101))
        ),
        error=106,
    )
    checks.append(
        "same-Replay marketing location/count schema and native empty message collection"
    )
    import marketing_fixtures

    marketing_fixture = marketing_fixtures.exercise(
        client,
        directory,
        title,
        (structure, pb_integer, pb_text, pb_bytes),
        checks,
    )

    import loot_fixtures

    loot_fixture = loot_fixtures.exercise(
        client,
        directory,
        title,
        user,
        (structure, pb_integer, pb_text, pb_bytes, pb_fields),
        checks,
    )

    def enroll_params(owner, context="iw8"):
        return structure(
            pb_text(1, "POST")
            + pb_text(
                2,
                f"/v2/users/bnet-{owner}/enrollments/?client=replaylocal&context={context}",
            )
        )

    enrollment = pb_fields(client.task(194, 1, enroll_params(user), structured=True))
    assert (2, 0, 200) in enrollment
    enrollment_json = json.loads(next(v for t, k, v in enrollment if t == 3))
    assert (
        0 < enrollment_json["expiresIn"] <= 3600
        and len(enrollment_json["ABToken"]) == 64
        and enrollment_json["enrollments"] == []
    )
    client.task(194, 1, enroll_params(user + 1), error=101)
    client.task(
        194,
        1,
        structure(
            pb_text(1, "GET") + pb_text(2, f"/v2/users/bnet-{user}/enrollments/")
        ),
        error=106,
    )
    checks.append(
        "native A/B enrollment HTTP envelope, owned token lifetime and no experimental treatments"
    )
    import abtesting_fixtures

    ab_fixture = abtesting_fixtures.exercise(
        client, directory, title, user, enroll_params, pb_fields, checks
    )
    event_params = (
        u32(2)
        + u32(1)
        + boolean(False)
        + text("local-fixture")
        + u32(2)
        + boolean(True)
        + blob(bytes([1, 2, 3]))
    )
    assert client.task(67, 5, u32(0)) == []
    event_result = client.task(67, 5, event_params)
    assert event_result == u64(1) + u64(2)
    event_path = directory / "event-log" / str(title) / (str(user) + ".json")
    event_state = json.loads(event_path.read_text())
    assert event_state["nextId"] == 3 and len(event_state["events"]) == 2
    before_events = event_path.read_bytes()
    client.task(
        67,
        5,
        u32(2)
        + u32(1)
        + boolean(False)
        + text("first")
        + u32(2)
        + boolean(True)
        + b"\x13"
        + u32(5)
        + b"x",
        error=106,
    )
    assert event_path.read_bytes() == before_events
    large_event = os.urandom(32000)
    assert client.task(
        67,
        5,
        u32(2)
        + u32(2)
        + boolean(True)
        + blob(b"")
        + u32(3)
        + boolean(True)
        + blob(large_event),
    ) == u64(3) + u64(4)
    archives = list((event_path.parent / str(user) / "batches").glob("*.json"))
    assert len(archives) == 2
    archived_events = [
        event for path in archives for event in json.loads(path.read_text())["events"]
    ]
    assert sorted(event["id"] for event in archived_events) == [1, 2, 3, 4]
    near_limit = json.loads(event_path.read_text())
    near_limit["events"] = [
        {
            "id": i + 1,
            "category": 1,
            "binary": True,
            "contentHex": "00" * 12000,
            "recorded": 123,
        }
        for i in range(170)
    ]
    near_limit["events"] += json.loads(event_path.read_text())["events"]
    event_path.write_text(json.dumps(near_limit, separators=(",", ":")))
    assert event_path.stat().st_size < 4 * 1024 * 1024
    assert client.task(
        67, 5, u32(1) + u32(1) + boolean(True) + blob(bytes(120000))
    ) == u64(5)
    assert (
        event_path.stat().st_size < 4 * 1024 * 1024
        and json.loads(event_path.read_text())["events"][-1]["id"] == 5
    )
    assert any(
        json.loads(path.read_text())["first_id"] == 5
        for path in (event_path.parent / str(user) / "batches").glob("*.json")
    )
    checks.append(
        "native event ingestion archives full batches and keeps the recent-event window within its byte budget"
    )
    checks.append(
        "native mixed event serializers, durable monotonic result IDs and atomic malformed-batch rejection"
    )
    qos_query = text(
        json.dumps(
            {"qos_build_name": "iw8-local-fixture", "qos_build_name_context": "iw8"}
        )
    )
    initiated = client.task(145, 25, qos_query)
    empty_qos = json.loads(initiated[1:-1])
    assert initiated[0] == 16 and initiated[-1] == 0
    assert (
        empty_qos["transaction_id"] > 0
        and empty_qos["hosts"] == []
        and empty_qos["num_probes"] == 3
    )
    assert client.task(145, 4, u64(empty_qos["transaction_id"]) + u64(0)) == []
    assert client.task(145, 16, u64(1) + u64(user)) == bytes([116, 8]) + struct.pack(
        "<II", 0, 0
    )
    client.task(145, 25, text("[]"), error=106)
    client.task(145, 16, u64(1) + u64(user + 1), error=101)
    client.task(145, 4, u64(0) + u64(0), error=101)
    checks.append(
        "native DCQoS empty-fleet transaction/report/preferences and owner/parameter rejection"
    )
    client.task(145, 3, error=108)
    player_info = {
        "dedicated_server": {"build_name": "replay-local-fixture"},
        "listen_server": {
            "local_address": base64.b64encode(bytes(84)).decode(),
            "security_id": base64.b64encode(bytes(8)).decode(),
            "security_key": base64.b64encode(bytes(16)).decode(),
        },
        "game_state": {"map_packs": ["MP_ORIGINAL_MAPS"]},
        "hardware": "pc",
    }
    player_json = json.dumps(player_info, separators=(",", ":"))
    assert client.task(145, 2, text(player_json)) == []
    player_path = (
        directory / "matchmaking" / str(title) / "players" / (str(user) + ".json")
    )
    player_before = player_path.read_bytes()
    assert (
        client.task(145, 2, text(player_json)) == []
        and player_path.read_bytes() == player_before
    )
    for malformed in ("{}", "[]", "broken"):
        client.task(145, 2, text(malformed), error=106)
        assert player_path.read_bytes() == player_before
    client.task(145, 2, blob(player_json.encode() + b"\0"), error=106)
    client.task(145, 20, error=14526)
    match_token_result = client.task(145, 3)
    assert len(match_token_result) == 9 and match_token_result[0] == 10
    match_token = struct.unpack_from("<Q", match_token_result, 1)[0]
    assert match_token and client.task(145, 3) == u64(match_token)
    player_state = json.loads(player_path.read_text())
    assert (
        player_state["user"] == user
        and player_state["title"] == title
        and player_state["info"] == player_info
        and player_state["revision"] == 1
    )
    assert (
        player_state["token"] == match_token
        and player_state["token_expires"] > time.time()
    )
    checks.append(
        "native player-info typed string, atomic idempotent persistence, account-bound UInt64 matchmaking token and not-in-tournament completion"
    )
    import runpy

    catalog_receipt = runpy.run_path(
        str(root / "tools" / "prepare-playlist-catalog.py")
    )["prepare"](directory, ["mp_shipment"], 1)
    match_query = {
        "members": [user],
        "tokens": [match_token],
        "player_id_to_slots": {str(user): 0},
        "ruleset_payload": {
            "filter": {
                "playlist_id": 1,
                "netcode_version": 1,
                "playlist_version": catalog_receipt["version"],
            }
        },
    }

    def string_results(raw):
        strings = []
        while raw:
            assert raw[0] == 16
            end = raw.index(0, 1)
            strings.append(raw[1:end].decode())
            raw = raw[end + 1 :]
        return strings

    search = json.loads(
        string_results(client.task(145, 18, text(json.dumps(match_query))))[0]
    )
    mm_id = search["mm_id"]
    assert mm_id > 0
    lobbytype, lobby_push = client.receive()
    assert lobbytype == 2 and lobby_push.startswith(u32(2005) + u64(mm_id))
    lobby_id = struct.unpack_from("<Q", lobby_push, 15)[0]
    assert lobby_id > 0 and lobby_push[23:32] == u64(1)
    host_doc, backend_doc = map(json.loads, string_results(lobby_push[32:]))
    assert (
        host_doc["listen_server"]["host_player_id"] == user
        and backend_doc["lobby_id"] == lobby_id
    )
    assert backend_doc["dtls"] == {
        k: player_info["listen_server"][k] for k in ["security_id", "security_key"]
    }
    assert host_doc["player_state"] == {str(user): 2} and backend_doc[
        "player_id_to_mm_id"
    ] == {str(user): mm_id}
    rules = backend_doc["ruleset_payload"]
    assert rules["map_weights"]["mp_shipment"] == 1 and all(
        weight == 0
        for name, weight in rules["map_weights"].items()
        if name != "mp_shipment"
    )
    assert (
        rules["dvar_overrides"]["LLNLRTQRPO"] == 1
        and rules["dvar_overrides"]["MRQQOSRRPK"] == 1
    )
    selection = json.loads(
        (
            directory
            / "matchmaking"
            / str(title)
            / "lobbies"
            / (str(lobby_id) + ".json")
        ).read_text()
    )["match_selection"]
    assert selection["playlist_id"] == 1 and all(
        e["map"] == "mp_shipment" for e in selection["eligible_entries"]
    )
    assert selection["game_types"]["tdm"]["script"] == "war"
    client.task(
        145,
        18,
        text(
            json.dumps(
                {
                    **match_query,
                    "ruleset_payload": {
                        "filter": {
                            "playlist_id": 127,
                            "playlist_version": catalog_receipt["version"],
                        }
                    },
                }
            )
        ),
        error=108,
    )
    client.task(
        145,
        18,
        text(
            json.dumps(
                {
                    **match_query,
                    "ruleset_payload": {
                        "filter": {
                            "playlist_id": 1,
                            "playlist_version": catalog_receipt["version"] + 1,
                        }
                    },
                }
            )
        ),
        error=108,
    )
    checks.append(
        "owner playlist catalog, native version and map weights, Shipment-only policy, exact mode script/rules and unavailable selection rejection"
    )
    assert list(
        map(json.loads, string_results(client.task(145, 13, u64(lobby_id))))
    ) == [host_doc, backend_doc]
    updated = {**host_doc, "game_state": {"state": "countdown"}}
    assert client.task(
        145, 15, u64(lobby_id) + u64(1) + text(json.dumps(updated))
    ) == boolean(True)
    push_kind, push = client.receive()
    assert push_kind == 2 and push.startswith(u32(2006) + u64(lobby_id) + u64(2))
    docs = list(map(json.loads, string_results(push[23:])))
    assert docs[0]["game_state"]["state"] == "countdown" and docs[1]["update_id"] == 2
    assert client.task(
        145, 15, u64(lobby_id) + u64(1) + text(json.dumps(updated))
    ) == boolean(False)
    client.task(
        145,
        18,
        text(json.dumps({**match_query, "tokens": [match_token + 1]})),
        error=14507,
    )
    client.task(
        145,
        18,
        text(
            json.dumps(
                {
                    **match_query,
                    "members": [user, user],
                    "tokens": [match_token, match_token],
                }
            )
        ),
        error=106,
    )
    assert client.task(145, 8, u64(mm_id)) == boolean(True)
    assert client.task(145, 9, u64(mm_id)) == boolean(True)
    client.task(145, 13, u64(lobby_id + 1), error=108)
    client.task(145, 8, u64(0), error=106)
    assert client.task(145, 10, u64(lobby_id)) == []
    assert client.receive() == (2, u32(2002) + u64(lobby_id) + u64(0))
    assert client.task(145, 10, u64(lobby_id)) == []
    client.task(145, 13, u64(lobby_id), error=108)
    client.task(145, 10, u64(0), error=106)
    client.task(145, 10, u64(lobby_id + 1), error=108)
    assert json.loads(
        (
            directory
            / "matchmaking"
            / str(title)
            / "lobbies"
            / (str(lobby_id) + ".json")
        ).read_text()
    )["disbanded"]
    checks.append(
        "native matchmaker search/token checks, complete create/update pushes, persisted lobby documents, revision conflicts and cancel/shutdown results"
    )
    checks.append(
        "native owner-only lobby disband, async notification, closed document reads and idempotent teardown"
    )
    cancelled = json.loads(
        string_results(client.task(145, 18, text(json.dumps(match_query))))[0]
    )["mm_id"]
    assert client.task(145, 8, u64(cancelled)) == boolean(True)
    time.sleep(0.35)
    assert client.task(12, 6).startswith(
        b"\x08"
    )  # no queued create push precedes this reply
    retired = json.loads(
        string_results(client.task(145, 18, text(json.dumps(match_query))))[0]
    )["mm_id"]
    client.close()
    client = Client()
    time.sleep(0.35)
    assert client.task(12, 6).startswith(b"\x08")
    assert client.task(145, 8, u64(retired)) == boolean(True)
    checks.append(
        "cancelled searches suppress queued create notifications and fresh connections do not inherit retired-session pushes"
    )
    # Exercise every supplied playlist's backend selection on the encrypted
    # wire. No maps are launched, and the game-root policy is never changed.
    catalog_root = directory / "playlists" / str(title)
    policy_path = catalog_root / "policy.json"
    original_policy = policy_path.read_bytes()
    policy_path.unlink()
    catalog = json.loads((catalog_root / "catalog.json").read_text())
    for playlist in catalog["playlists"]:
        query = {
            **match_query,
            "ruleset_payload": {
                "filter": {
                    "playlist_id": playlist["playlist"],
                    "playlist_version": catalog["system"]["version"],
                }
            },
        }
        search_id = json.loads(
            string_results(client.task(145, 18, text(json.dumps(query))))[0]
        )["mm_id"]
        kind, push = client.receive()
        assert kind == 2 and push.startswith(u32(2005) + u64(search_id))
        identifier = struct.unpack_from("<Q", push, 15)[0]
        host, backend = map(json.loads, string_results(push[32:]))
        assert (
            backend["ruleset_payload"]["filter"]["playlist_id"] == playlist["playlist"]
        )
        assert (
            backend["ruleset_payload"]["filter"]["playlist_version"]
            == catalog["system"]["version"]
        )
        expected = {e["map"]: e["weight"] for e in playlist["maps"][:20]}
        assert backend["ruleset_payload"]["map_weights"] == expected
        persisted = json.loads(
            (
                directory
                / "matchmaking"
                / str(title)
                / "lobbies"
                / (str(identifier) + ".json")
            ).read_text()
        )
        assert persisted["match_selection"]["eligible_entries"] == [
            e for e in playlist["maps"][:20] if e["weight"] > 0
        ]
        assert client.task(145, 10, u64(identifier)) == []
        assert client.receive() == (2, u32(2002) + u64(identifier) + u64(0))
    policy_path.write_bytes(original_policy)
    checks.append(
        "all 63 owner playlists select with matching versions, native 20-entry weight bounds, exact mode/map metadata and encrypted lifecycle replies"
    )

    def channel_request(category, channel=0, subscriber=0):
        return structure(
            pb_text(1, category) + pb_integer(2, channel) + pb_integer(3, subscriber)
        )

    def channel_info(params):
        envelope = pb_fields(client.task(198, 6, params, structured=True))
        assert len(envelope) == 1 and envelope[0][:2] == (1, 2)
        return dict((t, v) for t, k, v in pb_fields(envelope[0][2]))

    channel_fields = channel_info(channel_request("party"))
    channel_id = channel_fields[2]
    assert channel_fields[1] == b"party" and channel_id > 0 and channel_fields[3] == 1
    assert (
        channel_fields[4] == 200
        and channel_fields[5] == user
        and channel_fields[6] == 0
        and channel_fields[7] == 0
        and channel_fields[8] > 0
    )
    repeat = channel_info(channel_request("party", channel_id))
    assert repeat == channel_fields
    query = structure(
        pb_bytes(1, pb_text(1, "party") + pb_integer(2, channel_id) + pb_integer(3, 0))
    )
    infos = pb_fields(client.task(198, 7, query, structured=True))
    assert (
        len(infos) == 1
        and dict((t, v) for t, k, v in pb_fields(infos[0][2])) == channel_fields
    )
    members = pb_fields(
        client.task(198, 5, channel_request("party", channel_id, 200), structured=True)
    )
    assert len(members) == 1
    member_fields = dict((t, v) for t, k, v in pb_fields(members[0][2]))
    assert (
        member_fields[1] == user
        and member_fields[2] == b"DWPlayer"
        and member_fields[3] == 0
    )
    assert (
        client.task(198, 5, channel_request("party", channel_id, 0), structured=True)
        == b""
    )
    # A second independently encrypted connection receives unsolicited pushes
    # without sending a task first. Both connections belong to this fixture
    # account; no real game/player data or external recipient is involved.
    peer = Client()
    message = b"native-channel-fixture"
    sent = structure(
        pb_text(1, "party")
        + pb_integer(2, channel_id)
        + pb_bytes(3, message)
        + pb_integer(4, 7)
    )
    assert client.task(198, 3, sent, structured=True) == b""
    expected = (
        u32(22)
        + u64(user)
        + text("DWPlayer")
        + text("party")
        + u64(channel_id)
        + blob(message)
        + u32(7)
    )
    assert client.receive() == (2, expected) and peer.receive() == (2, expected)
    whisper = structure(
        pb_text(1, "party")
        + pb_integer(2, channel_id)
        + pb_integer(3, user)
        + pb_bytes(4, message)
        + pb_integer(5, 8)
    )
    assert client.task(198, 4, whisper, structured=True) == b""
    expected = (
        u32(23)
        + u64(user)
        + text("DWPlayer")
        + text("party")
        + u64(channel_id)
        + blob(message)
        + u32(8)
    )
    assert client.receive() == (2, expected) and peer.receive() == (2, expected)
    peer.close()
    client.task(
        198,
        3,
        structure(
            pb_text(1, "party")
            + pb_integer(2, channel_id)
            + pb_bytes(3, bytes(1025))
            + pb_integer(4, 7)
        ),
        error=106,
    )
    client.task(
        198,
        4,
        structure(
            pb_text(1, "party")
            + pb_integer(2, channel_id)
            + pb_integer(3, user + 1)
            + pb_bytes(4, message)
            + pb_integer(5, 8)
        ),
        error=101,
    )
    checks.append(
        "unsolicited authenticated cross-connection channel/whisper pushes, native message DTO, bounds and recipient membership"
    )
    assert (
        client.task(198, 2, channel_request("party", channel_id), structured=True)
        == b""
    )
    channelpath = directory / "channels" / (str(title) + ".json")
    assert not json.loads(channelpath.read_text())["channels"][
        "party:" + str(channel_id)
    ]["members"]
    assert (
        client.task(198, 1, channel_request("party", channel_id), structured=True)
        == b""
    )
    assert (
        str(user)
        in json.loads(channelpath.read_text())["channels"]["party:" + str(channel_id)][
            "members"
        ]
    )
    client.task(198, 1, channel_request("party", channel_id, user + 1), error=101)
    client.task(198, 1, channel_request("party", 0), error=106)
    client.task(198, 1, channel_request("missing", 123), error=108)
    client.task(198, 6, channel_request("../bad"), error=106)
    assert client.task(198, 12, structure(pb_text(1, "party")), structured=True) == b""
    assert not json.loads(channelpath.read_text())["channels"][
        "party:" + str(channel_id)
    ]["members"]
    checks.append(
        "native complete channel-info DTO, idempotent create/join, persisted subscriptions, category unsubscribe and caller ownership"
    )
    qos_config = directory / "qos" / str(title) / "configuration.json"
    qos_config.parent.mkdir(parents=True, exist_ok=True)
    address = bytes(range(84))
    qos_config.write_text(
        json.dumps(
            {
                "num_probes": 3,
                "datacenters": ["local"],
                "hosts": [
                    {
                        "address": base64.b64encode(address).decode(),
                        "security_id": base64.b64encode(b"12345678").decode(),
                        "security_key": base64.b64encode(b"0123456789abcdef").decode(),
                        "datacenter": base64.b64encode(b"local").decode(),
                    }
                ],
            }
        )
    )
    issued = client.task(145, 25, qos_query)
    qos_transaction = json.loads(issued[1:-1])["transaction_id"]
    samples = bytes([113, 8]) + struct.pack("<II3f", 12, 3, 0.01, 0.02, 0.03)
    # Same-Replay offsets +184/+188/+192 are bandwidthDown/bandwidthUp/
    # minLatency. Successful probes may report zero/UINT32_MAX bandwidth.
    record = (
        blob(address)
        + blob(bytes([127, 0, 0, 1]) + struct.pack("<H", 3074))
        + samples
        + blob(b"")
        + boolean(False)
        + u32(0)
        + u32(0xFFFFFFFF)
        + bytes([13])
        + struct.pack("<f", 0.01)
    )
    qos_report = u64(qos_transaction) + u64(1) + record
    client.task(145, 4, u64(qos_transaction) + u64(0), error=106)
    client.task(145, 4, qos_report[:-1], error=106)
    assert (
        client.task(145, 4, qos_report) == [] and client.task(145, 4, qos_report) == []
    )
    client.task(145, 4, qos_report[:-4] + struct.pack("<f", 0.03), error=106)
    assert (
        client.task(145, 16, u64(1) + u64(user))
        == bytes([116, 8]) + struct.pack("<II", 64, 1) + b"local\0"
    )
    checks.append(
        "native packed QoS float/string arrays, issued-host validation, durable reports and idempotent retries"
    )
    assert client.task(29, 10, text("iw8") + u32(0) + u32(10) + boolean(True)) == []
    assert (
        client.task(
            29,
            10,
            text("iw8") + u32(0) + u32(10) + boolean(False) + u64(user) + text("uno"),
        )
        == []
    )
    client.task(
        29,
        10,
        text("iw8") + u32(0) + u32(10) + boolean(False) + u64(user + 1) + text("uno"),
        error=101,
    )
    client.task(29, 10, text("iw8") + u32(0) + u32(1025) + boolean(True), error=106)
    checks.append(
        "native empty mail-header queries, request bounds and account ownership"
    )

    def mail_send(content, category=7, duration=0, bounce=False, sender=None):
        payload = (
            (b"" if sender is None else u64(sender) + text("uno"))
            + text("iw8")
            + blob(content)
            + b"\x06"
            + struct.pack("<H", category)
            + u32(1)
            + u64(user)
            + text("uno")
            + u32(duration)
            + boolean(bounce)
        )
        return client.task(
            29,
            9 if sender is None else 7,
            payload,
            error=101 if sender is not None and sender != user else 0,
        )

    def mail_headers(raw):
        offset = 0
        out = []

        def value(tag, fmt):
            nonlocal offset
            assert raw[offset] == tag
            offset += 1
            result = struct.unpack_from(fmt, raw, offset)[0]
            offset += struct.calcsize(fmt)
            return result

        def string():
            nonlocal offset
            assert raw[offset] == 16
            end = raw.index(0, offset + 1)
            result = raw[offset + 1 : end].decode()
            offset = end + 1
            return result

        while offset < len(raw):
            out.append(
                {
                    "sender": value(10, "<Q"),
                    "account": string(),
                    "name": string(),
                    "id": value(10, "<Q"),
                    "created": value(8, "<I"),
                    "size": value(8, "<I"),
                    "category": value(6, "<H"),
                    "read": value(1, "<?"),
                    "undelivered": value(1, "<?"),
                    "updated": value(8, "<I"),
                    "duration": value(8, "<I"),
                    "remaining": value(8, "<I"),
                }
            )
        return out

    def mail_ids(values):
        return (
            bytes([110, 8])
            + struct.pack("<II", 8 * len(values), len(values))
            + b"".join(struct.pack("<Q", v) for v in values)
        )

    def mail_get(values, remove=False, owner=None, error=0):
        return client.task(
            29,
            4,
            text("iw8")
            + boolean(remove)
            + mail_ids(values)
            + (b"" if owner is None else u64(owner) + text("uno")),
            error=error,
        )

    assert (
        mail_send(b"first message") == []
        and mail_send(b"second message", category=8) == []
    )
    mailpage = mail_headers(
        client.task(29, 10, text("iw8") + u32(0) + u32(1) + boolean(True))
    )
    assert (
        len(mailpage) == 1
        and mailpage[0]["id"] == 2
        and mailpage[0]["sender"] == user
        and mailpage[0]["name"] == "DWPlayer"
        and mailpage[0]["size"] == 14
        and mailpage[0]["category"] == 8
    )
    assert (
        not mailpage[0]["read"]
        and not mailpage[0]["undelivered"]
        and mailpage[0]["duration"] == 0
        and mailpage[0]["remaining"] == 0
    )
    assert mail_get([1]) == u64(1) + blob(b"first message")
    readpage = mail_headers(
        client.task(29, 10, text("iw8") + u32(0) + u32(10) + boolean(False))
    )
    assert [r["id"] for r in readpage] == [1, 2] and readpage[0]["read"]
    mailpath = directory / "mail" / str(title) / "iw8" / "messages.json"
    before_mail = mailpath.read_bytes()
    mail_get([1], owner=user + 1, error=101)
    assert mailpath.read_bytes() == before_mail
    mail_get([1, 1], error=106)
    assert mailpath.read_bytes() == before_mail
    assert (
        mail_send(b"impersonation", sender=user + 1) == []
        and mailpath.read_bytes() == before_mail
    )
    assert (
        mail_get([1], remove=True) == u64(1) + blob(b"first message")
        and mail_get([1]) == []
    )
    assert (
        client.task(29, 5, text("iw8") + mail_ids([123456])) == []
    )  # Missing deletion is idempotent.
    assert mail_send(b"expiration return", duration=1, bounce=True) == []
    # Move only this isolated fixture's timestamp into the past to check the
    # expiration boundary deterministically without waiting on wall-clock time.
    mail_store = json.loads(mailpath.read_text())
    mail_store["messages"][-1]["created"] = int(time.time()) - 2
    mailpath.write_text(json.dumps(mail_store))
    bounced = mail_headers(
        client.task(29, 10, text("iw8") + u32(0) + u32(10) + boolean(True))
    )
    assert (
        [r["id"] for r in bounced] == [4, 2]
        and bounced[0]["undelivered"]
        and not bounced[0]["read"]
    )
    assert mail_get([4], remove=True) == u64(4) + blob(b"expiration return")
    mailpage = mail_headers(
        client.task(29, 10, text("iw8") + u32(0) + u32(10) + boolean(True))
    )
    assert [r["id"] for r in mailpage] == [2]
    mail_saved = mailpath.read_bytes()
    for persisted_field, value in [
        ("next_id", -1),
        ("next_id", 4.5),
        ("recipient", -1),
        ("category", 1.5),
    ]:
        corrupt = json.loads(mail_saved)
        if persisted_field == "next_id":
            corrupt[persisted_field] = value
        else:
            corrupt["messages"][0][persisted_field] = value
        mailpath.write_text(json.dumps(corrupt))
        client.task(29, 10, text("iw8") + u32(0) + u32(10) + boolean(True), error=102)
    mailpath.write_bytes(mail_saved)
    checks.append(
        "complete native mail header/body DTOs, self-send, paging/read/delete, sender/owner binding and expiration return"
    )
    assert client.task(150, 1, u32(10)) == []
    scheduled = {
        "id": 73,
        "start": 100,
        "end": 200,
        "status": 1,
        "affinity": 18,
        "metadata": base64.b64encode(b'{"mode":"tdm"}').decode(),
        "users": [
            {"userID": user, "accountType": "uno"},
            {"userID": user + 1, "accountType": "bnet"},
        ],
    }
    schedulepath = directory / "scheduled-matches" / str(title) / "matches.json"
    schedulepath.parent.mkdir(parents=True)
    foreign_schedule = dict(
        scheduled, id=74, users=[{"userID": user + 1, "accountType": "uno"}]
    )
    schedulepath.write_text(
        json.dumps({"schema": 1, "matches": [scheduled, foreign_schedule]})
    )

    def schedule_info(row):
        users = row["users"]
        types = b"".join(u["accountType"].encode() + b"\0" for u in users)
        return (
            u64(row["id"])
            + u32(row["start"])
            + u32(row["end"])
            + blob(base64.b64decode(row["metadata"]))
            + u64(row["affinity"])
            + u32(row["status"])
            + bytes([110, 8])
            + struct.pack("<II", len(users) * 8, len(users))
            + b"".join(struct.pack("<Q", u["userID"]) for u in users)
            + bytes([116, 0])
            + struct.pack("<II", len(types), len(users))
            + types
        )

    assert client.task(150, 1, u32(10)) == schedule_info(scheduled) and client.task(
        150, 2, u64(73)
    ) == schedule_info(scheduled)
    client.task(150, 2, u64(74), error=101)
    client.task(150, 2, u64(75), error=108)
    assert client.task(150, 3, u64(73) + blob(b"round_started")) == []
    schedule_events = client.task(150, 4, u64(73) + u32(10))
    assert schedule_events.startswith(
        u64(73) + blob(b"round_started")
    ) and schedule_events.endswith(u64(1))
    eventpath = schedulepath.parent / "events.json"
    event_before = eventpath.read_bytes()
    client.task(150, 3, u64(74) + blob(b"forbidden"), error=101)
    assert eventpath.read_bytes() == event_before
    client.task(150, 1, u32(129), error=106)
    schedule_saved = schedulepath.read_bytes()
    corrupt = json.loads(schedule_saved)
    corrupt["matches"][0]["id"] = -1
    schedulepath.write_text(json.dumps(corrupt))
    client.task(150, 1, u32(10), error=102)
    schedulepath.write_bytes(schedule_saved)
    corrupt = json.loads(event_before)
    corrupt["events"][0]["owner"] = 1.5
    eventpath.write_text(json.dumps(corrupt))
    client.task(150, 4, u64(73) + u32(10), error=102)
    eventpath.write_bytes(event_before)
    checks.append(
        "published scheduled match DTOs with paired packed arrays, member filtering, bounded queries and atomic authenticated event journaling"
    )
    performance_params = text("iw8") + u32(2)
    assert (
        client.task(
            152, 1, performance_params + u64(user) + b"\x09" + struct.pack("<q", -71)
        )
        == []
    )
    performancepath = (
        directory / "performance" / str(title) / "iw8" / (str(user) + ".json")
    )
    performance_before = performancepath.read_bytes()
    client.task(
        152,
        1,
        performance_params
        + u64(user)
        + b"\x09"
        + struct.pack("<q", 20)
        + u64(user + 1)
        + b"\x09"
        + struct.pack("<q", 30),
        error=101,
    )
    assert performancepath.read_bytes() == performance_before
    assert client.task(152, 1, performance_params + u64(user) + b"\x14") == []
    assert json.loads(performancepath.read_text())["types"]["2"]["recent"] == [
        -71,
        None,
    ]
    performance_saved = performancepath.read_bytes()
    client.task(
        152,
        1,
        performance_params
        + u64(user)
        + b"\x09"
        + struct.pack("<q", 9223372036854775807),
        error=106,
    )
    client.task(
        152,
        1,
        text("iw8") + u32(0xFFFFFFFF) + u64(user) + b"\x09" + struct.pack("<q", 1),
        error=106,
    )
    for persisted_field, value in [("count", -1), ("recent", [1.5]), ("updated", -1)]:
        corrupt = json.loads(performance_saved)
        corrupt["types"]["2"][persisted_field] = value
        performancepath.write_text(json.dumps(corrupt))
        client.task(
            152,
            1,
            performance_params + u64(user) + b"\x09" + struct.pack("<q", 1),
            error=102,
        )
    performancepath.write_bytes(performance_saved)
    client.task(152, 1, text("../bad") + u32(2), error=106)
    client.task(152, 1, performance_params + u64(user), error=106)
    assert client.task(152, 1, performance_params) == []
    checks.append(
        "native performance batches preserve signed values/NAN, enforce owner isolation and reject whole malformed batches without partial commits"
    )
    user_state_request = structure(pb_text(1, "iw8"))
    assert client.task(125, 9, user_state_request, structured=True) == pb_text(1, "{}")
    assert client.task(
        125, 9, structure(pb_text(1, str(title))), structured=True
    ) == pb_text(1, "{}")
    statepath = (
        directory
        / "achievement-user-state"
        / str(title)
        / "iw8"
        / (str(user) + ".json")
    )
    assert json.loads(statepath.read_text()) == {}
    user_state = {
        "br_tutorial_rewarded": True,
        "battlepass0_owned": False,
        "player_xp_end_time": 0,
    }
    statepath.write_text(json.dumps(user_state))
    state_result = dict(
        (t, v)
        for t, k, v in pb_fields(
            client.task(125, 9, user_state_request, structured=True)
        )
    )
    # Battle Pass ownership is derived from authoritative season states. Keep
    # unrelated saved keys intact while clearing a stale projected flag.
    expected_state = {key: value for key, value in user_state.items()
                      if key != "battlepass0_owned"}
    assert json.loads(state_result[1]) == expected_state
    assert json.loads(statepath.read_text()) == user_state
    client.task(125, 9, structure(pb_text(1, "../escape")), error=106)
    client.task(125, 9, structure(pb_text(1, "iw8") + pb_text(1, "other")), error=106)
    checks.append(
        "native achievement user-state JSON, persistent per-account defaults and bounded context"
    )

    def reconcile_params(token):
        return structure(
            pb_text(1, str(title))
            + pb_text(2, token)
            + pb_text(3, "US")
            + pb_integer(4, 25)
            + pb_text(5, "")
        )

    assert client.task(
        80, 243, reconcile_params(credentials["session_token"]), structured=True
    ) == pb_integer(3, 0)
    assert client.task(
        80,
        243,
        structure(
            pb_text(1, str(title))
            + pb_text(2, credentials["session_token"])
            + pb_text(3, "US")
            + pb_integer(4, 25)
            + pb_text(5, "opaque-external-sso")
        ),
        structured=True,
    ) == pb_integer(3, 0)
    client.task(80, 243, reconcile_params("f" * 64), error=101)
    reconcile_receipt = (
        directory / "marketplace" / str(title) / str(user) / "reconciliation.json"
    )
    assert json.loads(reconcile_receipt.read_text())["granted"] == []
    assert credentials["session_token"] not in reconcile_receipt.read_text()
    checks.append(
        "native Battle.net license reconciliation schema, issued credential binding and durable receipt"
    )
    inventory_path = (
        directory / "marketplace" / str(title) / str(user) / "inventory.json"
    )

    def inventory_params(page="", maximum=1):
        return structure(
            pb_text(1, str(title)) + pb_text(2, page) + pb_integer(3, maximum)
        )

    empty_inventory = client.task(80, 69, inventory_params(), structured=True)
    assert pb_map(empty_inventory) == {
        1: [pb_integer(1, user) + pb_text(2, "bnet")],
        2: [str(title).encode()],
        3: [b""],
    }
    inventory_path.write_text(
        json.dumps(
            {
                "items": [{"1": 20, "2": 3, "10": -1}, {"1": 10, "2": 1}],
                "balances": [{"currency": 20, "amount": 123, "source": 1}],
            }
        )
    )
    first = pb_map(client.task(80, 69, inventory_params(), structured=True))
    page = first[3][0].decode()
    assert page and pb_map(first[4][0])[1] == [10]
    second = pb_map(client.task(80, 69, inventory_params(page), structured=True))
    assert (
        second[3] == [b""]
        and pb_map(second[4][0])[1] == [20]
        and pb_map(second[4][0])[10] == [1]
    )
    balance_reply = pb_map(
        client.task(
            80,
            245,
            structure(pb_text(1, str(title)) + pb_integer(2, 16)),
            structured=True,
        )
    )
    assert pb_map(balance_reply[1][0]) == {1: [20], 2: [246], 3: [1]}
    client.task(80, 69, inventory_params("invalid"), error=106)
    client.task(80, 69, inventory_params(maximum=1001), error=106)
    from legacy_market_fixtures import exercise as exercise_legacy_market

    exercise_legacy_market(
        client,
        directory,
        title,
        user,
        inventory_path,
        (u32, text, blob, boolean),
        checks,
    )
    inventory_path.unlink()
    from redemption_fixtures import exercise as exercise_redemption

    redemption_fixture = exercise_redemption(
        client,
        directory,
        title,
        user,
        (structure, pb_text, pb_integer, pb_bytes, pb_map),
        checks,
    )
    checks.append(
        "native inventory full item layout, stable ordered pagination, empty identity and ZigZag balances"
    )

    def achievement_query(page="", maximum=1, extra=b""):
        return structure(
            pb_text(1, str(title))
            + pb_integer(3, maximum)
            + pb_text(4, page)
            + pb_integer(8, 0)
            + extra
        )

    assert client.task(125, 3, achievement_query(), structured=True) == pb_text(2, "")
    default_definitions = pb_map(
        client.task(
            125,
            4,
            structure(pb_text(1, str(title)) + pb_integer(3, 100) + pb_text(4, "")),
            structured=True,
        )
    )
    assert len(default_definitions[1]) == 100 and default_definitions[2][0]
    first_definition = pb_map(default_definitions[1][0])
    assert first_definition[14] == [1500] and first_definition[3] == [15]
    assert first_definition[1] == [b"ch_quest001_stage001"] and first_definition[7] == [1]
    achievement_path = (
        directory / "achievements" / str(title) / str(title) / str(user) / "states.json"
    )
    rows = [
        {
            "id": 2,
            "name": "second",
            "kind": 1,
            "status": 3,
            "progress": 5,
            "target": 5,
            "multiProgress": [{"name": "wins", "current": 5, "target": 5}],
        },
        {"id": 1, "name": "first", "kind": 0, "status": 1, "progress": 0, "target": 10},
    ]
    achievement_path.write_text(json.dumps(rows))
    first_states = pb_map(client.task(125, 3, achievement_query(), structured=True))
    state_page = first_states[2][0].decode()
    assert state_page and pb_map(first_states[1][0])[11] == [1]
    second_states = pb_map(
        client.task(125, 3, achievement_query(state_page), structured=True)
    )
    assert second_states[2] == [b""] and pb_map(second_states[1][0])[11] == [2]
    assert pb_map(pb_map(second_states[1][0])[10][0]) == {1: [b"wins"], 2: [5], 3: [5]}
    filtered = pb_map(
        client.task(125, 3, achievement_query(extra=pb_integer(5, 3)), structured=True)
    )
    assert pb_map(filtered[1][0])[11] == [2] and filtered[2] == [b""]
    client.task(
        125,
        3,
        achievement_query(
            extra=pb_bytes(9, pb_integer(1, user + 1) + pb_text(2, "bnet"))
        ),
        error=106,
    )
    client.task(125, 3, achievement_query(maximum=101), error=106)
    rows[0]["progress"] = 4
    achievement_path.write_text(json.dumps(rows))
    client.task(125, 3, achievement_query(state_page), error=106)
    rows[1]["status"] = 2
    achievement_path.write_text(json.dumps(rows))
    assert (
        client.task(
            125,
            5,
            structure(
                pb_text(1, str(title))
                + pb_text(2, "first")
                + pb_integer(3, 123)
                + pb_integer(4, 1)
            ),
            structured=True,
        )
        == b""
    )
    active = json.loads(achievement_path.read_text())
    assert active[1]["status"] == 1 and active[1]["activationTimestamp"] == 123
    assert (
        client.task(
            125,
            6,
            structure(pb_text(1, str(title)) + pb_text(2, "first") + pb_integer(3, 1)),
            structured=True,
        )
        == b""
    )
    assert json.loads(achievement_path.read_text())[1]["status"] == 2
    client.task(
        125,
        5,
        structure(
            pb_text(1, str(title))
            + pb_text(2, "unknown")
            + pb_integer(3, 123)
            + pb_integer(4, 999)
        ),
        error=108,
    )
    achievement_path.unlink()
    checks.append(
        "native achievement complete state objects, filters, bounded account queries and stale-page rejection"
    )
    definitions_path = achievement_path.parent.parent / "definitions.json"
    definition = {
        "1": "fixture",
        "2": "description",
        "3": 1,
        "14": 123,
        "4": {
            "1": [{"1": 7}],
            "2": [{"1": 20, "2": 100}],
            "3": [
                {
                    "1": "activate",
                    "2": {"1": 1, "2": {"1": 2026, "2": 10, "3": 4, "4": 0, "5": 0}},
                }
            ],
        },
        "11": [{"1": "wins", "2": 10}],
        "12": {"1": {"1": 1, "2": 2}},
        "15": 12,
        "16": [{"1": 1, "2": 2}],
        "17": [42],
    }
    definitions_path.write_text(json.dumps([definition]))
    definition_reply = pb_map(
        client.task(
            125,
            4,
            structure(pb_text(1, str(title)) + pb_integer(3, 100) + pb_text(4, "")),
            structured=True,
        )
    )
    parsed_definition = pb_map(definition_reply[1][0])
    assert parsed_definition[14] == [123]
    assert pb_map(pb_map(parsed_definition[4][0])[2][0]) == {1: [20], 2: [100]}
    assert pb_map(pb_map(parsed_definition[12][0])[1][0]) == {1: [1], 2: [2]}
    definitions_path.unlink()
    event = (
        pb_text(1, "fixture_event")
        + pb_integer(2, 123)
        + pb_bytes(3, pb_text(1, "wins") + pb_integer(2, 1))
        + pb_integer(4, 0)
    )
    event_request = structure(
        pb_text(1, str(title)) + pb_bytes(2, event) + pb_text(3, "fixture-idempotent")
    )
    assert (
        client.task(125, 1, event_request, structured=True) == b""
        and client.task(125, 1, event_request, structured=True) == b""
    )
    event_store = achievement_path.parent / "events.json"
    assert len(json.loads(event_store.read_text())["events"]) == 1
    client.task(
        125,
        1,
        structure(
            pb_text(1, str(title))
            + pb_bytes(2, event.replace(pb_integer(2, 123), pb_integer(2, 124)))
            + pb_text(3, "fixture-idempotent")
        ),
        error=106,
    )
    assert len(json.loads(event_store.read_text())["events"]) == 1
    checks.append(
        "complete achievement definition nested layouts, activation persistence and idempotent event batches"
    )
    group = pb_integer(1, 1) + pb_integer(2, 123) + pb_integer(3, 0) + pb_integer(4, 0)
    assert client.task(197, 21, structure(pb_bytes(1, group)), structured=True) == b""
    assert client.task(197, 21, structure(b""), structured=True) == b""
    client.task(
        197,
        21,
        structure(pb_bytes(1, pb_integer(1, 65536) + pb_integer(2, 123))),
        error=106,
    )
    client.task(
        197,
        21,
        structure(
            pb_bytes(1, pb_integer(1, 1) + pb_integer(2, 123) + pb_integer(2, 456))
        ),
        error=106,
    )
    checks.append(
        "native clan group-identifier schema, empty result arrays and malformed-field rejection"
    )

    def stat_row(board, rating, columns, mode=0, entity=None):
        result = (
            u32(board)
            + u64(user if entity is None else entity)
            + b"\x03"
            + bytes([mode])
        )
        result += b"\x14" if rating is None else b"\x09" + struct.pack("<q", rating)
        for column in columns:
            result += b"\x14" if column is None else b"\x07" + struct.pack("<i", column)
        return result

    statpath = directory / "leaderboard-stats" / str(title) / (str(user) + ".json")
    assert (
        client.task(4, 1, stat_row(6000, 5, [5, None]) + stat_row(6001, 7, [7])) == []
    )
    assert client.task(4, 1, stat_row(6000, 3, [3, 2], 1)) == []
    assert client.task(4, 1, stat_row(6000, 12, [12, None], 2)) == []
    statdocument = json.loads(statpath.read_text())
    assert statdocument["6000"]["rating"] == 12 and statdocument["6000"]["columns"] == [
        12,
        2,
    ]
    assert (
        statdocument["6000"]["name"] == "DWPlayer"
        and statdocument["6000"]["updated"] > 0
    )
    before = statpath.read_bytes()
    client.task(
        4,
        1,
        stat_row(6000, 15, [15]) + stat_row(6001, 1, [1], entity=user + 1),
        error=101,
    )
    assert statpath.read_bytes() == before
    client.task(4, 1, stat_row(6000, 15, [15]) + stat_row(6001, 1, [1] * 11), error=106)
    assert statpath.read_bytes() == before
    client.task(4, 1, stat_row(6000, 1, [2147483647], 1), error=106)
    assert statpath.read_bytes() == before
    assert client.task(4, 1, stat_row(6002, 9223372036854775807, [])) == []
    before = statpath.read_bytes()
    client.task(4, 1, stat_row(6000, 15, [15]) + stat_row(6002, 1, [], 1), error=106)
    assert statpath.read_bytes() == before
    checks.append(
        "native leaderboard row persistence, replace/add/max/NAN semantics and atomic batch rejection"
    )
    import validated_stats_fixtures

    validated_stats_fixture = validated_stats_fixtures.exercise(
        client, directory, title, user, stat_row, blob, checks
    )
    import inventory_validation_fixtures

    inventory_validation_fixture = inventory_validation_fixtures.exercise(
        client, directory, title, user, text, blob, checks
    )
    # The shared restart gate must include the newly authorized rows/receipts.
    before = statpath.read_bytes()
    # Exercise public rankings across independently stored owners; only the
    # authenticated owner can write these records through the task API.
    peerstat = statpath.with_name(str(user + 1) + ".json")
    peerstat.write_text(
        json.dumps(
            {
                "6000": {
                    "rating": 50,
                    "columns": [8, 9],
                    "name": "Peer",
                    "updated": int(time.time()),
                }
            }
        )
    )

    def stat_results(raw, extended=False, column_count=10):
        offset = 0
        results = []

        def value(tag, fmt):
            nonlocal offset
            assert raw[offset] == tag
            offset += 1
            result = struct.unpack_from(fmt, raw, offset)[0]
            offset += struct.calcsize(fmt)
            return result

        while offset < len(raw):
            item = {}
            if extended:
                item["board"] = value(8, "<I")
                item["error"] = value(8, "<I")
                if item["error"]:
                    item["user"] = value(10, "<Q")
                    results.append(item)
                    continue
            item["user"] = value(10, "<Q")
            item["rating"] = value(9, "<q")
            item["rank"] = value(10, "<Q")
            assert raw[offset] == 16
            end = raw.index(0, offset + 1)
            item["name"] = raw[offset + 1 : end].decode()
            offset = end + 1
            item["age"] = value(8, "<I")
            item["columns"] = [value(7, "<i") for _ in range(column_count)]
            results.append(item)
        return results

    read = stat_results(
        client.task(4, 13, u32(6000) + u32(2) + u64(user) + u64(user + 1) + u32(0))
    )
    assert [r["user"] for r in read] == [user, user + 1] and [
        r["rank"] for r in read
    ] == [2, 1]
    assert read[0]["columns"] == [12, 2] + [0] * 8 and read[1]["name"] == "Peer"
    page = stat_results(client.task(4, 17, u32(6000) + u64(1) + u32(1) + u32(0)))
    assert len(page) == 1 and page[0]["user"] == user + 1
    page = stat_results(client.task(4, 17, u32(6000) + u64(2) + u32(1) + u32(0)))
    assert len(page) == 1 and page[0]["user"] == user
    assert client.task(4, 17, u32(6000) + u64(3) + u32(1) + u32(0)) == []
    assert client.task(4, 13, u32(6000) + u32(1) + u64(user + 2) + u32(0)) == []
    matrix = stat_results(
        client.task(4, 11, u32(2) + u64(user) + u64(user + 2) + u32(1) + u32(6000)),
        True,
    )
    assert (
        matrix[0]["board"] == 6000
        and matrix[0]["error"] == 0
        and matrix[1] == {"board": 6000, "error": 108, "user": user + 2}
    )
    client.task(4, 17, u32(6000) + u64(0) + u32(1) + u32(0), error=106)
    client.task(4, 13, u32(6000) + u32(201), error=106)
    client.task(4, 11, u32(0), error=106)
    projection = u32(6000) + u64(1) + u32(1) + u32(1) + text("score")
    client.task(4, 4, projection, error=108)
    definition = directory / "leaderboard-definitions" / str(title) / "6000.json"
    definition.parent.mkdir(parents=True)
    definition.write_text(
        json.dumps({"columns": ["score", "wins"] + [f"col{i}" for i in range(2, 10)]})
    )
    projected = stat_results(client.task(4, 4, projection), column_count=9)
    assert projected[0]["columns"] == [9] + [0] * 8
    included = stat_results(client.task(4, 17, projection), column_count=1)
    assert included[0]["columns"] == [8]
    included = stat_results(
        client.task(
            4,
            16,
            u32(6000) + u32(2) + u64(user) + u64(user + 1) + u32(1) + text("wins"),
        ),
        column_count=1,
    )
    assert [r["columns"] for r in included] == [[2], [9]]
    checks.append(
        "native leaderboard entity/rank/matrix reads, full row layouts, stable ordering, paging and asset-defined column projection"
    )
    assert client.task(27, 2) == text("US") + text("United States") + text(
        "Local"
    ) + text("Local") + b"\x0d" + struct.pack("<f", 0) + b"\x0d" + struct.pack(
        "<f", 0
    ) + u32(
        0
    ) + text(
        "UTC"
    )
    client.task(27, 2, u32(0), error=106)
    assert client.task(67, 6) == []
    kind, filtered = client.receive()
    assert kind == 2 and filtered == u32(45) + u32(0)
    assert client.task(67, 6) == []
    kind, filtered = client.receive()
    assert kind == 2 and filtered == u32(45) + u32(0)
    checks.append(
        "complete native DML result and authenticated event-filter push/reinitialization"
    )
    assert client.task(198, 12, structure(pb_text(1, "clan")), structured=True) == b""
    client.task(198, 12, structure(pb_text(1, "x" * 16)), error=106)
    account = pb_integer(1, user) + pb_text(2, "bnet")
    proposal = pb_bytes(1, account) + pb_integer(3, 10) + pb_text(4, "")
    assert client.task(197, 28, structure(proposal), structured=True) == pb_text(2, "")
    assert (
        client.task(
            197, 30, structure(pb_bytes(1, account) + pb_integer(3, 1)), structured=True
        )
        == b""
    )
    assert (
        client.task(
            197,
            30,
            structure(pb_bytes(1, pb_integer(1, user + 1) + pb_text(2, "bnet"))),
            structured=True,
        )
        == b""
    )
    native_clan_user = pb_integer(1, user) + pb_text(2, "")
    assert client.task(
        197,
        28,
        structure(pb_bytes(2, native_clan_user) + pb_integer(3, 100) + pb_text(4, "")),
        structured=True,
    ) == pb_text(2, "")
    assert client.task(
        197,
        28,
        structure(pb_bytes(2, native_clan_user) + pb_integer(3, 0) + pb_text(4, "")),
        structured=True,
    ) == pb_text(2, "")
    assert (
        client.task(
            197,
            30,
            structure(pb_bytes(1, native_clan_user) + pb_integer(3, 1)),
            structured=True,
        )
        == b""
    )
    assert (
        client.task(
            50,
            2,
            u64(user) + u32(0) + b"\x06\x0a\x00\x06\x00\x00\x06\x01\x00" + text(""),
        )
        == []
    )
    checks.append(
        "category cleanup, native clan collection/pagination and content-owner list"
    )

    # Stateful clan DTOs are decoded independently using the target readers'
    # full required field sets. No production/player clan data is touched.
    def clan_identifier(clan_id):
        return (
            pb_integer(1, 1)
            + pb_integer(2, clan_id)
            + pb_integer(3, 0)
            + pb_integer(4, 0)
        )

    clan_create = structure(
        pb_integer(1, 1)
        + pb_integer(3, 0)
        + pb_integer(4, 0)
        + pb_text(5, "Fixture Regiment")
        + pb_integer(7, 3)
        + pb_text(12, "FIX")
    )
    clan_info = pb_map(client.task(197, 20, clan_create, structured=True))
    clan_id = clan_info[2][0]
    clan_group = clan_identifier(clan_id)
    assert 0 < clan_id < 2**53 and int(float(clan_id)) == clan_id
    assert (
        set(clan_info) == set(range(1, 13))
        and clan_info[8] == [1]
        and clan_info[9] == [0]
        and clan_info[11] == [1]
    )
    assert pb_map(clan_info[6][0]) == {1: [user], 2: [b"uno"]} and clan_info[5] == [
        b"Fixture Regiment"
    ]
    assert pb_map(client.task(197, 20, clan_create, structured=True))[2] == [clan_id]
    client.task(
        197,
        20,
        structure(
            pb_integer(1, 1)
            + pb_integer(3, 0)
            + pb_integer(4, 0)
            + pb_text(5, "Other")
            + pb_integer(7, 3)
            + pb_text(12, "FIX")
        ),
        error=106,
    )
    queried = pb_map(
        client.task(197, 21, structure(pb_bytes(1, clan_group)), structured=True)
    )
    assert pb_map(queried[1][0]) == clan_info
    my_membership = pb_map(
        pb_map(
            client.task(
                197,
                30,
                structure(pb_bytes(1, account) + pb_integer(3, 1)),
                structured=True,
            )
        )[1][0]
    )
    assert pb_map(my_membership[1][0]) == {
        1: [user],
        2: [b"uno"],
        3: [b"DWPlayer#0"],
    } and my_membership[3] == [1]
    assert pb_map(my_membership[2][0])[1] == [3] and pb_map(my_membership[2][0])[3] == [
        1
    ]
    clanpath = directory / "clans" / str(title) / "groups.json"

    def propose(target, attachment=b"", role=1):
        proposal = (
            pb_bytes(1, pb_integer(1, target) + pb_text(2, "uno") + pb_text(3, ""))
            + pb_integer(2, role)
            + pb_bytes(3, attachment)
        )
        return pb_bytes(2, proposal)

    proposal_request = structure(
        pb_bytes(1, clan_group)
        + propose(user + 1, b"invite one")
        + propose(user + 2, b"invite two", 2)
    )
    sent = pb_map(client.task(197, 25, proposal_request, structured=True))
    assert len(sent[1]) == 2
    for payload in sent[1]:
        parsed = pb_map(payload)
        assert (
            set(parsed) == set(range(1, 8))
            and pb_map(parsed[1][0])[1] == [user]
            and parsed[7][0] > 0
        )
    before_clans = clanpath.read_bytes()
    client.task(
        197,
        25,
        structure(pb_bytes(1, clan_group) + propose(user + 3) + propose(user + 3)),
        error=106,
    )
    assert clanpath.read_bytes() == before_clans
    client.task(
        197,
        25,
        structure(pb_bytes(1, clan_group) + propose(user + 3, role=3)),
        error=106,
    )
    assert clanpath.read_bytes() == before_clans

    def proposal_page(token=""):
        return structure(pb_bytes(1, account) + pb_integer(3, 1) + pb_text(4, token))

    page1 = pb_map(client.task(197, 28, proposal_page(), structured=True))
    assert len(page1[1]) == 1 and page1[2][0]
    page2 = pb_map(
        client.task(197, 28, proposal_page(page1[2][0].decode()), structured=True)
    )
    assert len(page2[1]) == 1 and page2[2] == [b""]
    assert pb_map(page1[1][0])[2] != pb_map(page2[1][0])[2]
    client.task(197, 28, proposal_page("1:wrong"), error=106)
    outgoing = pb_map(
        client.task(
            197,
            27,
            structure(pb_bytes(1, clan_group) + pb_integer(2, 64) + pb_text(3, "")),
            structured=True,
        )
    )
    assert len(outgoing[1]) == 2
    outgoing = pb_map(
        client.task(
            197,
            27,
            structure(pb_bytes(1, clan_group) + pb_integer(2, 0) + pb_text(3, "")),
            structured=True,
        )
    )
    assert len(outgoing[1]) == 2
    remove = structure(
        pb_bytes(
            1,
            pb_bytes(1, pb_integer(1, user + 1) + pb_text(2, "uno") + pb_text(3, ""))
            + pb_bytes(2, clan_group)
            + pb_integer(3, 0),
        )
    )
    removed = pb_map(client.task(197, 26, remove, structured=True))
    assert pb_map(removed[1][0])[3] == [0]
    client.task(
        197, 28, proposal_page(page1[2][0].decode()), error=106
    )  # Old cursor cannot silently skip a changed collection.
    assert (
        len(
            pb_map(
                client.task(
                    197,
                    28,
                    structure(
                        pb_bytes(1, account) + pb_integer(3, 10) + pb_text(4, "")
                    ),
                    structured=True,
                )
            )[1]
        )
        == 1
    )
    file_selector = pb_bytes(1, clan_group) + pb_text(2, "happyHour")
    client.task(197, 31, structure(pb_bytes(1, file_selector)), error=19734)

    def upload_clan_file(payload, collision=0):
        return structure(
            pb_bytes(1, file_selector + pb_bytes(3, payload) + pb_integer(4, collision))
        )

    clan_file = pb_map(
        pb_map(client.task(197, 32, upload_clan_file(bytes(8)), structured=True))[1][0]
    )
    assert (
        set(clan_file) == set(range(1, 7))
        and clan_file[3] == [bytes(8)]
        and clan_file[4] == [1]
        and clan_file[5][0] > 0
    )
    updated_file = pb_map(
        pb_map(client.task(197, 32, upload_clan_file(b"updated!"), structured=True))[1][
            0
        ]
    )
    assert updated_file[4] == [2] and updated_file[5] == clan_file[5]
    before_clans = clanpath.read_bytes()
    client.task(197, 32, upload_clan_file(b"rejected", 1), error=106)
    assert clanpath.read_bytes() == before_clans
    assert (
        pb_map(
            pb_map(
                client.task(
                    197, 31, structure(pb_bytes(1, file_selector)), structured=True
                )
            )[1][0]
        )
        == updated_file
    )
    # An independently seeded foreign-owner invitation tests the authenticated
    # user's acceptance/permission path without fabricating another auth token.
    clans = json.loads(clanpath.read_text())
    foreign_group = 987654321
    foreign = {
        "kind": 1,
        "id": foreign_group,
        "root_kind": 0,
        "root_id": 0,
        "name": "Peer Regiment",
        "tag": "PEER",
        "privacy": 3,
        "owner": user + 10,
        "title": title,
        "created": int(time.time()),
        "members": [{"user": user + 10, "role": 3, "name": "Peer"}],
        "proposals": [
            {
                "proposer": user + 10,
                "proposer_name": "Peer",
                "target": user,
                "target_name": "DWPlayer",
                "role": 2,
                "attachment": "",
                "updated": int(time.time()),
            }
        ],
        "files": {},
    }
    clans["groups"].append(foreign)
    clanpath.write_text(json.dumps(clans))
    foreign_identifier = clan_identifier(foreign_group)
    accept = structure(
        pb_bytes(1, foreign_identifier) + pb_integer(2, 2) + pb_integer(4, 0)
    )
    accepted = pb_map(client.task(197, 23, accept, structured=True))
    assert accepted[3] == [2] and pb_map(accepted[1][0])[1] == [user]
    memberships_reply = pb_map(
        client.task(
            197, 30, structure(pb_bytes(1, account) + pb_integer(3, 1)), structured=True
        )
    )
    assert len(memberships_reply[1]) == 1
    memberships_row = pb_map(memberships_reply[1][0])
    assert len(memberships_row[2]) == 2  # One user, all group memberships.
    client.task(
        197, 22, structure(foreign_identifier + pb_text(5, "Denied")), error=101
    )
    client.task(
        197,
        23,
        structure(
            pb_bytes(1, foreign_identifier) + pb_integer(2, 3) + pb_integer(4, 0)
        ),
        error=101,
    )
    assert (
        client.task(
            197, 37, structure(pb_bytes(1, foreign_identifier)), structured=True
        )
        == b""
    )
    memberships_reply = pb_map(
        client.task(197, 30, structure(pb_bytes(1, account)), structured=True)
    )
    membership_rows = [pb_map(row) for row in pb_map(memberships_reply[1][0])[2]]
    assert [pb_map(row[2][0])[2][0] for row in membership_rows if row[3] == [1]] == [
        foreign_group
    ]
    checks.append(
        "native clan create/invite/paged queries/acceptance, complete DTOs, ownership, active membership and group-file version persistence"
    )
    from clan_membership_fixtures import run as test_clan_transitions

    clan_transition_fixture = test_clan_transitions(
        client,
        directory,
        title,
        user,
        checks,
        structure,
        pb_integer,
        pb_bytes,
        pb_text,
        pb_map,
    )

    def rest_params(resource="FixtureResource", has_body=False, body=b""):
        params = (
            pb_integer(1, 1)
            + pb_integer(2, 0)
            + pb_integer(3, 1)
            + pb_integer(100, 10000)
            + pb_bytes(200, bytes(256))
            + pb_text(300, resource)
            + pb_text(301, "get")
        )
        message = (
            pb_bytes(1, params)
            + pb_integer(2, 1)
            + pb_integer(10, 0x474554)
            + pb_text(11, "/fixture?token=DO_NOT_LOG_QUERY")
            + pb_text(101, "fixture")
            + pb_integer(102, 1)
        )
        message += pb_bytes(
            14, pb_text(1, "Authorization") + pb_text(2, "DO_NOT_LOG_HEADER")
        )
        return u32(713) + blob(message) + boolean(has_body) + blob(body)

    def rest_response(raw):
        assert raw[:5] == u32(713)
        assert raw[5] == 19 and raw[6] == 8
        length = struct.unpack_from("<I", raw, 7)[0]
        metadata = dict((t, v) for t, k, v in pb_fields(raw[11 : 11 + length]))
        position = 11 + length
        assert (
            raw[position : position + 2] == boolean(True)
            and raw[position + 2 : position + 4] == b"\x13\x08"
        )
        size = struct.unpack_from("<I", raw, position + 4)[0]
        assert len(raw) == position + 8 + size
        extra = dict((t, v) for t, k, v in pb_fields(metadata[1000]))
        assert (
            metadata[203] == struct.pack("<d", 0)
            and metadata[302] == 1
            and extra[102] == 0
            and extra[101] > 0
        )
        return metadata[1], json.loads(raw[position + 8 :])

    status, body = rest_response(client.task(255, 10, rest_params()))
    assert status == 503 and body["error"]["name"] == "LocalServiceUnavailable"
    restpath = directory / "rest" / str(title) / "fixture" / "FixtureResource"
    restpath.mkdir(parents=True)
    (restpath / "get.json").write_text(
        json.dumps({"status": 200, "body": {"fixture_value": 7}})
    )
    status, body = rest_response(client.task(255, 10, rest_params()))
    assert status == 200 and body == {"fixture_value": 7}
    for invalid_status in (199, 600, -1, 200.5, (1 << 32) + 200):
        (restpath / "get.json").write_text(
            json.dumps({"status": invalid_status, "body": {"fixture_value": 7}})
        )
        client.task(255, 10, rest_params(), error=102)
    (restpath / "get.json").write_text(
        json.dumps({"status": 599, "body": {"fixture_value": 7}})
    )
    assert rest_response(client.task(255, 10, rest_params()))[0] == 599
    (restpath / "get.json").write_text(
        json.dumps({"status": 200, "body": {"fixture_value": 7}})
    )
    checks.append("configured REST statuses reject invalid types/ranges before numeric narrowing")
    client.task(255, 10, rest_params("../escape"), error=106)
    client.task(255, 10, rest_params(body=b"illegal"), error=106)
    checks.append(
        "native REST ordinary-result envelope, configured GET, explicit HTTP error and bounded routing"
    )

    def native_rest(
        service,
        resource,
        operation,
        method=0x474554,
        body=None,
        uri="/fixture",
        headers=None,
    ):
        params = (
            pb_integer(1, 1)
            + pb_integer(2, 0)
            + pb_integer(3, 1)
            + pb_integer(100, 10000)
            + pb_bytes(200, bytes(256))
            + pb_text(300, resource)
            + pb_text(301, operation)
        )
        message = (
            pb_bytes(1, params)
            + pb_integer(2, 1)
            + pb_integer(10, method)
            + pb_text(11, uri)
            + pb_text(101, service)
            + pb_integer(102, 1)
            + pb_integer(302, 1)
        )
        for name, value in (headers or {}).items():
            message += pb_bytes(14, pb_text(1, name) + pb_text(2, value))
        payload = (
            b""
            if body is None
            else body if isinstance(body, bytes) else json.dumps(body).encode()
        )
        return u32(713) + blob(message) + boolean(body is not None) + blob(payload)

    import regulation_fixtures

    regulation_restart = regulation_fixtures.exercise(
        client, directory, title, user, native_rest, rest_response, blob, checks
    )
    import identity_rest_fixtures

    rename_restart = identity_rest_fixtures.exercise(
        client,
        rename_access_token,
        directory,
        title,
        seed,
        post,
        Client,
        native_rest,
        rest_response,
        blob,
        checks,
    )
    import account_auth_fixtures

    account_prepare_restart, account_stopped, account_after_restart = (
        account_auth_fixtures.exercise(
            client,
            rename_access_token,
            user,
            directory,
            title,
            seed,
            post,
            Client,
            native_rest,
            rest_response,
            blob,
            checks,
        )
    )

    event_body = {
        "titleID": title,
        "idempotentRequestID": "00000000-0000-0000-0000-000000000001",
        "userEvents": [
            {
                "accountType": "bnet",
                "userID": user,
                "events": [
                    {"name": "frontend_login", "timestamp": 123, "values": {"count": 1}}
                ],
            }
        ],
    }
    event_rest = lambda body: native_rest(
        "ae.demonware.net",
        "user_events",
        "report_user_events_batch",
        0x504F5354,
        body,
        uri=f"/v2/user-events/$batch/?context={title}&client=replaylocal&titleID={title}",
    )
    assert rest_response(client.task(255, 10, event_rest(event_body))) == (
        200,
        {"allSucceeded": True},
    )
    assert rest_response(client.task(255, 10, event_rest(event_body))) == (
        200,
        {"allSucceeded": True},
    )
    assert len(json.loads(event_store.read_text())["events"]) == 2
    event_body["userEvents"][0]["userID"] = user + 1
    client.task(255, 10, event_rest(event_body), error=101)
    checks.append(
        "native achievement REST event batching, durable retry deduplication and account ownership"
    )
    import achievement_rest_fixtures

    achievement_rest_fixtures.exercise(
        client, event_store, title, user, native_rest, rest_response, checks
    )
    import achievement_batch_fixtures

    achievement_batch_fixture = achievement_batch_fixtures.exercise(
        client,
        directory,
        title,
        user,
        struct.unpack_from("<I", platform, 64)[0],
        pb_text,
        pb_integer,
        pb_bytes,
        structure,
        native_rest,
        checks,
    )
    list_uri = f"/v1/user/uno-{user}/list/recent/?context=iw8"
    status, body = rest_response(
        client.task(
            255,
            10,
            native_rest("social-service", "UserLists", "get_user_list", uri=list_uri),
        )
    )
    assert status == 200 and body == {"pageToken": "", "userList": []}
    for operation in ("get_friends", "get_pending_friend_requests"):
        suffix = "pending/" if operation == "get_pending_friend_requests" else ""
        status, body = rest_response(
            client.task(
                255,
                10,
                native_rest(
                    "social-service",
                    "Friends",
                    operation,
                    uri=f"/v1/friends/uno-{user}/{suffix}?context=i%77%38",
                ),
            )
        )
        assert status == 200 and body == {"context": "iw8", "page": "", "users": []}
    client.task(
        255,
        10,
        native_rest(
            "social-service", "Friends", "get_friends", uri="/v1/friends?context=%00"
        ),
        error=106,
    )
    client.task(
        255,
        10,
        native_rest(
            "social-service",
            "Friends",
            "get_friends",
            uri="/v1/friends?context=iw8&context=other",
        ),
        error=106,
    )
    checks.append(
        "native Friends and pending-invitation REST response schema and bounded requested context"
    )
    objects = [
        {"owner": "replay", "name": "present.json"},
        {"owner": "replay", "name": "absent.json"},
    ]
    objectpath = directory / "objectstore" / "publisher" / str(title) / "iw8" / "replay"
    objectpath.mkdir(parents=True)
    metadata = {
        "name": "present.json",
        "owner": "replay",
        "context": "iw8",
        "contentLength": 4,
        "checksum": "0" * 32,
        "objectVersion": "1",
        "acl": "public",
        "created": 0,
        "modified": 0,
        "expiresOn": 0,
        "category": None,
    }
    (objectpath / "present.json.metadata.json").write_text(json.dumps(metadata))

    def object_params(items):
        header = pb_text(1, "DW-Objectstore-ObjectIDs") + pb_text(2, json.dumps(items))
        return structure(
            pb_text(1, "GET")
            + pb_text(2, "/v2/core/publishers/objects/?context=iw8")
            + pb_bytes(4, header)
        )

    raw = client.task(193, 16, object_params(objects), structured=True)
    fields = pb_fields(raw)
    header = dict(
        (t, v) for t, k, v in pb_fields(next(v for t, k, v in fields if t == 1))
    )
    response = json.loads(next(v for t, k, v in fields if t == 3))
    assert next(v for t, k, v in fields if t == 2) == 200
    assert header[1] == b"Content-Length" and int(header[2]) == len(
        next(v for t, k, v in fields if t == 3)
    )
    assert (
        response["objects"][0]["requestIndex"] == 0
        and response["objects"][0]["metadata"]["name"] == "present.json"
    )
    assert response["errors"] == [
        {
            "requestIndex": 1,
            "owner": "replay",
            "name": "absent.json",
            "error": "Error:ClientError:NotFound",
        }
    ]
    client.task(
        193, 16, object_params([{"owner": "replay", "name": "../escape"}]), error=106
    )
    client.task(193, 16, object_params([]), error=106)
    checks.append(
        "vectorized publisher metadata, full HTTP/blob wrapper, per-object missing state and path rejection"
    )
    publisher_bytes = b"local-publisher-fixture\x00" + os.urandom(32000)
    metadata.update(
        contentLength=len(publisher_bytes),
        checksum=base64.b64encode(hashlib.md5(publisher_bytes).digest()).decode(),
    )
    (objectpath / "present.json.metadata.json").write_text(json.dumps(metadata))
    (objectpath / "present.json.content.bin").write_bytes(publisher_bytes)

    def publisher_single(name):
        return structure(
            pb_text(1, "GET")
            + pb_text(
                2,
                "/v1/core/publishers/replay/objects/"
                + name
                + "/metadata/?context=iw8&extra=contentURL",
            )
        )

    fields = pb_fields(
        client.task(193, 8, publisher_single("present.json"), structured=True)
    )
    document = json.loads(next(v for t, k, v in fields if t == 3))
    assert next(v for t, k, v in fields if t == 2) == 200
    assert (
        len(document["checksum"]) < 29
        and base64.b64decode(document["checksum"], validate=True)
        == hashlib.md5(publisher_bytes).digest()
    )
    assert document["objectID"] == int.from_bytes(
        hashlib.sha256(b"5800/iw8/replay/present.json").digest()[:8], "big"
    )
    authorization = [
        dict((t, v) for t, k, v in pb_fields(h)) for t, k, h in fields if t == 1
    ]
    assert {1: b"Authorization", 2: b"public"} in authorization
    assert [t for t, k, v in fields] == [
        1,
        1,
        2,
        3,
    ]  # native reader's ordered repeated tags
    assert (
        document["contentURL"]
        == base + "/objectstore/content/" + hashlib.sha256(publisher_bytes).hexdigest()
    )
    with urllib.request.urlopen(document["contentURL"]) as download:
        assert (
            download.read() == publisher_bytes
            and download.headers["Content-Type"] == "application/octet-stream"
        )
    for value, first, last in (
        ("bytes=7-1023", 7, 1023),
        ("bytes=1024-", 1024, len(publisher_bytes) - 1),
        ("bytes=-17", len(publisher_bytes) - 17, len(publisher_bytes) - 1),
        ("bytes=0-999999", 0, len(publisher_bytes) - 1),
    ):
        range_request = urllib.request.Request(
            document["contentURL"], headers={"Range": value}
        )
        with urllib.request.urlopen(range_request) as download:
            assert (
                download.status == 206
                and download.read() == publisher_bytes[first : last + 1]
            )
            assert (
                download.headers["Content-Range"]
                == f"bytes {first}-{last}/{len(publisher_bytes)}"
            )
    for value in (
        "bytes=999999-",
        "bytes=4-2",
        "bytes=-0",
        "bytes=0-1,4-5",
        "items=0-2",
    ):
        try:
            urllib.request.urlopen(
                urllib.request.Request(document["contentURL"], headers={"Range": value})
            )
            raise AssertionError("Malformed/unavailable byte range accepted")
        except urllib.error.HTTPError as error:
            assert (
                error.code == 416
                and error.headers["Content-Range"] == f"bytes */{len(publisher_bytes)}"
            )
    fields = pb_fields(client.task(193, 16, object_params(objects), structured=True))
    assert (
        json.loads(next(v for t, k, v in fields if t == 3))["objects"][0]["metadata"]
        == document
    )
    missing = pb_fields(
        client.task(193, 8, publisher_single("absent.json"), structured=True)
    )
    assert next(v for t, k, v in missing if t == 2) == 404
    client.task(193, 8, publisher_single(".."), error=106)
    (objectpath / "present.json.content.bin").write_bytes(b"corrupt")
    client.task(193, 8, publisher_single("present.json"), error=106)
    (objectpath / "present.json.content.bin").write_bytes(publisher_bytes)
    metadata["acl"] = "private"
    (objectpath / "present.json.metadata.json").write_text(json.dumps(metadata))
    missing = pb_fields(
        client.task(193, 8, publisher_single("present.json"), structured=True)
    )
    assert next(v for t, k, v in missing if t == 2) == 404
    metadata["acl"] = "public"
    (objectpath / "present.json.metadata.json").write_text(json.dumps(metadata))
    for route in (
        "/objectstore/content/../platform.json",
        "/objectstore/content/" + "a" * 64,
    ):
        try:
            urllib.request.urlopen(base + route)
            raise AssertionError("Unpublished content accessible")
        except urllib.error.HTTPError as error:
            assert error.code == 404
    checks.append(
        "native publisher single/vector download metadata, required headers, immutable HTTP content, integrity and public ACL"
    )

    def object_reply(task, params):
        fields = pb_fields(client.task(193, task, params, structured=True))
        assert next(v for t, k, v in fields if t == 2) == 200
        result = next(v for t, k, v in fields if t == 3)
        headers = dict(
            (t, v) for t, k, v in pb_fields(next(v for t, k, v in fields if t == 1))
        )
        assert int(headers[2]) == len(result)
        return json.loads(result)

    def user_read(items):
        header = pb_text(1, "DW-Objectstore-ObjectIDs") + pb_text(2, json.dumps(items))
        return structure(
            pb_text(1, "GET")
            + pb_text(2, "/v2/core/users/objects/?context=iw8")
            + pb_bytes(4, header)
        )

    def user_upload(items):
        header = pb_text(1, "Content-Type") + pb_text(2, "application/json")
        return structure(
            pb_text(1, "PUT")
            + pb_text(2, "/v2/core/users/objects/?context=iw8")
            + pb_text(3, json.dumps({"objects": items}))
            + pb_bytes(4, header)
        )

    userobject = {"owner": "me", "name": "profile_stats.bin"}
    missing = object_reply(6, user_read([userobject]))
    assert not missing["objects"] and len(missing["errors"]) == 1
    userstats = os.urandom(1536)
    extra = os.urandom(37)
    uploadobject = {
        "metadata": {
            **userobject,
            "expiresOn": 0,
            "checksum": "",
            "acl": "private",
            "category": "stats",
            "extraData": base64.b64encode(extra).decode(),
        },
        "content": base64.b64encode(userstats).decode(),
        "tags": [
            {"key": "kind", "value": "profile"},
            {"key": None, "value": "fixture"},
        ],
    }
    saved = object_reply(7, user_upload([uploadobject]))
    assert not saved["errors"] and saved["validationTokens"] == []
    saved_metadata = saved["objects"][0]["metadata"]
    assert saved_metadata["owner"] == "uno-" + str(user) and saved_metadata[
        "contentLength"
    ] == len(userstats)
    assert saved_metadata["checksum"] == hashlib.md5(
        userstats
    ).hexdigest() and saved_metadata["extraDataSize"] == len(extra)
    downloaded = object_reply(
        6, user_read([userobject, {"owner": "me", "name": "not-present.bin"}])
    )
    assert base64.b64decode(downloaded["objects"][0]["content"]) == userstats
    assert (
        downloaded["objects"][0]["metadata"] == saved_metadata
        and downloaded["objects"][0]["tags"] == uploadobject["tags"]
    )
    assert (
        downloaded["objects"][0]["requestIndex"] == 0
        and downloaded["errors"][0]["requestIndex"] == 1
    )
    original_created = saved_metadata["created"]
    original_version = saved_metadata["objectVersion"]
    userstats = os.urandom(2048)
    uploadobject["content"] = base64.b64encode(userstats).decode()
    saved = object_reply(7, user_upload([uploadobject]))
    saved_metadata = saved["objects"][0]["metadata"]
    assert (
        saved_metadata["created"] == original_created
        and saved_metadata["objectVersion"] != original_version
    )
    assert saved_metadata["checksum"] == hashlib.md5(userstats).hexdigest()
    assert (
        base64.b64decode(
            object_reply(6, user_read([userobject]))["objects"][0]["content"]
        )
        == userstats
    )
    # The live Replay queue supplied platform=6 for all six profile blobs.
    # Exercise that exact owner representation, rather than only the `me` alias.
    native_owner = "uno-" + str(user)
    nativeobject = {
        **uploadobject,
        "metadata": {**uploadobject["metadata"], "owner": native_owner},
    }
    saved = object_reply(7, user_upload([nativeobject]))
    saved_metadata = saved["objects"][0]["metadata"]
    assert saved_metadata["owner"] == native_owner
    assert (
        base64.b64decode(
            object_reply(
                6, user_read([{"owner": native_owner, "name": userobject["name"]}])
            )["objects"][0]["content"]
        )
        == userstats
    )
    client.task(
        193,
        7,
        user_upload(
            [
                {
                    **nativeobject,
                    "metadata": {
                        **nativeobject["metadata"],
                        "owner": "uno-" + str(user + 1),
                    },
                }
            ]
        ),
        error=101,
    )
    client.task(
        193,
        7,
        user_upload(
            [
                {
                    **uploadobject,
                    "metadata": {
                        **uploadobject["metadata"],
                        "owner": "bnet-" + str(user + 1),
                    },
                }
            ]
        ),
        error=101,
    )
    client.task(193, 7, user_upload([{**uploadobject, "content": "AA=A"}]), error=106)
    client.task(
        193, 6, object_params(objects), error=106
    )  # publisher task must not masquerade as user download
    client.task(193, 7, user_upload([uploadobject, uploadobject]), error=106)
    checks.append(
        "native user-object read/upload, metadata/content/checksum/tags, missing indexes and caller ownership"
    )
    checks.append(
        "live-Replay platform-6 universal-ID owner upload/read and cross-account rejection"
    )

    if args.startup_only:
        receipt = {
            "schema": 1, "passed": True, "scope": "startup", "native_game_verified": False,
            "checks": checks, "server_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(),
            "kdf_sha256": hashlib.sha256((root / "data/replay-traffic-kdf.bin").read_bytes()).hexdigest(),
            "fixture_directory": str(directory),
        }
        (root / "data/lobby-startup-verification.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(f"PASS: {len(checks)} encrypted startup/social/profile-storage groups; later domain tests were not run")
        raise SystemExit(0)
    search_uri = "/v1.0/users/?client=replaylocal&searchType=username&username="
    for value in ("Fixture%20Peer", "fixture%20peer%230", "Fixture%25"):
        status, result = rest_response(
            client.task(
                255,
                10,
                native_rest(
                    "umbrella",
                    "UserResource",
                    "usernamesearch",
                    uri=search_uri + value + "&provider=uno",
                ),
            )
        )
        assert status == 200 and len(result["users"]) == 1
        accounts = result["users"][0]["accounts"]
        assert [row["provider"] for row in accounts] == ["uno", "bnet"]
        assert all(
            row["username"] == "Fixture Peer#0"
            and row["accountID"] > 0
            and len(row["created"]) == 20
            and len(row["updated"]) == 20
            for row in accounts
        )
    for value in ("NoSuchReplayUser", "Fixture%20Peer&provider=psn"):
        status, result = rest_response(
            client.task(
                255,
                10,
                native_rest(
                    "umbrella", "UserResource", "usernamesearch", uri=search_uri + value
                ),
            )
        )
        assert status == 200 and result == {"users": []}
    client.task(
        255,
        10,
        native_rest(
            "umbrella", "UserResource", "usernamesearch", uri=search_uri + "bad%00name"
        ),
        error=106,
    )
    checks.append(
        "Replay native username search, UNO account schema, exact/tag/prefix matching and malformed query rejection"
    )
    # Use actual Replay route versions/methods, not a synthetic endpoint alias.
    mutation_uri = f"/v3/user/bnet-{user}/list/recent/"
    assert client.task(
        255,
        10,
        native_rest(
            "userlists", "UserLists", "create_user_list", 0x504F5354, uri=mutation_uri
        ),
    )[-8:] == boolean(False) + blob(b"")
    list_rows = [
        {"userID": user + i, "accountType": "uno", "score": i, "metadata": {"round": i}}
        for i in range(1, 5)
    ]
    update_list = lambda rows, suffix="": native_rest(
        "userlists",
        "UserLists",
        "add_or_update_users_in_user_list",
        0x505554,
        {"userList": rows},
        uri=mutation_uri + "add/?context=iw8" + suffix,
    )
    client.task(255, 10, update_list(list_rows))
    get_list = lambda suffix="": rest_response(
        client.task(
            255,
            10,
            native_rest(
                "social-service", "UserLists", "get_user_list", uri=list_uri + suffix
            ),
        )
    )[1]
    first = get_list("&sortOrder=DESCENDING&maxUsersInResponse=2")
    assert [r["score"] for r in first["userList"]] == [4, 3] and first["pageToken"]
    last = get_list(
        "&sortOrder=DESCENDING&maxUsersInResponse=2&pageToken=" + first["pageToken"]
    )
    assert [r["score"] for r in last["userList"]] == [2, 1] and last["pageToken"] == ""
    snapshot = get_list()
    client.task(255, 10, update_list([list_rows[0], list_rows[0]]), error=106)
    assert get_list() == snapshot
    client.task(255, 10, update_list([dict(list_rows[0], score=10)]))
    client.task(
        255,
        10,
        native_rest(
            "social-service",
            "UserLists",
            "get_user_list",
            uri=list_uri
            + "&sortOrder=DESCENDING&maxUsersInResponse=2&pageToken="
            + first["pageToken"],
        ),
        error=106,
    )
    client.task(
        255,
        10,
        native_rest(
            "userlists",
            "UserLists",
            "create_user_list",
            0x504F5354,
            uri=mutation_uri.replace(str(user), str(user + 1)),
        ),
        error=101,
    )
    client.task(
        255,
        10,
        native_rest(
            "social-service",
            "UserLists",
            "get_user_list",
            uri=list_uri.replace("recent", "%2e%2e"),
        ),
        error=106,
    )
    client.task(255, 10, update_list([], suffix="&trimLength=2&trimOrder=ASCENDING"))
    assert [r["score"] for r in get_list()["userList"]] == [4, 10]
    client.task(
        255,
        10,
        native_rest(
            "userlists",
            "UserLists",
            "remove_users_from_user_list",
            0x504F5354,
            {"userList": [dict(list_rows[0], score=10)]},
            uri=mutation_uri + "remove/",
        ),
    )
    assert get_list()["userList"] == [list_rows[3]]
    checks.append(
        "native v1/v3 user lists: atomic add/update/remove, metadata, score trimming, authenticated owner and stale-safe pagination"
    )
    friend_uri = f"/v1/friends/uno-{user}/"
    peer = {"userID": user + 9, "accountType": "uno"}
    invite = lambda users: rest_response(
        client.task(
            255,
            10,
            native_rest(
                "friends",
                "Friends",
                "invite_friend",
                0x504F5354,
                {"users": users},
                uri=friend_uri + "invitation/?context=iw8",
            ),
        )
    )[1]
    invited = invite([peer])
    assert invited == {
        "context": "iw8",
        "pending": [peer],
        "friended": [],
        "errors": [],
    }
    assert invite([peer]) == invited
    pending = lambda direction: rest_response(
        client.task(
            255,
            10,
            native_rest(
                "social-service",
                "Friends",
                "get_pending_friend_requests",
                uri=friend_uri + "pending/?context=iw8&direction=" + direction,
            ),
        )
    )[1]
    assert pending("OUTGOING")["users"] == [peer] and pending("INCOMING")["users"] == []
    client.task(
        255,
        10,
        native_rest(
            "friends",
            "Friends",
            "invite_friend",
            0x504F5354,
            {"users": [peer, peer]},
            uri=friend_uri + "invitation/",
        ),
        error=106,
    )
    assert pending("OUTGOING")["users"] == [peer]
    reject = lambda who: client.task(
        255,
        10,
        native_rest(
            "friends",
            "Friends",
            "reject_friend_request",
            0x44454C45,
            uri=friend_uri + f"{who['accountType']}-{who['userID']}/",
        ),
    )
    reject(peer)
    assert pending("OUTGOING")["users"] == []
    # Fixture-only second-account invitation; production files are untouched.
    graph = (
        directory
        / "social"
        / str(title)
        / hashlib.sha256(b"iw8").hexdigest()
        / "friends.json"
    )
    state = json.loads(graph.read_text())
    state["pending"].append(
        {
            "from": peer,
            "to": {"userID": user, "accountType": "uno"},
            "from_name": "Fixture Peer",
        }
    )
    graph.write_text(json.dumps(state))
    assert pending("INCOMING")["users"] == [dict(peer, username="Fixture Peer#0")]
    assert invite([peer])["friended"] == [peer] and pending("INCOMING")["users"] == []
    friends = lambda: rest_response(
        client.task(
            255,
            10,
            native_rest("social-service", "Friends", "get_friends", uri=friend_uri),
        )
    )[1]
    assert friends()["users"] == [peer]
    checks.append(
        "native friend invitation/retry/revoke, reciprocal consent, complete result arrays and caller-scoped relationship lists"
    )
    import social_store_fixtures

    social_store_fixtures.exercise(
        client, graph, user, peer, native_rest, rest_response, checks
    )
    nonce = os.urandom(32)
    with post("/platform/login/peer", nonce) as response:
        peer_platform = response.read()
    rsa.RSAPublicNumbers(exponent, modulus).public_key().verify(
        peer_platform[256:],
        peer_platform[:256],
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    assert peer_platform[8:40] == nonce
    peer_user = struct.unpack_from("<Q", peer_platform, 56)[0]
    assert peer_user != user
    peer_credentials = {
        "session_token": peer_platform[112:176].decode(),
        "account_token": peer_platform[177:241].decode(),
    }
    with post(
        "/auth/", dict(request, extra_data=json.dumps(peer_credentials))
    ) as response:
        peer_auth = json.load(response)
    peer_client = Client(
        auth_identity=(
            base64.b64decode(peer_auth["server_ticket"]),
            base64.b64decode(peer_auth["client_ticket"])[97:121],
        )
    )
    import username_fixtures

    username_fixtures.exercise(
        client, title, user, peer_user, native_rest, rest_response, blob, checks
    )
    import abtesting_rest_fixtures

    ab_rest_fixture = abtesting_rest_fixtures.exercise(
        client,
        peer_client,
        directory,
        title,
        user,
        peer_user,
        native_rest,
        rest_response,
        enroll_params,
        (blob, structure, pb_text, pb_bytes, pb_integer, pb_fields),
        checks,
    )

    import objectstore_rest_fixtures

    objectstore_rest_restart = objectstore_rest_fixtures.exercise(
        client,
        peer_client,
        directory,
        title,
        user,
        peer_user,
        native_rest,
        rest_response,
        (blob, structure, pb_text, pb_bytes, pb_integer, pb_fields),
        checks,
    )
    peer_client.task(58, 6, content_fixture["post"], error=101)
    import host_bot_control_fixtures
    host_bot_control_fixtures.exercise(client, peer_client, directory, title, user,
                                     match_query, (u32, u64, text, boolean), checks)
    import auto_fill_bot_fixtures
    auto_fill_bot_fixtures.exercise(client, peer_client, directory, title, user,
                                  match_query, (u32, u64, text, boolean), checks)
    if args.host_controls_only:
        proof = dict(passed=True, native_game_verified=False, checks=checks,
                     server_sha256=hashlib.sha256(exe.read_bytes()).hexdigest())
        (root / "data/lobby-host-controls-verification.json").write_text(json.dumps(proof, indent=2)+"\n")
        print(f"PASS: {len(checks)} native startup and host-control groups")
        raise SystemExit(0)
    import lobby_join_fixtures

    lobby_join_fixtures.exercise(
        client,
        peer_client,
        directory,
        title,
        user,
        peer_user,
        player_info,
        match_query,
        (u32, u64, text, boolean),
        checks,
    )
    import matchmaking_transaction_fixtures

    matchmaking_transaction_fixture = matchmaking_transaction_fixtures.exercise(
        client, directory, title, user, match_query, (u32, u64, text, boolean), checks
    )
    if args.matchmaking_transaction_only:
        proof = dict(passed=True, native_game_verified=False, checks=checks,
                     server_sha256=hashlib.sha256(exe.read_bytes()).hexdigest())
        (root / "data/lobby-transaction-verification.json").write_text(json.dumps(proof, indent=2) + "\n")
        print(f"PASS: {len(checks)} native startup and matchmaking transaction groups")
        raise SystemExit(0)
    import public_matchmaking_fixtures

    public_matchmaking_fixtures.exercise(
        client,
        peer_client,
        directory,
        title,
        user,
        peer_user,
        player_info,
        match_query,
        (u32, u64, text, boolean),
        checks,
    )
    import matchmaking_membership_fixtures

    matchmaking_membership_fixtures.exercise(
        client,
        peer_client,
        directory,
        title,
        user,
        peer_user,
        match_query,
        (u32, u64, text, boolean),
        checks,
    )
    import matchmaking_constraint_fixtures

    matchmaking_constraint_fixtures.exercise(
        client,
        peer_client,
        directory,
        title,
        user,
        peer_user,
        match_query,
        (u32, u64, text, boolean),
        checks,
    )
    import tournament_fixtures

    tournament_fixture = tournament_fixtures.exercise(
        client,
        peer_client,
        directory,
        title,
        user,
        peer_user,
        (u64, text, boolean),
        checks,
    )
    import copy_content_fixtures

    tournament_fixtures.live_publications(
        client,
        peer_client,
        directory,
        title,
        user,
        peer_user,
        (u64, text, boolean),
        checks,
    )

    import tournament_join_fixtures

    tournament_join_fixtures.exercise(
        client,
        peer_client,
        directory,
        title,
        user,
        peer_user,
        (u64, text, boolean),
        checks,
    )

    import tournament_formation_fixtures

    def new_tournament_client(index, *, signer=None, player_name=None, expected_name=None):
        from cryptography.hazmat.primitives.asymmetric import ec, utils

        # Use the production machine-owned registration flow. No development
        # profile provisioning, copied identity, credentials or seeded account ID.
        signer = signer or ec.generate_private_key(ec.SECP256R1())
        numbers = signer.public_key().public_numbers()
        public_key = (
            struct.pack("<II", 0x31534345, 32)
            + numbers.x.to_bytes(32, "big")
            + numbers.y.to_bytes(32, "big")
        )
        nonce = os.urandom(32)
        with post("/platform/client/challenge", public_key + nonce) as response:
            challenge = response.read()
        assert len(challenge) == 32
        name = (player_name or "Tournament Fixture " + str(index)).encode().ljust(36, b"\0")
        prefix = (
            struct.pack("<II", 0x31494452, 1) + nonce + challenge + public_key + name
        )
        assert len(prefix) == 180
        r, s = utils.decode_dss_signature(
            signer.sign(prefix, ec.ECDSA(hashes.SHA256()))
        )
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        with post("/platform/client/login", prefix + signature) as response:
            issued = response.read()
        assert len(issued) == 512 and issued[8:40] == nonce
        if expected_name is not None:
            assert issued[72:108].split(b"\0", 1)[0].decode() == expected_name
        identity = struct.unpack_from("<Q", issued, 56)[0]
        credentials = {
            "session_token": issued[112:176].decode(),
            "account_token": issued[177:241].decode(),
        }
        with post(
            "/auth/", dict(request, extra_data=json.dumps(credentials))
        ) as response:
            auth = json.load(response)
        return identity, Client(
            auth_identity=(
                base64.b64decode(auth["server_ticket"]),
                base64.b64decode(auth["client_ticket"])[97:121],
            )
        )

    import platform_name_fixtures

    platform_name_fixtures.exercise(new_tournament_client, checks)

    tournament_formation_fixtures.exercise(
        client,
        peer_client,
        directory,
        title,
        user,
        peer_user,
        player_info,
        new_tournament_client,
        (u64, text, boolean),
        checks,
    )

    import tournament_round_fixtures

    tournament_round_fixtures.exercise(
        directory,
        title,
        player_info,
        match_query,
        new_tournament_client,
        (u64, text, boolean),
        checks,
    )

    import channel_membership_fixtures

    channel_membership_fixtures.exercise(
        directory,
        title,
        new_tournament_client,
        (u64, text, structure, pb_text, pb_integer, pb_bytes, pb_fields),
        checks,
    )

    copy_fixture = copy_content_fixtures.exercise(
        client,
        peer_client,
        directory,
        title,
        user,
        peer_user,
        base,
        (u32, u64, text, blob, boolean),
        checks,
    )
    import user_content_fixtures

    user_content_fixture = user_content_fixtures.exercise(
        client,
        peer_client,
        directory,
        title,
        user,
        peer_user,
        base,
        (u32, u64, text, blob),
        checks,
    )
    checks.append(
        "separately authenticated content commit cannot impersonate the original uploader"
    )
    multipart_content_fixtures.check_peer(peer_client, multipart_fixture, checks)
    peer_client.task(123, 1, redemption_fixture["peer_request"], error=101)
    import purchase_fixtures

    purchase_fixture = purchase_fixtures.exercise(
        peer_client,
        client,
        directory,
        title,
        peer_user,
        (u32, u64, text, blob, boolean),
        checks,
    )
    import relay_fixtures

    relay_fixture = relay_fixtures.exercise(
        client, peer_client, directory, exe, user, peer_user, checks
    )
    assert peer_client.task(23, 1, counters([(71, 4)])) == []
    assert client.task(23, 2, u32(71)) == counters([(71, 12)])
    checks.append(
        "separately authenticated accounts contribute to the same per-title global counter aggregate"
    )
    check_peer_challenge_responses(
        peer_client, directory, title, peer_user, challenge_fixture, checks
    )
    message = bytes(range(256)) * 16
    assert peer_client.task(6, 14, u64(user) + blob(message)) == []
    assert client.receive() == (
        2,
        u32(21) + u64(peer_user) + text("Fixture Peer") + blob(message),
    )
    assert client.task(6, 14, u64(peer_user) + blob(b"reply")) == []
    assert peer_client.receive() == (
        2,
        u32(21) + u64(user) + text("DWPlayer") + blob(b"reply"),
    )
    assert client.task(6, 14, u64(user) + blob(b"")) == []
    assert client.receive() == (2, u32(21) + u64(user) + text("DWPlayer") + blob(b""))
    client.task(6, 14, u64(1) + blob(b"unknown recipient"), error=108)
    client.task(6, 14, u64(peer_user) + blob(bytes(4097)), error=106)
    client.task(6, 14, u64(peer_user) + blob(b"bad sender") + u64(peer_user), error=106)
    assert peer_client.task(12, 6)[0] == 8
    checks.append(
        "native global instant-message push 21, exact sender identity/name/blob, bidirectional peer routing, empty/max payload and malformed/unknown rejection"
    )
    from clan_push_fixtures import run as test_clan_pushes

    test_clan_pushes(
        client,
        peer_client,
        user,
        peer_user,
        clan_id,
        checks,
        structure,
        u32,
        pb_integer,
        pb_bytes,
        pb_text,
        pb_map,
    )
    real_peer = {"userID": peer_user, "accountType": "uno"}
    own_user = {"userID": user, "accountType": "uno"}

    def friend_notification(c, schema, field, who, name=None):
        kind, raw = c.receive()
        prefix = u32(199) + text("friends") + text(schema) + text("application/json")
        assert kind == 2 and raw.startswith(prefix)
        actor = dict(who, username=name) if name else who
        assert json.loads(raw[len(prefix) + 6 :]) == {"context": "iw8", field: actor}

    peer_uri = f"/v1/friends/uno-{peer_user}/"
    peer_invite = lambda: peer_client.task(
        255,
        10,
        native_rest(
            "friends",
            "Friends",
            "invite_friend",
            0x504F5354,
            {"users": [own_user]},
            uri=peer_uri + "invitation/",
        ),
    )
    peer_invite()
    friend_notification(
        client, "InviteCreatedPushMessage", "invitingUser", real_peer, "Fixture Peer#0"
    )
    peer_invite()
    assert client.task(12, 6)[0] == 8  # Retry emits no extra push.
    assert pending("INCOMING")["users"] == [dict(real_peer, username="Fixture Peer#0")]
    reject(real_peer)
    friend_notification(
        peer_client, "InviteRejectedPushMessage", "rejectingUser", own_user
    )
    invite([real_peer])
    friend_notification(
        peer_client, "InviteCreatedPushMessage", "invitingUser", own_user, "DWPlayer#0"
    )
    peer_invite()
    friend_notification(client, "InviteAcceptedPushMessage", "acceptingUser", real_peer)
    assert (
        dict(real_peer, username="Fixture Peer#0", presence={"online": False})
        in friends()["users"]
    )
    reject(real_peer)
    friend_notification(
        peer_client, "FriendshipRevokedPushMessage", "revokingUser", own_user
    )
    peer_client.task(
        255,
        10,
        native_rest(
            "friends",
            "Friends",
            "reject_friend_request",
            0x44454C45,
            uri=peer_uri + f"uno-{user}/",
        ),
    )
    assert client.task(12, 6)[0] == 8 and friends()["users"] == [peer]
    for invalid_profile in ("unknown", "../peer", "peer/extra", ""):
        route = "/platform/login/" + invalid_profile
        try:
            with post(route, os.urandom(32)):
                raise AssertionError("Invalid profile login accepted")
        except urllib.error.HTTPError as error:
            assert error.code == 400
    peer_client.task(
        255,
        10,
        native_rest(
            "presence",
            "UserPresence",
            "set_user_presence",
            0x505554,
            {"online": True, "platform": "bnet", "data": {"multiuser": 1}},
            uri=f"/v2/users/uno-{peer_user}/presence/",
        ),
    )
    peer_presence = lambda: rest_response(
        client.task(
            255,
            10,
            native_rest(
                "social-service",
                "UsersPresence",
                "get_users_presence",
                uri=f"/v1/users/presence/?context=iw8&users=bnet-{peer_user}",
            ),
        )
    )[1]["users"][0]
    assert (
        peer_presence()["presence"]["online"] is True
        and peer_presence()["accountType"] == "uno"
    )
    peer_subscription = f"/v2/users/uno-{user}/subscriptions/presence/?context=iw8"
    status, snapshots = rest_response(
        client.task(
            255,
            10,
            native_rest(
                "presence",
                "UsersPresence",
                "subscribe_to_users",
                0x504F5354,
                {"users": [real_peer]},
                uri=peer_subscription,
            ),
        )
    )
    assert status == 200 and snapshots["users"][0]["presence"]["online"] is True
    other_context = lambda: rest_response(
        client.task(
            255,
            10,
            native_rest(
                "social-service",
                "UsersPresence",
                "get_users_presence",
                uri=f"/v1/users/presence/?context=cod-shared&users=uno-{peer_user}",
            ),
        )
    )[1]["users"][0]["presence"]
    assert other_context() == {"online": False}
    peer_client.task(
        255,
        10,
        native_rest(
            "presence",
            "UserPresence",
            "set_user_presence",
            0x505554,
            {"online": False, "data": {"separate": 2}},
            uri=f"/v2/users/uno-{peer_user}/presence/?context=cod-shared",
        ),
    )
    assert (
        other_context()["data"] == {"separate": 2}
        and peer_presence()["presence"]["online"] is True
    )
    # A different context must not notify an iw8 subscriber.
    assert client.task(12, 6)[0] == 8
    offline_lobby = lobby_join_fixtures.prepare_offline_lobby(
        peer_client, peer_user, match_query, (u32, u64, text, boolean)
    )
    peer_client.close()
    kind, push = client.receive()
    prefix = (
        u32(199)
        + text("presence")
        + text("UserPresenceUpdatedPushMessage")
        + text("application/json")
    )
    assert kind == 2 and push.startswith(prefix)
    offline_message = json.loads(push[len(prefix) + 6 :])
    assert (
        offline_message["context"] == "iw8" and offline_message["userID"] == peer_user
    )
    assert offline_message["presence"]["online"] is False and offline_message[
        "presence"
    ]["data"] == {"multiuser": 1}
    for attempt in range(30):
        if not peer_presence()["presence"]["online"]:
            break
        time.sleep(0.01)
    else:
        raise AssertionError("Disconnected peer remained online")
    # A still-unexpired party token cannot introduce an offline member into
    # a new lobby. Reauthenticating the same account cannot revive that token.
    disconnected_peer_state = json.loads(
        (
            directory / "matchmaking" / str(title) / "players" / f"{peer_user}.json"
        ).read_text()
    )
    offline_party_query = {
        **match_query,
        "members": [user, peer_user],
        "tokens": [
            struct.unpack_from("<Q", client.task(145, 3), 1)[0],
            disconnected_peer_state["token"],
        ],
    }
    client.task(145, 18, text(json.dumps(offline_party_query)), error=14507)
    client.task(6, 14, u64(peer_user) + blob(b"offline"), error=108)
    lobby_join_fixtures.reject_offline_owner(
        client,
        peer_user,
        offline_lobby,
        directory,
        title,
        user,
        (u32, u64, text, boolean),
        checks,
    )
    checks.append(
        "global instant messages do not report successful delivery to a disconnected recipient"
    )
    unsubscribe_peer = lambda: rest_response(
        client.task(
            255,
            10,
            native_rest(
                "presence",
                "UsersPresence",
                "unsubscribe_from_users",
                0x44454C45,
                uri=peer_subscription + "&users=uno-" + str(peer_user),
            ),
        )
    )
    assert unsubscribe_peer() == (200, {"errorUsers": []})
    assert unsubscribe_peer() == (200, {"errorUsers": []})
    # Reauth rotates the existing signed peer key. A new live connection for
    # that account must not revive the lobby created with the old endpoint/key.
    with post(
        "/auth/", dict(request, extra_data=json.dumps(peer_credentials))
    ) as response:
        renewed_peer_auth = json.load(response)
    renewed_peer = Client(
        auth_identity=(
            base64.b64decode(renewed_peer_auth["server_ticket"]),
            base64.b64decode(renewed_peer_auth["client_ticket"])[97:121],
        )
    )
    assert renewed_peer.task(12, 6).startswith(b"\x08")
    client.task(145, 18, text(json.dumps(offline_party_query)), error=14507)
    renewed_peer.task(
        145,
        18,
        text(
            json.dumps(
                {
                    **match_query,
                    "members": [peer_user],
                    "tokens": [disconnected_peer_state["token"]],
                }
            )
        ),
        error=14507,
    )
    renewed_peer.task(145, 2, text(player_json))
    renewed_match_token = struct.unpack_from("<Q", renewed_peer.task(145, 3), 1)[0]
    assert renewed_match_token != disconnected_peer_state["token"]
    renewed_peer.task(
        145,
        18,
        text(
            json.dumps(
                {
                    **match_query,
                    "members": [peer_user],
                    "tokens": [renewed_match_token],
                    "player_id_to_slots": {str(peer_user): 0},
                }
            )
        ),
    )
    kind, renewed_push = renewed_peer.receive()
    assert kind == 2 and renewed_push.startswith(u32(2005))
    renewed_lobby = struct.unpack_from("<Q", renewed_push, 15)[0]
    assert renewed_peer.task(145, 10, u64(renewed_lobby)) == []
    assert renewed_peer.receive() == (2, u32(2002) + u64(renewed_lobby) + u64(0))
    checks.append(
        "party tokens require live issuer sessions; offline/reauthenticated members and old owner tokens reject, while a refreshed token creates a new lobby"
    )
    lobby_join_fixtures.reject_offline_owner(
        client,
        peer_user,
        offline_lobby,
        directory,
        title,
        user,
        (u32, u64, text, boolean),
        [],
    )
    old_lobby_path = (
        directory / "matchmaking" / str(title) / "lobbies" / f"{offline_lobby}.json"
    )
    old_lobby = json.loads(old_lobby_path.read_bytes())
    before_old_lobby = old_lobby_path.read_bytes()
    renewed_peer.task(
        145,
        15,
        u64(offline_lobby)
        + u64(old_lobby["update_id"])
        + text(json.dumps(old_lobby["host_doc"])),
        error=108,
    )
    assert old_lobby_path.read_bytes() == before_old_lobby
    # Read-only inspection and owner cleanup remain available for old records.
    assert renewed_peer.task(145, 13, u64(offline_lobby))[0] == 16
    assert renewed_peer.task(145, 10, u64(offline_lobby)) == []
    assert renewed_peer.receive() == (2, u32(2002) + u64(offline_lobby) + u64(0))
    from host_migration_fixtures import exercise as test_host_migration

    renewed_peer = test_host_migration(
        client,
        renewed_peer,
        renewed_peer_auth,
        Client,
        directory,
        title,
        user,
        peer_user,
        match_query,
        native_rest,
        rest_response,
        (u32, u64, text, boolean),
        checks,
    )
    from mail_notification_fixtures import exercise as test_mail_notifications

    renewed_peer = test_mail_notifications(
        client,
        renewed_peer,
        renewed_peer_auth,
        Client,
        directory,
        title,
        user,
        peer_user,
        (u32, u64, text, boolean, blob),
        checks,
    )
    from session_presence_fixtures import exercise as test_session_presence

    test_session_presence(
        client,
        renewed_peer,
        renewed_peer_auth,
        peer_credentials,
        request,
        post,
        Client,
        native_rest,
        rest_response,
        user,
        peer_user,
        u32,
        text,
        checks,
    )
    renewed_peer.close()
    checks.append(
        "a reauthenticated online host cannot revive an old lobby's endpoint/DTLS session through either presence target or a host update; read-only inspection and owner disband remain available"
    )
    checks.append(
        "two separately signed identities, independent sessions, real encrypted friend lifecycle notifications and disconnect-aware peer presence"
    )
    checks.append(
        "presence context isolation and unsolicited last-connection offline notification preserve the correct scoped payload"
    )
    mapped = lambda task, items: pb_map(
        client.task(
            197,
            task,
            structure(
                b"".join(
                    pb_bytes(1, pb_integer(1, uid) + pb_text(2, kind))
                    for uid, kind in items
                )
            ),
            structured=True,
        )
    )
    assert [
        pb_map(v)
        for v in mapped(10, [(user, "bnet"), (user + 1, "uno"), (user, "xbl")])[1]
    ] == [{1: [user], 2: [b"uno"]}, {1: [0], 2: [b""]}, {1: [0], 2: [b""]}]
    assert pb_map(mapped(11, [(user, "uno")])[1][0]) == {1: [user], 2: [b"bnet"]}
    assert pb_map(mapped(10, [(peer_user, "bnet")])[1][0]) == {
        1: [peer_user],
        2: [b"uno"],
    }
    client.task(
        197, 10, structure(pb_bytes(1, pb_integer(1, user))), error=106, structured=True
    )
    assert len(mapped(10, [(user, "uno")] * 200)[1]) == 200
    client.task(
        197,
        10,
        structure(
            b"".join(
                pb_bytes(1, pb_integer(1, user) + pb_text(2, "uno")) for _ in range(201)
            )
        ),
        error=106,
        structured=True,
    )
    checks.append(
        "native identity mapping retains ordered valid/invalid slots, signed known aliases and 200-account bound"
    )
    presence = {"online": True, "platform": "bnet", "data": {"fixture": 7}}
    presence_uri = f"/v2/users/uno-{user}/presence/?context=iw8"
    set_presence = lambda body: client.task(
        255,
        10,
        native_rest(
            "presence",
            "UserPresence",
            "set_user_presence",
            0x505554,
            body,
            uri=presence_uri,
        ),
    )
    raw = set_presence(presence)
    assert raw[-8:] == boolean(False) + blob(b"")
    valid_parameters = native_rest(
        "presence",
        "UserPresence",
        "set_user_presence",
        0x505554,
        presence,
        uri=presence_uri,
    )
    old_body = json.dumps(presence).encode()
    for invalid_body in (b'{"online":', b"[" * 40 + b"0" + b"]" * 40):
        invalid_parameters = valid_parameters[: -len(blob(old_body))] + blob(
            invalid_body
        )
        client.task(255, 10, invalid_parameters, error=106)
    presence_path = (
        directory
        / "presence"
        / str(title)
        / hashlib.sha256(b"iw8").hexdigest()
        / (str(user) + ".json")
    )
    persisted_presence = json.loads(presence_path.read_text())
    assert (
        persisted_presence
        == dict(presence, updateTime=persisted_presence["updateTime"])
        and abs(persisted_presence["updateTime"] - time.time()) < 5
    )
    client.task(
        255,
        10,
        native_rest(
            "presence",
            "UserPresence",
            "set_user_presence",
            0x505554,
            [],
            uri=presence_uri,
        ),
        error=106,
    )
    client.task(
        255,
        10,
        native_rest(
            "presence",
            "UserPresence",
            "set_user_presence",
            0x505554,
            presence,
            uri=presence_uri.replace(str(user), str(user + 1)),
        ),
        error=101,
    )
    get_presence = lambda users: rest_response(
        client.task(
            255,
            10,
            native_rest(
                "social-service",
                "UsersPresence",
                "get_users_presence",
                uri="/v1/users/presence/?context=iw8&users="
                + ",".join("uno-" + str(u) for u in users),
            ),
        )
    )[1]
    own_presence = get_presence([user, user + 1])["users"]
    assert own_presence[0] == {
        "userID": user,
        "accountType": "uno",
        "context": "iw8",
        "username": "DWPlayer#0",
        "presence": persisted_presence,
    }
    assert own_presence[1] == {
        "userID": user + 1,
        "accountType": "uno",
        "context": "iw8",
        "presence": {"online": False},
    }
    sub_uri = f"/v2/users/uno-{user}/subscriptions/presence/?context=iw8"
    observer = Client()
    raw = observer.task(
        255,
        10,
        native_rest(
            "presence",
            "UsersPresence",
            "subscribe_to_users",
            0x504F5354,
            {"users": [{"userID": user, "accountType": "bnet"}]},
            uri=sub_uri,
        ),
    )
    status, snapshot = rest_response(raw)
    assert status == 200 and snapshot == {"errorUsers": [], "users": [own_presence[0]]}
    updated = dict(presence, data={"fixture": 8})
    set_presence(updated)

    def presence_notification(c):
        kind, raw = c.receive()
        assert kind == 2
        prefix = (
            u32(199)
            + text("presence")
            + text("UserPresenceUpdatedPushMessage")
            + text("application/json")
        )
        assert raw.startswith(prefix)
        message = json.loads(raw[len(prefix) + 6 :])
        assert (
            len(raw)
            == len(prefix) + 6 + struct.unpack_from("<I", raw, len(prefix) + 2)[0]
        )
        assert (
            message["userID"] == user
            and message["context"] == "iw8"
            and message["presence"]["data"] == {"fixture": 8}
        )

    presence_notification(client)
    presence_notification(observer)
    assert rest_response(
        observer.task(
            255,
            10,
            native_rest(
                "presence",
                "UsersPresence",
                "unsubscribe_from_users",
                0x44454C45,
                uri=sub_uri + "&users=uno-" + str(user),
            ),
        )
    ) == (200, {"errorUsers": []})
    set_presence(presence)
    assert client.task(12, 6)[0] == 8 and observer.task(12, 6)[0] == 8
    observer.close()
    checks.append(
        "native single-presence snapshots, v2 subscriptions, encrypted Demonata notifications, unsubscribe and owner isolation"
    )
    checks.append(
        "same-Replay unsubscribe response includes mandatory errorUsers JSON, including idempotent already-removed users"
    )
    checks.append(
        "malformed and over-nested social request JSON is rejected as caller input without altering persisted presence"
    )
    assert client.task(12, 1, text("DWPlayer")) == u32(0)
    assert client.task(12, 1, text("")) == u32(2)
    checks.append(
        "native empty social lists, persisted caller-scoped presence and local string-verification policy"
    )
    import objectstore_transaction_fixtures

    objectstore_transaction_fixture = objectstore_transaction_fixtures.exercise(
        client, directory, title, user, user_upload, user_read, object_reply, checks
    )
    # More than the old lifetime limit of 128 pings, at a non-flood rate. The
    # same authenticated session must still accept its next encrypted task.
    for _ in range(140):
        client.s.sendall(bytes(4))
        assert client.s.recv(4) == bytes(4)
        time.sleep(0.012)
    assert client.task(12, 6).startswith(b"\x08")
    checks.append("long-lived lobby keepalives remain connected beyond 128 pings")
    log = (directory / "server.log").read_text()
    assert "rest_service=fixture resource=FixtureResource operation_name=get" in log
    assert "DO_NOT_LOG_HEADER" not in log and "DO_NOT_LOG_QUERY" not in log
    checks.append(
        "modern service diagnostics omit header credentials, query values and request bodies"
    )
    matchmaking_transaction_fixtures.prepare_restart(
        client, matchmaking_transaction_fixture, (u32, u64, text, boolean), checks
    )
    objectstore_transaction_fixtures.prepare_restart(
        client, objectstore_transaction_fixture
    )
    client.close()
    c = Client()
    c.task(38, 7, text(credentials["session_token"]))
    c.task(38, 7, text("0" * 64), error=101)
    with post("/auth/", request) as response:
        json.load(response)
    from session_presence_fixtures import expect_disconnect

    try:
        c.s.sendall(c.record(bytes([12, 3, 6, 0])))
    except ConnectionResetError:
        pass  # The guard already retired this revoked idle connection.
    expect_disconnect(c.s)
    c.close()
    # Recover this fixture's new native tickets before testing another connection.
    with post("/auth/", request) as response:
        auth = json.load(response)
    ticket = base64.b64decode(auth["server_ticket"])
    key = base64.b64decode(auth["client_ticket"])[97:121]
    checks.append("reported session-token binding and superseded-session rejection")
    for mode in ("mac", "sequence"):
        c = Client()
        record = bytearray(
            c.record(bytes([12, 3, 6, 0]), sequence=2 if mode == "sequence" else None)
        )
        if mode == "mac":
            record[-1] ^= 1
        c.s.sendall(record)
        # Authentication may already have queued a valid idle notification.
        # Decode every preceding frame before requiring FIN/RST. A task reply,
        # invalid authenticated frame, timeout or notification flood still fails.
        deadline = time.monotonic() + 3
        closed = False
        for _ in range(64):
            remaining = deadline - time.monotonic()
            assert remaining > 0, "Malformed native record did not close its connection"
            c.s.settimeout(remaining)
            try:
                if c.s.recv(1, socket.MSG_PEEK) == b"":
                    closed = True
                    break
                kind, packet = c.receive_record()
            except ConnectionResetError:
                closed = True
                break
            assert kind == 2
            if packet.startswith(u32(67)):
                from progression_delivery_fixtures import decode_reward
                decode_reward(packet)
            else:
                assert packet == u32(18), "Unexpected response before malformed-record close"
        assert closed, "Malformed native record caused a notification flood without closing"
        c.close()
    checks.append(
        "unknown ticket, invalid verify, modified MAC and out-of-order counter rejection"
    )
    # A full service suite can outlive the real five-minute QoS lease. Verify
    # expiry explicitly, then obtain a new server-issued lease immediately
    # before the restart persistence check. Never extend a production TTL or
    # rewrite the new transaction's expiry to make the check pass.
    qos_transactions = directory / "qos" / str(title) / "transactions" / f"{user}.json"
    qos_rows = json.loads(qos_transactions.read_text())
    for row in qos_rows:
        if row["id"] == qos_transaction:
            row["expires"] = int(time.time()) - 1
    qos_transactions.write_text(json.dumps(qos_rows))
    qos_lease_client = Client()
    try:
        qos_lease_client.task(145, 4, qos_report, error=101)
        issued = qos_lease_client.task(145, 25, qos_query)
        qos_transaction = json.loads(issued[1:-1])["transaction_id"]
        qos_report = u64(qos_transaction) + qos_report[9:]
        assert qos_lease_client.task(145, 4, qos_report) == []
    finally:
        qos_lease_client.close()
    # Restart only the fixture child. Actual server, game and player data stay untouched.
    account_prepare_restart()
    process.terminate()
    process.wait(timeout=5)
    account_stopped()
    output.flush()
    matchmaking_transaction_fixtures.before_restart(matchmaking_transaction_fixture)
    objectstore_transaction_fixtures.before_restart(objectstore_transaction_fixture)
    import gift_fixtures

    gift_fixtures.prepare_restart(purchase_fixture["gift"])
    # Turn on the actual loopback QoS peer for the restart phase. The earlier
    # empty/configured-fleet checks remain unchanged and production is untouched.
    (directory / "qos" / "local-provider.json").write_text('{"enabled":true}')
    (directory / "relay" / "local-provider.json").write_text('{"enabled":true}')
    qos_config.unlink()
    process = subprocess.Popen(
        [str(exe), str(directory), "--port-offset", str(offset)],
        stdout=output,
        stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    for _ in range(100):
        try:
            with post("/platform/login", os.urandom(32)) as response:
                restarted = response.read()
            break
        except (OSError, urllib.error.URLError):
            time.sleep(0.05)
    else:
        raise RuntimeError("Fixture restart failed")
    assert restarted[56:108] == platform[56:108]  # Stable user, account, license, name.
    credentials = {
        "session_token": restarted[112:176].decode(),
        "account_token": restarted[177:241].decode(),
    }
    with post("/auth/", {**request, "extra_data": json.dumps(credentials)}) as response:
        auth = json.load(response)
    ticket = base64.b64decode(auth["server_ticket"])
    key = base64.b64decode(auth["client_ticket"])[97:121]
    client = Client()
    matchmaking_transaction_fixtures.check_restart(
        client, matchmaking_transaction_fixture, (u32, u64, text, boolean), checks
    )
    objectstore_transaction_fixtures.check_restart(
        client, objectstore_transaction_fixture, pb_fields, checks
    )
    assert client.task(58, 6, content_fixture["post"]) == u64(content_fixture["id"])
    relay_fixtures.check_restart(client, relay_fixture, checks)
    regulation_restart(client)
    rename_restart()
    account_after_restart()
    objectstore_rest_fixtures.check_restart(
        client, objectstore_rest_restart, rest_response, checks
    )
    tournament_fixtures.check_restart(client, tournament_fixture, checks)
    validated_stats_fixtures.check_restart(client, validated_stats_fixture, checks)
    inventory_validation_fixtures.check_restart(
        client, inventory_validation_fixture, checks
    )
    copy_content_fixtures.check_restart(client, copy_fixture, checks)
    user_content_fixtures.check_restart(client, user_content_fixture, checks)
    marketing_fixtures.check_restart(client, marketing_fixture, checks)
    loot_fixtures.check_restart(client, loot_fixture, checks)
    multipart_content_fixtures.check_restart(client, multipart_fixture, checks)
    with post("/platform/login/peer", os.urandom(32)) as response:
        purchase_peer_platform = response.read()
    assert (
        struct.unpack_from("<Q", purchase_peer_platform, 56)[0]
        == purchase_fixture["user"]
    )
    purchase_peer_credentials = {
        "session_token": purchase_peer_platform[112:176].decode(),
        "account_token": purchase_peer_platform[177:241].decode(),
    }
    with post(
        "/auth/", dict(request, extra_data=json.dumps(purchase_peer_credentials))
    ) as response:
        purchase_peer_auth = json.load(response)
    purchase_peer_client = Client(
        auth_identity=(
            base64.b64decode(purchase_peer_auth["server_ticket"]),
            base64.b64decode(purchase_peer_auth["client_ticket"])[97:121],
        )
    )
    purchase_fixtures.check_restart(purchase_peer_client, purchase_fixture, checks)
    import relay_transport_fixtures

    relay_transport_fixtures.exercise(
        client,
        purchase_peer_client,
        user,
        purchase_fixture["user"],
        directory,
        base,
        checks,
        relay_fixture["token"],
    )
    purchase_peer_client.close()
    achievement_batch_fixtures.check_restart(client, achievement_batch_fixture, checks)
    assert client.task(38, 2, challenge_fixture["request"]) == []
    assert challenge_fixture["path"].read_bytes() == challenge_fixture["bytes"]
    checks.append(
        "challenge-response receipts survive server restart and exact retry without duplicate records"
    )
    assert (
        client.task(50, 9, u64(content_fixture["id"]) + u32(0))
        == content_fixture["metadata"]
    )
    assert (
        client.task(3, 46, content_fixture["team_query"])
        == content_fixture["team_result"]
    )
    with urllib.request.urlopen(content_fixture["download"]) as response:
        assert (
            hashlib.sha256(response.read()).hexdigest()
            == content_fixture["content_sha256"]
        )
    checks.append(
        "streaming commit/bytes/native metadata and published legacy teams survive backend restart"
    )
    import redemption_fixtures

    redemption_fixtures.check_restart(client, redemption_fixture, checks)
    offline = get_presence([user])["users"][0]["presence"]
    assert offline["online"] is False and offline["data"] == presence["data"]
    set_presence(presence)
    assert get_presence([user])["users"][0]["presence"]["online"] is True
    assert client.task(12, 6)[0] == 8
    assert client.task(23, 2, u32(71) + u32(72)) == counters([(71, 12), (72, -9)])
    checks.append("shared signed counter totals survive a server process restart")
    checks.append(
        "persisted presence survives restart while online state and subscriptions reset to connection lifetime"
    )
    assert get_list()["userList"] == [list_rows[3]] and friends()["users"] == [peer]
    reject(peer)
    assert friends()["users"] == []
    checks.append(
        "user-list metadata and consented friend relationship survive server restart; deletion clears both sides"
    )
    resumed_mail = mail_headers(
        client.task(29, 10, text("iw8") + u32(0) + u32(10) + boolean(True))
    )
    assert resumed_mail == mailpage
    assert (
        client.task(150, 2, u64(73)) == schedule_info(scheduled)
        and client.task(150, 4, u64(73) + u32(10)) == schedule_events
    )
    assert json.loads(performancepath.read_text())["types"]["2"]["recent"] == [
        -71,
        None,
    ]
    checks.append(
        "scheduled match events and native performance samples survive a server process restart"
    )
    assert mail_get([2]) == u64(2) + blob(b"second message")
    assert client.task(29, 5, text("iw8") + mail_ids([2])) == []
    assert client.task(29, 10, text("iw8") + u32(0) + u32(10) + boolean(False)) == []
    checks.append(
        "native mail survives process restart and explicit deletion empties only the authenticated inbox"
    )
    persisted_clan = pb_map(
        client.task(197, 21, structure(pb_bytes(1, clan_group)), structured=True)
    )
    assert pb_map(persisted_clan[1][0])[2] == [clan_id]
    clan_restart_bytes = clan_transition_fixture["path"].read_bytes()
    client.task(197, 25, clan_transition_fixture["invite"], error=106)
    assert clan_transition_fixture["path"].read_bytes() == clan_restart_bytes
    checks.append(
        "invitation cooldown remains enforced after a backend process restart"
    )
    assert (
        pb_map(
            pb_map(
                client.task(
                    197, 31, structure(pb_bytes(1, file_selector)), structured=True
                )
            )[1][0]
        )
        == updated_file
    )
    memberships_reply = pb_map(
        client.task(197, 30, structure(pb_bytes(1, account)), structured=True)
    )
    assert len(pb_map(memberships_reply[1][0])[2]) == 2
    assert (
        client.task(
            197, 24, structure(pb_bytes(1, foreign_identifier)), structured=True
        )
        == b""
    )
    assert (
        client.task(197, 24, structure(pb_bytes(1, clan_group)), structured=True) == b""
    )
    assert (
        client.task(197, 21, structure(pb_bytes(1, clan_group)), structured=True) == b""
    )
    assert client.task(197, 30, structure(pb_bytes(1, account)), structured=True) == b""
    checks.append(
        "clan metadata/files/multiple memberships survive a server process restart and self-removal clears the active group"
    )
    renewed = client.task(145, 3)
    assert renewed != u64(match_token) and len(renewed) == 9 and renewed[0] == 10
    assert client.task(145, 3) == renewed
    checks.append(
        "matchmaking token renewal binds a fresh auth session instead of inheriting the previous login expiry"
    )
    assert client.task(8, 1, u64(user)) == u64(user) + blob(profile)
    assert client.task(8, 2) == u64(user) + blob(private)
    assert client.task(10, 12, path + owner) == blob(stats)
    restored_presence = json.loads(presence_path.read_text())
    assert restored_presence == dict(
        presence, updateTime=restored_presence["updateTime"]
    )
    persisted = object_reply(6, user_read([userobject]))
    assert base64.b64decode(persisted["objects"][0]["content"]) == userstats
    assert persisted["objects"][0]["metadata"] == saved_metadata
    assert (
        json.loads(
            dict(
                (t, v)
                for t, k, v in pb_fields(
                    client.task(125, 9, user_state_request, structured=True)
                )
            )[1]
        )
        == expected_state
    )
    assert json.loads(statpath.read_text()) == json.loads(before)
    assert client.task(
        67, 5, u32(1) + u32(1) + boolean(False) + text("after-restart")
    ) == u64(6)
    resumed = json.loads(
        next(
            v
            for t, k, v in pb_fields(
                client.task(194, 1, enroll_params(user), structured=True)
            )
            if t == 3
        )
    )
    assert (
        resumed["ABToken"] == enrollment_json["ABToken"]
        and resumed["enrollments"] == []
    )
    abtesting_fixtures.after_restart(client, ab_fixture, pb_fields, checks)
    abtesting_rest_fixtures.after_restart(
        client, ab_rest_fixture, rest_response, pb_fields, checks
    )
    assert client.task(145, 4, qos_report) == []
    native_host = json.loads(client.task(145, 25, qos_query)[1:-1])["hosts"][0]
    host_address = base64.b64decode(native_host["address"], validate=True)
    assert (
        len(host_address) == 84
        and host_address[41] == 1
        and host_address[42:] == bytes(42)
    )
    ip = socket.inet_ntoa(host_address[:4])
    port = struct.unpack_from("<H", host_address, 4)[0]
    assert ip == "127.0.0.1" and port > 0
    sec_id = struct.unpack_from(
        "<I", base64.b64decode(native_host["security_id"], validate=True)
    )[0]
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(1)
    # Same-Replay NAT introduction (type/version/HMAC/id/src/dest). The reply
    # preserves the opaque native challenge and returns only to its sender.
    intro = (
        bytes([13])
        + struct.pack("<H", 2)
        + os.urandom(10)
        + struct.pack("<I", 73)
        + socket.inet_aton(ip)
        + struct.pack("<H", 1234)
        + host_address[:6]
    )
    udp.sendto(intro, (ip, port))
    packet, _ = udp.recvfrom(1290)
    assert packet == bytes([12]) + intro[1:]
    for requesting in (0, 1):
        timestamp = 123456789
        probe_id = 731 + requesting
        probe = struct.pack("<BQII?", 40, timestamp, probe_id, sec_id, bool(requesting))
        udp.sendto(probe, (ip, port))
        packet, _ = udp.recvfrom(1290)
        kind, result_id, echo, enabled, size, bandwidth, processing, has_data = (
            struct.unpack_from("<BIQ?IIf?", packet)
        )
        assert (
            kind == 41
            and result_id == probe_id
            and echo == timestamp
            and enabled
            and bandwidth == 0
            and 0 <= processing < 0.1
        )
        assert (
            has_data == bool(requesting)
            and packet[27:] == (b"local\0" if requesting else b"")
            and size == len(packet) - 27
        )
    udp.settimeout(0.15)
    udp.sendto(struct.pack("<BQII?", 40, 1, 1, sec_id ^ 0xFFFFFFFF, False), (ip, port))
    try:
        udp.recvfrom(1290)
        raise AssertionError("Unissued QoS security ID accepted")
    except socket.timeout:
        pass
    udp.close()
    with urllib.request.urlopen(base + "/health") as response:
        live_qos = json.load(response)
    assert (
        live_qos["local_qos_enabled"]
        and live_qos["local_qos_probes"] == 2
        and live_qos["local_nat_introductions"] == 1
    )
    checks.append(
        "real local UDP NAT introduction/QoS echo, target packet layouts, expiring issued security ID and malformed-peer rejection"
    )
    assert "server_info" in json.loads(
        client.task(145, 24, text("replay") + text("pc"))[1:-1]
    )
    client.task(145, 24, text("replay"), error=106)
    checks.append(
        "native datacenter/real relay discovery, complete build-name request and malformed request rejection"
    )
    assert client.task(10, 11, path + owner) == []
    assert client.task(10, 12, path + owner, error=1000) == []
    assert client.task(8, 5) == [] and client.task(8, 1, u64(user)) == []
    client.close()
    checks.append("process-restart identity/profile/storage persistence and deletion")
    receipt = {
        "schema": 1,
        "passed": True,
        "native_game_verified": False,
        "checks": checks,
        "server_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(),
        "kdf_sha256": hashlib.sha256(
            (root / "data" / "replay-traffic-kdf.bin").read_bytes()
        ).hexdigest(),
        "fixture_directory": str(directory),
    }
    (root / "data" / "lobby-verification.json").write_text(
        json.dumps(receipt, indent=2) + "\n"
    )
    print(
        "PASS: independent encrypted native-wire client; "
        + str(len(checks))
        + " protocol/service checks, no game launched"
    )
finally:
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=5)
    output.close()
