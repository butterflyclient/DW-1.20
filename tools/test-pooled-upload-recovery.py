"""Exercise native pooled-file tasks and durable HTTP staging on disposable data.

This starts only the supplied backend with a fresh data directory and isolated
ports. It never starts the game or contacts the primary DW server.
"""

import argparse
import copy
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

from native_wire_client import NativeClient, u32, u64


ROOT = Path(__file__).resolve().parents[1]
TITLE = 5800


def text(value):
    return b"\x10" + value.encode() + b"\0"


def u16(value):
    return b"\x06" + struct.pack("<H", value)


def blob(value):
    return b"\x13" + u32(len(value)) + value


def tags(pairs):
    return b"\x6e\x08" + struct.pack("<II", len(pairs) * 16, len(pairs) * 2) + b"".join(
        struct.pack("<QQ", *pair) for pair in pairs)


class Client(NativeClient):
    def task(self, service, task, params=b"", error=0, structured=False):
        try:
            result = super().task(service, task, params, structured)
        except RuntimeError as failure:
            if not error or str(failure) != f"Native task {service}/{task} returned {error}":
                raise
            return []
        assert not error, f"Expected {service}/{task} error {error}, got success"
        return [] if result == b"" else result


def transfer(url, body, expected=200):
    request = urllib.request.Request(url, body, method="PUT")
    try:
        with urllib.request.urlopen(request, timeout=15) as reply:
            assert reply.status == expected, (reply.status, expected)
            if expected == 200:
                assert reply.read() == b""
    except urllib.error.HTTPError as error:
        assert error.code == expected, (error.code, expected)


def upload_descriptor(raw, base):
    assert raw[0] == 16
    end = raw.index(0, 1)
    url = raw[1:end].decode()
    offset = end + 1
    assert raw[offset:offset + 3] == u16(0)
    offset += 3
    assert raw[offset] == 16
    end = raw.index(0, offset + 1)
    server = raw[offset + 1:end].decode()
    offset = end + 1
    assert raw[offset] == 10 and len(raw) == offset + 9
    file = struct.unpack_from("<Q", raw, offset + 1)[0]
    assert file not in (0, 2**64 - 1) and server == str(file)
    prefix = f"{base}/content-streaming/upload/pooled/{TITLE}/"
    assert url.startswith(prefix)
    token = url[len(prefix):]
    assert len(token) == 32 and all(c in "0123456789abcdef" for c in token)
    return dict(file=file, url=url, token=token)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--kdf", type=Path, default=ROOT / "data/replay-traffic-kdf.bin")
    args = parser.parse_args()
    server = args.server.resolve(strict=True)
    fixture = ROOT / "data" / f"pooled-upload-fixture-{time.time_ns()}"
    data = fixture / "data"
    data.mkdir(parents=True)
    shutil.copy2(args.kdf, data / "replay-traffic-kdf.bin")
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    for profile in ("upload-host", "upload-peer"):
        subprocess.run([str(server), str(data), "--provision-profile", profile, profile],
                       check=True, stdout=subprocess.DEVNULL, creationflags=flags)
    offset = None
    for candidate in range(12500, 12600):
        probes = []
        try:
            for port in (8085, 8443, 3075):
                probe = socket.socket()
                probes.append(probe)
                probe.bind(("127.0.0.1", candidate + port))
            offset = candidate
            break
        except OSError:
            pass
        finally:
            for probe in probes:
                probe.close()
    if offset is None:
        raise RuntimeError("No isolated fixture ports available")
    base = f"http://127.0.0.1:{8085 + offset}"
    checks = []
    connections = []
    process = None
    stage = data / "content-streaming" / str(TITLE) / "pooled-uploads.json"
    catalog = stage.with_name("files.json")
    pending = stage.with_name(stage.name + ".pending")
    log = (fixture / "stdout.log").open("wb")

    def start():
        nonlocal process
        process = subprocess.Popen([str(server), str(data), "--port-offset", str(offset)],
                                   stdout=log, stderr=subprocess.STDOUT, creationflags=flags)
        for _ in range(150):
            if process.poll() is not None:
                raise RuntimeError("Isolated backend exited during startup")
            try:
                with urllib.request.urlopen(base + "/health", timeout=0.3):
                    return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("Isolated backend startup timed out")

    def stop():
        nonlocal process
        for connection in connections:
            connection.close()
        connections.clear()
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
        process = None

    def client(profile="upload-host", title=TITLE):
        connection = Client(fixture, profile=profile, title=title, port_offset=offset)
        connections.append(connection)
        return connection

    def restart():
        stop()
        start()
        return client()

    def prepare(connection, name="recovery.bin"):
        return upload_descriptor(connection.task(58, 5, text(name) + u16(7) +
                                                  tags([(1, 9)]) + text("")), base)

    def commit(connection, descriptor, body, error=0):
        return connection.task(58, 6, u64(descriptor["file"]) + u16(0) +
                               text(str(descriptor["file"])) + u32(len(body)), error=error)

    def complete(connection, descriptor, body):
        assert commit(connection, descriptor, body) == u64(descriptor["file"])

    def find_row(file):
        rows = [row for row in json.loads(catalog.read_bytes())["files"] if row["id"] == file]
        assert len(rows) == 1
        return rows[0]

    def save_stage(document):
        stage.write_text(json.dumps(document))

    try:
        start()
        host = client()
        owner = host.user
        body = b"durable-native-pooled-upload\0" * 16000
        descriptor = prepare(host)
        commit(host, descriptor, body, error=108)
        persisted = stage.read_bytes()
        host = restart()
        assert host.user == owner and stage.read_bytes() == persisted
        transfer(descriptor["url"], body)
        transfer(descriptor["url"], body)
        transfer(descriptor["url"], b"changed", 409)
        transfer(descriptor["url"].replace(f"/pooled/{TITLE}/", f"/pooled/{TITLE + 1}/"), body, 404)
        transfer(descriptor["url"].replace(f"/pooled/{TITLE}/", f"/pooled/0{TITLE}/"), body, 404)
        host = restart()
        complete(host, descriptor, body)
        assert json.loads(stage.read_bytes())["sessions"] == []
        host = restart()
        complete(host, descriptor, body)
        commit(client("upload-peer"), descriptor, body, error=101)
        commit(host, descriptor, body + b"x", error=106)
        row = find_row(descriptor["file"])
        assert row["owner"] == owner and row["size"] == len(body) and row["tags"] == [[1, 9]]
        assert row["content"] == hashlib.sha256(body).hexdigest()
        download = f"{base}/content-streaming/download/{TITLE}/{row['content']}"
        with urllib.request.urlopen(download, timeout=5) as response:
            assert response.read() == body
        with urllib.request.urlopen(urllib.request.Request(download, headers={"Range": "bytes=91-117"})) as response:
            assert response.status == 206 and response.read() == body[91:118]
        transfer(descriptor["url"], body, 404)
        checks.append("Prepared session, HTTP bytes and committed retry survive three independent backend restarts")
        checks.append("Native URL/file-ID DTO, owner denial, retry size check, realm isolation, exact download and byte ranges")

        # Catalog publication succeeds, but removing staging is intentionally blocked.
        recovering = prepare(host, "catalog-before-cleanup.bin")
        transfer(recovering["url"], body)
        pending.mkdir()
        try:
            commit(host, recovering, body, error=102)
            find_row(recovering["file"])
            assert any(row["file"] == recovering["file"] for row in json.loads(stage.read_bytes())["sessions"])
        finally:
            pending.rmdir()
        host = restart()
        complete(host, recovering, body)
        complete(host, recovering, body)
        find_row(recovering["file"])
        checks.append("Interrupted staging cleanup recovers an already-published catalog row without duplicate IDs")

        uploading = prepare(host, "body-before-stage.bin")
        pending.mkdir()
        try:
            transfer(uploading["url"], b"write-before-ack", 500)
            unfinished = next(row for row in json.loads(stage.read_bytes())["sessions"] if row["file"] == uploading["file"])
            assert unfinished["content"] == "" and unfinished["size"] == 0
        finally:
            pending.rmdir()
        host = restart()
        transfer(uploading["url"], b"write-before-ack")
        complete(host, uploading, b"write-before-ack")
        checks.append("HTTP acknowledgement waits for durable staging; a failed publish retries the verified blob")

        empty = prepare(host, "empty.bin")
        transfer(empty["url"], b"")
        host = restart()
        complete(host, empty, b"")
        assert find_row(empty["file"])["content"] == hashlib.sha256(b"").hexdigest()
        checks.append("Empty files remain distinguishable from missing HTTP transfers after restart")

        corruptible = prepare(host, "blob-validation.bin")
        transfer(corruptible["url"], b"original-blob")
        blob_path = stage.parent / "blobs" / (hashlib.sha256(b"original-blob").hexdigest() + ".bin")
        blob_path.write_bytes(b"damaged--blob")
        transfer(corruptible["url"], b"original-blob", 500)
        commit(host, corruptible, b"original-blob", error=102)
        blob_path.write_bytes(b"original-blob")
        complete(host, corruptible, b"original-blob")
        checks.append("Immutable blob corruption is detected before repeat PUT acknowledgement or native commit")

        malformed = prepare(host, "strict-store.bin")
        original = stage.read_bytes()
        valid = json.loads(original)
        corruptions = []
        for key, value in (("owner", 0), ("file", 0), ("token", "../not-a-token"),
                           ("expires", valid["sessions"][0]["created"]),
                           ("size", 1), ("content", "g" * 64), ("name", "bad\0name")):
            broken = copy.deepcopy(valid)
            broken["sessions"][0][key] = value
            corruptions.append(json.dumps(broken).encode())
        broken = copy.deepcopy(valid)
        broken["title"] += 1
        corruptions.append(json.dumps(broken).encode())
        broken = copy.deepcopy(valid)
        broken["sessions"].append(copy.deepcopy(broken["sessions"][0]))
        corruptions.append(json.dumps(broken).encode())
        corruptions.append(original.replace(b'"schema":1', b'"schema":1,"schema":1', 1))
        assert corruptions[-1] != original
        for broken in corruptions:
            stage.write_bytes(broken)
            host.task(58, 5, text("blocked.bin") + u16(7) + tags([]) + text(""), error=102)
            transfer(malformed["url"], b"data", 500)
            assert stage.read_bytes() == broken
        stage.write_bytes(original)
        host = restart()
        transfer(malformed["url"], b"valid-after-repair")
        complete(host, malformed, b"valid-after-repair")
        checks.append("Duplicate JSON keys/IDs/tokens, wrong realm, invalid owner/hash/size/expiry and NUL names fail without mutation")

        expired = prepare(host, "expired.bin")
        document = json.loads(stage.read_bytes())
        stamp = int(time.time())
        document["sessions"][0].update(created=stamp - 100, expires=stamp - 1)
        save_stage(document)
        host = restart()
        transfer(expired["url"], b"late", 404)
        commit(host, expired, b"late", error=108)
        valid = prepare(host, "replacement.bin")
        assert all(row["file"] != expired["file"] for row in json.loads(stage.read_bytes())["sessions"])
        transfer(valid["url"], b"replacement")
        complete(host, valid, b"replacement")
        checks.append("Expired capabilities fail across restart and are reclaimed by the next preparation")

        capped = prepare(host, "capacity.bin")
        original = stage.read_bytes()
        document = json.loads(original)
        seed = document["sessions"][0]
        document["sessions"] = [dict(seed, file=index + 1, token=f"{index:032x}") for index in range(128)]
        save_stage(document)
        host.task(58, 5, text("over-cap.bin") + u16(7) + tags([]) + text(""), error=102)
        stage.write_bytes(original)
        transfer(capped["url"], b"cap")
        complete(host, capped, b"cap")
        checks.append("Persistent stage capacity remains bounded at 128 sessions")

        large = b"q" * (16 * 1024 * 1024)
        quota_uploads = [prepare(host, f"quota-{index}.bin") for index in range(5)]
        for descriptor in quota_uploads[:3]:
            transfer(descriptor["url"], large)
        multipart_page = host.task(58, 20, text("shared-quota.bin") + u16(7) + tags([]) +
                                   b"\x05\x00\x00\x05\x01\x00" + u64(0))
        multipart_file = struct.unpack_from("<Q", multipart_page, 1)[0]
        assert multipart_page[9:11] == b"\x74\x08"
        multipart_size, multipart_count = struct.unpack_from("<II", multipart_page, 11)
        assert multipart_count == 1 and len(multipart_page) == 19 + multipart_size
        multipart_url = multipart_page[19:-1].decode()
        transfer(multipart_url, large)
        transfer(quota_uploads[3]["url"], large, 503)
        transfer(quota_uploads[4]["url"], b"over", 503)
        multipart_path = stage.with_name("multipart.json")
        document = json.loads(multipart_path.read_bytes())
        stamp = int(time.time())
        next(row for row in document["sessions"] if row["id"] == multipart_file).update(
            created=stamp - 100, expires=stamp - 1)
        multipart_path.write_text(json.dumps(document))
        host = restart()
        transfer(quota_uploads[3]["url"], large)
        host.task(58, 21, u64(multipart_file) + u16(1) + u32(len(large)) + b"\x07\0\0\0\0", error=108)
        transfer(quota_uploads[4]["url"], b"over", 503)
        complete(host, quota_uploads[0], large)
        transfer(quota_uploads[4]["url"], b"over")
        for descriptor in quota_uploads[1:4]:
            complete(host, descriptor, large)
        complete(host, quota_uploads[4], b"over")
        checks.append("64 MiB staging quota combines pooled/multipart sessions and releases committed and expired transfers")

        # The shared atomic writer and ID allocator also serve these existing paths.
        import user_content_fixtures
        import multipart_content_fixtures
        import copy_content_fixtures
        peer = client("upload-peer")
        user_content_fixtures.exercise(host, peer, data, TITLE, host.user, peer.user,
                                      base, (u32, u64, text, blob), checks)
        multipart_content_fixtures.exercise(host, data, TITLE, host.user, base, (u32, u64, text), checks)
        copy_content_fixtures.exercise(host, peer, data, TITLE, host.user, peer.user,
                                      base, (u32, u64, text, blob, lambda value: b"\x01" + bytes([bool(value)])),
                                      checks)
        result = dict(schema=1, passed=True, native_game_verified=False,
                      server_sha256=hashlib.sha256(server.read_bytes()).hexdigest(),
                      fixture_directory=str(fixture), checks=checks,
                      test_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      transport="Replay 210 authenticated native tasks and real HTTP; no mocked storage")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
        print(f"PASS: {len(checks)} focused pooled durability/content regression groups; no game launched")
    finally:
        stop()
        log.close()


if __name__ == "__main__":
    main()
