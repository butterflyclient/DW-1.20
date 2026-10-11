"""Verify publisher cache recovery and publication authority on an isolated server."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request

from native_wire_client import NativeClient, binary, fields, structure, text

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    server = args.server.resolve(strict=True)
    fixture = ROOT / "data" / f"publisher-cache-fixture-{time.time_ns()}"
    data = fixture / "data"
    data.mkdir(parents=True)
    shutil.copy2(ROOT / "data/replay-traffic-kdf.bin", data / "replay-traffic-kdf.bin")
    for offset in range(21000, 21200):
        sockets = []
        try:
            for port in (8085, 8443, 3075):
                channel = socket.socket()
                sockets.append(channel)
                channel.bind(("127.0.0.1", port + offset))
            break
        except OSError:
            continue
        finally:
            for channel in sockets:
                channel.close()
    else:
        raise RuntimeError("No isolated cache fixture ports available")
    base = f"http://127.0.0.1:{8085+offset}"
    output = (fixture / "stdout.log").open("wb")
    process = None
    checks = []

    def start():
        nonlocal process
        process = subprocess.Popen(
            [str(server), str(data), "--port-offset", str(offset)],
            stdout=output,
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError("Cache fixture server exited")
            try:
                with urllib.request.urlopen(base + "/health", timeout=0.3):
                    return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("Cache fixture server did not become ready")

    def stop():
        nonlocal process
        if process and process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        process = None

    parent = data / "objectstore/publisher/5800/iw8/replay"
    parent.mkdir(parents=True)
    content = bytes(range(256)) * 128
    digest = hashlib.sha256(content).hexdigest()
    metadata = dict(
        name="cache.bin",
        owner="replay",
        context="iw8",
        contentLength=len(content),
        checksum=base64.b64encode(hashlib.md5(content).digest()).decode(),
        objectVersion="1",
        acl="public",
        created=0,
        modified=0,
        expiresOn=0,
        category=None,
    )
    metadata_path = parent / "cache.bin.metadata.json"
    original_path = parent / "cache.bin.content.bin"
    original_path.write_bytes(content)

    def save_metadata():
        metadata_path.write_text(json.dumps(metadata))

    save_metadata()
    cache = data / "objectstore/content" / (digest + ".bin")
    references = cache.with_name(digest + ".references.json")
    pending = cache.with_name(cache.name + ".pending")
    url = base + "/objectstore/content/" + digest

    def query(client, vector=False, error=0):
        if vector:
            request = structure(
                text(1, "GET")
                + text(2, "/v2/core/publishers/objects/?context=iw8")
                + binary(
                    4,
                    text(1, "DW-Objectstore-ObjectIDs")
                    + text(2, json.dumps([dict(owner="replay", name="cache.bin")])),
                )
            )
        else:
            request = structure(
                text(1, "GET")
                + text(
                    2,
                    "/v1/core/publishers/replay/objects/cache.bin/metadata/?context=iw8&extra=contentURL",
                )
            )
        task = 16 if vector else 8
        try:
            result = client.task(193, task, request, structured=True)
        except RuntimeError as failure:
            assert error and str(failure) == f"Native task 193/{task} returned {error}"
            return None
        assert not error, "A failed cache publication was reported as success"
        parsed = fields(result)
        assert parsed[2] == [200]
        body = json.loads(parsed[3][0])
        document = body["objects"][0]["metadata"] if vector else body
        assert document["contentURL"] == url
        return document

    def download(expected=200):
        try:
            with urllib.request.urlopen(url, timeout=5) as reply:
                assert expected == reply.status == 200 and reply.read() == content
        except urllib.error.HTTPError as error:
            assert error.code == expected != 200

    try:
        start()
        with NativeClient(fixture, port_offset=offset) as client:
            first = query(client)
            download()
            for key in ("expiresOn", "created", "modified"):
                for invalid in (1 << 63, (1 << 64) - 1, 0.5):
                    metadata[key] = invalid
                    save_metadata()
                    query(client, error=102)
                metadata[key] = 0
                save_metadata()
            metadata.update(extraData="eA==", extraDataSize=(1 << 32) + 1)
            save_metadata()
            query(client, error=102)
            metadata["extraDataSize"] = 2049
            save_metadata()
            query(client, error=102)
            metadata["extraDataSize"] = 1
            save_metadata()
            assert query(client)["extraDataSize"] == 1
            metadata.pop("extraData")
            metadata.pop("extraDataSize")
            save_metadata()
            checks.append("Publisher signed timestamps and native extraDataSize reject overflow before narrowing")
            stamp = cache.stat().st_mtime_ns
            assert query(client, vector=True) == first and cache.stat().st_mtime_ns == stamp
            checks.append(
                "Single/vector metadata publish one durable reference; healthy cache is retained"
            )
            for damaged, vector in [(b"truncated", False), (b"x" * len(content), True)]:
                cache.write_bytes(damaged)
                assert query(client, vector=vector) == first
                assert cache.read_bytes() == content
                download()
            checks.append(
                "Truncated and same-length corrupt cache is repaired before returning either native metadata envelope"
            )
            cache.write_bytes(b"interrupted")
            pending.mkdir()
            query(client, error=102)
            assert cache.read_bytes() == b"interrupted" and pending.is_dir()
            pending.rmdir()
            query(client)
            download()
            checks.append(
                "Real blocked atomic publication reports storage failure; retry repairs without a false successful URL"
            )
            saved = references.read_bytes()
            references.write_text('{"schema":1,"schema":1}')
            query(client, error=102)
            assert references.read_text() == '{"schema":1,"schema":1}'
            references.write_bytes(saved)
            original_path.write_bytes(b"invalid original")
            query(client, error=106)
            assert cache.read_bytes() == content
            original_path.write_bytes(content)
            checks.append(
                "Malformed durable references and checksum-invalid source fail without destroying valid stored bytes"
            )
            metadata["acl"] = "private"
            save_metadata()
            download(404)
            metadata.update(acl="public", expiresOn=int(time.time()) - 1)
            save_metadata()
            download(404)
            metadata["expiresOn"] = 0
            save_metadata()
            shared = dict(metadata, owner="other-publisher")
            other = data / "objectstore/publisher/5800/iw8/other-publisher"
            other.mkdir()
            (other / "cache.bin.metadata.json").write_text(json.dumps(shared))
            (other / "cache.bin.content.bin").write_bytes(content)
            request = structure(
                text(1, "GET")
                + text(
                    2,
                    "/v1/core/publishers/other-publisher/objects/cache.bin/metadata/?context=iw8&extra=contentURL",
                )
            )
            client.task(193, 8, request, structured=True)
            metadata["acl"] = "private"
            save_metadata()
            download()
            (other / "cache.bin.metadata.json").unlink()
            download(404)
            metadata["acl"] = "public"
            save_metadata()
            checks.append(
                "Retained URLs respect current ACL/expiry/removal; identical bytes remain public through another valid publisher"
            )
        stop()
        cache.write_bytes(b"damaged between server runs")
        pending.write_bytes(b"abandoned partial cache")
        start()
        with NativeClient(fixture, port_offset=offset) as client:
            query(client, vector=True)
            assert cache.read_bytes() == content and not pending.exists()
            download()
        checks.append(
            "Actual process restart retains publication identity and repairs both damaged cache and abandoned staging"
        )
        proof = dict(
            schema=1,
            passed=True,
            server_sha256=hashlib.sha256(server.read_bytes()).hexdigest(),
            fixture_directory=str(fixture),
            checks=checks,
            native_game_verified=False,
        )
        args.output.write_text(json.dumps(proof, indent=2) + "\n")
        print(f"PASS: {len(checks)} publisher cache and publication authority groups")
    finally:
        stop()
        output.close()


if __name__ == "__main__":
    main()
