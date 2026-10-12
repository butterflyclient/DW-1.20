"""Actual backend whisper writes and immutable asset HTTP on private profiles."""

import argparse, hashlib, importlib.util, json, os, shutil, socket, struct, subprocess, tempfile, time
from pathlib import Path
import urllib.request, urllib.error
from native_wire_client import NativeClient, u32, u64

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--server", type=Path, required=True)
    p.add_argument("--package-proof", type=Path, required=True)
    p.add_argument("--catalog", type=Path)
    p.add_argument(
        "--skip-original-native",
        action="store_true",
        help="Linux route checks; original Replay execution remains a separate Windows gate",
    )
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    image = a.server.resolve()
    sha = hashlib.file_digest(image.open("rb"), "sha256").hexdigest()
    proof = json.loads(a.package_proof.read_bytes())
    assert proof["packaged"] and not proof["game_modified"]
    payloads = {
        entry["sha256"]: Path(entry["source"])
        for entry in proof["installation_manifest"]
    }
    assert len(payloads) == 4
    checks = []
    native_cases = 0
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    with tempfile.TemporaryDirectory(
        prefix="whisper-route-", dir=ROOT / "data"
    ) as temporary:
        fixture = Path(temporary).resolve()
        assert fixture.is_relative_to(ROOT / "data")
        data = fixture / "data"
        data.mkdir()
        shutil.copyfile(
            ROOT / "data/replay-traffic-kdf.bin", data / "replay-traffic-kdf.bin"
        )
        assets = data / "updates/assets"
        assets.mkdir(parents=True)
        for digest, path in payloads.items():
            assert hashlib.file_digest(path.open("rb"), "sha256").hexdigest() == digest
            shutil.copyfile(path, assets / (digest + ".bin"))
        for profile, name in (
            ("whisper-host", "Whisper Transport Host"),
            ("whisper-peer", "Whisper Transport Peer"),
        ):
            subprocess.run(
                [str(image), str(data), "--provision-profile", profile, name],
                check=True,
                stdout=subprocess.DEVNULL,
                creationflags=flags,
            )
        offset = None
        for candidate in range(26000, 26200):
            probes = []
            try:
                for port in (8085, 8443, 3075):
                    sock = socket.socket()
                    probes.append(sock)
                    sock.bind(("127.0.0.1", port + candidate))
                offset = candidate
                break
            except OSError:
                pass
            finally:
                for sock in probes:
                    sock.close()
        assert offset is not None
        log = (fixture / "stdout.log").open("wb")
        process = subprocess.Popen(
            [str(image), str(data), "--port-offset", str(offset)],
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=flags,
        )
        host = peer = None
        try:
            base = "http://127.0.0.1:" + str(8085 + offset)
            for attempt in range(200):
                assert process.poll() is None
                try:
                    with urllib.request.urlopen(base + "/health", timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.03)
            else:
                raise RuntimeError("private backend did not become ready")
            for digest, path in payloads.items():
                with urllib.request.urlopen(
                    base + "/updates/v2/asset/" + digest, timeout=10
                ) as response:
                    body = response.read()
                    assert response.status == 200 and len(body) == path.stat().st_size
                    assert (
                        response.headers["Cache-Control"]
                        == "public, max-age=31536000, immutable"
                    )
                    assert hashlib.sha256(body).hexdigest() == digest
            checks.append(
                "Four owned native FF/FP payloads streamed exactly through immutable asset route"
            )
            valid = next(iter(payloads))
            invalid = [
                (valid, "POST", {}, None, 400),
                (valid, "HEAD", {}, None, 400),
                (valid, "GET", {"Range": "bytes=0-7"}, None, 400),
                (valid, "GET", {}, b"x", 400),
                (valid.upper(), "GET", {}, None, 400),
                ("0" * 64, "GET", {}, None, 404),
                ("../common_base_mp.ff", "GET", {}, None, 400),
            ]
            for digest, method, headers, body, status in invalid:
                request = urllib.request.Request(
                    base + "/updates/v2/asset/" + digest,
                    data=body,
                    headers=headers,
                    method=method,
                )
                try:
                    urllib.request.urlopen(request, timeout=5)
                except urllib.error.HTTPError as error:
                    assert error.code == status, (method, digest, error.code, status)
                else:
                    raise AssertionError("malformed asset request was accepted")
            checks.append(
                "POST, HEAD, Range, body, uppercase, unknown hash and traversal rejected"
            )
            oversized = "f" * 64
            with (assets / (oversized + ".bin")).open("wb") as sparse:
                sparse.seek(64 * 1024 * 1024)
                sparse.write(b"X")
            try:
                urllib.request.urlopen(
                    base + "/updates/v2/asset/" + oversized, timeout=5
                )
            except urllib.error.HTTPError as error:
                assert error.code == 404
            else:
                raise AssertionError("asset exceeding64MiB accepted")
            checks.append("Asset size bound enforced before streaming")
            host = NativeClient(fixture, profile="whisper-host", port_offset=offset)
            peer = NativeClient(fixture, profile="whisper-peer", port_offset=offset)
            native = None
            if not a.skip_original_native:
                import pefile

                assert a.catalog is not None
                spec = importlib.util.spec_from_file_location(
                    "whisper_native", ROOT / "tools/test-whisper-native.py"
                )
                native = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(native)
                assert (
                    hashlib.file_digest(native.IMAGE.open("rb"), "sha256").hexdigest()
                    == native.IMAGE_SHA
                )
                catalog = json.loads(a.catalog.read_bytes())
                byid = {r["id"]: r for r in catalog["functions"]}
                rows = {key: byid[key] for key in native.BODIES}
                original = pefile.PE(str(native.IMAGE), fast_load=True)
                for (key, digest), size in zip(native.BODIES.items(), native.SIZES):
                    assert (
                        hashlib.sha256(
                            original.get_data(rows[key]["rva"], size)
                        ).hexdigest()
                        == digest
                    )
            blob = lambda body: b"\x13" + u32(len(body)) + body
            for sender, recipient, name, body in (
                (host, peer, "Whisper Transport Host", b"CHAT:hello\0"),
                (peer, host, "Whisper Transport Peer", b"CHAT:reply\0"),
            ):
                assert (
                    sender.task(
                        6, 14, u64(recipient.user) + blob(body), structured=False
                    )
                    == b""
                )
                kind, packet = recipient.receive()
                assert kind == 2
                assert packet == u32(21) + u64(
                    sender.user
                ) + b"\x10" + name.encode() + b"\0" + blob(body)
                if native is not None:
                    vm = native.Native(
                        original, rows, packet, local_user=recipient.user
                    )
                    vm.run()
                    assert (
                        vm.received
                        == [
                            dict(
                                chat=vm.pool,
                                sender=sender.user,
                                recipient=recipient.user,
                                name=name,
                                body=body[5:-1].hex(),
                                state=2,
                            )
                        ]
                        and vm.history == 1
                    )
                    native_cases += 1
            checks.append(
                "Both authenticated peers receive exact Push21"
                + (
                    " accepted by original Replay receiver"
                    if native is not None
                    else " (native execution is a separate Windows gate)"
                )
            )
            assert host.task(6, 14, u64(host.user) + blob(b""), structured=False) == b""
            assert host.pushes.pop(0) == u32(21) + u64(
                host.user
            ) + b"\x10Whisper Transport Host\0" + blob(b"")
            checks.append(
                "Self-addressed Push21 safely precedes successful acknowledgement"
            )
            peer_user = peer.user
            peer.close()
            peer = None
            time.sleep(0.1)
            try:
                host.task(
                    6, 14, u64(peer_user) + blob(b"CHAT:offline\0"), structured=False
                )
            except RuntimeError as error:
                assert str(error) == "Native task 6/14 returned 108"
            else:
                raise AssertionError("disconnected recipient reported success")
            checks.append("Disconnected recipient returns native108")
            text = (fixture / "stdout.log").read_text(errors="replace")
            if "push_written=" not in text:
                text += (data / "server.log").read_text(errors="replace")
            routed = [
                line
                for line in text.splitlines()
                if "operation=global-instant-message-routed error=0" in line
            ]
            assert len(routed) == 3 and all("push_written=1" in line for line in routed)
            assert (
                sum(
                    "message_kind=chat_whisper chat_layout=valid" in line
                    for line in routed
                )
                == 2
            )
            checks.append(
                "Actual task logs confirm packet writes and native whisper layout without text"
            )
        finally:
            for connection in (host, peer):
                if connection is not None:
                    connection.close()
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            log.close()
    assert hashlib.file_digest(image.open("rb"), "sha256").hexdigest() == sha
    a.output.write_text(
        json.dumps(
            dict(
                passed=True,
                server_sha256=sha,
                checks=checks,
                original_native_consumer_cases=native_cases,
                private_fixture_removed=True,
                production_changed=False,
                native_game_verified=False,
                package_proof_sha256=hashlib.sha256(
                    a.package_proof.read_bytes()
                ).hexdigest(),
            ),
            indent=2,
        )
        + "\n"
    )
    print(
        "PASS",
        len(checks),
        "actual backend whisper/update-route groups;",
        native_cases,
        "original native receiver packets",
    )


if __name__ == "__main__":
    main()
