"""Check unsupported native/REST failures on a disposable encrypted backend."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import urllib.request

from native_wire_client import NativeClient, binary, integer, text, u32

ROOT = Path(__file__).resolve().parents[1]
ROUTES = ((50, 22), (58, 22), (193, 9), (193, 10), (193, 12), (193, 24))


def rest_packet(method=0x474554):
    params = (integer(1, 1) + integer(2, 0) + integer(3, 1) + integer(100, 10000)
              + binary(200, bytes(256)) + text(300, "UnconfiguredResource")
              + text(301, "unconfigured_operation"))
    message = (binary(1, params) + integer(2, 1) + integer(10, method)
               + text(11, "/unconfigured") + text(101, "unconfigured") + integer(102, 1))
    blob = lambda value: b"\x13" + u32(len(value)) + value
    return u32(713) + blob(message) + b"\x01\x00" + blob(b"")


def rest_status(raw):
    assert raw[:7] == u32(713) + b"\x13\x08"
    size = struct.unpack_from("<I", raw, 7)[0]
    metadata = raw[11:11 + size]
    # Status is the first protobuf integer field. The rest contains fixed64
    # timing fields; do not feed it through the structured-task-only decoder.
    assert metadata[0] == 8
    status, shift, position = 0, 0, 1
    while True:
        value = metadata[position]
        position += 1
        status |= (value & 127) << shift
        if not value & 128:
            break
        shift += 7
        assert shift < 35
    position = 11 + size
    assert raw[position:position + 4] == b"\x01\x01\x13\x08"
    size = struct.unpack_from("<I", raw, position + 4)[0]
    assert len(raw) == position + 8 + size
    return status, json.loads(raw[position + 8:])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    server = args.server.resolve(strict=True)
    parent = ROOT / "data/remaining-response-bindings-20261011"
    parent.mkdir(parents=True, exist_ok=True)
    cases = []
    with tempfile.TemporaryDirectory(prefix="exclusion-fixture-", dir=parent) as temporary:
        fixture = Path(temporary)
        data = fixture / "data"
        data.mkdir()
        shutil.copy2(ROOT / "data/replay-traffic-kdf.bin", data / "replay-traffic-kdf.bin")
        for offset in range(24000, 24200):
            channels = []
            try:
                for port in (8085, 8443, 3075):
                    channel = socket.socket()
                    channels.append(channel)
                    channel.bind(("127.0.0.1", port + offset))
                break
            except OSError:
                continue
            finally:
                for channel in channels:
                    channel.close()
        else:
            raise RuntimeError("No disposable fixture ports available")
        with (fixture / "server.log").open("wb") as log:
            process = subprocess.Popen([str(server), str(data), "--port-offset", str(offset)],
                                       stdout=log, stderr=subprocess.STDOUT,
                                       creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError("Disposable backend exited")
                    try:
                        with urllib.request.urlopen(f"http://127.0.0.1:{8085 + offset}/health", timeout=.3):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise RuntimeError("Disposable backend readiness timeout")
                with NativeClient(fixture, port_offset=offset) as client:
                    packets = []
                    original_receive = client.receive

                    def receive():
                        result = original_receive()
                        packets.append(result)
                        return result

                    client.receive = receive
                    for service, task in ROUTES:
                        for params in (b"", b"\xff\x00\xff"):
                            try:
                                client.task(service, task, params)
                            except RuntimeError as error:
                                assert str(error) == f"Native task {service}/{task} returned 108"
                            else:
                                raise AssertionError("Excluded route returned success")
                            kind, reply = packets[-1]
                            assert kind == 1 and len(reply) == 14
                            assert reply[9] == 8 and struct.unpack_from("<I", reply, 10)[0] == 108
                            cases.append(dict(service=service, task=task, malformed_payload=bool(params),
                                              native_error=108, result_bytes=0, passed=True))
                    for method in (0x474554, 0x505554):
                        status, body = rest_status(client.task(255, 10, rest_packet(method), structured=False))
                        assert status == 503 and body["error"]["name"] == "LocalServiceUnavailable"
                        cases.append(dict(rest_method=method, status=503, error="LocalServiceUnavailable", passed=True))
                    # A later real task must still work after every exclusion.
                    current = client.task(12, 6, b"", structured=False)
                    assert current[:1] == b"\x08" and len(current) == 5
                    for name in ("content-streaming", "objectstore", "rest"):
                        assert not (data / name).exists(), name
            finally:
                process.terminate()
                process.wait(timeout=10)
    proof = dict(schema=1, passed=True, server_sha256=hashlib.sha256(server.read_bytes()).hexdigest(),
                 cases=cases, connection_survived=True, excluded_route_domain_writes=False,
                 native_game_verified=False, disposable_fixture_removed=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(proof, indent=2) + "\n")
    print("PASS: 12 explicit native 108 errors, two REST 503 errors, connection survives, no domain writes")


if __name__ == "__main__":
    main()
