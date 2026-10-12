"""Compile exact lobby endpoint/record code and test private loopback writes.

Account validity, service delivery validity and delayed queue are modeled;
endpoint selection, locking, immediate delivery, instant reply decisions,
native encrypted record serialization and Windows CNG execute actual source.
An independent Python decoder and original Replay consumer verify TCP packets.
"""

import argparse, ast, hashlib, hmac, importlib.util, json, struct, subprocess, tempfile
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import pefile

ROOT = Path(__file__).resolve().parents[1]


def extract(source, marker):
    start = source.index(marker)
    while True:
        opening = source.index("{", start)
        semicolon = source.find(";", start, opening)
        if semicolon < 0:
            break
        start = source.index(marker, semicolon + 1)
    depth = 1
    end = opening + 1
    while depth:
        depth += int(source[end] == "{") - int(source[end] == "}")
        end += 1
    return source[start:end]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--catalog", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    source = (ROOT / "src/lobby.cpp").read_text()
    chunks = {
        "endpoint_layout.h": extract(source, "struct PushEndpoint")
        + ";\n"
        + extract(source, "struct DeliveryOutcome")
        + ";\n",
        "endpoint_functions.h": "\n".join(
            extract(source, marker)
            for marker in (
                "std::vector<std::shared_ptr<PushEndpoint>> targetsFor",
                "DeliveryOutcome deliver",
                "DeliveryOutcome route",
                "void publishInstantMessage",
            )
        ),
        "traffic_layout.h": extract(source, "struct Traffic") + ";\n",
        "send_record.h": extract(source, "auto sendRecord = [&]") + ";\n",
    }
    # Require the real serve() call to complete recipient writes before constructing
    # or publishing its task reply. Clearing deliveries prevents duplicate writes.
    dispatch = source.index(
        "auto reply = services::dispatch(identity, service, task, reader);"
    )
    prepare = source.index("publishInstantMessage(identity.titleId, reply);", dispatch)
    response = source.index("auto response = services::taskReply(", dispatch)
    publication = source.index("if (!sendRecord(1, response))", dispatch)
    assert dispatch < prepare < response < publication
    assert "if (service == 6 && task == 14)" in source[dispatch:prepare]
    with tempfile.TemporaryDirectory(
        prefix="whisper-transport-", dir=ROOT / "data"
    ) as temp:
        folder = Path(temp)
        for name, value in chunks.items():
            (folder / name).write_text(value)
        exe = folder / "fixture.exe"
        cmd = [
            r"C:\Program Files\LLVM\bin\clang++.exe",
            "-std=c++20",
            "-O2",
            "-I" + str(ROOT / "src"),
            "-I" + str(folder),
            str(ROOT / "tools/whisper_transport_harness.cpp"),
            str(ROOT / "src/crypto.cpp"),
            "-o",
            str(exe),
            "-lbcrypt",
            "-lws2_32",
        ]
        compiled = subprocess.run(cmd, capture_output=True, text=True)
        assert compiled.returncode == 0, compiled.stderr
        result = subprocess.run([str(exe)], capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stderr
        transport = json.loads(result.stdout)
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
    pe = pefile.PE(str(native.IMAGE), fast_load=True)
    for (key, sha), size in zip(native.BODIES.items(), native.SIZES):
        assert hashlib.sha256(pe.get_data(rows[key]["rva"], size)).hexdigest() == sha
    material = bytes(range(72))
    bodies = []
    native_cases = 0
    for sequence, encoded in enumerate(transport["packets"], 1):
        packet = bytes.fromhex(encoded)
        assert struct.unpack_from("<I", packet)[0] == len(packet) - 4
        assert (
            packet[4:6] == b"\xab\x85"
            and struct.unpack_from("<I", packet, 6)[0] == sequence
        )
        assert hmac.compare_digest(
            packet[-8:], hmac.digest(material[20:40], packet[:-8], "sha1")[:8]
        )
        decryptor = Cipher(
            algorithms.AES(material[56:72]), modes.CBC(packet[10:26])
        ).decryptor()
        plain = decryptor.update(packet[26:-8]) + decryptor.finalize()
        length = struct.unpack_from("<I", plain)[0]
        assert plain[4] == 2 and not any(plain[5 + length :])
        push = plain[5 : 5 + length]
        assert push[:5] == b"\x08\x15\0\0\0" and push[5:14] == b"\x0a" + struct.pack(
            "<Q", 101
        )
        assert push[14:22] == b"\x10Sender\0" and push[22:24] == b"\x13\x08"
        body_length = struct.unpack_from("<I", push, 24)[0]
        body = push[28:]
        assert len(body) == body_length and body.startswith(b"CHAT:") and body[-1] == 0
        number = int(body[5:-1])
        assert 0 <= number < 100
        bodies.append(number)
        if sequence in (1, 2, 50, 99, 100):
            vm = native.Native(pe, rows, push)
            vm.run()
            assert (
                len(vm.received) == 1
                and vm.received[0]["body"] == body[5:-1].hex()
                and vm.history == 1
            )
            native_cases += 1
    assert sorted(bodies) == list(
        range(100)
    ), "concurrent writes lost/duplicated a recipient packet"
    # Exercise the actual independent wire client's targeted self-Push21 queue.
    # Construct it without running its provision/handshake initializer.
    client_tree = ast.parse((ROOT / "tools/test-lobby.py").read_text())
    client_class = next(
        node
        for node in ast.walk(client_tree)
        if isinstance(node, ast.ClassDef) and node.name == "Client"
    )
    namespace = dict(
        struct=struct,
        send_fragments=lambda *_: None,
        u32=lambda value: b"\x08" + struct.pack("<I", value),
    )
    exec(
        compile(
            ast.Module(body=[client_class], type_ignores=[]),
            "<actual-test-lobby-Client>",
            "exec",
        ),
        namespace,
    )
    client = object.__new__(namespace["Client"])
    client.s = None
    client.record = lambda value: value
    client.mail_notifications = []
    client.progression_notifications = []
    client.instant_notifications = []
    ack = (
        b"\x0a"
        + struct.pack("<Q", 1)
        + b"\x08"
        + struct.pack("<I", 0)
        + b"\x03\x0e\x08"
        + struct.pack("<I", 0)
    )
    incoming = [(2, push), (1, ack)]
    client.receive_record = lambda: incoming.pop(0)
    assert client.task(6, 14, b"") == [] and not incoming
    assert client.receive() == (2, push) and not client.instant_notifications
    mail = (2, b"\x08" + struct.pack("<I", 18))
    incoming = [(2, push), mail, (1, ack)]
    assert client.task(6, 14, b"") == [] and not incoming
    assert client.receive() == (2, push) and client.receive_mail() == mail
    incoming = [(2, b"\x08" + struct.pack("<I", 23))]
    try:
        client.task(6, 14, b"")
    except AssertionError:
        pass
    else:
        raise AssertionError(
            "unrelated Push23 cannot be silently queued by an instant task"
        )
    incoming = [(2, push)]
    try:
        client.task(12, 6, b"")
    except AssertionError:
        pass
    else:
        raise AssertionError("ordinary task reply ordering must stay strict")
    receipt = dict(
        passed=True,
        outcome_checks=transport["outcome_checks"],
        tcp_packets=100,
        independent_mac_sequence_and_plaintext_verified=True,
        original_native_consumers=native_cases,
        independent_wire_client_order_cases=4,
        live_game_tested=False,
        backend_restarted=False,
        boundaries=__doc__,
        image_sha256=native.IMAGE_SHA,
        source_sha256=hashlib.sha256((ROOT / "src/lobby.cpp").read_bytes()).hexdigest(),
        chunks={
            name: hashlib.sha256(value.encode()).hexdigest()
            for name, value in chunks.items()
        },
        crypto_sha256=hashlib.sha256(
            (ROOT / "src/crypto.cpp").read_bytes()
        ).hexdigest(),
        harness_sha256=hashlib.sha256(
            (ROOT / "tools/whisper_transport_harness.cpp").read_bytes()
        ).hexdigest(),
    )
    a.output.write_text(json.dumps(receipt, indent=2) + "\n")
    print(
        "PASS",
        transport["outcome_checks"],
        "write-outcome cases, 100 real encrypted TCP packets,",
        native_cases,
        "original native consumer cases",
    )


if __name__ == "__main__":
    main()
