"""Check local personalization against a real EXE and isolated server signatures.

Requires the Windows build tools and cryptography (test only).
Does not launch the game, edit production sources, or contact the droplet.
"""

import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("setup_local", ROOT / "tools/setup-local-client.py")
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


def rejects(action):
    try:
        action()
    except (ValueError, OSError):
        return
    raise AssertionError("Invalid setup was accepted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    original = args.client.read_bytes()
    checks = []
    with tempfile.TemporaryDirectory(prefix="local-client-check-", dir=ROOT / "data") as folder:
        folder = Path(folder)
        data = folder / "server-data"
        log = (folder / "server.log").open("wb")
        process = subprocess.Popen(
            [str(args.server.resolve()), str(data), "--port-offset", "12000"],
            stdout=log, stderr=log, creationflags=subprocess.CREATE_NO_WINDOW,
        )
        try:
            base = "http://127.0.0.1:20085"
            for attempt in range(40):
                if process.poll() is not None:
                    raise RuntimeError("Isolated server failed to start")
                try:
                    with urllib.request.urlopen(base + "/health", timeout=1) as response:
                        assert json.load(response)["server"] == "iw8-dw"
                    break
                except OSError:
                    time.sleep(0.25)
            else:
                raise RuntimeError("Isolated server health timeout")
            public = (data / "platform-public.blob").read_bytes()
            private_before = setup.sha((data / "platform-private.blob").read_bytes())
            game = folder / "Game with spaces"
            game.mkdir()
            source = game / "game_dx12_ship_replay_dw.exe"
            source.write_bytes(original)
            report = setup.setup(source, data)
            patched = Path(report["output"]).read_bytes()
            assert source.read_bytes() == original and len(patched) == len(original)
            assert setup.sha((data / "platform-private.blob").read_bytes()) == private_before
            assert patched.count(public) == 2 and patched.count(setup.public_der(public)) == 2
            restored = bytearray(patched)
            for item in report["changed_ranges"]:
                at, size = item["offset"], item["bytes"]
                restored[at:at + size] = original[at:at + size]
            assert restored == original
            checks.append("Real EXE: exactly four public-key ranges changed; original EXE and private key unchanged")
            assert Path(report["output"]).with_suffix(".ini").read_text() == "host=127.0.0.1\nbypass_update_restart=1\n"
            assert setup.LOCAL_NAME in (game / "Run_Replay_DW_Local.cmd").read_text()
            rejects(lambda: setup.setup(source, data))
            rejects(lambda: setup.personalize(patched, public))
            rejects(lambda: setup.personalize(b"not an executable", public))
            rejects(lambda: setup.public_der((data / "platform-private.blob").read_bytes()))
            rejects(lambda: setup.personalize(original, setup.original_keys()[0]))
            missing = original.replace(setup.original_keys()[1], b"\0" * 294, 1)
            rejects(lambda: setup.personalize(missing, public))
            checks.append("Existing outputs, personalized/unknown images, missing keys and private-key inputs rejected")
            # Compile the actual game verifier unchanged, with trust extracted from
            # the personalized image. This tests native CNG, not just Python RSA.
            crypto = folder / "crypto"
            crypto.mkdir()
            for name in ("DW_LocalPlatformCrypto.cpp", "dw_platform_protocol.h"):
                shutil.copyfile(ROOT / "integration/replay" / name, crypto / name)
            embedded_at = next(x["offset"] for x in report["changed_ranges"] if x["purpose"] == "platform")
            embedded = patched[embedded_at:embedded_at + 283]
            (crypto / "dw_local_trust.h").write_text(
                "static const unsigned char s_dwLocalPlatformPublicKey[] = {" +
                ",".join(str(x) for x in embedded) + "};\n"
            )
            (crypto / "CMakeLists.txt").write_text(
                "cmake_minimum_required(VERSION 3.24)\nproject(local_crypto LANGUAGES CXX)\n"
                "add_library(local_crypto SHARED DW_LocalPlatformCrypto.cpp)\n"
                "target_compile_features(local_crypto PRIVATE cxx_std_20)\n"
                "set_target_properties(local_crypto PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)\n"
            )
            subprocess.run(["cmake", "-S", str(crypto), "-B", str(crypto / "build"), "-A", "x64"], check=True)
            subprocess.run(["cmake", "--build", str(crypto / "build"), "--config", "Release"], check=True)
            library = ctypes.CDLL(str(crypto / "build/Release/local_crypto.dll"))
            try:
                verify = library.DW_LocalPlatform_VerifyReply
                verify.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64)
                verify.restype = ctypes.c_bool
                nonce = os.urandom(32)
                with urllib.request.urlopen(urllib.request.Request(base + "/platform/login", nonce), timeout=5) as response:
                    signed = response.read()
                now = int(time.time())
                assert len(signed) == 512 and verify(signed, nonce, now)
                assert not verify(signed, os.urandom(32), now)
                assert not verify(signed, nonce, now + 3601)
                damaged = bytearray(signed)
                damaged[400] ^= 1
                assert not verify(bytes(damaged), nonce, now)
                checks.append("Actual game CNG verifier accepts local signature; wrong nonce, expiry and tampering rejected")
                local_key = serialization.load_der_public_key(setup.public_der(embedded))
                local_key.verify(signed[256:], signed[:256], padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
                production = serialization.load_der_public_key(setup.original_keys()[1])
                try:
                    production.verify(signed[256:], signed[:256], padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
                except InvalidSignature:
                    pass
                else:
                    raise AssertionError("Production trust unexpectedly accepted local signature")
                checks.append("Personalized DER and BCRYPT keys agree; production public key rejects the same local reply")
            finally:
                import _ctypes
                _ctypes.FreeLibrary(library._handle)
        finally:
            process.terminate()
            process.wait(timeout=15)
            log.close()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(dict(passed=True, source_sha256=setup.sha(original), checks=checks, game_run_tested=False), indent=2) + "\n")
    print("PASS:", len(checks), "local-client setup contract groups; game not launched")


if __name__ == "__main__":
    main()
