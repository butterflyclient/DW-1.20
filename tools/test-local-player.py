"""Check real Windows-protected local identities and automatic server registration.

No test identity or private key is included in a distributable. Fixture local
profiles live under ignored data and separate processes check persistence.
"""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
DLL = ROOT / "build/Release/iw8-dw-platform-client.dll"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--probe", type=Path)
parser.add_argument("--name", default="")
parser.add_argument("--public-only", action="store_true")
parser.add_argument("--resume", type=Path)
parser.add_argument("--client-dll", type=Path,
                    default=Path(os.environ.get("IW8_DW_IDENTITY_TEST_DLL", str(DLL))))
parser.add_argument("--backend-url", default=os.environ.get("IW8_DW_IDENTITY_TEST_BASE", "http://127.0.0.1:8085"))
parser.add_argument("--server", type=Path, default=ROOT / "build/Release/iw8-dw-server.exe")
parser.add_argument("--output", type=Path, default=ROOT / "data/local-player-verification.json")
parser.add_argument(
    "--legacy-name",
    help="A private legacy fixture name to verify upgrade compatibility",
)
args = parser.parse_args()
DLL = args.client_dll.resolve(strict=True)
os.environ["IW8_DW_IDENTITY_TEST_DLL"] = str(DLL)
os.environ["IW8_DW_IDENTITY_TEST_BASE"] = args.backend_url


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def probe(directory, name, public_only=False):
    directory.mkdir(parents=True, exist_ok=True)
    os.environ["LOCALAPPDATA"] = str(directory.resolve())
    dll = ctypes.CDLL(str(DLL))
    public = dll.DW_LocalIdentity_PublicKey
    public.argtypes = (ctypes.c_void_p,)
    public.restype = ctypes.c_bool
    out = ctypes.create_string_buffer(72)
    error = dll.DW_LocalIdentity_Error
    error.restype = ctypes.c_char_p
    if not public(out):
        return {"passed": False, "error": error().decode()}
    fingerprint = hashlib.sha256(out.raw).hexdigest()
    record = directory / "ReplayDW/player-identity.bin"
    if public_only:
        return {
            "passed": True,
            "fingerprint": fingerprint,
            "file_sha256": digest(record),
        }
    post_type = ctypes.CFUNCTYPE(
        ctypes.c_bool,
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.c_uint,
        ctypes.c_void_p,
        ctypes.c_uint,
    )
    captured = {}

    def post(path, source, length, output, capacity):
        data = ctypes.string_at(source, length)
        try:
            with urllib.request.urlopen(
                urllib.request.Request(
                    args.backend_url + path,
                    data,
                    {"Content-Type": "application/octet-stream"},
                ),
                timeout=10,
            ) as response:
                value = response.read()
            if len(value) != capacity:
                return False
            ctypes.memmove(output, value, capacity)
            captured[path] = data
            return True
        except urllib.error.URLError:
            return False

    callback = post_type(post)
    login = dll.DW_LocalIdentity_Login
    login.argtypes = (ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p, post_type)
    login.restype = ctypes.c_bool
    nonce = os.urandom(32)
    reply = ctypes.create_string_buffer(512)
    if not login(name.encode("ascii"), nonce, reply, callback):
        return {"passed": False, "error": error().decode()}
    verify = dll.DW_LocalPlatform_VerifyReply
    verify.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64)
    verify.restype = ctypes.c_bool
    assert verify(
        reply, nonce, int(time.time())
    ), "Native reply signature verification failed"
    request = captured["/platform/client/login"]

    def rejected(body):
        try:
            urllib.request.urlopen(
                urllib.request.Request(
                    args.backend_url + "/platform/client/login", body
                ),
                timeout=10,
            )
        except urllib.error.HTTPError as failure:
            assert failure.code == 400
            return
        raise AssertionError("Invalid/replayed login accepted")

    rejected(request)
    # A fresh challenge followed by a changed signed name cannot rename a player.
    challenge_request = captured["/platform/client/challenge"]
    with urllib.request.urlopen(
        urllib.request.Request(
            args.backend_url + "/platform/client/challenge", challenge_request
        ),
        timeout=10,
    ) as response:
        challenge = response.read()
    changed = bytearray(request)
    changed[40:72] = challenge
    changed[144] = ord("A")
    rejected(bytes(changed))
    data = reply.raw
    uid, game_id = struct.unpack_from("<QI", data, 56)
    return {
        "passed": True,
        "fingerprint": fingerprint,
        "file_sha256": digest(record),
        "user_id": uid,
        "game_account_id": game_id,
        "name": data[72:108].split(b"\0")[0].decode("ascii"),
        "signed_reply": True,
        "replay_rejected": True,
        "changed_request_rejected": True,
    }


def child(directory, name="", public_only=False):
    command = [
        sys.executable,
        "-B",
        str(Path(__file__).resolve()),
        "--probe",
        str(directory),
        "--name",
        name,
    ]
    if public_only:
        command.append("--public-only")
    return json.loads(subprocess.check_output(command, text=True))


if args.probe:
    print(json.dumps(probe(args.probe, args.name, args.public_only)))
else:
    if args.resume:
        receipt_path = args.resume
        evidence = json.loads(receipt_path.read_text())
        resumed = child(
            Path(evidence["directory"]) / "player-a", evidence["renamed"]["name"]
        )
        assert resumed == evidence["renamed"], "Identity changed across backend restart"
        evidence["backend_restart_persistence"] = True
    else:
        directory = ROOT / "data" / ("local-player-validation-" + uuid.uuid4().hex[:12])
        directory.mkdir()
        first = child(directory / "player-a")
        assert first["passed"], first
        second = child(directory / "player-a")
        assert second == first, "Local player changed between processes"
        other = child(directory / "player-b")
        assert other["passed"] and other["user_id"] != first["user_id"]
        assert other["game_account_id"] != first["game_account_id"]
        assert other["name"] != first["name"]
        renamed = child(directory / "player-a", "LocalTest-" + uuid.uuid4().hex[:12])
        assert renamed["passed"]
        for field in ("user_id", "game_account_id", "fingerprint", "file_sha256"):
            assert renamed[field] == first[field], "Rename changed player identity"
        pending = directory / "pending-recovery/ReplayDW"
        pending.mkdir(parents=True)
        shutil.copy2(
            directory / "player-a/ReplayDW/player-identity.bin",
            pending / "player-identity.creating",
        )
        recovered = child(pending.parent, public_only=True)
        assert recovered["passed"] and recovered["fingerprint"] == first["fingerprint"]
        assert recovered["file_sha256"] == first["file_sha256"]
        corrupt = directory / "corrupt/ReplayDW"
        corrupt.mkdir(parents=True)
        bad = corrupt / "player-identity.bin"
        bad.write_bytes(b"invalid-local-profile")
        original = digest(bad)
        refused = child(corrupt.parent, public_only=True)
        assert not refused["passed"] and digest(bad) == original
        assert refused["error"] == "local-identity-record-format", refused
        locked = directory / "player-a/ReplayDW/player-identity.lock"
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        )
        kernel.CreateFileW.restype = ctypes.c_void_p
        kernel.CloseHandle.argtypes = (ctypes.c_void_p,)
        lock = kernel.CreateFileW(str(locked), 0x40000000, 0, None, 4, 0x80, None)
        assert lock != ctypes.c_void_p(-1).value
        try:
            busy = child(directory / "player-a", public_only=True)
            assert (
                not busy["passed"] and busy["error"] == "local-identity-lock:0x00000020"
            ), busy
            assert (
                digest(directory / "player-a/ReplayDW/player-identity.bin")
                == first["file_sha256"]
            )
        finally:
            kernel.CloseHandle(lock)
        assert child(directory / "player-a", public_only=True)["passed"]
        # Valid record framing, damaged DPAPI ciphertext: do not regenerate it.
        damaged = directory / "damaged-dpapi/ReplayDW"
        damaged.mkdir(parents=True)
        protected = bytearray(
            (directory / "player-a/ReplayDW/player-identity.bin").read_bytes()
        )
        protected[-1] ^= 1
        damaged_file = damaged / "player-identity.bin"
        damaged_file.write_bytes(protected)
        dpapi = child(damaged.parent, public_only=True)
        assert not dpapi["passed"] and dpapi["error"].startswith(
            "local-identity-dpapi-decrypt:"
        ), dpapi
        assert damaged_file.read_bytes() == protected
        for invalid in ("#bad", "%bad", " leading", "trailing ", "x" * 36):
            invalid_name = child(directory / "player-a", invalid)
            assert (
                not invalid_name["passed"]
                and invalid_name["error"] == "local-identity-player-name"
            ), invalid_name
            assert (
                digest(directory / "player-a/ReplayDW/player-identity.bin")
                == first["file_sha256"]
            )
        evidence = {
            "schema": 1,
            "passed": True,
            "directory": str(directory),
            "first": first,
            "other": other,
            "renamed": renamed,
            "new_process_persistence": True,
            "distinct_players": True,
            "rename_preserves_identity": True,
            "interrupted_write_recovered": True,
            "corrupt_identity_preserved_and_rejected": True,
            "precise_identity_failure_stages": True,
            "lock_contention_preserves_identity": True,
            "damaged_dpapi_preserved_and_rejected": True,
            "invalid_names_preserve_identity": True,
            "backend_restart_persistence": False,
        }
        receipt_path = directory / "proof.json"
    if args.legacy_name:
        directory = Path(evidence["directory"])
        migrated = child(directory / "player-b", args.legacy_name)
        assert (
            migrated["passed"] and migrated["user_id"] == evidence["other"]["user_id"]
        )
        duplicate = child(directory / "player-a", args.legacy_name)
        assert not duplicate["passed"], "Duplicate machine-owned name accepted"
        restored = child(directory / "player-b", evidence["other"]["name"])
        assert restored == evidence["other"]
        evidence["legacy_names_do_not_block_machine_players"] = True
        evidence["duplicate_machine_names_rejected"] = True
    evidence["server_sha256"] = digest(args.server)
    evidence["client_dll_sha256"] = digest(DLL)
    evidence["identity_source_sha256"] = digest(
        ROOT / "integration/replay/DW_LocalIdentity.cpp"
    )
    receipt_path.write_text(json.dumps(evidence, indent=2) + "\n")
    args.output.write_text(
        json.dumps(evidence, indent=2) + "\n"
    )
    print(
        "PASS: local identity, registration, persistence and rejection checks; proof:",
        receipt_path,
    )
