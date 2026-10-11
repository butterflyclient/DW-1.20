"""Verify signed full-image updates and the embedded helper without launching a game."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import secrets
import shutil
import struct
import subprocess
import tempfile
import time
import urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = Path(__file__).resolve().parents[1]
MAGIC = 0x3155505744594C50
PLAN = struct.Struct("<QIIQQ32s32s32s32sQQQQ")


def array(header, name):
    match = re.search(r"\b" + re.escape(name) + r"\[\]\s*=\s*\{(.*?)\}",
                      header.read_text(), re.S)
    if not match:
        raise ValueError("Missing frozen helper/trust array: " + name)
    return bytes(int(value, 16) for value in re.findall(r"0x([0-9a-fA-F]{2})", match[1]))


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publication", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--base-exe", required=True, type=Path)
    parser.add_argument("--host", default="162.243.115.160")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    catalog = json.loads((args.publication / "full-image-catalog.json").read_bytes())
    image = args.publication / (catalog["latest"] + ".exe")
    assert sha(image) == catalog["latest"] and image.stat().st_size == catalog["target_size"]
    trust = array(args.source_root / "dw_local_trust.h", "s_dwLocalPlatformPublicKey")
    magic, bits, exponent_size, modulus_size, prime1, prime2 = struct.unpack_from("<6I", trust)
    assert magic == 0x31415352 and bits == 2048 and prime1 == prime2 == 0
    exponent = int.from_bytes(trust[24:24 + exponent_size], "big")
    modulus = int.from_bytes(trust[24 + exponent_size:24 + exponent_size + modulus_size], "big")
    public = rsa.RSAPublicNumbers(exponent, modulus).public_key()
    checks = []
    old = {row["sha256"] for row in json.loads((ROOT / "data/executable-releases/releases.json").read_bytes())}
    old.add(sha(args.base_exe))
    old.add("a" * 64)  # Full images do not require an inventory of prior builds.

    def check(base_hash, expected_status):
        nonce = secrets.token_bytes(32)
        request = struct.pack("<QII32s32s", MAGIC, 2, 0, nonce, bytes.fromhex(base_hash))
        before = int(time.time())
        with urllib.request.urlopen(urllib.request.Request(
            "http://" + args.host + ":8085/updates/v2/check", data=request,
            headers={"Content-Type": "application/octet-stream"}), timeout=30) as response:
            reply = response.read(449)
        assert len(reply) == 448
        public.verify(reply[192:], reply[:192],
                      padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
        values = PLAN.unpack(reply[:192])
        identity, version, status, issued, expires, echoed, base, target, payload, base_size, target_size, size, release = values
        assert identity == MAGIC and version == 2 and status == expected_status
        assert before - 5 <= issued <= int(time.time()) + 5 and expires > issued
        assert echoed == nonce and base.hex() == base_hash and target.hex() == catalog["latest"]
        assert target_size == catalog["target_size"] and release == catalog["release"] and base_size == 0
        if expected_status == 1:
            assert payload == target and size == target_size
        else:
            assert size == 0

    for digest in sorted(old - {catalog["latest"]}):
        check(digest, 1)
    checks.append("Signed fresh-nonce full-image replies point all tested older hashes directly to the latest release")
    check(catalog["latest"], 0)
    checks.append("Latest executable receives current status without another download/update loop")

    helper = array(args.source_root / "DW_UpdateHelper.h", "s_dwUpdateHelper")
    helper_hash = hashlib.sha256(helper).hexdigest()
    assert image.read_bytes().count(helper) == 1, "Published PE must contain the exact helper that is exercised"
    assert b"/\x00u\x00p\x00d\x00a\x00t\x00e\x00s\x00/\x00v\x002\x00/\x00c\x00h\x00e\x00c\x00k\x00" in helper
    with tempfile.TemporaryDirectory(prefix="published-update-", dir=ROOT / "data") as name:
        folder = Path(name).resolve()
        assert folder.parent == (ROOT / "data").resolve()
        runner = folder / "replay-update-client.exe"
        runner.write_bytes(helper)
        base = folder / "old-release.exe"
        shutil.copyfile(args.base_exe, base)
        base_hash = sha(base)
        result = subprocess.run([str(runner), "--prepare", str(base), args.host],
                                cwd=folder, creationflags=subprocess.CREATE_NO_WINDOW, timeout=300)
        assert result.returncode == 20, "Embedded helper must stage the full update"
        staged = Path(str(base) + ".update") / "next.exe"
        assert sha(staged) == catalog["latest"] and sha(base) == base_hash
        checks.append("Actual embedded Windows helper verifies and stages exact published EXE; installed older bytes remain unchanged")
        current = folder / "current-release.exe"
        shutil.copyfile(image, current)
        result = subprocess.run([str(runner), "--prepare", str(current), args.host],
                                cwd=folder, creationflags=subprocess.CREATE_NO_WINDOW, timeout=60)
        assert result.returncode == 10 and sha(current) == catalog["latest"]
        assert not (Path(str(current) + ".update") / "next.exe").exists()
        checks.append("Actual embedded helper recognizes the current release and stages no replacement")
    result = dict(passed=True, host=args.host, release=catalog["release"],
                  executable_sha256=catalog["latest"], bytes=catalog["target_size"],
                  tested_older_hashes=len(old - {catalog["latest"]}),
                  helper_sha256=helper_hash, pinned_trust_sha256=hashlib.sha256(trust).hexdigest(),
                  checks=checks, game_runs_performed=False, installed_game_modified=False,
                  apply_or_relaunch_invoked=False, temporary_fixture_removed=True,
                  legacy_delta_only_clients_require_bootstrap=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print("PASS: signed published full-image plans and actual embedded helper staging; no game launched")


if __name__ == "__main__":
    main()
