"""Create a separate Replay DW client pinned to a local server's public key.

No compiler, production source edits, private keys, or network access are used.
Only exact existing public-key constants in the rebuilt PE section are changed.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[1]
LOCAL_NAME = "game_dx12_ship_replay_local_dw.exe"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def public_der(blob):
    # BCRYPT_RSAKEY_BLOB followed by big-endian exponent and modulus.
    if len(blob) != 283 or struct.unpack_from("<6I", blob) != (
        0x31415352, 2048, 3, 256, 0, 0
    ) or blob[24:27] != b"\x01\x00\x01":
        raise ValueError("Expected a 2048-bit platform-public.blob, not a private key")
    if not blob[27] & 128 or not blob[-1] & 1:
        raise ValueError("Invalid RSA public modulus")
    # Fixed-size RSA-2048 SubjectPublicKeyInfo; matches configure-platform-trust.py.
    return bytes.fromhex(
        "30820122300d06092a864886f70d01010105000382010f003082010a0282010100"
    ) + blob[27:] + bytes.fromhex("0203010001")


def original_keys():
    text = (ROOT / "integration/replay/dw_local_trust.h").read_text(encoding="utf-8")
    keys = []
    for name in ("s_dwLocalPlatformPublicKey", "s_dwLocalAuthDer"):
        match = re.search(name + r"\[\]\s*=\s*\{([^}]+)\}", text)
        if not match:
            raise ValueError("Cannot find original public trust constants")
        keys.append(bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", match[1])))
    if public_der(keys[0]) != keys[1]:
        raise ValueError("Source public-key formats disagree")
    return keys


def cpp_section(image):
    if len(image) < 256 or image[:2] != b"MZ":
        raise ValueError("Input is not a Replay DW PE executable")
    pe = struct.unpack_from("<I", image, 60)[0]
    if pe + 264 > len(image) or image[pe:pe + 4] != b"PE\0\0":
        raise ValueError("Invalid PE header")
    machine, count = struct.unpack_from("<HH", image, pe + 4)
    optional_size = struct.unpack_from("<H", image, pe + 20)[0]
    optional = pe + 24
    if machine != 0x8664 or struct.unpack_from("<H", image, optional)[0] != 0x20B:
        raise ValueError("Expected a 64-bit Replay client")
    if optional_size < 152 or not 1 <= count <= 96:
        raise ValueError("Unsupported PE layout")
    if any(struct.unpack_from("<II", image, optional + 144)):
        raise ValueError("Signed PE images are not supported by local personalization")
    table = optional + optional_size
    if table + count * 40 > len(image):
        raise ValueError("Truncated PE section table")
    sections = []
    for index in range(count):
        row = table + index * 40
        name = image[row:row + 8].rstrip(b"\0")
        size, offset = struct.unpack_from("<II", image, row + 16)
        if size and (offset < table + count * 40 or offset + size > len(image)):
            raise ValueError("Invalid PE section bounds")
        if name == b".cpp":
            sections.append((offset, offset + size))
    if len(sections) != 1:
        raise ValueError("No unique rebuilt .cpp section; use a compatible DW client")
    return sections[0]


def personalize(image, public):
    old_blob, old_der = original_keys()
    new_der = public_der(public)
    if public == old_blob:
        raise ValueError("This is the production public key; use your own local server data")
    if b"bypass_update_restart=1; updater bypassed;" not in image:
        raise ValueError("Client does not have the supported local updater-bypass behavior")
    start, end = cpp_section(image)
    edits = []
    for name, old, new in (("platform", old_blob, public), ("auth_content", old_der, new_der)):
        offsets = [match.start() for match in re.finditer(re.escape(old), image)]
        # Two platform copies: game verifier and embedded updater. Two DER copies:
        # native authentication and cached content. Reject other layouts explicitly.
        if len(offsets) != 2 or any(not start <= at < at + len(old) <= end for at in offsets):
            raise ValueError(
                f"Unsupported or already personalized client: expected two {name} keys in .cpp; "
                "start from an untouched compatible production DW executable"
            )
        edits.extend((at, old, new, name) for at in offsets)
    result = bytearray(image)
    previous_end = 0
    for at, old, new, _ in sorted(edits):
        if at < previous_end or len(old) != len(new):
            raise ValueError("Overlapping or differently sized trust constants")
        result[at:at + len(old)] = new
        previous_end = at + len(old)
    restored = bytearray(result)
    for at, old, new, _ in edits:
        if result[at:at + len(new)] != new:
            raise ValueError("Personalized key readback failed")
        restored[at:at + len(old)] = old
    if restored != image:
        raise ValueError("Bytes outside public-key constants changed")
    return bytes(result), [dict(offset=at, bytes=len(old), purpose=name) for at, old, _, name in edits]


def setup(client, server_data, ini_content=None):
    client = client.resolve(strict=True)
    if client.name != "game_dx12_ship_replay_dw.exe":
        raise ValueError("Select the original game_dx12_ship_replay_dw.exe in your game folder")
    public_path = server_data.resolve(strict=True) / "platform-public.blob"
    public = public_path.read_bytes()
    original = client.read_bytes()
    result, changes = personalize(original, public)
    output = client.with_name(LOCAL_NAME)
    ini = output.with_suffix(".ini")
    launcher = client.with_name("Run_Replay_DW_Local.cmd")
    receipt = output.with_suffix(".setup.json")
    targets = (output, ini, launcher, receipt)
    if any(path.exists() for path in targets):
        raise ValueError("Local client files already exist. Back them up and move them aside before running setup again")
    # Read-only preflight is complete before creating any output.
    if client.read_bytes() != original or public_path.read_bytes() != public:
        raise ValueError("Client or server public key changed during setup")
    report = dict(
        schema=1, source=str(client), source_sha256=sha(original),
        output=str(output), output_sha256=sha(result),
        public_key_sha256=sha(public), changed_ranges=changes,
        only_public_key_constants_changed=True, game_run_tested=False,
        production_publication=False,
    )
    contents = (
        result,
        ini_content or b"host=127.0.0.1\r\nbypass_update_restart=1\r\n",
        ('@echo off\r\ncd /d "%~dp0"\r\nstart "" "' + LOCAL_NAME + '"\r\n').encode("ascii"),
        (json.dumps(report, indent=2) + "\n").encode("utf-8"),
    )
    created = []
    try:
        for path, content in zip(targets, contents):
            with path.open("xb") as stream:
                created.append(path)
                stream.write(content)
        if output.read_bytes() != result:
            raise ValueError("Written local client failed verification")
    except BaseException:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise
    return report


def local_files(client):
    output = client.with_name(LOCAL_NAME)
    return (output, output.with_suffix(".ini"), client.with_name("Run_Replay_DW_Local.cmd"),
            output.with_suffix(".setup.json"))


def check(client, server_data):
    """Is the local client present and built from this EXE and this server's key?"""
    client = client.resolve(strict=True)
    files = local_files(client)
    present = [path.exists() for path in files]
    if not any(present):
        return dict(state="missing", reasons=["no local client files"])
    reasons = []
    if not all(present):
        reasons.append("incomplete local client files")
    try:
        receipt = json.loads(files[3].read_text(encoding="utf-8"))
    except (OSError, ValueError):
        receipt = {}
        reasons.append("unreadable setup receipt")
    if receipt.get("source_sha256") != sha(client.read_bytes()):
        reasons.append("original DW EXE changed (updated) since setup")
    public = (server_data.resolve(strict=True) / "platform-public.blob").read_bytes()
    if receipt.get("public_key_sha256") != sha(public):
        reasons.append("server public key differs from the one the local client trusts")
    if files[0].exists() and receipt.get("output_sha256") != sha(files[0].read_bytes()):
        reasons.append("local EXE does not match its receipt")
    return dict(state="stale" if reasons else "current", reasons=reasons)


def refresh(client, server_data):
    """Create, or regenerate a stale, local client; the user's INI is kept."""
    client = client.resolve(strict=True)
    current = check(client, server_data)
    if current["state"] == "current":
        return dict(current, refreshed=False)
    ini_content = None
    if current["state"] == "stale":
        files = local_files(client)
        if files[1].exists():
            ini_content = files[1].read_bytes()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = client.parent / "dw-local-client-backup" / stamp
        backup.mkdir(parents=True, exist_ok=False)
        for path in files:
            if path.exists():
                path.replace(backup / path.name)
    report = setup(client, server_data, ini_content)
    return dict(report, state="current", refreshed=True, previous=current)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=Path, required=True, help="Original DW EXE in the game folder")
    parser.add_argument("--server-data", type=Path, required=True, help="The running local server's data folder")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Report missing/stale/current and exit")
    mode.add_argument("--refresh", action="store_true",
                      help="Create the local client, or back up and regenerate a stale one (keeps the INI)")
    args = parser.parse_args()
    try:
        if args.check:
            print(json.dumps(check(args.client, args.server_data), indent=2))
            return
        report = refresh(args.client, args.server_data) if args.refresh else setup(args.client, args.server_data)
    except (OSError, ValueError, struct.error) as error:
        parser.exit(1, "Local client setup failed: " + str(error) + "\n")
    print(json.dumps(report, indent=2))
    if not args.refresh:
        print("Start your local backend, then launch Run_Replay_DW_Local.cmd from the game folder.")
        print("Automatic updates are disabled for this separate local client; keep required game assets installed.")


if __name__ == "__main__":
    main()
