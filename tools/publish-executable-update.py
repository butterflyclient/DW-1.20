"""Build and verify a direct patch from EVERY retained release to a fresh build.

The output directory is uploaded to the backend's data/updates directory, blobs
first and catalog.json last. Never prune the release archive: it is what keeps
clients multiple versions behind updatable in one restart.
"""

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import os
import shutil

MAX_IMAGE = 512 * 1024 * 1024


class Input(ctypes.Structure):
    _fields_ = [("data", ctypes.c_void_p), ("size", ctypes.c_size_t), ("editable", wintypes.BOOL)]


class Output(ctypes.Structure):
    _fields_ = [("data", ctypes.c_void_p), ("size", ctypes.c_size_t)]


def delta_api():
    dll = ctypes.WinDLL("msdelta", use_last_error=True)
    dll.CreateDeltaB.argtypes = (
        [ctypes.c_int64] * 3
        + [Input] * 5
        + [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Output)]
    )
    dll.ApplyDeltaB.argtypes = [ctypes.c_int64, Input, Input, ctypes.POINTER(Output)]
    dll.DeltaFree.argtypes = [ctypes.c_void_p]
    return dll


def digest(data):
    return hashlib.sha256(data).hexdigest()


def make_patch(base, target):
    api = delta_api()
    a, b = ctypes.create_string_buffer(base), ctypes.create_string_buffer(target)
    source, destination = Input(ctypes.addressof(a), len(base), False), Input(
        ctypes.addressof(b), len(target), False
    )
    output = Output()
    # RAW reproduces exact target bytes. Replay exceeds MSDelta's default
    # 32 MiB cap; IGNORE_FILE_SIZE_LIMIT is safe here because our own 512 MiB
    # bound is checked before calling the native compression API.
    if not api.CreateDeltaB(
        1, 0x20000, 0, source, destination, Input(), Input(), Input(), None, 0, ctypes.byref(output)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        patch = ctypes.string_at(output.data, output.size)
    finally:
        api.DeltaFree(output.data)
    restored = apply_patch(base, patch)
    if restored != target:
        raise ValueError("Delta round trip did not reproduce the compiled image")
    return patch


def apply_patch(base, patch):
    api = delta_api()
    a, b = ctypes.create_string_buffer(base), ctypes.create_string_buffer(patch)
    output = Output()
    if not api.ApplyDeltaB(
        0,
        Input(ctypes.addressof(a), len(base), False),
        Input(ctypes.addressof(b), len(patch), False),
        ctypes.byref(output),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if output.size > MAX_IMAGE:
            raise ValueError("Delta output exceeds maximum image size")
        return ctypes.string_at(output.data, output.size)
    finally:
        api.DeltaFree(output.data)


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + ".pending")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def verify_image(image, report):
    target = image.read_bytes()
    proof = json.loads(report.read_bytes())
    target_hash = digest(target)
    if (
        proof.get("sha256") != target_hash
        or not proof.get("cpp")
        or not target.startswith(b"MZ")
        or not 0 < len(target) <= MAX_IMAGE
    ):
        raise ValueError("Image is not bound to a fresh, verified Replay compiler report")
    verification = json.loads((report.parent / "verification-report.json").read_bytes())
    relocations = json.loads((report.parent / "relocation-audit.json").read_bytes())
    if (
        verification.get("sha256") != target_hash
        or verification.get("unresolved_symbols") != 0
        or relocations.get("sha256") != target_hash
        or not relocations.get("passed")
    ):
        raise ValueError(
            "Executable has no successful hash-bound linker and relocation verification"
        )
    return target, target_hash


def retain_release(image, report, release, archive):
    """Retain a distributed compiler build without advertising it as latest.

    Separately coordinated client builds need an upgrade path too. Verify their
    actual compiler/linker receipts before adding them to the source archive;
    the next publication generates and round-trips their deltas normally.
    """
    target, target_hash = verify_image(image, report)
    archive.mkdir(parents=True, exist_ok=True)
    lock = archive / "publish.lock"
    descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    try:
        index = archive / "releases.json"
        records = json.loads(index.read_bytes()) if index.exists() else []
        report_hash = digest(report.read_bytes())
        for row in records:
            if row["sha256"] == target_hash:
                if (
                    row["report_sha256"] != report_hash
                    or row["size"] != len(target)
                    or digest((archive / (target_hash + ".exe")).read_bytes()) != target_hash
                    or digest((archive / (target_hash + ".build-report.json")).read_bytes())
                    != report_hash
                ):
                    raise ValueError("Retained release provenance changed")
                return dict(retained=True, already_retained=True, **row)
        if release <= 0 or (records and release <= max(row["release"] for row in records)):
            raise ValueError("Retained release numbers must increase")
        shutil.copyfile(image, archive / (target_hash + ".exe"))
        shutil.copyfile(report, archive / (target_hash + ".build-report.json"))
        row = dict(
            release=release, sha256=target_hash, size=len(target), report_sha256=report_hash
        )
        records.append(row)
        atomic_json(index, records)
        return dict(retained=True, **row)
    finally:
        os.close(descriptor)
        lock.unlink()


def publish(image, report, release, archive, output):
    target, target_hash = verify_image(image, report)
    archive.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    (output / "patches").mkdir(exist_ok=True)
    lock = archive / "publish.lock"
    descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    try:
        index = archive / "releases.json"
        records = json.loads(index.read_bytes()) if index.exists() else []
        retry = bool(
            records
            and records[-1]["release"] == release
            and records[-1]["sha256"] == target_hash
            and records[-1]["report_sha256"] == digest(report.read_bytes())
        )
        if retry:
            # A crash after archiving the release but before catalog publication
            # can be retried with the identical compiler artifact and receipt.
            records = records[:-1]
        if release <= 0 or (records and release <= max(row["release"] for row in records)):
            raise ValueError("Release numbers must increase; republishing/rollback is explicit")
        if any(row["sha256"] == target_hash for row in records):
            raise ValueError("This exact image is already published")
        patches = {}
        for row in records:
            base = (archive / (row["sha256"] + ".exe")).read_bytes()
            if digest(base) != row["sha256"] or len(base) != row["size"]:
                raise ValueError("A retained release is missing or changed")
            patch = make_patch(base, target)
            patch_hash = digest(patch)
            path = output / "patches" / (patch_hash + ".delta")
            if path.exists() and digest(path.read_bytes()) != patch_hash:
                raise ValueError("Content-addressed patch was changed")
            path.write_bytes(patch)
            patches[row["sha256"]] = {
                "base_size": len(base),
                "size": len(patch),
                "sha256": patch_hash,
            }
            print(
                f"Verified release {row['release']} -> {release}: {len(patch):,} patch bytes",
                flush=True,
            )
        # Archive the exact compiled EXE and its provenance, not an edited copy.
        shutil.copyfile(image, archive / (target_hash + ".exe"))
        shutil.copyfile(report, archive / (target_hash + ".build-report.json"))
        records.append(
            {
                "release": release,
                "sha256": target_hash,
                "size": len(target),
                "report_sha256": digest(report.read_bytes()),
            }
        )
        catalog = {
            "schema": 1,
            "format": "msdelta-raw-v1",
            "release": release,
            "latest": target_hash,
            "target_size": len(target),
            "patches": patches,
        }
        atomic_json(index, records)
        atomic_json(output / "catalog.json", catalog)
        return catalog
    finally:
        os.close(descriptor)
        lock.unlink()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--build-report", type=Path, required=True)
    parser.add_argument("--release", type=int, required=True)
    parser.add_argument("--archive", type=Path, default=Path("data/executable-releases"))
    parser.add_argument("--output", type=Path, default=Path("data/executable-update-publication"))
    parser.add_argument(
        "--retain-only", action="store_true",
        help="Verify and archive a distributed compiler build for the next release's deltas",
    )
    args = parser.parse_args()
    print(
        json.dumps(
            retain_release(args.image, args.build_report, args.release, args.archive)
            if args.retain_only
            else publish(args.image, args.build_report, args.release, args.archive, args.output),
            indent=2,
        )
    )
