"""Build the release-manifest server candidate source from the exact production archive.

Local only: nothing is uploaded, built remotely or activated. The candidate is the archive that
production was built from (data/tls-deadline-candidate-20261018T201209Z/source.tar.gz, hash-pinned
by its receipt) with exactly four files replaced by this checkout's versions. Unrelated uncommitted
edits (for example src/lobby.h) are never included.

    python tools/prepare-release-manifest-candidate.py
"""
import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "data" / "tls-deadline-candidate-20261018T201209Z"
CHANGED = ("src/executable_updates.h", "src/platform.cpp", "src/platform.h", "src/server.cpp")
VALIDATION = (BASE / "validation" / "test-tls-transport.py", BASE / "validation" / "test-connection-budget.py",
              ROOT / "tools" / "test-release-manifest.py")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main():
    receipt = json.loads((BASE / "source-receipt.json").read_bytes())
    archive_bytes = (BASE / "source.tar.gz").read_bytes()
    if sha(archive_bytes) != receipt["archive_sha256"]:
        raise SystemExit("Production source archive does not match its receipt")
    production = json.loads((ROOT / "data" / "droplet-deployment.json").read_bytes())
    if production["source_receipt"]["path"] != str(Path("data/tls-deadline-candidate-20261018T201209Z/source-receipt.json")).replace("\\", "/"):
        raise SystemExit("Production is no longer the TLS-deadline release; rebase this candidate first")

    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as source:
        members = {m.name: source.extractfile(m).read() for m in source.getmembers() if m.isfile()}
    for name in CHANGED:
        if name not in members:
            raise SystemExit(f"{name} missing from production archive")
        head = (ROOT / ".git").exists() and __import__("subprocess").check_output(
            ["git", "show", f"HEAD:{name}"], cwd=ROOT)
        if head is not False and head != members[name]:
            raise SystemExit(f"{name}: production differs from HEAD; the patch base is not production")

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out = ROOT / "data" / f"release-manifest-candidate-{stamp}"
    out.mkdir(parents=True)
    changed = {}
    for name in CHANGED:
        data = (ROOT / name).read_bytes().replace(b"\r\n", b"\n")   # archive sources are LF
        changed[name] = dict(before=sha(members[name]), after=sha(data))
        members[name] = data

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz", format=tarfile.PAX_FORMAT) as candidate:
        for name in sorted(members):
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(members[name]), 0, 0o644
            candidate.addfile(info, io.BytesIO(members[name]))
    archive = buffer.getvalue()
    (out / "source.tar.gz").write_bytes(archive)
    (out / "validation").mkdir()
    for script in VALIDATION:
        shutil.copyfile(script, out / "validation" / script.name)
    shutil.copyfile(ROOT / "tools" / "activate-release-manifest-candidate.sh", out / "activate-release-manifest-candidate.sh")

    record = dict(schema=1, baseline_commit=receipt["baseline_commit"],
                  base_archive_sha256=receipt["archive_sha256"],
                  base_production_server_sha256=production["sha256"],
                  production_changed_files=receipt["production_changed_files"] + list(CHANGED),
                  release_manifest_changes=changed, archive_sha256=sha(archive),
                  validation_inputs={p.name: sha((out / "validation" / p.name).read_bytes()) for p in VALIDATION},
                  activation_script_sha256=sha((out / "activate-release-manifest-candidate.sh").read_bytes()),
                  remote_staging=f"/tmp/replay-dw-release-manifest-candidate-{stamp}", deployed=False)
    (out / "source-receipt.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(dict(candidate=str(out), archive_sha256=record["archive_sha256"],
                          remote_staging=record["remote_staging"]), indent=2))


if __name__ == "__main__":
    main()
