"""Retry a failed DW snapshot job through the complete locked workstation worker."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import argparse

parser = argparse.ArgumentParser()
parser.add_argument(
    "--reason", default="retained verification fixtures added; full pipeline retry"
)
parser.add_argument("--receipt-directory", type=Path,
                    help="Private job receipts produced by build-frozen-workstation")
args = parser.parse_args()

ROOT = Path(__file__).resolve().parents[1]
receipts = args.receipt_directory.resolve() if args.receipt_directory else ROOT / "data"
receipt_path = receipts / "compiler-snapshot-receipt.json"
receipt = json.loads(receipt_path.read_text())
snapshot = Path(receipt["snapshot"])
configuration = json.loads((snapshot / "replay-project.local.json").read_text())
dispatch = json.loads((receipts / "workstation-job.json").read_text())
directory = Path(configuration["cache"]) / "jobs" / dispatch["id"]
job_path = directory / "job.json"
job = json.loads(job_path.read_text())
if job["status"] != "failed" or job["profile"] != "engine":
    raise RuntimeError("Only the recorded failed DW engine job may be retried")
for item in receipt["files"]:
    file = Path(item["snapshot"])
    if file == snapshot / "generated" / "manifest.json":
        continue
    if hashlib.sha256(file.read_bytes()).hexdigest() != item["sha256"]:
        raise RuntimeError("Frozen job input changed; start a new build: " + str(file))

# Add the omitted test data; no linked source or compiler input is altered.
original = Path(r"E:\replay-compiler")
fixture_count = 0
existing = {item["snapshot"] for item in receipt["files"]}
for relative in (
    "evidence/mw131-canonical-selected-scripts/1806.gscbin",
    "evidence/replay120-global-mp-scriptfiles/1806.gscbin",
    "evidence/mw131-scriptfile-dump",
    "evidence/mw131-frontend6-scriptfiles",
):
    path = original / relative
    sources = (
        [path]
        if path.is_file()
        else sorted(path.rglob("*.gscbin")) if path.is_dir() else []
    )
    for source in sources:
        raw = source.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        destination = snapshot / source.relative_to(original)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if (
            destination.exists()
            and hashlib.sha256(destination.read_bytes()).hexdigest() != digest
        ):
            raise RuntimeError("Retained test fixture changed: " + str(source))
        destination.write_bytes(raw)
        if hashlib.sha256(source.read_bytes()).hexdigest() != digest:
            raise RuntimeError("Fixture changed during copy: " + str(source))
        if str(destination) not in existing:
            receipt["files"].append(
                {
                    "original": str(source),
                    "snapshot": str(destination),
                    "sha256": digest,
                }
            )
            existing.add(str(destination))
        fixture_count += 1
if not fixture_count:
    raise RuntimeError("No retained ScriptFile test fixtures are available")
receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
job.setdefault("retry_history", []).append(
    {"time": time.time(), "error": job.get("error"), "reason": args.reason}
)
job.pop("error", None)
job.pop("finished", None)
job.update(status="queued", phase="Retry queued")
job_path.write_text(json.dumps(job, indent=2) + "\n")
command = [
    sys.executable,
    str(snapshot / "tools" / "run_compiler_locked.py"),
    "--lock",
    str(snapshot / ".workstation-compiler.lock"),
    "--",
    sys.executable,
    str(snapshot / "tools" / "workstation_build_job.py"),
    "--job",
    str(directory),
]
environment = {
    **os.environ,
    "REPLAY_GAME_ROOT": configuration["game"],
    "REPLAY_SQLITE": configuration["sqlite"],
    "REPLAY_WORKSTATION_CACHE": configuration["cache"],
}
print(
    "Full workstation retry:",
    job["id"],
    "; retained fixtures:",
    fixture_count,
    flush=True,
)
with (directory / "compiler.log").open("ab", buffering=0) as log:
    log.write(
        ("\nRetry: " + args.reason + "; full compiler worker follows.\n").encode()
    )
    result = subprocess.run(
        command,
        cwd=snapshot,
        env=environment,
        stdout=log,
        stderr=subprocess.STDOUT,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
current = json.loads(job_path.read_text())
(receipts / "workstation-job.json").write_text(
    json.dumps(current, indent=2) + "\n"
)
print(current["status"], current["phase"], current.get("error", ""), flush=True)
raise SystemExit(
    0 if result.returncode == 0 and current["status"] == "succeeded" else 1
)
