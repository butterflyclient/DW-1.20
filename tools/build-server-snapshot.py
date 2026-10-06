"""Build a backend from committed sources plus an explicit owned overlay.

This preserves unrelated dirty source files and writes no deployed image. Stop
the live server separately before deploying the resulting verified executable.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import subprocess
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--overlay", nargs="*", default=[])
args = parser.parse_args()
revision = (
    subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip()
)
snapshot = ROOT / "data" / f"backend-snapshot-{time.time_ns()}"
source, build = snapshot / "source", snapshot / "build"
source.mkdir(parents=True)
archive = subprocess.check_output(
    [
        "git",
        "archive",
        "--format=zip",
        revision,
        "CMakeLists.txt",
        "src",
        "integration",
        "third_party",
        "tools",
    ],
    cwd=ROOT,
)
with zipfile.ZipFile(io.BytesIO(archive)) as entries:
    for entry in entries.infolist():
        path = (source / entry.filename).resolve()
        if not path.is_relative_to(source.resolve()):
            raise ValueError("Source archive path escapes its snapshot")
    entries.extractall(source)
overlays = []
for name in args.overlay:
    relative = Path(name)
    original = (ROOT / relative).resolve()
    target = (source / relative).resolve()
    if (
        relative.is_absolute()
        or not original.is_relative_to(ROOT)
        or not target.is_relative_to(source)
        or (
            relative.parts[0] not in ("src", "integration")
            and relative != Path("CMakeLists.txt")
        )
        or not original.is_file()
    ):
        raise ValueError("Only explicit backend build inputs may be overlaid")
    contents = original.read_bytes()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(contents)
    overlays.append(
        dict(path=relative.as_posix(), sha256=hashlib.sha256(contents).hexdigest())
    )
inputs = {
    path.relative_to(source).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
    for path in source.rglob("*")
    if path.is_file()
}
cmake = Path(r"C:\Program Files\CMake\bin\cmake.exe")
subprocess.run(
    [str(cmake), "-S", str(source), "-B", str(build), "-A", "x64"], check=True
)
subprocess.run(
    [
        str(cmake),
        "--build",
        str(build),
        "--config",
        "Release",
        "--target",
        "iw8-dw-server",
        "--parallel",
        "2",
    ],
    check=True,
)
for name, digest in inputs.items():
    if hashlib.sha256((source / name).read_bytes()).hexdigest() != digest:
        raise ValueError("A frozen source changed during compilation")
executable = build / "Release" / "iw8-dw-server.exe"
receipt = dict(
    schema=1,
    generated_utc=datetime.now(timezone.utc).isoformat(),
    committed_revision=revision,
    source_directory=str(source),
    build_directory=str(build),
    explicit_overlays=overlays,
    inputs=inputs,
    executable=str(executable),
    sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
    compile_passed=True,
    deployed=False,
)
destination = snapshot / "build-receipt.json"
destination.write_text(json.dumps(receipt, indent=2) + "\n")
(ROOT / "data/backend-build-latest.json").write_bytes(destination.read_bytes())
print(f"Fresh backend build receipt: {destination}")
print(f"Executable SHA256: {receipt['sha256']}")
