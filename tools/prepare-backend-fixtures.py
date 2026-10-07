"""Freeze an isolated native-wire fixture tree from a successful backend build."""

import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "--build-receipt", type=Path, default=ROOT / "data/backend-build-latest.json"
)
parser.add_argument("--overlay", nargs="*", default=[])
parser.add_argument("--fixture-revision", help="Use tools from an explicit committed revision")
args = parser.parse_args()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


receipt = args.build_receipt.resolve()
assert receipt.is_relative_to(ROOT / "data")
build = json.loads(receipt.read_text())
assert build["compile_passed"]
source = Path(build["source_directory"]).resolve()
executable = Path(build["executable"]).resolve()
assert source.is_relative_to(ROOT / "data") and executable.is_relative_to(ROOT / "data")
assert digest(executable) == build["sha256"]
for name, expected in build["inputs"].items():
    assert digest(source / name) == expected

destination = ROOT / "data" / f"backend-validation-{time.time_ns()}"
destination.mkdir()
for name in ("tools", "src", "integration", "third_party"):
    shutil.copytree(source / name, destination / name)
shutil.copy2(source / "CMakeLists.txt", destination / "CMakeLists.txt")
fixture_revision = build.get("committed_revision")
if args.fixture_revision:
    fixture_revision = subprocess.check_output(
        ["git", "rev-parse", "--verify", args.fixture_revision + "^{commit}"], cwd=ROOT
    ).decode().strip()
    archive = subprocess.check_output(
        ["git", "archive", "--format=zip", fixture_revision, "tools"], cwd=ROOT
    )
    with zipfile.ZipFile(io.BytesIO(archive)) as entries:
        for entry in entries.infolist():
            path = (destination / entry.filename).resolve()
            if not path.is_relative_to(destination / "tools"):
                raise ValueError("Fixture archive escapes its tools directory")
        entries.extractall(destination)
overlays = []
for name in args.overlay:
    relative = Path(name)
    original, target = (ROOT / relative).resolve(), (destination / relative).resolve()
    assert relative.parts[0] == "tools" and not relative.is_absolute()
    assert original.is_relative_to(ROOT / "tools") and target.is_relative_to(
        destination
    )
    assert original.is_file() and original.suffix == ".py"
    shutil.copy2(original, target)
    overlays.append(dict(path=relative.as_posix(), sha256=digest(target)))

image = destination / "build/Release/iw8-dw-server.exe"
image.parent.mkdir(parents=True)
shutil.copy2(executable, image)
data = destination / "data"
data.mkdir()
for name in ("replay-traffic-kdf.bin", "unified_large_playlist_tu19.aggr"):
    shutil.copy2(ROOT / "data" / name, data / name)
metadata = dict(
    schema=1,
    root=str(destination),
    build_receipt=build,
    fixture_source_revision=fixture_revision,
    explicit_fixture_overlays=overlays,
    frozen_input_hashes={
        path.relative_to(destination).as_posix(): digest(path)
        for path in destination.rglob("*")
        if path.is_file()
    },
)
(destination / "fixture-inputs.json").write_text(json.dumps(metadata, indent=2) + "\n")
(ROOT / "data/backend-validation-latest.json").write_text(
    json.dumps(metadata, indent=2) + "\n"
)
print(f"Frozen fixture root: {destination}")
