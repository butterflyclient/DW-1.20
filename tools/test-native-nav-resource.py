"""Standalone serializer/geometry regression; synthetic geometry is not Gulag evidence."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "nav", ROOT / "generate-native-nav-resource.py"
)
nav = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nav)


def box(lo, hi):
    return dict(
        points=[
            [x, y, z]
            for x in (lo[0], hi[0])
            for y in (lo[1], hi[1])
            for z in (lo[2], hi[2])
        ],
        flags=3,
    )


def main():
    directory = ROOT / "build" / "native-nav-resource" / "regression"
    directory.mkdir(parents=True, exist_ok=True)
    geometry = dict(
        schema=1,
        coordinate_space="world",
        provenance=dict(
            kind="synthetic_regression_only",
            description="two floor levels and split wall with real opening; not Gulag geometry",
        ),
        hulls=[
            box([-256, -256, -16], [256, 256, 0]),
            box([-8, -256, 0], [8, -48, 128]),
            box([-8, 48, 0], [8, 256, 128]),
            box([80, -80, 0], [160, 80, 16]),
        ],
        triangles=[],
        spawns=[[-192, 0, 4], [192, 0, 4]],
        pathNodes=[],
    )
    input = directory / "geometry.json"
    input.write_text(json.dumps(geometry))
    resource = directory / "geometry.bfx"
    report = directory / "report.json"
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "generate-native-nav-resource.py"),
            "--input",
            str(input),
            "--output",
            str(resource),
            "--report",
            str(report),
        ],
        check=True,
        capture_output=True,
    )
    result = json.loads(report.read_bytes())
    assert result["areas"] > 1 and result["portal_sides"] > 0
    audit = result["collision_fidelity"]
    assert not audit["sampled_checks_passed"]
    assert audit["height_failures"] > 0 and audit["clearance_failures"] > 0
    assert audit["area_centers"] > 0 and audit["edge_midpoints"] > 0
    assert audit["interior_fan_samples"] > 0 and audit["uncovered_spawns"] == 0
    data = bytearray(resource.read_bytes())
    data[-1] ^= 1
    try:
        nav.validate_resource(data)
    except ValueError:
        pass
    else:
        raise AssertionError("corrupted checksum accepted")
    invalid = dict(geometry)
    invalid["coordinate_space"] = "unverified-local"
    try:
        nav.geometry_binary(invalid)
    except ValueError:
        pass
    else:
        raise AssertionError("unresolved transform accepted")
    incomplete = dict(geometry)
    incomplete["collision_complete"] = False
    try:
        nav.geometry_binary(incomplete)
    except ValueError:
        pass
    else:
        raise AssertionError("explicitly incomplete collision accepted")
    geometry["hulls"] = geometry["hulls"][:1]
    geometry["spawns"] = [[0, 0, 4]]
    geometry["provenance"][
        "description"
    ] = "synthetic clean platform positive auditor control"
    input.write_text(json.dumps(geometry))
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "generate-native-nav-resource.py"),
            "--input",
            str(input),
            "--output",
            str(directory / "clean-control.bfx"),
            "--report",
            str(directory / "clean-control-report.json"),
        ],
        check=True,
        capture_output=True,
    )
    control = json.loads((directory / "clean-control-report.json").read_bytes())
    assert control["collision_fidelity"]["sampled_checks_passed"]
    print(
        "PASS: serializer, structural validation, unsafe-geometry audit rejection, clean control, input contract"
    )


if __name__ == "__main__":
    main()
