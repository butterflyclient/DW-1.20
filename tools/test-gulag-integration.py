"""Verify the compiled additive Gulag package and native ownership lifecycle."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report_path = args.build / "build-report.json"
    report = json.loads(report_path.read_bytes())
    assert report["unresolved_symbols"] == 0
    assert digest(report["executable"]) == report["sha256"]
    source = Path(report["source_root"])
    proof_path = source / "generated/gulag-navigation/package-proof.json"
    proof = json.loads(proof_path.read_bytes())
    assert proof["production_ready"] and not proof["synthetic_format_fixture"]
    assert len(proof["resources"]) == 6
    assert proof["existing_asset_replacements"] == []
    assert (
        proof["canonical_nav_metadata"]["values"]["asset"]
        == "maps/mp/mp_donetsk.d3dbsp"
    )

    header = source / "src/DW_GulagNavPackage.h"
    assert digest(header) == proof["header_sha256"]
    units = [
        row
        for row in report["cpp"]
        if row["source"].replace("\\", "/").endswith("src/DW_BotStyleZone.cpp")
    ]
    assert len(units) == 1
    unit = units[0]
    assert digest(source / "src/DW_BotStyleZone.cpp") == unit["source_sha256"]
    assert digest(unit["object"]) == unit["object_sha256"]
    dependencies = [
        row
        for row in unit["dependencies"]
        if Path(row["path"]).resolve() == header.resolve()
    ]
    assert len(dependencies) == 1 and dependencies[0]["sha256"] == digest(header)

    folder = args.output.parent / "gulag-checks"
    folder.mkdir(exist_ok=True)
    package_output = folder / "native-package.json"
    lifecycle_output = folder / "native-lifecycle.json"
    subprocess.run(
        [
            sys.executable,
            "-B",
            str(ROOT / "tools/test-gulag-navigation-package.py"),
            "--proof",
            str(proof_path),
            "--output",
            str(package_output),
        ],
        check=True,
        cwd=ROOT,
    )
    subprocess.run(
        [
            sys.executable,
            "-B",
            str(ROOT / "tools/test-gulag-zone-lifecycle.py"),
            "--output",
            str(lifecycle_output),
        ],
        check=True,
        cwd=ROOT,
    )
    package = json.loads(package_output.read_bytes())
    lifecycle = json.loads(lifecycle_output.read_bytes())
    assert package["passed"] and package["production_ready"]
    assert lifecycle["passed"]

    native_checker = ROOT / "tools/test-native-bfx-consumer.py"
    stock_output = folder / "stock-navigation.json"
    subprocess.run(
        [
            sys.executable,
            "-B",
            str(native_checker),
            "--output",
            str(stock_output),
        ],
        check=True,
        cwd=ROOT,
    )
    native_results = []
    for index, resource in enumerate(proof["resources"]):
        audit = json.loads(Path(resource["report"]).read_bytes())
        native_output = folder / f"arena-{index}-native.json"
        subprocess.run(
            [
                sys.executable,
                "-B",
                str(native_checker),
                "--resource",
                resource["path"],
                "--geometry",
                audit["input"],
                "--report",
                resource["report"],
                "--stock-baseline",
                str(stock_output),
                "--output",
                str(native_output),
            ],
            check=True,
            cwd=ROOT,
        )
        native = json.loads(native_output.read_bytes())
        assert native["passed"] and native["collision_geometry_certified"]
        native_results.append(
            dict(path=str(native_output), sha256=digest(native_output))
        )

    result = dict(
        passed=True,
        executable_sha256=report["sha256"],
        build_report_sha256=digest(report_path),
        compiled_loader_source_sha256=unit["source_sha256"],
        compiled_loader_object_sha256=unit["object_sha256"],
        compiled_package_header_sha256=digest(header),
        package_proof_sha256=digest(proof_path),
        native_package_check=dict(
            path=str(package_output), sha256=digest(package_output)
        ),
        native_lifecycle_check=dict(
            path=str(lifecycle_output), sha256=digest(lifecycle_output)
        ),
        native_bfx_stock_check=dict(
            path=str(stock_output), sha256=digest(stock_output)
        ),
        native_bfx_arena_checks=native_results,
        arena_resources=6,
        stock_navigation_preserved=True,
        delivery="Hash-bound embedded native package staged only when mp_donetsk loads",
        game_execution=False,
        limitation="Offline compiled source, loader and collision checks; live bot movement remains a separate test.",
    )
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print("PASS compiled six-arena package and native resource lifecycle", flush=True)


if __name__ == "__main__":
    main()
