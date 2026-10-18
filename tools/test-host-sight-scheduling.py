"""Check compiled sight fairness and native/compiled perception boundaries.

--authored is a focused pre-build check against current authored C++ with the
snapshot's verified Replay bindings. Without it, --build verifies the exact
linked candidate and frozen header. No game process is opened or modified.
"""

import argparse
import ctypes
from _ctypes import FreeLibrary
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

import pefile

ROOT = Path(__file__).resolve().parents[1]
CLANG = Path(r"C:\Program Files\LLVM\bin\clang++.exe")
LINK = Path(r"C:\Program Files\LLVM\bin\lld-link.exe")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def compile_object(source, target, includes):
    command = [
        str(CLANG),
        "--target=x86_64-pc-windows-msvc",
        "-c",
        str(source),
        "-o",
        str(target),
        "-O2",
        "-std=c++20",
        "-ffreestanding",
        "-fno-stack-protector",
        "-fno-exceptions",
        "-fno-rtti",
        "-funwind-tables",
        "-ffunction-sections",
        "-fdata-sections",
        "-Wall",
        "-Wextra",
        "-Werror",
    ]
    subprocess.run(command + ["-I" + str(path) for path in includes], check=True)


def scheduler_cases(library):
    library.Reserve.argtypes = [
        ctypes.c_uint,
        ctypes.c_uint,
        ctypes.c_int,
        ctypes.c_size_t,
        ctypes.c_size_t,
    ]
    library.Reserve.restype = ctypes.c_uint
    library.Finish.argtypes = [ctypes.c_uint, ctypes.c_uint]
    library.Disable.argtypes = [ctypes.c_uint, ctypes.c_uint]

    def simulate(slots, frames, stride=1, reverse=False):
        library.Reset()
        for slot in range(200):
            library.Disable(slot, 0)
        visits = [[] for _ in range(slots)]
        totals = []
        for frame in range(frames):
            total = 0
            if frame % stride == 0:
                order = list(range(slots))
                if reverse and frame % (2 * stride):
                    order.reverse()
                for slot in order:
                    count = library.Reserve(slot, slots, frame * 16, 1, slot + 100)
                    assert count <= 4
                    library.Finish(slot, count)
                    total += count
                    if count:
                        visits[slot].append(frame)
                assert total <= 64
            totals.append(total)
        assert all(visits)
        gap = max(b - a for rows in visits for a, b in zip(rows, rows[1:]))
        assert gap <= ((slots + 15) // 16) * stride
        return dict(
            slots=slots,
            frames=frames,
            think_stride=stride,
            evaluations=sum(totals),
            old_background_evaluations=4 * slots * ((frames + stride - 1) // stride),
            max_frame_evaluations=max(totals),
            min_visits_per_slot=min(map(len, visits)),
            max_service_gap_frames=gap,
        )

    rows = [
        simulate(150, 100),
        simulate(200, 100),
        simulate(150, 220, 11),
        simulate(150, 100, reverse=True),
    ]
    checks = []
    library.Reset()
    assert library.Reserve(0, 150, 0, 1, 100) == 0
    assert library.Reserve(0, 150, 16, 1, 100) == 4
    library.Finish(0, 4)
    assert library.Reserve(0, 150, 16, 1, 100) == 0
    checks.append("duplicate caller receives no second visit in one frame")
    for slot in range(1, 150):
        count = library.Reserve(slot, 150, 16, 1, slot + 100)
        library.Finish(slot, count)
    for slot in range(150):
        library.Disable(slot, 1)
    library.Disable(149, 0)
    assert library.Reserve(149, 150, 32, 1, 249) == 4
    library.Finish(149, 4)
    checks.append("invalid pending owners removed using fresh roster eligibility")
    for now, slots, map_token, label in (
        (32, 150, 2, "map identity"),
        (0, 150, 2, "clock rollback"),
        (16, 151, 2, "slot capacity"),
    ):
        assert library.Reserve(149, slots, now, map_token, 249) == 0
        assert library.Reserve(149, slots, now + 16, map_token, 249) == 4
        library.Finish(149, 4)
        checks.append(label + " resets pending admission")
    assert library.Reserve(200, 201, 0, 2, 300) == 0
    checks.append("out-of-range slot rejected")
    library.Reset()
    for slot in range(200):
        library.Disable(slot, 0)
    for slot in range(16):
        assert library.Reserve(slot, 200, 0, 1, 100 + slot) == 0
    assert library.Reserve(199, 200, 16, 1, 299) == 0
    # All head identities remain valid, but they never request work again.
    # The tail remains within its refreshed lease when the old heads expire.
    assert library.Reserve(199, 200, 1001, 1, 299) == 4
    library.Finish(199, 4)
    checks.append("identity-valid abandoned head requests expire after 1000ms")
    for before, after in ((2147483640, -2147483640), (-1, 0)):
        library.Reset()
        assert library.Reserve(0, 200, before, 1, 100) == 0
        # Signed wrap resets; unsigned wrap has one millisecond elapsed.
        expected = 0 if after < before else 4
        assert library.Reserve(0, 200, after, 1, 100) == expected
        library.Finish(0, expected)
        if not expected:
            assert library.Reserve(0, 200, after + 16, 1, 100) == 4
            library.Finish(0, 4)
    checks.append("signed clock boundary resets and unsigned wrap retains fresh requests")
    return dict(cases=rows, checks=checks)


def authored_runner(boundary, snapshot, object_path):
    runner = object.__new__(boundary.Runner)
    runner.snapshot = snapshot
    runner.proof = json.loads(
        (snapshot / "generated/host-scale-integration.json").read_bytes()
    )
    original = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
    assert (
        hashlib.file_digest(original.open("rb"), "sha256").hexdigest()
        == runner.proof["image_sha256"]
    )
    runner.original = pefile.PE(str(original), fast_load=True)
    runner.base = runner.original.OPTIONAL_HEADER.ImageBase
    runner.native = json.loads(
        (snapshot / "generated/native-symbols.json").read_bytes()
    )
    runner.imports = {
        row["name"]: runner.base + row["original_rva"]
        for row in runner.proof["bindings"]
    }
    runner.entries = {
        row["symbol"]: runner.base + row["original_rva"]
        for row in runner.proof["replacements"]
    }
    runner.report = None
    coff = load_module("sight_check_coff", snapshot / "tools/coff.py")
    runner.objects = {"AICommon_UpdateSight": coff.read(object_path)}
    return runner


def integration_cases(runner):
    results = []
    for population in (1, 20, 64, 100):
        case = dict(count=150, population=population, mode=0, seed=150)
        original = runner.run("AICommon_UpdateSight", False, case)
        rebuilt = runner.run("AICommon_UpdateSight", True, case)
        for key in ("threat", "vision", "perfect"):
            assert original[key] == rebuilt[key], (population, key)
        results.append(dict(kind="disabled_native_equivalence", population=population))
    for population, expected in ((20, 149), (64, 8), (100, 6)):
        result = runner.run(
            "AICommon_UpdateSight", True, dict(count=150, population=population, mode=1)
        )
        assert len(result["vision"]) == expected
        results.append(
            dict(
                kind="existing_low_population_policy",
                population=population,
                evaluations=expected,
            )
        )
    for case in (
        dict(count=150, population=150, mode=1, target=50),
        dict(count=150, population=150, mode=1, humans=[1, 2]),
        dict(count=150, population=150, mode=1, humans=[49], target=50),
    ):
        result = runner.run("AICommon_UpdateSight", True, case)
        expected = sorted(
            set(
                case.get("humans", [])
                + ([case["target"] - 1] if case.get("target") else [])
            )
        )
        assert sorted(result["vision"]) == expected
        assert len(result["threat"]) == 149
        results.append(
            dict(
                kind="urgent_candidates_bypass_deferred_background",
                target=case.get("target", 0),
                humans=case.get("humans", []),
                visibility_calls=result["vision"],
                threat_updates=149,
            )
        )
    result = runner.run(
        "AICommon_UpdateSight",
        True,
        dict(count=150, population=150, mode=1, sight_owner=True, frames=2),
    )
    assert len(result["vision"]) == 4, result
    results.append(dict(kind="live_roster_owner_admitted_next_frame", evaluations=4))
    for failure in (
        "null-client",
        "disconnected",
        "not-bot",
        "entity-reuse",
        "slot-mismatch",
        "player-reuse",
        "dead",
        "frozen",
        "jail",
        "movement",
    ):
        result = runner.run(
            "AICommon_UpdateSight",
            True,
            dict(
                count=150,
                population=150,
                mode=1,
                sight_owner=True,
                frames=2,
                invalidate_sight_at=1,
                sight_failure=failure,
            ),
        )
        assert not result["vision"], failure
        results.append(
            dict(kind="actual_typed_queued_owner_invalidated", failure=failure)
        )
    result = runner.run(
        "AICommon_UpdateSight",
        True,
        dict(
            count=150,
            population=150,
            mode=1,
            sight_owner=True,
            frames=3,
            mode_by_frame=[1, 0, 1],
        ),
    )
    assert len(result["vision"]) == 149
    results.append(
        dict(kind="disabled_mode_clears_pending_admission", native_evaluations=149)
    )
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--authored", action="store_true")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.authored == bool(args.build):
        parser.error("Choose --authored pre-build mode or --build linked mode")
    snapshot = args.snapshot.resolve()
    sources = ROOT / "integration/host-scale" if args.authored else snapshot / "src"
    tools = ROOT / "tools" if args.authored else snapshot / "tools"
    header = sources / "SightDiscoverySchedule.h"
    assert header.is_file()
    scratch = ROOT / "tools/build"
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="host-sight-check-", dir=scratch
    ) as temporary:
        temporary = Path(temporary)
        bridge = temporary / "schedule.obj"
        dll = temporary / "schedule.dll"
        compile_object(
            tools / "host_sight_schedule_harness.cpp",
            bridge,
            [sources, snapshot / "src"],
        )
        subprocess.run(
            [
                str(LINK),
                "/dll",
                "/noentry",
                "/nodefaultlib",
                "/out:" + str(dll),
                str(bridge),
            ],
            check=True,
        )
        library = ctypes.CDLL(str(dll))
        try:
            scheduler = scheduler_cases(library)
        finally:
            FreeLibrary(library._handle)
        boundary = load_module("sight_host_boundary", tools / "test-host-scale.py")
        if args.authored:
            object_path = temporary / "AICommon_UpdateSight.obj"
            compile_object(
                sources / "AICommon_UpdateSight.cpp",
                object_path,
                [sources, snapshot / "src"],
            )
            runner = authored_runner(boundary, snapshot, object_path)
        else:
            runner = boundary.Runner(
                snapshot, args.build, only=["AICommon_UpdateSight"]
            )
        integration = integration_cases(runner)
    result = dict(
        passed=True,
        authored_prebuild=args.authored,
        linked_build_tested=bool(args.build),
        executable_sha256=runner.report['sha256'] if args.build else None,
        schedule_header_sha256=hashlib.sha256(header.read_bytes()).hexdigest(),
        scheduler=scheduler,
        integration=integration,
        game_runs_performed=False,
        scope="Compiled scheduling and instruction/ABI checks; evaluation counts are not native ray counts or live frame timings",
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
