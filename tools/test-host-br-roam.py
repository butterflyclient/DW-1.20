"""Compile the actual BR coordinator; preserve all existing coordinator cases.

--snapshot verifies prepared sources. --current-source explicitly overlays authored
host-scale sources for focused development; neither mode executes the game.
"""

import argparse, hashlib, json, subprocess, tempfile, shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--snapshot", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--current-source", action="store_true")
    p.add_argument("--build", type=Path)
    a = p.parse_args()
    source = ROOT / "integration/host-scale" if a.current_source else a.snapshot / "src"
    if a.build and a.current_source:
        p.error("--build requires frozen sources")
    report = json.loads((a.build / "build-report.json").read_bytes()) if a.build else None
    compiler = "C:/Program Files/LLVM/bin/clang++.exe"
    if report:
        assert Path(report["source_root"]).resolve() == a.snapshot.resolve()
        assert sha(report["executable"]) == report["sha256"]
        row = next(x for x in report["cpp"] if Path(x["source"]).name == "SV_HostBotGpuPlanner.cpp")
        assert row["source_sha256"] == sha(source / "SV_HostBotGpuPlanner.cpp") and row[
            "object_sha256"
        ] == sha(row["object"])
        compiler = row["compiler"]["path"]
    tools = ROOT / "tools" if a.current_source else a.snapshot / "tools"
    with tempfile.TemporaryDirectory(prefix="br-roam-", dir=ROOT / "data") as td:
        td = Path(td)
        exe = td / "roam.exe"
        args = [
            compiler,
            "-std=c++20",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I" + str(source),
            "-I" + str(a.snapshot / "src"),
            str(tools / "host_bot_br_roam_harness.cpp"),
            "-o",
            str(exe),
        ]
        subprocess.run(args, check=True, capture_output=True, text=True)
        run = subprocess.run([str(exe)], capture_output=True, text=True)
        assert run.returncode == 0, run.stdout + run.stderr
        assert "PASS BR roam:" in run.stdout and "PASS actual coordinator:" in run.stdout
        result = {
            "passed": True,
            "mode": "current-source" if a.current_source else "frozen-source",
            "compiler": compiler,
            "stdout": run.stdout,
            "sources": {
                str(x): sha(x)
                for x in [
                    source / "SV_HostBotGpuPlanner.cpp",
                    source / "SV_HostBotGpuPlanner.h",
                    source / "SV_HostBotGpu.h",
                    tools / "host_bot_br_roam_harness.cpp",
                    tools / "host_bot_gpu_planner_harness.cpp",
                ]
            },
            "limitation": "Actual coordinator instructions; modeled engine graph/GPU boundaries. Separate hardware/native movement tests required.",
        }
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, indent=2))
    print(run.stdout, end="")


if __name__ == "__main__":
    main()
