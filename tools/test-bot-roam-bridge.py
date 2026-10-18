"""Compile actual BR script bridge ownership and one-use vector handoff.
No game launch. Native VM/profile/resource boundaries are modeled.
"""

import argparse, hashlib, json, shutil, subprocess, tempfile
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
    if a.build and a.current_source:
        p.error("--build requires frozen sources")
    source = ROOT / "integration/replay" if a.current_source else a.snapshot / "src"
    tools = ROOT / "tools" if a.current_source else a.snapshot / "tools"
    if a.build:
        report = json.loads((a.build / "build-report.json").read_bytes())
        assert Path(report["source_root"]).resolve() == a.snapshot.resolve()
        assert sha(report["executable"]) == report["sha256"]
        row = next(x for x in report["cpp"] if Path(x["source"]).name == "DW_BotStyleWeapon.cpp")
        assert row["source_sha256"] == sha(source / "DW_BotStyleWeapon.cpp") and row[
            "object_sha256"
        ] == sha(row["object"])
        assert report["unresolved_symbols"] == 0
        for dependency in row["dependencies"]:
            assert sha(dependency["path"]) == dependency["sha256"]
    with tempfile.TemporaryDirectory(prefix="br-roam-bridge-", dir=ROOT / "data") as tmp:
        tmp = Path(tmp)
        for folder in [a.snapshot / "src"] + (
            [ROOT / "integration/host-scale", ROOT / "integration/replay"]
            if a.current_source
            else []
        ):
            for file in folder.glob("*.h"):
                shutil.copy2(file, tmp / file.name)
        shutil.copy2(source / "DW_BotStyleWeapon.cpp", tmp / "DW_BotStyleWeapon.cpp")
        cmd = [
            "C:/Program Files/LLVM/bin/clang++.exe",
            "-std=c++20",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I" + str(tmp),
            str(tmp / "DW_BotStyleWeapon.cpp"),
            str(tools / "bot_roam_bridge_harness.cpp"),
            "-o",
            str(tmp / "bridge.exe"),
        ]
        compiled = subprocess.run(cmd, capture_output=True, text=True)
        assert not compiled.returncode, compiled.stdout + compiled.stderr
        result = subprocess.run([str(tmp / "bridge.exe")], capture_output=True, text=True)
        assert not result.returncode, result.stdout + result.stderr
        assert "PASS BR roam bridge:" in result.stdout
        sources = [
            source / "DW_BotStyleWeapon.cpp",
            tools / "bot_roam_bridge_harness.cpp",
            tools / "bot_style_weapon_harness.cpp",
        ]
        proof = {
            "passed": True,
            "mode": "current-source" if a.current_source else "frozen-source",
            "sources": {str(x): sha(x) for x in sources},
            "headers": {x.name: sha(x) for x in tmp.glob("*.h")},
            "stdout": result.stdout,
            "limitation": "Actual compiled bridge; VM/profile/planner/resource boundaries modeled. No live game claim.",
        }
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(proof, indent=2))
    print(result.stdout, end="")


if __name__ == "__main__":
    main()
