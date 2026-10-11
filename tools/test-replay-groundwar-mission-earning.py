"""Compile Ground War predicates against original native packets."""

import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "data/remaining-mp-missions-20261011"
proof_path = ROOT / "validation/20261011-ground-war-mission-contracts.json"
proof = json.loads(proof_path.read_bytes())
assert proof["original_contract_verified"] and proof["case_count"] == 12
checks = []


def check(expression):
    checks.append(f"    if (!({expression})) return {len(checks)+1};")


for row in proof["cases"]:
    values = row["values"]
    mode = (
        int(row["input"].split(",")[0])
        if row["name"] == "capture"
        else int(row["input"].split(",")[5])
    )
    if row["name"] == "capture":
        event = (
            "ReplayObjectiveEvent{{" + ",".join(f"UINT64_C({v})" for v in values) + "}}"
        )
        for stage in (1515, 1572, 1591):
            check(f"captureProgress({stage},{event})=={int(mode==32)}")
        check(f"captureProgress(1512,{event})==0")
    else:
        event = "ReplayKillEvent{{" + ",".join(f"UINT64_C({v})" for v in values) + "}}"
        weapon = row["input"].split(",")[1]
        target = int(row["input"].split(",")[8])
        check(
            f'killProgress(10048,{event})=={int(mode==32 and weapon=="iw8_pi_decho_mp" and target==1)}'
        )
        check(f"killProgress(10047,{event})==0")
# All native mode values reject the three capture criteria except verified arm32.
for mode in range(44):
    for stage in (1515, 1572, 1591):
        check(
            f"captureProgress({stage},ReplayObjectiveEvent{{{{{mode},0}}}})=={int(mode==32)}"
        )
source = WORK / "groundwar-helper-test.cpp"
source.write_text(
    '#include "replay_groundwar_mission_earning.h"\nusing namespace replay_groundwar_mission_earning;\nint main()\n{\n'
    + "\n".join(checks)
    + "\n    return 0;\n}\n"
)
vswhere = Path(r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe")
installation = subprocess.check_output(
    [str(vswhere), "-latest", "-property", "installationPath"], text=True
).strip()
vcvars = Path(installation) / "VC/Auxiliary/Build/vcvars64.bat"
batch = WORK / "compile-groundwar-helper.cmd"
batch.write_text(
    f'@call "{vcvars}" >nul\n@if errorlevel 1 exit /b 1\n'
    + f'@cl /nologo /std:c++20 /EHsc /W4 /WX /I"{ROOT/"src"}" "{source}" /Fo"{WORK/"groundwar-helper-test.obj"}" /Fe"{WORK/"groundwar-helper-test.exe"}"\n'
)
result = subprocess.run(
    ["cmd", "/d", "/c", str(batch)], cwd=WORK, capture_output=True, text=True
)
(WORK / "groundwar-helper-compile.log").write_text(result.stdout + result.stderr)
assert result.returncode == 0, result.stdout + result.stderr
subprocess.run([str(WORK / "groundwar-helper-test.exe")], cwd=WORK, check=True)
receipt = {
    "passed": True,
    "stage_ids": [1515, 1572, 1591, 10048],
    "original_parser_cases": 12,
    "checks": len(checks),
    "header_sha256": hashlib.sha256(
        (ROOT / "src/replay_groundwar_mission_earning.h").read_bytes()
    ).hexdigest(),
    "parser_proof_sha256": hashlib.sha256(proof_path.read_bytes()).hexdigest(),
    "scope": "Isolated C++20 MSVC/W4/WX helper; no combined backend build, deployment or game interaction.",
}
(ROOT / "validation/20261011-ground-war-mission-helper.json").write_text(
    json.dumps(receipt, indent=2) + "\n"
)
print(json.dumps(receipt))
