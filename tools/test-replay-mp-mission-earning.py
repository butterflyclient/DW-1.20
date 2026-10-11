"""Compile and exercise the MP helper using original-instruction parser packets.

Does not start the backend or interact with the game. All generated files stay
in the project's private research directory.
"""

import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "data/remaining-mp-missions-20261011"
proof = json.loads((WORK / "parser-probes.json").read_bytes())
assert proof["passed"] and proof["case_count"] == 123
assert (
    proof["target_image_sha256"]
    == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
)
rows = proof["cases"]
checks = []


def check(expression):
    checks.append(f"    if (!({expression})) return {len(checks) + 1};")


def packet(row):
    return (
        "ReplayKillEvent{{" + ",".join(f"UINT64_C({v})" for v in row["values"]) + "}}"
    )


for row in rows:
    if row["name"] == "field_end":
        values = row["values"]
        argument = (
            "std::array<uint64_t,3>{" + ",".join(f"UINT64_C({v})" for v in values) + "}"
        )
        valid = values[0] <= 0xFFFFFFFF and values[1] <= 0xFFFFFFFF
        field_ids = {
            280009,
            280010,
            280011,
            280012,
            280015,
            280017,
            280018,
            280019,
            280021,
        }
        counters = {
            10014: 280010,
            10017: 280010,
            10015: 280019,
            10016: 280019,
            10018: 280017,
            10019: 280012,
            10020: 280015,
            10023: 280011,
            10024: 280021,
        }
        expected_values = {
            1566: int(valid and values[0] in field_ids),
            10021: int(valid and values[0] == 280009),
            10022: int(valid and values[0] == 280018 and values[1] == 1),
            1502: 0,
        }
        expected_values.update(
            {
                stage: values[1] if valid and values[0] == super_id else 0
                for stage, super_id in counters.items()
            }
        )
        for stage, expected in expected_values.items():
            check(f"fieldProgress({stage}, {argument}) == UINT64_C({expected})")
    elif row["name"] == "killstreak_end":
        values = row["values"]
        argument = (
            "std::array<uint64_t,7>{" + ",".join(f"UINT64_C({v})" for v in values) + "}"
        )
        valid = (
            all(value <= 0xFFFFFFFF for value in values) and 70000 <= values[0] <= 70032
        )
        call_ins = {
            1545: 70009,
            1547: 70000,
            10009: 70000,
            1548: 70001,
            10010: 70001,
            10011: 70002,
        }
        kill_counts = {1546: 70012, 1549: 70013, 1550: 70003, 1551: 70017, 1552: 70018}
        expected_values = {1502: int(valid), 1575: values[1] if valid else 0, 1567: 0}
        expected_values.update(
            {
                stage: int(valid and values[0] == streak)
                for stage, streak in call_ins.items()
            }
        )
        expected_values.update(
            {
                stage: values[1] if valid and values[0] == streak else 0
                for stage, streak in kill_counts.items()
            }
        )
        for stage, expected in expected_values.items():
            check(f"killstreakProgress({stage}, {argument}) == UINT64_C({expected})")
    elif row["name"] == "kill":
        refs = row["input"].split(",")[6].split("|")
        laser = any(
            ref in ("laser", "laserir", "laserrange", "laserbalanced", "laserads")
            for ref in refs
        )
        suppressed = any(
            ref in ("silencer", "silencer2", "silencer3", "silencer4") for ref in refs
        )
        fast_melee = (
            "gunperk_fastmelee" in refs and row["input"].split(",")[11] == "MOD_MELEE"
        )
        for stage, expected in (
            (1516, suppressed),
            (1601, fast_melee),
            (1602, laser),
            (10005, laser),
        ):
            check(f"killProgress({stage}, {packet(row)}) == {int(expected)}")
        # Change only the victim type: attachment context never credits a
        # vehicle/killstreak destruction as a player kill.
        mutation = dict(row, values=list(row["values"]))
        mutation["values"][5] &= ~(1 << 16)
        for stage in (1516, 1601, 1602, 10005):
            check(f"killProgress({stage}, {packet(mutation)}) == 0")
        if laser:
            mutation = dict(row, values=list(row["values"]))
            mutation["values"][1] = 0
            check(f"killProgress(1602, {packet(mutation)}) == 0")
            mutation["values"][1] = 16
            mutation["values"][5] = (mutation["values"][5] & ((1 << 48) - 1)) | (
                3 << 48
            )
            check(f"killProgress(10005, {packet(mutation)}) == 0")
            check(f"killProgress(1602, {packet(mutation)}) == 1")

check("fieldProgress(10015, std::array<uint64_t,2>{280019,17}) == 0")
check("fieldProgress(10021, std::array<uint64_t,4>{280009,17,0,0}) == 0")
check("killstreakProgress(1575, std::array<uint64_t,6>{70003,17,0,0,0,1234}) == 0")
# Ignore partial sixth attachment bits, unknown packed values and the explicit
# no-attachments sentinel. Fifth-slot positives come from the native parser.
check(
    "!hasAttachment(ReplayKillEvent{{0,0,0,UINT64_C(0x6000000000000000),0,6,0}},54,58)"
)
check("!hasAttachment(ReplayKillEvent{{0,0,0,54,0,255,0}},54,58)")
check("!hasAttachment(ReplayKillEvent{{0,0,0,54,0,0,0}},54,58)")

source = WORK / "helper-test.cpp"
source.write_text(
    '#include "replay_mp_mission_earning.h"\nusing namespace replay_mp_mission_earning;\nint main()\n{\n'
    + "\n".join(checks)
    + "\n    return 0;\n}\n"
)
vswhere = Path(r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe")
installation = subprocess.check_output(
    [str(vswhere), "-latest", "-property", "installationPath"], text=True
).strip()
vcvars = Path(installation) / "VC/Auxiliary/Build/vcvars64.bat"
batch = WORK / "compile-helper.cmd"
batch.write_text(
    f'@call "{vcvars}" >nul\n@if errorlevel 1 exit /b 1\n'
    + f'@cl /nologo /std:c++20 /EHsc /W4 /WX /I"{ROOT / "src"}" "{source}" '
    + f'/Fo"{WORK / "helper-test.obj"}" /Fe"{WORK / "helper-test.exe"}"\n'
)
result = subprocess.run(
    ["cmd", "/d", "/c", str(batch)], cwd=WORK, capture_output=True, text=True
)
(WORK / "helper-compile.log").write_text(result.stdout + result.stderr)
assert result.returncode == 0, result.stdout + result.stderr
subprocess.run([str(WORK / "helper-test.exe")], cwd=WORK, check=True)
receipt = {
    "passed": True,
    "checks": len(checks),
    "stage_ids": [
        1502,
        1516,
        1545,
        1546,
        1547,
        1548,
        1549,
        1550,
        1551,
        1552,
        1566,
        1575,
        1601,
        1602,
        10005,
        10009,
        10010,
        10011,
        10014,
        10015,
        10016,
        10017,
        10018,
        10019,
        10020,
        10021,
        10022,
        10023,
        10024,
    ],
    "original_parser_cases": len(rows),
    "header_sha256": hashlib.sha256(
        (ROOT / "src/replay_mp_mission_earning.h").read_bytes()
    ).hexdigest(),
    "parser_proof_sha256": hashlib.sha256(
        (WORK / "parser-probes.json").read_bytes()
    ).hexdigest(),
    "compiler": "MSVC /std:c++20 /W4 /WX",
    "game_interactions": 0,
    "full_backend_build": False,
}
output = ROOT / "validation/20261011-replay-mp-mission-helper.json"
output.write_text(json.dumps(receipt, indent=2) + "\n")
print(json.dumps(receipt))
