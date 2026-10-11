"""Compile and run isolated BR predicates with retained original native packets."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    folder = ROOT / "data/remaining-br-cp-20261011"
    rows = json.loads((folder / "native-cases.json").read_bytes())
    fixtures = {row["fixture_label"]: row for row in rows}
    calls = []
    for label, expected in (("br_victim_downed", True), ("br_attacker_downed", False), ("br_equipment_downed", False)):
        values = ",".join(str(value) + "ULL" for value in fixtures[label]["values"])
        calls.append(f'assert(killMatches(50017, ReplayKillEvent{{{{{values}}}}}) == {str(expected).lower()});')
    source = '#include "replay_br_cp_mission_earning.h"\n#include <cassert>\nusing namespace replay_br_cp_mission_earning;\nint main(){\n'
    source += "\n".join(calls)
    source += """
    for (auto id : Top15Stages) {
        for (uint64_t rank = 1; rank <= 15; ++rank)
            assert(placementMatches(id, {{24, rank, 0}}));
        for (auto rank : {uint64_t{0}, uint64_t{16}, UINT64_MAX})
            assert(!placementMatches(id, {{24, rank, 0}}));
        assert(!placementMatches(id, {{6, 15, 0}}));
        assert(!placementMatches(id, {{39, 15, 0}}));
        assert(!placementMatches(id, {{UINT64_MAX, 15, 0}}));
    }
    assert(!placementMatches(50017, {{24, 15, 0}}));
    assert(!placementMatches(10062, {{24, 15, 0}}));
    ReplayKillEvent wrongMode{{0, UINT64_C(8796093022208), UINT64_C(6)<<32, 0, 0, UINT64_C(1)<<16, 0}};
    assert(!killMatches(50017, wrongMode));
    wrongMode.parameters[2] = UINT64_C(24)<<32;
    assert(!killMatches(50013, wrongMode));
    assert(!killMatches(50020, wrongMode));
    assert(!killMatches(10058, wrongMode));
}
"""
    cpp = folder / "predicate-test.cpp"
    cpp.write_text(source)
    compiler = Path(r"C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat")
    command = f'call "{compiler}" >nul && cl /nologo /std:c++17 /EHsc /W4 /WX /I"{ROOT / "src"}" "{cpp}" /Fo"{folder / "predicate-test.obj"}" /Fe"{folder / "predicate-test.exe"}" && "{folder / "predicate-test.exe"}"'
    runner = folder / "run-predicate-test.cmd"
    runner.write_text("@echo off\n" + command + "\n")
    run = subprocess.run(["cmd", "/d", "/c", str(runner)], cwd=ROOT, text=True, capture_output=True)
    (folder / "predicate-test.log").write_text(run.stdout + run.stderr)
    assert run.returncode == 0, run.stdout + run.stderr
    result = dict(passed=True, tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  header_sha256=hashlib.sha256((ROOT / "src/replay_br_cp_mission_earning.h").read_bytes()).hexdigest(),
                  native_cases=len(rows), placement_boundary_checks=11 * 21,
                  scope="Isolated MSVC helper assertions, no server build, game launch or interaction")
    (ROOT / "validation/20261011-replay-br-cp-predicates.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
