"""Verify original Replay end-match outcomes, packet widths and mission predicates."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    folder = ROOT / "data/remaining-match-completion-20261011"
    folder.mkdir(exist_ok=True)
    previous = ROOT / "data/remaining-match-outcomes-20261010"
    recovery_path = previous / "producer-recovery.json"
    recovery = json.loads(recovery_path.read_bytes())
    zone = next(zone for zone in recovery if zone["zone"] == "common_base_mp")
    for source in (zone["source"], *zone["source"]["patches"]):
        assert digest(Path(source["path"])) == source["sha256"]
    selected = [next(row for row in zone["matching_scripts"] if row["asset_index"] == index) for index in (10793, 10702)]
    evidence = []
    for row in selected:
        payload, source = ROOT / row["retained_payload"], ROOT / row["decompiled_path"]
        assert digest(payload) == row["payload_sha256"]
        assert digest(source) == row["decompiled_sha256"]
        evidence.extend([dict(path=str(path.relative_to(ROOT)), sha256=digest(path)) for path in (source, payload)])
    text = (ROOT / selected[0]["decompiled_path"]).read_text()
    producer = text.split("stopkeyearning( var_0 )\n", 1)[1].split("_visionsetnakedforplayer", 1)[0]
    assert 'if ( var_0 == "tie" )\n                var_3 = 3;' in producer
    assert 'self.pers["team"] == var_0 )\n                var_3 = 1;' in producer
    assert 'self.pers["team"] != var_0 )\n                var_3 = 2;' in producer
    assert 'self.reportchallengeuserevent_done' in producer and 'level.playerxpenabled' in producer
    assert 'min( level.placement["all"].size, 3 )' in producer
    assert 'self reportchallengeuserevent( "end_match", var_1, var_3, var_6, var_7, var_8, var_9 )' in producer
    caller = (ROOT / selected[1]["decompiled_path"]).read_text()
    assert 'stopkeyearning( var_0 )' in caller and 'stopkeyearning();' in caller
    sys.path.insert(0, r"E:\replay-compiler\tools")
    from workstation_asset_codecs import normalize_replay_scriptfile_for_gsc_tool, _convert_gsc_local_reference_scale, inspect_gscbin, _script_instructions
    config = json.loads(Path(r"E:\replay-compiler\replay-project.local.json").read_bytes())
    tool = Path(r"E:\replay-compiler") / config["tools"]["gsc"]["path"]
    assert digest(tool) == config["tools"]["gsc"]["sha256"]
    original = (ROOT / selected[0]["retained_payload"]).read_bytes()
    normalized = normalize_replay_scriptfile_for_gsc_tool(original)
    assert _convert_gsc_local_reference_scale(normalized, to_replay=True) == original
    code = inspect_gscbin(original).bytecode
    assert list(_script_instructions(code)) == list(_script_instructions(inspect_gscbin(normalized).bytecode))
    binary = folder / "producer.gscbin"
    binary.write_bytes(normalized)
    run = subprocess.run([str(tool), "-g", "iw8", "-s", "pc", "-m", "disasm", binary.name], cwd=folder, text=True, capture_output=True)
    assert run.returncode == 0, run.stdout + run.stderr
    assembly = folder / "disassembled/iw8/producer.gscasm"
    instructions = assembly.read_text().split("sub:stopkeyearning\n", 1)[1].split("end:stopkeyearning", 1)[0]
    for operand in ('OP_GetString "tie"', 'OP_GetString "team"', 'OP_GetString "end_match"',
                    'OP_EvalLevelFieldVariable teambased', 'OP_EvalLevelFieldVariable ismp',
                    'OP_CallBuiltin1 isbot', 'OP_GetByte 1', 'OP_GetByte 2', 'OP_GetByte 3'):
        assert operand in instructions
    # These constants are original bytes, not source-oracle enum numbers.
    constants = [dict(offset=pc, value=code[pc + 1], bytes=code[pc:end].hex())
                 for pc, opcode, end in _script_instructions(code)
                 if opcode == 0x16 and 0x4B0 <= pc < 0x770 and code[pc + 1] in (1, 2, 3)]
    assert {row["value"] for row in constants} == {1, 2, 3}
    parser_path = previous / "challenge-parser-verified.json"
    parser = json.loads(parser_path.read_bytes())
    assert parser["target_image_sha256"] == SHA
    packets = [row for row in parser["cases"] if row["name"] == "end_match"]
    packed = next(row for row in packets if row.get("fixture_label") == "end_match_mode_operators")
    assert packed["values"][0] & 0xFFFFFFFF == 6 and packed["values"][0] >> 32 != 0
    negative = next(row for row in packets if row["input"] == "-1,-2,-3,-4,-5")
    assert negative["values"] == [0xFFFFFFFF, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFD, 0xFFFFFFFFFFFFFFFC, 0xFFFFFFFFFFFFFFFB]
    (folder / "native-end-packets.json").write_text(json.dumps(packets, indent=2) + "\n")
    header = ROOT / "src/replay_match_completion.h"
    cpp = folder / "predicate-test.cpp"
    cpp.write_text('''#include "replay_match_completion.h"
#include <cassert>
int main() {
    for (uint64_t mode : {uint64_t{6},uint64_t{7},uint64_t{25},uint64_t{26}})
for (uint64_t result : {uint64_t{0},uint64_t{1},uint64_t{2},uint64_t{3},uint64_t{4},UINT64_C(4294967297),UINT64_MAX}) {
        ReplayMatchCompletion e{{(UINT64_C(0x4e210c58)<<32)|mode,result,0,0,0}};
        bool complete=result>=1 && result<=3, win=result==1;
        assert(e.matches(1500)==complete); assert(e.matches(1511)==complete);
        for (auto id : {1504u,1568u,1579u}) assert(e.matches(id)==win);
        assert(e.matches(1574)==(win && mode==7));
        assert(e.matches(1578)==(win && mode==25));
        assert(e.matches(1587)==(complete && mode==25));
        assert(e.matches(1593)==(win && mode==26));
        assert(!e.matches(50018));
    }
}
''')
    setup = Path(r"C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat")
    runner = folder / "predicate-test.cmd"
    runner.write_text(f'@echo off\ncall "{setup}" >nul && cl /nologo /std:c++17 /EHsc /W4 /WX /I"{ROOT / "src"}" "{cpp}" /Fo"{folder / "predicate-test.obj"}" /Fe"{folder / "predicate-test.exe"}" && "{folder / "predicate-test.exe"}"\n')
    test = subprocess.run(["cmd", "/d", "/c", str(runner)], cwd=ROOT, text=True, capture_output=True)
    (folder / "predicate-test.log").write_text(test.stdout + test.stderr)
    assert test.returncode == 0, test.stdout + test.stderr
    for name in ("predicate-test.obj", "predicate-test.exe"):
        (folder / name).unlink()
    evidence.extend([dict(path=str(path.relative_to(ROOT)), sha256=digest(path)) for path in (recovery_path, parser_path, assembly, header)])
    result = dict(passed=True, target_image_sha256=SHA, tool_sha256=digest(Path(__file__)), evidence=evidence,
                  original_outcome_constants=constants, outcomes={"0":"unclassified, undefined result, unqualified FFA or postgame join", "1":"team win or qualified FFA top three", "2":"team loss or qualified FFA outside top three", "3":"team tie"},
                  stages=[1500,1504,1511,1568,1574,1578,1579,1587,1593], native_packets=packets,
                  native_widths={"Param0":"low32 game type; upper32 packed operator IDs", "Param1":"full64 result; no truncation", "Param2":"full64 unused producer zero", "Param3":"full64 scavenger count", "Param4":"full64 restock count"},
                  predicate_assertions=280,
                  lifecycle_requirements=["eligible public MP owner", "previous native start and exact specificgameMode", "first native end only", "completion requires result 1,2,3; result0 is never completion", "win requires exact result1", "disconnect or synthetic end without native outcome earns nothing"],
                  limits=["Packet assertions are isolated helper tests; root owns backend lifecycle integration.", "Original producer branch meanings are bytecode-corroborated; no live callback execution claim.", "RIP/parser acceptance alone does not establish completion."])
    (ROOT / "validation/20261011-match-completion-contracts.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(dict(passed=True, stages=9, predicate_assertions=280)))


if __name__ == "__main__":
    main()
