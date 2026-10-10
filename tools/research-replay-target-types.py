"""Corroborate Replay's complete target mask against native ScriptFile bytes.

The recovered assembly selects semantics and candidate blocks. The unmodified
payload proves each GetByte/GetUnsignedShort operand followed by bit_or. This
does not prove a gameplay upload or an application's reward callback.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "data/remaining-contracts-20261009/native-challenge-scripts"


def digest(value):
    return hashlib.sha256(value).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parser-proof", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.parser_proof = args.parser_proof.resolve()
    args.output = args.output.resolve()
    assert args.parser_proof.resolve().is_relative_to(ROOT)
    assert args.output.resolve().is_relative_to(ROOT)
    parsed = json.loads(args.parser_proof.read_bytes())
    assert parsed["target_image_sha256"] == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
    payload_path = SCRIPT / "scripts/cp_mp/challenges.gscbin"
    assembly_path = SCRIPT / "disassembled/iw8/challenge-normalized.gscasm"
    payload, assembly = payload_path.read_bytes(), assembly_path.read_bytes()
    assert digest(payload) == "074bcfaf5cd6fe39c6fde4f02321b7db9ab90197f1eab7d43afbc47a938694f7"
    assert digest(assembly) == "eb56bccf022463022125d7374a15548a47fda3efb3628edc67dafa5ef8c51576"
    bytecode = payload[16 + struct.unpack_from("<I", payload, 4)[0]:]
    assert digest(bytecode) == "cc6d1a3a47ed7c10ce372fabf1ca59a6426b2d8d49ae8efc2e3e1d2b15a0ba54"
    source = assembly.decode()
    enemy = source.split("sub:findenemytype\n", 1)[1].split("end:findenemytype", 1)[0]
    agent = source.split("sub:return_enemy_type_mask\n", 1)[1].split("end:return_enemy_type_mask", 1)[0]
    assert "OP_CallBuiltin1 isplayer" in enemy
    for field in ("streakinfo", "vehiclename", "equipmentref"):
        assert "OP_EvalFieldVariable " + field in enemy
    assert "OP_ScriptLocalFunctionCall return_enemy_type_mask" in enemy
    assert "OP_EvalFieldVariable aitype" in agent
    labels = [int(value, 16) for value in re.findall(r"\tloc_([0-9A-F]+)\n", enemy)]
    start, end = min(labels), max(labels)
    assert (start, end) == (0x13CA, 0x1533)
    names = {
        "Player": 1, "Killstreak": 2, "AirborneStreak": 4,
        "Ground": 8, "SupportStreak": 16, "Vehicle": 32, "Equipment": 64,
    }
    records = []
    for name, value in names.items():
        pattern = bytes((0x16, value, 0x0F))
        # Player's unchanged instruction window precedes the first branch label.
        offsets = ([5062] if name == "Player" else
                   [i for i in range(start, end) if bytecode[i:i + 3] == pattern])
        assert len(offsets) == (2 if name == "Ground" else 1), (name, offsets)
        assert all(bytecode[i:i + 3] == pattern for i in offsets)
        records.append(dict(name=name, bit=value, original_offsets=offsets,
                            original_bytes_hex=pattern.hex()))
    branches = {
        "AgentSoldier": ("soldier", "loc_1553", 512),
        "AgentJuggernaut": ("juggernaut", "loc_155F", 128),
        "AgentSuicideBomber": ("suicidebomber", "loc_156A", 1024),
        "AgentShield": ("riotshield", "loc_1576", 256),
    }
    for name, (kind, label, value) in branches.items():
        assert f'case "{kind}" {label}' in agent
        branch = agent.split("\t" + label + "\n", 1)[1]
        opcode = "GetByte" if value < 256 else "GetUnsignedShort"
        assert re.match(r"\s*OP_EvalLocalVariableCached1\s+OP_" + opcode +
                        " " + str(value) + r"\s+OP_bit_or", branch)
        offset = int(label[4:], 16) + 1
        pattern = (bytes((0x16, value, 0x0F)) if value < 256 else
                   b"\x66" + struct.pack("<H", value) + b"\x0f")
        assert bytecode[offset:offset + len(pattern)] == pattern
        names[name] = value
        records.append(dict(name=name, bit=value, original_offsets=[offset],
                            original_bytes_hex=pattern.hex()))
    assert len(names) == 11 and set(names.values()) == {1 << bit for bit in range(11)}
    cases = {row["fixture_label"]: row for row in parsed["cases"] if "fixture_label" in row}
    for label, name in (("equipment_target", "Equipment"), ("vehicle_target", "Vehicle"),
                        ("killstreak_target", "Killstreak")):
        assert cases[label]["accepted"] and cases[label]["parameter_count"] == 7
        assert cases[label]["values"][5] >> 16 & 0xFFFF == names[name]
    header = ROOT / "src/replay_kill_target.h"
    lines = ["#pragma once", "#include <cstdint>", "",
             "// Generated from Replay's native findenemytype/return_enemy_type_mask.",
             "// Flags can overlap; unrecognized bits in the packet remain intact.",
             "enum class ReplayKillTarget : uint16_t", "{"]
    lines += [f"    {name} = {value}," for name, value in names.items()]
    lines += ["};", ""]
    header.write_text("\n".join(lines), encoding="utf-8")
    result = dict(passed=True, target_image_sha256=parsed["target_image_sha256"],
                  tool_sha256=digest(Path(__file__).read_bytes()),
                  parser_proof_path=args.parser_proof.relative_to(ROOT).as_posix(),
                  parser_proof_sha256=digest(args.parser_proof.read_bytes()),
                  sources=[dict(path=p.relative_to(ROOT).as_posix(), sha256=digest(p.read_bytes()))
                           for p in (payload_path, assembly_path)],
                  bytecode_sha256=digest(bytecode), flags=records,
                  generated=header.relative_to(ROOT).as_posix(), generated_sha256=digest(header.read_bytes()),
                  native_game_execution_verified=False,
                  scope="Original ScriptFile constant operands and original native parser output; overlapping masks retained")
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print("Verified and generated all 11 native target flags")


if __name__ == "__main__":
    main()
