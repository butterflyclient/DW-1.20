"""Bind shipped challenge locale assignments to original operands and MapEnts.

The retained disassembly has normalized string names. Verify its pinned identity
and each unchanged value operand in the original ScriptFile before using it.
Authored origins support geographic alias research, not retail cloud criteria.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy
import struct

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "data/remaining-contracts-20261009/native-challenge-scripts"
MAP = ROOT / "data/remaining-br-entry-20261010"


def digest(contents):
    return hashlib.sha256(contents).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert args.output.resolve().is_relative_to(ROOT)
    payload = (SCRIPT / "scripts/cp_mp/challenges.gscbin").read_bytes()
    disassembly = (SCRIPT / "disassembled/iw8/challenge-normalized.gscasm").read_bytes()
    assert digest(payload) == "074bcfaf5cd6fe39c6fde4f02321b7db9ab90197f1eab7d43afbc47a938694f7"
    assert digest(disassembly) == "eb56bccf022463022125d7374a15548a47fda3efb3628edc67dafa5ef8c51576"
    source = disassembly.decode()
    initializer = source.split("sub:setupchallengelocales\n", 1)[1].split("end:setupchallengelocales", 1)[0]
    assert 'OP_GetString "location_volume"' in initializer
    assert 'OP_GetString "targetname"' in initializer
    assert "OP_EvalFieldVariable script_noteworthy" in initializer
    assert "OP_endswitch 33" in initializer
    compressed_size = struct.unpack_from("<I", payload, 4)[0]
    bytecode = payload[16 + compressed_size:]
    assignments = []
    for name, label in re.findall(r'case "([^"\n]+)" (loc_[A-F0-9]+)', initializer):
        branch = initializer.split("\t" + label + "\n", 1)[1]
        match = re.match(r"\s*OP_GetByte (\d+)\s+OP_EvalLocalVariableObjectCached 1\s+OP_EvalFieldVariableRef localeid\s+OP_SetVariableField", branch)
        assert match, (name, label)
        identity = int(match[1])
        offset = int(label[4:], 16)
        assert bytecode[offset:offset + 2] == bytes((0x16, identity))
        assignments.append(dict(name=name, id=identity, original_byte_offset=offset,
                                original_bytes_hex=bytecode[offset:offset + 2].hex()))
    assert len(assignments) == 33
    assert len({row["name"] for row in assignments}) == 33
    assert sorted(row["id"] for row in assignments) == list(range(1, 34))
    span_path = ROOT / "validation/20261010-verdansk-mapents-native-span.json"
    span = json.loads(span_path.read_bytes())
    assert span["passed"] and span["original_loader"]["entity_char_count_offset"] == 16
    entities_raw = (MAP / "donetsk-entities.bin").read_bytes()
    assert digest(entities_raw) == span["entity_text_sha256"]
    header = (MAP / "donetsk-mapents-header.bin").read_bytes()
    assert digest(header) == span["header_sha256"]
    assert struct.unpack_from("<I", header, 16)[0] == len(entities_raw)
    reader_path = ROOT / "tools/read-replay-encoded-entities.py"
    entities = runpy.run_path(str(reader_path))["parse"](entities_raw)
    assert len(entities) == 47545
    ids = {row["name"]: row["id"] for row in assignments}
    volumes = []
    for index, fields in enumerate(entities):
        values = {row["code"]: row["value"] for row in fields if row["code"]}
        if values.get(1072) != "location_volume":
            continue
        name = values.get(845)
        assert name is not None
        volumes.append(dict(index=index, script_label=name, origin=values.get(709),
                            brush_model=values.get(652), locale_id=ids.get(name), fields=fields))
    assert len(volumes) == 46
    proof = dict(passed=True, tool_sha256=digest(Path(__file__).read_bytes()),
                 original_script_payload_sha256=digest(payload),
                 original_script_disassembly_sha256=digest(disassembly),
                 native_mapents_span_receipt_sha256=digest(span_path.read_bytes()),
                 entity_text_sha256=digest(entities_raw), entity_reader_sha256=digest(reader_path.read_bytes()),
                 assignments=assignments, authored_location_volumes=volumes,
                 authored_volume_count=len(volumes), original_value_opcodes_verified=True,
                 initializer_targetname="location_volume",
                 event_fields=dict(Param0="player first mapped touching locale",
                                   Param1="contract card first mapped touching locale", Param2="operator mask"),
                 first_locale_only=True, native_game_execution_verified=False,
                 scope="Pinned normalized initializer labels with unchanged original GetByte operands; native MapEnts span and complete grammar; numeric keys and fields retained; no brush-model index substituted for a locale ID")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(proof, indent=2) + "\n")
    print(f"PASS: {len(assignments)} original locale operands; {len(volumes)} authored volumes")


if __name__ == "__main__":
    main()
