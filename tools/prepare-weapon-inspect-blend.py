"""Prepare the narrow Replay viewmodel inspection blend owner, after approval.

--inspect-only checks original bytes/layouts without assembling or writing.
Normal preparation preserves the entire native nine-argument fallback owner.
"""

from workstation_preparation_context import cached_input_json, shared_original_pe, source_context

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

import capstone
import pefile

ROOT = Path(__file__).resolve().parents[1]
IMAGE = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
IMAGE_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
LATER_IMAGE = Path(r"D:\Games\iw8\1.64.5.13113888\Call of Duty Modern Warfare (1.64.5.13113888)\.proxy\dumped_exes\ModernWarfare_164_20260702_004354.exe")
LATER_SHA = "39ee20fb02a430eee8659aa4f091078c92a5d4c7496931767082c369bd710065"
SOURCE = "src/DW_WeaponInspectBlend.cpp"
OWNERS = ((0x1745700, "DW_WeaponInspectBlend_StartWeaponAnim", "WIB_OriginalStartWeaponAnim",
           "uint64_t(int32_t, const void *, int32_t, int32_t, uint32_t, int32_t, uint32_t, float, uint8_t)",
           1637, "12f4eb02a37cf7eff431ebc824a8fdc6ce75e1d6341833161f22bb90c8a8bb0a"),)
GLOBALS = {
    "WIB_ClientGlobals": (0xF26F940, "uint8_t *", "[2]"),
    "WIB_ViewmodelAnimBlending": (0x250F4C5, "uint8_t", ""),
}
# Later -> Replay WeaponAnimNumber. Reload18/19 were reordered; a later
# reload enum22 shifts the following enums. These are not player weapon states
# and not raw WeaponAnimPackage slot indices. Both native mapping bodies were
# inspected, including the corresponding constant/conditional XAnim nodes.
DESTINATIONS = (
    (0, 0, 100), (1, 1, 100), (2, 2, 100), (3, 3, 100),
    (16, 16, 200), (17, 17, 200), (18, 19, 200), (19, 18, 200), (20, 20, 200),
    (13, 13, 200), (29, 28, 100), (10, 10, 100), (11, 11, 100), (12, 12, 100),
    (23, 22, 200), (25, 24, 200), (26, 25, 200), (28, 27, 200),
    (62, 61, 200), (71, 70, 200), (72, 71, 100),
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def helper(snapshot):
    path = snapshot / "tools/prepare-weapon-inspect-input.py"
    spec = importlib.util.spec_from_file_location("inspect_blend_native_helper", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inspect(snapshot):
    snapshot = Path(snapshot).resolve(strict=True)
    catalog = cached_input_json(snapshot / 'generated/function-catalog.json')
    assert catalog["image_sha256"] == IMAGE_SHA and file_sha(IMAGE) == IMAGE_SHA
    pe = shared_original_pe(str(IMAGE), fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]])
    functions = {row["rva"]: row for row in catalog["functions"]}
    data = {row["rva"]: row for row in catalog["symbols"]
            if row.get("kind") == "data-address" and not row.get("quarantined")}
    native_helper = helper(snapshot)
    native, imports = {}, {}
    for rva, symbol, fallback, signature, size, digest in OWNERS:
        assert not functions[rva].get("quarantined")
        records = native_helper.unwind_family(pe, rva)
        body = b"".join(pe.get_data(r["begin"], r["end"] - r["begin"]) for r in records)
        assert len(body) == size and sha(body) == digest
        native[symbol] = dict(rva=rva, identity=functions[rva]["id"], bytes=size,
                              sha256=digest, unwind=records)
    for name, (rva, _, _) in GLOBALS.items():
        imports[name] = data[rva]["id"]
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(pe.get_data(0x1745700, 1637), 0x1745700))
    assert any(op.type == capstone.x86.X86_OP_MEM and op.mem.disp == 0xF26F940
               for instruction in instructions for op in instruction.operands)
    assert any(instruction.mnemonic == "lea" and instruction.op_str == "r13, [r14 + 8]"
               for instruction in instructions)
    assert any(instruction.mnemonic == "call" and instruction.operands[0].type == capstone.x86.X86_OP_IMM
               and instruction.operands[0].imm == 0x1748A10 for instruction in instructions)
    init_body = pe.get_data(0x173BBB0, 1068)
    caller_body = pe.get_data(0x1754A20, 4465)
    assert sha(init_body) == "893008916d1b509b7143e95d79f28a09fa4d06bd101d98cf8a50c955721c254f"
    assert sha(caller_body) == "73cc6a98ea9ca78cd9d51357b228d418f9c22b12da488bffb6e4c8de3fc758bd"
    init_instructions = list(decoder.disasm(init_body, 0x173BBB0))
    assert any(instruction.mnemonic == "mov" and len(instruction.operands) == 2
               and instruction.operands[0].type == capstone.x86.X86_OP_MEM
               and instruction.operands[0].mem.base == capstone.x86.X86_REG_R8
               and instruction.operands[0].mem.disp == 24
               and instruction.operands[1].type == capstone.x86.X86_OP_IMM
               and instruction.operands[1].imm & 0xffffffff == 0xffffffff
               for instruction in init_instructions)
    caller_instructions = list(decoder.disasm(caller_body[:600], 0x1754A20))
    assert any(instruction.mnemonic == "btr" and instruction.op_str == "eax, 7"
               for instruction in caller_instructions)
    assert any(instruction.mnemonic == "mov" and len(instruction.operands) == 2
               and instruction.operands[0].type == capstone.x86.X86_OP_MEM
               and instruction.operands[1].type == capstone.x86.X86_OP_IMM
               and instruction.operands[1].imm == 236 for instruction in caller_instructions)
    original_table = pe.get_data(0x251B270, 159 * 24)
    assert sha(original_table) == "9157cb7c74e7dbae138fc93a7ab48f7d3ad64e1e1e581ac86168ef302829680d"
    original_states = [struct.unpack_from("<IIffQ", original_table, i * 24) for i in range(159)]
    assert all(70 not in row[:2] for row in original_states)
    original_indices = [struct.unpack("<IIff", pe.get_data(0x251C160 + i * 16, 16)) for i in range(20)]
    assert all(380 not in row[:2] for row in original_indices)
    # Fast-ADS overrides do not intercept a transition from scripted70.
    assert 70 not in struct.unpack("<14I", pe.get_data(0x251C3E8, 56))
    # Pin the native later policy, not a source-engine constant or guessed enum.
    assert file_sha(LATER_IMAGE) == LATER_SHA
    later = shared_original_pe(str(LATER_IMAGE), fast_load=True)
    later_table = later.get_data(0x70B77C0, 193 * 24)
    assert sha(later_table) == "89381c33fcba9966d366e1bbfffc8ac3d57a8ab971a3b44078e0fe908bd007a2"
    pairs = [struct.unpack_from("<IIffQ", later_table, i * 24) for i in range(193)]
    wanted = {(old, new): (out_ms / 1000, in_ms / 1000) for old, new, out_ms, in_ms in
              [(0, 86, 100, 100), (1, 86, 100, 100)] +
              [(86, later_enum, ms, ms) for later_enum, replay_enum, ms in DESTINATIONS]}
    found = {(old, new): (out_time, in_time) for old, new, out_time, in_time, callback in pairs
             if old == 86 or new == 86}
    assert found.keys() == wanted.keys()
    assert all(abs(found[key][i] - wanted[key][i]) < 1e-7 for key in wanted for i in (0, 1))
    proof = dict(
        schema=1, passed=True, image_sha256=IMAGE_SHA, owners=native, imports=imports,
        later_native=dict(path=str(LATER_IMAGE), sha256=LATER_SHA, blend_helper_rva=0x5313530,
                          state_table_rva=0x70B77C0, state_table_sha256=sha(later_table),
                          map_function_rva=0x335ACA0, inspect_weapon_anim=86, inspect_tree_node=471,
                          raw_inspect_time_dependency_slot=652),
        replay_native=dict(blend_helper_rva=0x1748A10, state_table_rva=0x251B270,
                           state_table_sha256=sha(original_table), scripted_weapon_anim=70,
                           scripted_tree_node=380, client_globals_rva=0xF26F940, predicted_ps_offset=8,
                           blending_control_rva=0x250F4C5, map_function_rva=0x1175F20),
        destination_translation=[dict(later=l, replay=r, milliseconds=ms) for l, r, ms in DESTINATIONS],
        entry_milliseconds=100, entry_from_replay=[0, 1],
        first_entry=dict(init_rva=0x173BBB0, init_bytes=1068, init_sha256=sha(init_body),
                         caller_rva=0x1754A20, caller_bytes=4465, caller_sha256=sha(caller_body),
                         cached_animation_offset=24, reset_value=-1, toggle_bit=7,
                         masked_previous_animation=-129, default_previous_index=236,
                         initialized_idle_node=236, initialized_idle_weight=1.0,
                         milliseconds=100, exact_sentinel_and_node_required=True),
        ownership="exact retained type16 inspection clip via DW_WeaponInspect_HasClip, even after playing flag clears",
        original_rates_weights_time_notifies_preserved=True,
        explicit_forced_transitions_preserved=True, native_blending_control_preserved=True,
        unrelated_scripted_animations_preserved=True, cpp_compiled=False, game_runs_performed=False,
    )
    return pe, catalog, functions, proof


def prepare(snapshot):
    snapshot = Path(snapshot).resolve(strict=True)
    assert snapshot.is_relative_to(ROOT / "data")
    assert not any((snapshot.parent / name).exists() for name in
                   ("client-readiness.json", "readiness.json", "local-readiness.json", "source-receipt.json"))
    assert not list(snapshot.parent.glob("builds/*/build-report.json"))
    relatives = [SOURCE, "src/DW_WeaponInspectBlend.h", "src/DW_WeaponInspectBlendBindings.h",
                 "src/DW_WeaponInspectBlend_Native.cpp"]
    for relative in [*relatives, "source-units.json", "source-workstation/units.json"]:
        path = snapshot / relative
        assert not path.exists() or path.stat().st_nlink == 1
    pe, catalog, functions, proof = inspect(snapshot)
    sys.path.insert(0, str(snapshot / "tools"))
    from replay_owned_clone import assemble
    from workstation_sources import SourceWorkspace
    from coff import read

    output = snapshot / "generated/weapon-inspect-blend"
    output.mkdir(parents=True, exist_ok=False)
    workspace = SourceWorkspace(snapshot, output / "cache")
    workspace._catalog = catalog
    workspace._state = lambda: {"sources": {}}
    clone_sources, clones = [], []
    for rva, symbol, fallback, signature, size, digest in OWNERS:
        source, clone = assemble(workspace, pe, catalog, functions[rva], fallback, output,
                                 Path(r"C:\Program Files\LLVM\bin"), read,
                                 gs_unwind=proof["owners"][symbol]["unwind"])
        assert clone["bytes"] == size
        clone_sources.append(source)
        clones.append(clone)
        for fixup in clone["external_fixups"]:
            proof["imports"][fixup["stable_id"]] = fixup["stable_id"]
    for name in ("DW_WeaponInspectBlend.cpp", "DW_WeaponInspectBlend.h"):
        (snapshot / "src" / name).write_bytes((ROOT / "integration/replay" / name).read_bytes())
    declarations = ["#pragma once", '#include "DW_WeaponInspectBlend.h"', 'extern "C" {',
        "uint64_t WIB_OriginalStartWeaponAnim(int32_t, const void *, int32_t, int32_t, uint32_t, int32_t, uint32_t, float, uint8_t);"]
    for name, (rva, ctype, suffix) in GLOBALS.items():
        declarations.append(f"extern {ctype} {name}{suffix};")
    (snapshot / "src/DW_WeaponInspectBlendBindings.h").write_text("\n".join(declarations) + "\n}\n")
    (snapshot / "src/DW_WeaponInspectBlend_Native.cpp").write_text("\n".join(clone_sources))
    association_path = snapshot / "source-units.json"
    units_path = snapshot / "source-workstation/units.json"
    associations = json.loads(association_path.read_bytes())
    units = json.loads(units_path.read_bytes())
    digest = sha((snapshot / SOURCE).read_bytes())
    for rva, symbol, fallback, signature, size, body_digest in OWNERS:
        identity = functions[rva]["id"]
        assert not any(row["function_id"] == identity for row in associations["units"]), "Different root owner"
        assert not any(row["function_id"] == identity for row in units["units"]), "Different revision owner"
        associations["units"].append(dict(source=SOURCE, symbol=symbol, function_id=identity))
        units["units"].append(dict(function_id=identity, kind="cpp", source=SOURCE,
                                  symbol=symbol, sha256=digest, revision=digest, language="cpp"))
    for symbol, identity in proof["imports"].items():
        wanted = dict(symbol=symbol, symbol_id=identity)
        prior = [row for row in associations.get("imports", []) if row["symbol"] == symbol]
        assert not prior or prior == [wanted]
        if not prior:
            associations.setdefault("imports", []).append(wanted)
    association_path.write_text(json.dumps(associations, indent=2) + "\n")
    units_path.write_text(json.dumps(units, indent=2) + "\n")
    proof.update(source=SOURCE, source_sha256=digest, clones=clones, original_bodies_assembled=True,
                 generator_sha256=file_sha(Path(__file__)),
                 helper_tool_sha256=file_sha(snapshot / "tools/prepare-weapon-inspect-input.py"),
                 clone_tool_sha256=file_sha(snapshot / "tools/replay_owned_clone.py"))
    proof["dependencies"] = {relative: file_sha(snapshot / relative) for relative in
                             [*relatives, "src/DW_WeaponInspect.h", "src/DW_WeaponInspect.cpp"]}
    (snapshot / "generated/weapon-inspect-blend-integration.json").write_text(json.dumps(proof, indent=2) + "\n")
    return proof


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--inspect-only", action="store_true")
    args = parser.parse_args()
    print(json.dumps(inspect(args.snapshot)[3] if args.inspect_only else prepare(args.snapshot), indent=2))
