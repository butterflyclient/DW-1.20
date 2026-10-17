"""Prepare the optional Replay slide-pitch correction.

--inspect-only verifies original bytes and compiler source without assembling
or compiling anything. Native clone assembly occurs only in a later authorized
canonical preparation/build. No game image or database is modified.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM
import pefile

ROOT = Path(__file__).resolve().parents[1]
IMAGE = Path("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe")
IMAGE_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
OWNER_RVA = 0xD261B0
OWNER_SIZE = 243
OWNER_SHA = "19ad8df78554d570a1a991e90cb0e55131bf0dec29d090aee3d49ac2f5ed7df1"
SOURCE = "src/DW_SlideView.cpp"
SYMBOL = "DW_SlideView_StartTransition"
HELPER = "DSV_OriginalStartTransition"
SIGNATURE = "void(DWSlidePmove *, int32_t, int32_t, int32_t, const DWSlideGoalAngles *, int32_t)"
CALLERS = {
    0x1107895: "mantle_yaw",
    0x11287C3: "center_view_pitch",
    0x112EB5E: "slide_pitch",
}
CALL_FLAGS = {
    0x1107895: (0x1107843, 2),
    0x11287C3: (0x1128784, 1),
    0x112EB5E: (0x112EB39, 9),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def compiler_workspace(snapshot, catalog, cache):
    sys.path.insert(0, str(snapshot / "tools"))
    from workstation_sources import SourceWorkspace

    workspace = SourceWorkspace(snapshot, cache)
    workspace._catalog = catalog
    workspace._state = lambda: {"sources": {}}
    return workspace


def inspect(snapshot):
    raw = IMAGE.read_bytes()
    assert sha(raw) == IMAGE_SHA
    catalog = json.loads((snapshot / "generated/function-catalog.json").read_bytes())
    assert catalog["image_sha256"] == IMAGE_SHA
    functions = {row["rva"]: row for row in catalog["functions"]}
    row = functions[OWNER_RVA]
    assert not row.get("quarantined")
    pe = pefile.PE(data=raw, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]]
    )
    body = pe.get_data(OWNER_RVA, OWNER_SIZE)
    assert sha(body) == OWNER_SHA
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(body, OWNER_RVA))
    assert sum(instruction.size for instruction in instructions) == OWNER_SIZE
    assert instructions[-1].mnemonic == "ret"
    assert not any(
        instruction.mnemonic in ("call", "push", "pop") for instruction in instructions
    )
    assert not any(
        entry.struct.BeginAddress <= OWNER_RVA < entry.struct.EndAddress
        for entry in pe.DIRECTORY_ENTRY_EXCEPTION
    )
    offsets = {
        operand.mem.disp
        for instruction in instructions
        for operand in instruction.operands
        if operand.type == X86_OP_MEM
    }
    assert {8, 28, 460, 464, 524, 528, 536, 540, 544, 548, 552, 556, 560} <= offsets

    # Scan every possible E8 site in the original code section. Each matching
    # relative operand is independently decoded at its known native boundary.
    text = next(
        section for section in pe.sections if section.Name.rstrip(b"\0") == b".text"
    )
    text_bytes = text.get_data()
    call_sites = []
    position = text_bytes.find(b"\xe8")
    while position >= 0:
        if position + 5 <= len(text_bytes):
            site = text.VirtualAddress + position
            if (
                site + 5 + struct.unpack_from("<i", text_bytes, position + 1)[0]
                == OWNER_RVA
            ):
                instruction = next(
                    decoder.disasm(text_bytes[position : position + 5], site)
                )
                assert (
                    instruction.mnemonic == "call"
                    and instruction.operands[0].type == X86_OP_IMM
                )
                call_sites.append(site)
        position = text_bytes.find(b"\xe8", position + 1)
    assert set(call_sites) == set(CALLERS), call_sites
    assert struct.pack("<Q", pe.OPTIONAL_HEADER.ImageBase + OWNER_RVA) not in raw
    for site, (begin, flags) in CALL_FLAGS.items():
        arguments = list(decoder.disasm(pe.get_data(begin, site + 5 - begin), begin))
        assert arguments[-1].mnemonic == "call" and arguments[-1].operands[0].imm == OWNER_RVA
        assert any(instruction.mnemonic == "mov" and len(instruction.operands) == 2 and
                   instruction.operands[0].type == X86_OP_MEM and
                   instruction.operands[0].mem.disp == 0x28 and
                   instruction.operands[1].type == X86_OP_IMM and
                   instruction.operands[1].imm == flags for instruction in arguments)
    # The slide caller reads these three constants and supplies flags9. Native
    # mantle and center-view callers supply flags2 and flags1 respectively.
    assert pe.get_data(0x2438670, 12) == struct.pack("<iif", 4, 1100, 15.0)
    slide_call = list(decoder.disasm(pe.get_data(0x112EB39, 0x2A), 0x112EB39))
    assert any(
        i.mnemonic == "mov" and i.op_str == "dword ptr [rsp + 0x28], 9"
        for i in slide_call
    )
    assert (
        slide_call[-1].mnemonic == "call"
        and slide_call[-1].operands[0].imm == OWNER_RVA
    )
    native_proofs = {}
    for label, address, length in (
        ("slide_caller", 0x112EA70, 1273),
        ("camera_input_gate", 0xD25FE0, 208),
        ("angle_override", 0xD262B0, 540),
    ):
        data = pe.get_data(address, length)
        native_proofs[label] = dict(rva=address, bytes=length, sha256=sha(data))

    workspace = compiler_workspace(
        snapshot, catalog, snapshot / "generated/slide-view-inspect-cache"
    )
    original = workspace._assembly_source(row)
    assert original["editable"] and original["compilable"]
    assert original["provenance"]["ranges"] == [[OWNER_RVA, OWNER_RVA + OWNER_SIZE]]
    assert original["provenance"]["unwind"] == {
        "required": True,
        "original_unwind": False,
    }
    assert f".seh_proc {row['id']}" in original["content"]
    assert ".seh_endprologue" in original["content"]
    main_thread = functions[0x12CF280]
    proof = dict(
        passed=True,
        image_sha256=IMAGE_SHA,
        source=SOURCE,
        source_sha256=sha((ROOT / "integration/replay/DW_SlideView.cpp").read_bytes()),
        source_header_sha256=sha(
            (ROOT / "integration/replay/DW_SlideView.h").read_bytes()
        ),
        owners={
            SYMBOL: dict(
                identity=row["id"],
                rva=OWNER_RVA,
                bytes=OWNER_SIZE,
                sha256=OWNER_SHA,
                native_leaf=True,
            )
        },
        imports={"DSV_IsMainThread": main_thread["id"]},
        dvar=dict(
            name="cg_useOldSlide",
            type="bool",
            default=False,
            flags=1,
            zero="Bypass only the native slide-pitch transition",
            one="Execute the complete original native transition",
        ),
        transition=dict(
            duration_ms=1100,
            ease_in=4,
            ease_out=4,
            goal_pitch=15.0,
            goal_yaw=0.0,
            flags=9,
        ),
        direct_callers=[
            dict(rva=site, purpose=CALLERS[site], flags=CALL_FLAGS[site][1])
            for site in sorted(call_sites)
        ],
        native_proofs=native_proofs,
        compiler_leaf_source_sha256=sha(original["content"].encode()),
        clone_policy="Complete proven native leaf; existing compiler source provides its empty leaf unwind envelope",
        later_build_oracle=dict(
            database=r"D:\mw124\_ida_tmp\mw164_94 - diaph.sqlite",
            database_id=36814,
            rva=53110800,
            pseudocode_sha256="3d55fa7dc4e9eea94c45cc522c3951ab446434d9497c7b48841e43c3bce675fe",
            role="Read-only behavior reference: same 15-degree, 1100ms, flags9 slide transition; no Replay addresses/layouts imported",
        ),
        layout=dict(
            pmove_player_state=8,
            player_pitch=460,
            player_yaw=464,
            transition_flags=524,
            transition_active_otherflags_bit=0x10000,
        ),
        limitations=[
            "Shared movement setting: server is authoritative; client and server values must match",
            "Archive flag only; no unverified replication flags are introduced",
            "Changing the dvar affects subsequent slide starts; an already active transition ends natively",
            "Only the exact Replay slide tuple is bypassed; altered or unrelated transition calls use native behavior",
        ],
        cpp_compiled=False,
        native_bodies_assembled=False,
        game_runs_performed=False,
    )
    return pe, catalog, row, original, proof


def prepare(snapshot, *, replace_owned=False):
    snapshot = Path(snapshot).resolve(strict=True)
    assert snapshot.is_relative_to(ROOT / "data")
    for parent in (snapshot, snapshot.parent):
        for marker in (
            "client-readiness.json",
            "readiness.json",
            "local-readiness.json",
            "source-receipt.json",
        ):
            assert not (parent / marker).exists(), "Cannot prepare a sealed snapshot"
    assert not list(snapshot.parent.glob("builds/*/build-report.json"))
    dependencies = [
        SOURCE,
        "src/DW_SlideView.h",
        "src/DW_SlideViewBindings.h",
        "src/DW_SlideView_Native.cpp",
        "src/replay_dvar.h",
    ]
    for relative in dependencies + [
        "source-units.json",
        "source-workstation/units.json",
    ]:
        path = snapshot / relative
        assert not path.exists() or path.stat().st_nlink == 1
    pe, catalog, row, original, proof = inspect(snapshot)
    from replay_owned_clone import assemble
    from coff import read

    output = snapshot / "generated/slide-view"
    output.mkdir(parents=True, exist_ok=True)
    workspace = compiler_workspace(snapshot, catalog, output / "cache")
    # The existing compiler source already supplies an empty leaf unwind
    # envelope for its proven native CFG. Reuse it without rewriting the body.
    clone_source, clone = assemble(
        workspace,
        pe,
        catalog,
        row,
        HELPER,
        output,
        Path(r"C:\Program Files\LLVM\bin"),
        read,
    )
    assert clone["bytes"] == OWNER_SIZE and clone["unwind_records"] == 1
    for fixup in clone["external_fixups"]:
        proof["imports"][fixup["stable_id"]] = fixup["stable_id"]
    (snapshot / "src/DW_SlideView_Native.cpp").write_text(clone_source)
    for name in ("DW_SlideView.cpp", "DW_SlideView.h"):
        (snapshot / "src" / name).write_bytes(
            (ROOT / "integration/replay" / name).read_bytes()
        )
    (snapshot / "src/DW_SlideViewBindings.h").write_text(
        '#pragma once\n#include "DW_SlideView.h"\nextern "C" {\n'
        + "bool DSV_IsMainThread();\n"
        + f"void {HELPER}(DWSlidePmove *, int32_t, int32_t, int32_t, const DWSlideGoalAngles *, int32_t);\n"
        + "}\n"
    )
    association_path = snapshot / "source-units.json"
    units_path = snapshot / "source-workstation/units.json"
    associations = json.loads(association_path.read_bytes())
    units = json.loads(units_path.read_bytes())
    wanted = dict(source=SOURCE, symbol=SYMBOL, function_id=row["id"])
    prior = [unit for unit in associations["units"] if unit["function_id"] == row["id"]]
    assert not prior or (replace_owned and prior == [wanted]), "Different native owner"
    if not prior:
        associations["units"].append(wanted)
    prior = [unit for unit in units["units"] if unit["function_id"] == row["id"]]
    assert not prior or (replace_owned and prior[0]["source"] == SOURCE)
    units["units"] = [
        unit for unit in units["units"] if unit["function_id"] != row["id"]
    ]
    digest = sha((snapshot / SOURCE).read_bytes())
    units["units"].append(
        dict(
            function_id=row["id"],
            kind="cpp",
            source=SOURCE,
            symbol=SYMBOL,
            sha256=digest,
            revision=digest,
            language="cpp",
        )
    )
    for symbol, identity in proof["imports"].items():
        wanted = dict(symbol=symbol, symbol_id=identity)
        prior = [
            item for item in associations.get("imports", []) if item["symbol"] == symbol
        ]
        assert not prior or prior == [wanted]
        if not prior:
            associations.setdefault("imports", []).append(wanted)
    association_path.write_text(json.dumps(associations, indent=2) + "\n")
    units_path.write_text(json.dumps(units, indent=2) + "\n")
    proof.update(
        clones=[clone],
        native_bodies_assembled=True,
        leaf_unwind_synthesized=True,
        generator_sha256=sha(Path(__file__).read_bytes()),
        clone_tool_sha256=sha((ROOT / "tools/replay_owned_clone.py").read_bytes()),
        dependencies={
            relative: sha((snapshot / relative).read_bytes())
            for relative in dependencies
        },
    )
    (snapshot / "generated/slide-view-integration.json").write_text(
        json.dumps(proof, indent=2) + "\n"
    )
    return proof


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--inspect-only", action="store_true")
    parser.add_argument("--replace-owned", action="store_true")
    args = parser.parse_args()
    snapshot = args.snapshot.resolve(strict=True)
    result = (
        inspect(snapshot)[4]
        if args.inspect_only
        else prepare(snapshot, replace_owned=args.replace_owned)
    )
    print(json.dumps(result, indent=2))
