"""Prepare the complete Replay camera and scene-only secondary view owners."""

import argparse
import hashlib
import json
from pathlib import Path
import sys

import capstone
from capstone.x86 import X86_OP_MEM, X86_REG_RIP
import pefile

from replay_owned_clone import assemble

ROOT = Path(__file__).resolve().parents[1]
IMAGE = Path("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe")
IMAGE_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
SOURCE = "src/DW_AltKillcam.cpp"
LLVM = Path("C:/Program Files/LLVM/bin")
OWNERS = (
    ("entity", "DW_AltKillcam_EntityView", None),
    ("fov", "DW_AltKillcam_EntityFov", None),
    ("predict", "DW_AltKillcam_Predict", "AK_OriginalPredict"),
    ("calc", "DW_AltKillcam_CalcView", "AK_OriginalCalcView"),
    ("anim", "DW_AltKillcam_WeaponAnim", "AK_OriginalWeaponAnim"),
    ("weapon", "DW_AltKillcam_AddViewWeapon", "AK_OriginalAddViewWeapon"),
    ("lerp", "DW_AltKillcam_LerpView", "AK_OriginalLerpView"),
    ("render", "DW_AltKillcam_RenderScene", "AK_OriginalRenderScene"),
    ("streaming", "DW_AltKillcam_UpdateStreaming", "AK_OriginalUpdateStreaming"),
    ("third_person", "DW_AltKillcam_UpdateThirdPerson", "AK_OriginalUpdateThirdPerson"),
)
SIGNATURES = {
    "AK_UpdateObjectCamera": "void(uint32_t, int32_t)",
    "AK_SetLodOrigin": "void(const DWAltKillcamRefdef *, float)",
    "AK_DefaultFeatures": "void(DWAltKillcamFeatures *)",
    "AK_NextView": "void(int32_t *)",
    "AK_RenderNative": "void(const DWAltKillcamRefdef *, float, uint32_t, const DWAltKillcamFeatures *)",
    "AK_EndList": "void()",
    "AK_EndBatch": "void()",
    "AK_BeginBatch": "void(uint32_t)",
    "AK_MarkScene": "void()",
    "AK_ResetScene": "void()",
    "AK_ClearSceneView": "void(uint32_t)",
    "AK_IsMainThread": "bool()",
    "AK_GameMode": "uint8_t()",
    "AK_RealTime": "int32_t()",
    "AK_TextureAtlasTime": "void(int32_t)",
    "AK_IsPipView": "bool()",
    "AK_Exposure": "void(const void *)",
    "AK_SceneFrame": "int32_t()",
    "AK_SyncRenderThread": "void()",
    "AK_WaitWorkerType": "void(uint32_t)",
}
DATA = (
    ("AK_CgGlobals", "entity", 0, "void *", "[2]"),
    ("AK_Backend", "AK_NextView", 2, "void *", ""),
    ("AK_ViewCount", "AK_NextView", 0, "int32_t", ""),
    ("AK_SceneSubmitted", "render", 2, "int32_t", ""),
    ("AK_FirstClient", "render", 3, "int32_t", ""),
    ("AK_DefaultLod", "render", 4, "const float", ""),
    ("AK_MaxClients", "snapshot", 19, "int32_t", ""),
    ("AK_SceneEntityCount", "AK_MarkScene", 0, "int32_t", ""),
    ("AK_SceneObjectCount", "AK_MarkScene", 2, "int32_t", ""),
    ("AK_SceneModelCount", "AK_MarkScene", 4, "int32_t", ""),
    ("AK_SceneBrushCount", "AK_MarkScene", 6, "int32_t", ""),
    ("AK_SceneObjects", "AK_ResetScene", 4, "DWAltKillcamSceneDObj *", ""),
    ("AK_SceneModels", "AK_ResetScene", 8, "DWAltKillcamSceneModel", "[1024]"),
    ("AK_SceneBrushes", "AK_ResetScene", 13, "DWAltKillcamSceneBrush", "[512]"),
    ("AK_SceneObjectIndex", "scene_object_add", 13, "uint16_t *", ""),
    ("AK_SceneModelIndex", "scene_model_add", 15, "uint16_t *", ""),
    ("AK_SceneObjectModelCount", "shadow_entities", 5, "int32_t", ""),
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inspect_native(snapshot):
    catalog = json.loads((snapshot / "generated/function-catalog.json").read_bytes())
    assert catalog["image_sha256"] == IMAGE_SHA
    raw = IMAGE.read_bytes()
    assert sha(raw) == IMAGE_SHA
    pe = pefile.PE(data=raw)
    base = pe.OPTIONAL_HEADER.ImageBase
    by_id = {row["id"]: row for row in catalog["functions"] + catalog["symbols"]}
    by_rva = {
        row["rva"]: row
        for row in catalog["symbols"]
        if row.get("kind") == "data-address" and not row.get("quarantined")
    }
    expected = json.loads((ROOT / "tools/alt_killcam_native.json").read_bytes())
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    native, decoded = {}, {}
    for role, binding in expected.items():
        row = by_id[binding["id"]]
        assert not row.get("quarantined")
        ranges = []
        for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
            owner = entry
            while owner.unwindinfo and owner.unwindinfo.UNW_FLAG_CHAININFO:
                owner = owner.unwindinfo._chained_entry
            if owner.struct.BeginAddress == row["rva"]:
                ranges.append((entry.struct.BeginAddress, entry.struct.EndAddress))
        ranges.sort()
        assert not ranges or all(a[1] == b[0] for a, b in zip(ranges, ranges[1:]))
        code = (
            b"".join(pe.get_data(a, b - a) for a, b in ranges)
            if ranges
            else pe.get_data(row["rva"], binding["bytes"])
        )
        assert len(code) == binding["bytes"] and sha(code) == binding["sha256"], role
        instruction_bytes = binding.get("instruction_bytes", len(code))
        if instruction_bytes != len(code):
            assert code[instruction_bytes:].hex() == binding["embedded_tail_hex"]
        instructions = list(decoder.disasm(code[:instruction_bytes], base + row["rva"]))
        assert (
            sum(instruction.size for instruction in instructions) == instruction_bytes
        ), role
        native[role] = dict(binding, rva=row["rva"], ranges=ranges)
        decoded[role] = instructions
        if binding.get("derived_from"):
            origin = binding["derived_from"]
            calls = [
                instruction
                for instruction in decoded[origin["role"]]
                if instruction.mnemonic == "call"
                and instruction.operands[0].type == capstone.x86.X86_OP_IMM
            ]
            assert (
                calls[origin["direct_call_ordinal"]].operands[0].imm
                == base + row["rva"]
            )
    imports = {
        role: binding["id"]
        for role, binding in native.items()
        if role.startswith("AK_")
    }
    mode_table = next(
        instruction
        for instruction in decoded["mode_name"]
        if instruction.mnemonic == "lea"
    )
    operand = mode_table.operands[1]
    assert operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP
    table_rva = mode_table.address + mode_table.size + operand.mem.disp - base
    import struct

    modes = [
        pe.get_string_at_rva(
            struct.unpack("<Q", pe.get_data(table_rva + index * 8, 8))[0] - base
        ).decode("ascii")
        for index in range(4)
    ]
    assert modes == ["none", "sp", "mp", "cp"]
    native["mode_name"]["verified_modes"] = modes
    declarations, globals_ = [], {}
    for name, role, ordinal, type_, suffix in DATA:
        targets = [
            (instruction, operand)
            for instruction in decoded[role]
            for operand in instruction.operands
            if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP
        ]
        instruction, operand = targets[ordinal]
        rva = instruction.address + instruction.size + operand.mem.disp - base
        row = by_rva[rva]
        imports[name] = row["id"]
        declarations.append(f"extern {type_} {name}{suffix};")
        globals_[name] = dict(
            identity=row["id"],
            rva=rva,
            body_role=role,
            instruction_rva=instruction.address - base,
            rip_ordinal=ordinal,
        )
    # CachePost derives an image-base register then addresses the two native
    # arrays through that register. Verify this complete target idiom rather
    # than copying an address from the newer source.
    instructions = decoded["cache_post"]
    base_lea = [
        instruction
        for instruction in instructions
        if instruction.mnemonic == "lea"
        and any(
            operand.type == X86_OP_MEM
            and operand.mem.base == X86_REG_RIP
            and instruction.address + instruction.size + operand.mem.disp == base
            for operand in instruction.operands
        )
    ]
    assert len(base_lea) == 1
    tables = [
        (instruction, operand)
        for instruction in instructions
        if instruction.mnemonic == "mov"
        for operand in instruction.operands
        if operand.type == X86_OP_MEM
        and operand.mem.index
        and operand.mem.disp > 0x100000
    ]
    assert len(tables) == 2
    instruction, operand = tables[1]
    row = by_rva[operand.mem.disp]
    imports["AK_EntitySystems"] = row["id"]
    declarations.append("extern void *AK_EntitySystems[2];")
    globals_["AK_EntitySystems"] = dict(
        identity=row["id"],
        rva=row["rva"],
        body_role="cache_post",
        instruction_rva=instruction.address - base,
        image_base_lea_rva=base_lea[0].address - base,
    )
    return pe, catalog, native, imports, declarations, globals_


def prepare(snapshot, replace_owned=False):
    snapshot = Path(snapshot).resolve(strict=True)
    assert snapshot.is_relative_to(ROOT / "data")
    assert not (snapshot.parent / "client-readiness.json").exists()
    assert not list(snapshot.parent.glob("builds/*/build-report.json"))
    for relative in (
        "source-units.json",
        "source-workstation/units.json",
        SOURCE,
        "src/DW_AltKillcamBindings.h",
        "src/DW_AltKillcam_Native.cpp",
    ):
        path = snapshot / relative
        assert not path.exists() or path.stat().st_nlink == 1
    sys.path.insert(0, str(snapshot / "tools"))
    from workstation_sources import SourceWorkspace
    from coff import read

    pe, catalog, native, imports, declarations, globals_ = inspect_native(snapshot)
    output = snapshot / "generated/alt-killcam"
    output.mkdir(parents=True, exist_ok=True)
    workspace = SourceWorkspace(snapshot, output / "cache")
    workspace._catalog = catalog
    workspace._state = lambda: {"sources": {}}
    by_id = {row["id"]: row for row in catalog["functions"]}
    sources, clones = [], []
    header = ["#pragma once", '#include "DW_AltKillcam.h"', 'extern "C" {']
    for role, symbol, helper in OWNERS:
        if helper:
            source, proof = assemble(
                workspace,
                pe,
                catalog,
                by_id[native[role]["id"]],
                helper,
                output,
                LLVM,
                read,
                gs_unwind=native[role].get("unwind"),
            )
            assert proof["bytes"] == native[role]["bytes"]
            sources.append(source)
            clones.append(proof)
            for fixup in proof["external_fixups"]:
                imports[fixup["stable_id"]] = fixup["stable_id"]
            signature = {
                "render": "void(uint32_t, DWAltKillcamRefdef *, uint32_t)",
                "streaming": "void(DWAltKillcamSceneView *)",
                "third_person": "uint32_t(uint32_t)",
            }.get(role, "void(uint32_t)")
            result, parameters = signature.split("(", 1)
            header.append(f"{result} {helper}({parameters};")
    for name, signature in SIGNATURES.items():
        result, parameters = signature.split("(", 1)
        header.append(f"{result} {name}({parameters};")
    header.extend(declarations)
    header.append("}")
    for name in ("DW_AltKillcam.cpp", "DW_AltKillcam.h", "DW_AltKillcamRender.h"):
        (snapshot / "src" / name).write_bytes(
            (ROOT / "integration/replay" / name).read_bytes()
        )
    (snapshot / "src/DW_AltKillcamBindings.h").write_text("\n".join(header) + "\n")
    (snapshot / "src/DW_AltKillcam_Native.cpp").write_text("\n".join(sources))
    association_path = snapshot / "source-units.json"
    unit_path = snapshot / "source-workstation/units.json"
    associations = json.loads(association_path.read_bytes())
    units = json.loads(unit_path.read_bytes())
    digest = sha((snapshot / SOURCE).read_bytes())
    for role, symbol, helper in OWNERS:
        identity = native[role]["id"]
        wanted = dict(source=SOURCE, symbol=symbol, function_id=identity)
        prior = [row for row in associations["units"] if row["function_id"] == identity]
        assert not prior or (
            replace_owned and prior == [wanted]
        ), "Different root owner"
        if not prior:
            associations["units"].append(wanted)
        prior = [row for row in units["units"] if row["function_id"] == identity]
        assert not prior or (replace_owned and prior[0]["source"] == SOURCE)
        units["units"] = [
            row for row in units["units"] if row["function_id"] != identity
        ]
        units["units"].append(
            dict(
                function_id=identity,
                kind="cpp",
                source=SOURCE,
                symbol=symbol,
                sha256=digest,
                revision=digest,
                language="cpp",
            )
        )
    for symbol, identity in imports.items():
        wanted = dict(symbol=symbol, symbol_id=identity)
        prior = [
            row for row in associations.get("imports", []) if row["symbol"] == symbol
        ]
        assert not prior or prior == [wanted]
        if not prior:
            associations.setdefault("imports", []).append(wanted)
    association_path.write_text(json.dumps(associations, indent=2) + "\n")
    unit_path.write_text(json.dumps(units, indent=2) + "\n")
    dependencies = {
        str(path.relative_to(snapshot)): sha(path.read_bytes())
        for path in (
            snapshot / SOURCE,
            snapshot / "src/DW_AltKillcam.h",
            snapshot / "src/DW_AltKillcamRender.h",
            snapshot / "src/DW_AltKillcamBindings.h",
            snapshot / "src/DW_AltKillcam_Native.cpp",
        )
    }
    proof = dict(
        schema=1,
        passed=True,
        image_sha256=IMAGE_SHA,
        source=SOURCE,
        source_sha256=digest,
        native=native,
        derived_globals=globals_,
        imports=imports,
        clones=clones,
        dependencies=dependencies,
        generator_sha256=sha(Path(__file__).read_bytes()),
        binding_table_sha256=sha((ROOT / "tools/alt_killcam_native.json").read_bytes()),
        clone_tool_sha256=sha((ROOT / "tools/replay_owned_clone.py").read_bytes()),
        layout=dict(
            refdef_bytes=3232,
            refdef_view_bytes=108,
            refdef_origin=24,
            refdef_key=116,
            refdef_seed=120,
            refdef_local_client=860,
            refdef_time=148,
            scene_object_bytes=1688,
            scene_model_bytes=152,
            scene_brush_bytes=88,
            native_view_capacity=6,
            archived_dvar_flags=1,
            delayed_scene_worker_kind=109,
            renderer_sync="AK_SyncRenderThread",
            streaming_multi_view_bytes=548,
            streaming_saved_views_bytes=780,
            streaming_saved_clients=1,
            streaming_saved_buffers=2,
        ),
        game_run_performed=False,
        full_engine_build_performed=False,
    )
    (snapshot / "generated/alt-killcam-integration.json").write_text(
        json.dumps(proof, indent=2) + "\n"
    )
    return proof


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--replace-owned", action="store_true")
    args = parser.parse_args()
    print(json.dumps(prepare(args.snapshot, args.replace_owned), indent=2))
