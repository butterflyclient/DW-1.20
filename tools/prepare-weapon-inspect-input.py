"""Prepare inspection binding owners in a future private canonical snapshot.

--inspect-only is read-only and never invokes the assembler. Normal preparation
uses replay_owned_clone for complete original fallback bodies and their unwind
metadata, then registers the replacement owners in the canonical manifests.
"""

from workstation_preparation_context import cached_input_json, shared_original_pe, source_context

import argparse
import hashlib
import json
from pathlib import Path
import sys

import capstone
from capstone.x86 import X86_OP_MEM, X86_OP_IMM, X86_REG_RIP
import pefile

ROOT = Path(__file__).resolve().parents[1]
IMAGE = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
IMAGE_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
SOURCE = "src/DW_WeaponInspectInput.cpp"
OWNERS = (
    (
        0x19F9810,
        "DW_WeaponInspectInput_Capture",
        "WI_OriginalCapture",
        "int(void *)",
        331,
        "eab53ba3b92843713d6f1761c8f96dcba0fd4aad1f6d3b50e4268f871d40831c",
    ),
    (
        0x19F99E0,
        "DW_WeaponInspectInput_Unbind",
        "WI_OriginalUnbind",
        "int(void *)",
        345,
        "e5e0b44688e1f6186e5f2fcdaa7f0a3b62c11e0874a75f75a5e1d993a66ea551",
    ),
    (
        0x19F9C00,
        "DW_WeaponInspectInput_Reset",
        "WI_OriginalReset",
        "int(void *)",
        523,
        "033f1ea95eb03d55d5d70f48a6bd778e89d86cfe363a110c687638d194317585",
    ),
    (
        0x19FA720,
        "DW_WeaponInspectInput_GetDefault",
        "WI_OriginalGetDefault",
        "int(void *)",
        384,
        "02e47725e76f5b98f92978fa94d9348cad95f440ae55b1f6f75a2f2ae9ef0b25",
    ),
    (
        0x19FAC70,
        "DW_WeaponInspectInput_GetBound",
        "WI_OriginalGetBound",
        "int(void *)",
        384,
        "799b649c61b5ccfa98630df954c4c8dd218a0cbb79d5b43fdc9250cf22de4ffc",
    ),
    (
        0x19D1A80,
        "DW_WeaponInspectInput_HandleKey",
        "WI_OriginalHandleKey",
        "bool(uint32_t, uint32_t)",
        976,
        "41efc7c4e225375bc1ef9e294d472b4deb8b0e41cb0dc65fe9f2ccefeb523550",
    ),
)
FUNCTIONS = {
    "WI_LuaTop": (0x20838B0, "int(void *)"),
    "WI_LuaType": (0x2084AC0, "int(void *, int)"),
    "WI_LuaString": (0x2084950, "const char *(void *, int, size_t *)"),
    "WI_LuaInteger": (0x19B78C0, "int64_t(void *, int)"),
    "WI_LuaPushString": (0x2084120, "void(void *, const char *)"),
    "WI_LuaError": (0x2089FB0, "int(void *, const char *, ...)"),
    "WI_LuaCreateTable": (0x20833B0, "void(void *, int, int)"),
    "WI_LuaSetField": (0x2084510, "void(void *, int, const char *)"),
    "WI_KeyName": (0x10C9370, "const char *(uint32_t, int32_t)"),
    "WI_FormatKey": (0x1BA0A20, "void(char *, size_t, const char *, bool)"),
    "WI_KeyDown": (0x15C0320, "bool(uint32_t, int32_t)"),
    "WI_Connected": (0x15BCD30, "bool(uint32_t)"),
    "WI_ClientFromController": (0xD66C20, "uint32_t(int32_t)"),
    "WI_IsMainThread": (0x12CF280, "bool()"),
    "WI_BoundKey": (
        0x15BF9E0,
        "uint8_t(const void *, uint8_t, uint8_t, uint8_t, bool)",
    ),
    "WI_IsGamepad": (0x13EEBF0, "bool(uint8_t)"),
    "WI_SetWaiting": (0x19D6B10, "void(uint32_t, uint8_t, uint8_t, uint8_t)"),
    "WI_BeginEvent": (0x19BCC30, "bool(uint32_t, const char *, void *)"),
    "WI_EndEvent": (0x19BDA00, "bool(void *)"),
    "WI_TableBool": (0x19B76C0, "void(const char *, bool, void *)"),
    "WI_TableInt": (0x19B7700, "void(const char *, int64_t, void *)"),
}
GLOBALS = {
    "WI_Waiting": (0x11896013, "uint8_t", "[2]"),
    "WI_LuaVM": (0x11868880, "void *", ""),
    "WI_Bindings": (0xEEA61F0, "uint8_t", "[]"),
    "WI_ActiveContext": (0xEEA61EB, "uint8_t", "[2]"),
    "WI_KeyCatchers": (0xEEF1284, "uint32_t", "[]"),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unwind_family(pe, rva):
    records = []
    for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
        owner = entry
        while owner.unwindinfo and owner.unwindinfo.UNW_FLAG_CHAININFO:
            owner = owner.unwindinfo._chained_entry
        if owner.struct.BeginAddress != rva:
            continue
        header = pe.get_data(entry.struct.UnwindData, 4)
        flags = header[0] >> 3
        assert flags in (0, 3, 4), (hex(rva), flags)
        size = 4 + ((header[2] + 1) & ~1) * 2
        size += 12 if flags == 4 else 8 if flags == 3 else 0
        records.append(
            dict(
                begin=entry.struct.BeginAddress,
                end=entry.struct.EndAddress,
                unwind_rva=entry.struct.UnwindData,
                bytes=pe.get_data(entry.struct.UnwindData, size).hex(),
            )
        )
    records.sort(key=lambda row: row["begin"])
    assert records and records[0]["begin"] == rva
    assert all(a["end"] == b["begin"] for a, b in zip(records, records[1:]))
    return records


def inspect(snapshot):
    catalog = cached_input_json(snapshot / 'generated/function-catalog.json')
    assert catalog["image_sha256"] == IMAGE_SHA
    raw = IMAGE.read_bytes()
    assert sha(raw) == IMAGE_SHA
    pe = shared_original_pe(data=raw, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]]
    )
    functions = {row["rva"]: row for row in catalog["functions"]}
    data = {
        row["rva"]: row
        for row in catalog["symbols"]
        if row.get("kind") == "data-address" and not row.get("quarantined")
    }
    imports, declarations, native = {}, [], {}
    for rva, symbol, helper, signature, size, digest in OWNERS:
        row = functions[rva]
        assert not row.get("quarantined")
        records = unwind_family(pe, rva)
        body = b"".join(pe.get_data(r["begin"], r["end"] - r["begin"]) for r in records)
        assert len(body) == size and sha(body) == digest, symbol
        native[symbol] = dict(
            identity=row["id"], rva=rva, bytes=size, sha256=digest, unwind=records
        )
        result, parameters = signature.split("(", 1)
        declarations.append(f"{result} {helper}({parameters};")
    for symbol, (rva, signature) in FUNCTIONS.items():
        row = functions[rva]
        assert not row.get("quarantined")
        imports[symbol] = row["id"]
        result, parameters = signature.split("(", 1)
        declarations.append(f"{result} {symbol}({parameters};")
    for symbol, (rva, ctype, suffix) in GLOBALS.items():
        imports[symbol] = data[rva]["id"]
        declarations.append(f"extern {ctype} {symbol}{suffix};")

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True

    def operands(rva, size):
        return [
            operand
            for instruction in decoder.disasm(pe.get_data(rva, size), rva)
            for operand in instruction.operands
        ]

    # These are target instructions, not transferred source-engine layouts.
    key_down_instructions = list(decoder.disasm(pe.get_data(0x15C0320, 40), 0x15C0320))
    key_down = [
        o for instruction in key_down_instructions for o in instruction.operands
    ]
    assert any(o.type == X86_OP_IMM and o.imm == 4408 for o in key_down)
    assert any(
        o.type == X86_OP_MEM
        and o.mem.base == X86_REG_RIP
        and instruction.address + instruction.size + o.mem.disp == 0xEEAF0F4
        for instruction in key_down_instructions
        for o in instruction.operands
    )
    connected = operands(0x15BCD30, 65)
    assert any(o.type == X86_OP_IMM and o.imm == 440 for o in connected)
    assert any(o.type == X86_OP_IMM and o.imm == 9 for o in connected)
    waiting = operands(0x19D6B10, 42)
    assert any(o.type == X86_OP_MEM and o.mem.disp == 0x11896013 for o in waiting)
    assert any(o.type == X86_OP_MEM and o.mem.disp == 0x1189601A for o in waiting)
    binding_load = operands(0x15C0690, 80)
    assert any(o.type == X86_OP_IMM and o.imm == 18135 for o in binding_load)
    assert any(o.type == X86_OP_MEM and o.mem.disp == 0xEEA61F0 for o in binding_load)
    # Full CL_Keys_Event family: the catcher array is indexed by local*110
    # dwords, and the native client UI record is 440 bytes.
    event_records = unwind_family(pe, 0x15BEB80)
    event_code = b"".join(
        pe.get_data(r["begin"], r["end"] - r["begin"]) for r in event_records
    )
    event_operands = [
        o
        for instruction in decoder.disasm(event_code, 0x15BEB80)
        for o in instruction.operands
    ]
    assert any(o.type == X86_OP_IMM and o.imm == 440 for o in event_operands)
    assert any(o.type == X86_OP_MEM and o.mem.disp == 0xEEF1284 for o in event_operands)
    # Validate ONFOOT's actual table entry through the original context table.
    import struct

    contexts = {0: b"ONFOOT_SP", 1: b"ONFOOT_MP", 2: b"ONFOOT", 13: b"ONFOOT_BR"}
    for index, expected in contexts.items():
        pointer = struct.unpack("<Q", pe.get_data(0x23CCCB0 + index * 8, 8))[0]
        assert pe.get_string_at_rva(pointer - pe.OPTIONAL_HEADER.ImageBase) == expected
    proof = dict(
        passed=True,
        image_sha256=IMAGE_SHA,
        owners=native,
        imports=imports,
        globals={
            name: dict(rva=value[0], identity=imports[name])
            for name, value in GLOBALS.items()
        },
        layout=dict(
            client_ui_stride=440,
            bindings_stride=18135,
            physical_key_stride=16,
            physical_key_client_stride=4408,
            key_limit=222,
            native_action_limit=255,
            archived_dvar_flags=1,
            default_key=0,
            onfoot_context=2,
        ),
        cpp_compiled=False,
        game_runs_performed=False,
    )
    return pe, catalog, functions, declarations, proof


def prepare(snapshot, *, replace_owned=False):
    snapshot = Path(snapshot).resolve(strict=True)
    assert snapshot.is_relative_to(ROOT / "data")
    assert not any(
        (snapshot.parent / name).exists()
        for name in (
            "client-readiness.json",
            "readiness.json",
            "local-readiness.json",
            "source-receipt.json",
        )
    )
    assert not list(snapshot.parent.glob("builds/*/build-report.json"))
    relatives = [
        "source-units.json",
        "source-workstation/units.json",
        SOURCE,
        "src/DW_WeaponInspectInput.h",
        "src/DW_WeaponInspectInputBindings.h",
        "src/DW_WeaponInspectInput_Native.cpp",
    ]
    for relative in relatives:
        path = snapshot / relative
        assert not path.exists() or path.stat().st_nlink == 1
    pe, catalog, functions, declarations, proof = inspect(snapshot)
    # Assembly is deliberately deferred until this preparer is invoked by a
    # future authorized canonical build. --inspect-only never reaches here.
    from replay_owned_clone import assemble

    sys.path.insert(0, str(snapshot / "tools"))
    from workstation_sources import SourceWorkspace
    from coff import read

    output = snapshot / "generated/weapon-inspect-input"
    output.mkdir(parents=True, exist_ok=True)
    workspace = SourceWorkspace(snapshot, output / "cache")
    workspace._catalog = catalog
    workspace._state = lambda: {"sources": {}}
    clone_sources, clone_proofs = [], []
    for rva, symbol, helper, signature, size, digest in OWNERS:
        source, clone = assemble(
            workspace,
            pe,
            catalog,
            functions[rva],
            helper,
            output,
            Path(r"C:\Program Files\LLVM\bin"),
            read,
            gs_unwind=proof["owners"][symbol]["unwind"],
        )
        assert clone["bytes"] == size
        clone_sources.append(source)
        clone_proofs.append(clone)
        for fixup in clone["external_fixups"]:
            proof["imports"][fixup["stable_id"]] = fixup["stable_id"]
    for name in ("DW_WeaponInspectInput.cpp", "DW_WeaponInspectInput.h"):
        (snapshot / "src" / name).write_bytes(
            (ROOT / "integration/replay" / name).read_bytes()
        )
    header = '#pragma once\n#include <stdint.h>\n#include <stddef.h>\nextern "C" {\n'
    (snapshot / "src/DW_WeaponInspectInputBindings.h").write_text(
        header + "\n".join(declarations) + "\n}\n"
    )
    (snapshot / "src/DW_WeaponInspectInput_Native.cpp").write_text(
        "\n".join(clone_sources)
    )
    association_path = snapshot / "source-units.json"
    units_path = snapshot / "source-workstation/units.json"
    associations = json.loads(association_path.read_bytes())
    units = json.loads(units_path.read_bytes())
    digest = sha((snapshot / SOURCE).read_bytes())
    for rva, symbol, helper, signature, size, body_digest in OWNERS:
        identity = functions[rva]["id"]
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
    for symbol, identity in proof["imports"].items():
        wanted = dict(symbol=symbol, symbol_id=identity)
        prior = [
            row for row in associations.get("imports", []) if row["symbol"] == symbol
        ]
        assert not prior or prior == [wanted]
        if not prior:
            associations.setdefault("imports", []).append(wanted)
    association_path.write_text(json.dumps(associations, indent=2) + "\n")
    units_path.write_text(json.dumps(units, indent=2) + "\n")
    proof.update(
        clones=clone_proofs,
        source=SOURCE,
        source_sha256=digest,
        generator_sha256=sha(Path(__file__).read_bytes()),
        clone_tool_sha256=sha((ROOT / "tools/replay_owned_clone.py").read_bytes()),
        original_bodies_assembled=True,
    )
    proof["dependencies"] = {
        relative: sha((snapshot / relative).read_bytes()) for relative in relatives[2:]
    }
    (snapshot / "generated/weapon-inspect-input-integration.json").write_text(
        json.dumps(proof, indent=2) + "\n"
    )
    return proof


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--inspect-only", action="store_true")
    parser.add_argument("--replace-owned", action="store_true")
    args = parser.parse_args()
    if args.inspect_only:
        result = inspect(args.snapshot.resolve(strict=True))[4]
    else:
        result = prepare(args.snapshot, replace_owned=args.replace_owned)
    print(json.dumps(result, indent=2) + "\n")
