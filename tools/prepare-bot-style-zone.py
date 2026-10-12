"""Prepare the complete Replay native bot-style zone delivery owner.

The retained DB_LoadFastfiles body is a symbolic, byte-faithful PE clone with
real Win64 unwind metadata. The wrapper owns its original function identity;
the clone has a fresh symbol and cannot recurse through that identity.
"""

import hashlib
import json
import re
import struct
import subprocess
import sys
import os
import tempfile
from pathlib import Path
import pefile
import capstone
from capstone.x86_const import X86_OP_MEM, X86_REG_RIP

ROOT = Path(__file__).resolve().parents[1]
IMAGE = Path("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe")
IMAGE_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
LOADER = (
    "fn_633c94facfea5183",
    933,
    "67aca521a4a40ccf222ecb58a0010a6bc2a8fe0481bb60a215bdbb5e6bbc3c31",
)
POLL = (
    "fn_898aab2c422c379f",
    320,
    "5a03a11cbb1f705cafcb93348bfaa9d32abe76ba1433f4cf75f7ebdd5a7a7911",
)
FIFO_APPEND = (
    "fn_aa85de56d6a26af3",
    429,
    "a07e42a12e3589d8a7dfee1cc42dbd7364b59bb8232c3ee12b0877eccf1de9da",
)
FIFO_POP = (
    "fn_34b960055e9e04fc",
    418,
    "b3482891e9afad34cdd49cb5e2d8cad4cd51ba7d42d3e797cc32077623e0fdf4",
)
REGION = (
    "fn_7d3c68d083bb7a1d",
    78,
    "9211fe667e5f5b8165d0ba6f6e340a3750d809a55167fc037ad241a27661ecfb",
)
LANGUAGE = (
    "fn_f7e7b34c60acdbed",
    40,
    "e5fc19d19870e79517f49b3f3177d0de195d68fb1ecdbe5b16d39bcbe4d58e55",
)
OPEN = (
    "fn_0729dd559c87ecd5",
    827,
    "ecb85ef079351389aaf616aa967c749e69c44c16e9ba9f63a684274ed58ddd47",
)
UNLOAD_MASK = (
    "fn_3e67c614df68028a",
    59,
    "8832c1b71d658c5f4600e11994e13ef57846489e454872eaca1fb4becc4c8664",
)
UNLOAD_MATCH = (
    "fn_576611c682c2044a",
    57,
    "0b10ef7d5643c039d761f5bbd582c5099875b7ab6cc9449fcd099d8f91fdb51b",
)
UNLOAD_FREE = (
    "fn_ead13282a65d4a02",
    994,
    "01b16198eccb00ac62704a243ceaf4c3610634bd95c2148ab7a7a335195310e3",
)
DUPLICATE_LINK = (
    "fn_b21d18eff96477c9",
    1434,
    "1ef8d7aa996b64ac564cd2423bd42321b27e7ddfec405672c33eb65027051423",
)
DUPLICATE_BOUNDARIES = (
    ("fn_a6946a35977bb3b6", "find", 238, "948e27e075b06440cbcf1167277df32f4c671f4cdc01c0e9603a774fa54cfb58"),
    ("fn_a927526bc5ab00da", "current-zone", 8, "eb5e93d152cf9f67df324a291188bd280f2fca502da5f946074ae1103df5fd5a"),
    ("fn_a42669c9a5948c16", "zone-flags", 21, "49a7c8d7fbfecad4dfa93ab17d40d8159a1feff2bb242cf7355264ac1dc3b934"),
    ("fn_c1ef72b79b11f1cd", "duplicate", 589, "adf16f5dd8dfe0e3ea9f53e3eeadc0afada02d6609f87eb253d70df61f73c080"),
    ("fn_7a4aadfc048cc3de", "discard", 903, "eac9d6aeeb145d61e0aa4720f9dd31ac112cfb8487a211f486edf6e1bcd7fca1"),
)
HELPER = "DW_BotStyleZone_LoadFastfilesNative"
WRAPPER = "DW_BotStyleZone_LoadFastfiles"
SOURCE = "src/DW_BotStyleZone.cpp"
LLVM = Path("C:/Program Files/LLVM/bin")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_private(path, data):
    path = Path(path).resolve()
    if not path.is_relative_to(ROOT / "data"):
        raise ValueError("Generated zone output escaped the private DW workspace")
    payload = data.encode("utf-8") if isinstance(data, str) else data
    with tempfile.NamedTemporaryFile(
        dir=path.parent, prefix=path.name + ".", delete=False
    ) as stream:
        temporary = Path(stream.name)
        stream.write(payload)
    try:
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def prepare(snapshot, replace_owned=False):
    snapshot = Path(snapshot).resolve(strict=True)
    if (
        not snapshot.is_relative_to(ROOT / "data")
        or (snapshot.parent / "client-readiness.json").exists()
    ):
        raise ValueError("Zone preparation requires a fresh private DW snapshot")
    sys.path.insert(0, str(snapshot / "tools"))
    from workstation_sources import SourceWorkspace
    from coff import read

    output = snapshot / "generated/bot-style-zone"
    output.mkdir(parents=True, exist_ok=True)
    catalog = json.loads((snapshot / "generated/function-catalog.json").read_bytes())
    if catalog["image_sha256"] != IMAGE_SHA or sha(IMAGE.read_bytes()) != IMAGE_SHA:
        raise ValueError("Original Replay image binding changed")
    pe = pefile.PE(str(IMAGE), fast_load=True)
    workspace = SourceWorkspace(snapshot, output / "cache")
    workspace._catalog = catalog
    workspace._state = lambda: {"sources": {}}
    byid = {r["id"]: r for r in catalog["functions"] + catalog.get("symbols", [])}
    native = []
    import importlib.util
    path_spec = importlib.util.spec_from_file_location("dw_zone_paths", ROOT / "tools/bot_style_paths.py")
    path_policy = importlib.util.module_from_spec(path_spec)
    path_spec.loader.exec_module(path_policy)
    paths = path_policy.derive(snapshot)
    duplicate_boundaries = []
    for identity, role, size, digest in DUPLICATE_BOUNDARIES:
        row = byid[identity]
        if row.get("quarantined") or sha(pe.get_data(row["rva"], size)) != digest:
            raise ValueError("Native duplicate boundary changed: " + role)
        duplicate_boundaries.append(dict(identity=identity, role=role, rva=row["rva"], bytes=size, sha256=digest))
    for identity, size, digest in (
        LOADER,
        POLL,
        FIFO_APPEND,
        FIFO_POP,
        REGION,
        LANGUAGE,
        OPEN,
        UNLOAD_MASK,
        UNLOAD_MATCH,
        UNLOAD_FREE,
        DUPLICATE_LINK,
    ):
        row = byid[identity]
        if row.get("quarantined") or sha(pe.get_data(row["rva"], size)) != digest:
            raise ValueError("Native body hash mismatch: " + identity)
        native.append(
            dict(identity=identity, rva=row["rva"], bytes=size, sha256=digest)
        )
    row = byid[LOADER[0]]
    original = workspace._assembly_source(row)
    if (
        not original["compilable"]
        or not original["editable"]
        or ".seh_proc " + row["id"] not in original["content"]
    ):
        raise ValueError("Native loader lacks complete PE-owned body/unwind rendering")
    ranges = original["provenance"]["ranges"]
    native_bytes = b"".join(pe.get_data(a, b - a) for a, b in ranges)
    if len(native_bytes) != LOADER[1] or sha(native_bytes) != LOADER[2]:
        raise ValueError("Native loader renderer ranges do not exactly own pinned body")
    content = re.sub(r"\b" + row["id"] + r"\b", HELPER, original["content"])
    content = re.sub(
        r"\bL_([0-9a-f]{8})\b", lambda m: HELPER + "_L_" + m.group(1), content
    )
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    encoded = []
    retained_padding_bytes = 0
    address = row["rva"]
    fixups = {}
    for line in content.splitlines():
        label = re.fullmatch(re.escape(HELPER) + r"_L_([0-9a-f]{8}):", line)
        if label:
            label_address = int(label.group(1), 16)
            if label_address < address:
                raise ValueError("Native clone labels overlap decoded instructions")
            if label_address > address:
                # The renderer skips alignment NOPs. Original relative jumps
                # require those bytes too; preserve the PE-owned gap exactly.
                padding = pe.get_data(address, label_address - address)
                encoded.append(".byte " + ", ".join(hex(b) for b in padding))
                retained_padding_bytes += len(padding)
            address = label_address
        if line.startswith(".") or line.endswith(":") or not line.strip():
            encoded.append(line)
            continue
        size = workspace._instruction_size(address)
        raw = pe.get_data(address, size)
        instruction = next(decoder.disasm(raw, address))
        assert instruction.size == size
        refs = re.findall(r"\b(?:fn|sym)_[0-9a-f]{16}\b", line)
        if refs:
            assert len(refs) == 1
            field = (
                instruction.disp_offset
                if instruction.disp_size == 4
                else instruction.imm_offset
            )
            width = (
                instruction.disp_size
                if instruction.disp_size == 4
                else instruction.imm_size
            )
            assert width == 4 and field > 0
            tail = size - field - 4
            encoded.append(".byte " + ", ".join(hex(b) for b in raw[:field]))
            encoded.append(".long " + refs[0] + " - . - " + str(4 + tail))
            if tail:
                encoded.append(".byte " + ", ".join(hex(b) for b in raw[field + 4 :]))
            fixups[address - row["rva"] + field] = dict(
                original_site_rva=address + field,
                trailing_instruction_bytes=tail,
                stable_id=refs[0],
                original_relative_value=struct.unpack_from("<i", raw, field)[0],
            )
        else:
            encoded.append(".byte " + ", ".join(hex(b) for b in raw))
        address += size
    assembly = "\n".join(encoded) + "\n"
    assembly = assembly.replace(
        ".globl " + HELPER,
        ".globl " + HELPER + "\n.def " + HELPER + "; .scl 2; .type 32; .endef",
    )
    write_private(output / "native.s", assembly)
    clone = snapshot / "src/DW_BotStyleZone_Native.cpp"
    write_private(
        clone,
        (
            '// Complete original Replay native loader; verified source-derived fixups.\nasm(R"NATIVEBODY(\n'
            + assembly
            + ')NATIVEBODY");\n'
        ).encode(),
    )
    objpath = output / "native.obj"
    with tempfile.NamedTemporaryFile(
        dir=output, prefix="native-object-", delete=False
    ) as stream:
        object_temporary = Path(stream.name)
    command = [
        str(LLVM / "clang++.exe"),
        "--target=x86_64-pc-windows-msvc",
        "-c",
        str(clone),
        "-o",
        str(object_temporary),
        "-ffreestanding",
        "-fno-stack-protector",
        "-funwind-tables",
        "-ffunction-sections",
        "-fdata-sections",
        "-O2",
        "-std=c++20",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-fno-exceptions",
        "-fno-rtti",
    ]
    try:
        subprocess.run(command, check=True)
        os.replace(object_temporary, objpath)
    finally:
        if object_temporary.exists():
            object_temporary.unlink()
    obj = read(objpath)
    text = next(s for s in obj["sections"] if s["name"] == ".text")
    definitions = [
        s
        for s in obj["symbols"].values()
        if s["name"] == HELPER and s["section"] > 0 and s["storage"] == 2
    ]
    assert (
        len(definitions) == 1
        and definitions[0]["value"] == 0
        and definitions[0]["kind"] & 0x20
    )
    assert sum(len(s["data"]) for s in obj["sections"] if s["name"] == ".pdata") == 12
    assert any(s["name"] == ".xdata" and s["data"] for s in obj["sections"])
    expected = bytearray(native_bytes)
    actual = bytearray(text["data"])
    external = []
    assert len(expected) == len(actual) == LOADER[1]
    for offset, index, kind in text["relocations"]:
        assert kind == 4
        symbol = obj["symbols"][index]["name"]
        derived = fixups[offset]
        assert symbol == derived["stable_id"]
        assert (
            derived["original_relative_value"]
            + derived["original_site_rva"]
            + 4
            + derived["trailing_instruction_bytes"]
            == byid[symbol]["rva"]
        )
        assert (
            struct.unpack_from("<i", actual, offset)[0]
            == -derived["trailing_instruction_bytes"]
        )
        expected[offset : offset + 4] = actual[offset : offset + 4] = bytes(4)
        external.append(dict(offset=offset, kind=kind, **derived))
    assert actual == expected, "Compiled native clone changed original instructions"
    package_proof = json.loads(
        (snapshot / "generated/bot-style-scripts-integration.json").read_bytes()
    )
    assert package_proof["passed"] and package_proof["native_overlay_read_verified"]
    staged = snapshot / SOURCE
    owner = ROOT / "integration/replay/DW_BotStyleZone.cpp"
    if (
        staged.exists()
        and not replace_owned
        and staged.read_bytes() != owner.read_bytes()
    ):
        raise ValueError("Staged zone wrapper has another owner")
    write_private(staged, owner.read_bytes())
    write_private(
        snapshot / "src/DW_BotStyleZoneBindings.h",
        "#pragma once\n// Hash-bound native imports, four-argument loader, 24-byte records.\n",
    )
    imports = {f["stable_id"]: f["stable_id"] for f in external}
    imports["DWBSZ_PollFastfileState"] = POLL[0]
    imports["DWBSZ_CurrentRegionCode"] = REGION[0]
    for binding in paths["native"]:
        if binding["role"] in ("DWBSZ_IsLocalized", "DWBSZ_IsRegional", "DWBSZ_BuildAbsPath"):
            imports[binding["role"]] = binding["identity"]
    imports["DWBSZ_CurrentLanguageCode"] = LANGUAGE[0]
    # The printing identity is derived from the original loader's format-call
    # target; no runtime address appears in authored code or binding metadata.
    instructions = list(decoder.disasm(native_bytes, row["rva"]))
    print_calls = []
    for index, instruction in enumerate(instructions):
        if instruction.mnemonic != "lea" or len(instruction.operands) != 2:
            continue
        operand = instruction.operands[1]
        if operand.type != X86_OP_MEM or operand.mem.base != X86_REG_RIP:
            continue
        string_rva = instruction.address + instruction.size + operand.mem.disp
        if not pe.get_data(string_rva, 32).startswith(b"* Loading '%s'"):
            continue
        following = next(i for i in instructions[index + 1 :] if i.mnemonic == "call")
        print_calls = [
            f
            for f in external
            if f["original_site_rva"] == following.address + following.imm_offset
        ]
        break
    if len(print_calls) != 1:
        raise ValueError("Original loader format-call target was not uniquely derived")
    imports["DWBSZ_Print"] = print_calls[0]["stable_id"]
    for name in ("__imp_LoadLibraryA", "__imp_GetProcAddress", "__imp_CloseHandle"):
        rows = [
            r
            for r in catalog.get("symbols", [])
            if r["name"] == name and not r.get("quarantined")
        ]
        assert len(rows) == 1 and rows[0]["kind"] == "data-address"
        imports[name] = rows[0]["id"]
    association_path = snapshot / "source-units.json"
    associations = json.loads(association_path.read_bytes())
    expected_unit = dict(source=SOURCE, symbol=WRAPPER, function_id=LOADER[0])
    prior = [
        u
        for u in associations["units"]
        if u["function_id"] == LOADER[0] or u["symbol"] == WRAPPER
    ]
    if prior and (not replace_owned or prior != [expected_unit]):
        raise ValueError("Native loader has another root owner")
    for symbol, identity in imports.items():
        previous = [u for u in associations.get("imports", []) if u["symbol"] == symbol]
        wanted = dict(symbol=symbol, symbol_id=identity)
        if previous and previous != [wanted]:
            raise ValueError("Native zone import conflict: " + symbol)
        if not previous:
            associations.setdefault("imports", []).append(wanted)
    if not prior:
        associations["units"].append(expected_unit)
    units_path = snapshot / "source-workstation/units.json"
    units = json.loads(units_path.read_bytes())
    previous = [u for u in units["units"] if u["function_id"] == LOADER[0]]
    if previous and (not replace_owned or previous[0]["source"] != SOURCE):
        raise ValueError("Native loader has another editable source owner")
    units["units"] = [u for u in units["units"] if u["function_id"] != LOADER[0]]
    digest = sha(staged.read_bytes())
    units["units"].append(
        dict(
            function_id=LOADER[0],
            kind="cpp",
            source=SOURCE,
            symbol=WRAPPER,
            sha256=digest,
            revision=digest,
            language="cpp",
        )
    )
    assert association_path.stat().st_nlink == units_path.stat().st_nlink == 1
    write_private(association_path, json.dumps(associations, indent=2) + "\n")
    write_private(units_path, json.dumps(units, indent=2) + "\n")
    receipt = dict(
        schema=1,
        passed=True,
        image_sha256=IMAGE_SHA,
        native=native,
        record_bytes=24,
        record_offsets=dict(
            name=0, zoneFlags=8, failureMode=12, priority=16, reserved=20
        ),
        argument_count=4,
        source=SOURCE,
        source_sha256=digest,
        native_clone_source=str(clone),
        native_clone_source_sha256=sha(clone.read_bytes()),
        clone_object=str(objpath),
        clone_object_sha256=sha(objpath.read_bytes()),
        native_path_policy=paths,
        clone_native_bytes=933,
        original_body_reconstructed=True,
        retained_native_alignment_bytes=retained_padding_bytes,
        native_bytes_preserved_outside_fixups=True,
        coff_unwind_records=1,
        external_fixups=external,
        native_imports=imports,
        helper_has_no_original_mapping=True,
        native_queue_same_priority_fifo=True,
        overlay_precedes_common_base_mp=True,
        native_same_group_duplicate_first_wins=True,
        native_duplicate_link=dict(identity=DUPLICATE_LINK[0], rva=byid[DUPLICATE_LINK[0]]["rva"],
                                   bytes=DUPLICATE_LINK[1], sha256=DUPLICATE_LINK[2]),
        native_duplicate_boundaries=duplicate_boundaries,
        native_common_flag_mask_unloads_overlay=True,
        completed_unload_removes_native_zone_name_registry=True,
        native_poll_states=dict(absent=0, pending=1, loaded=2, paused=3, cancelled=4),
        package_sha256=package_proof["package_sha256"],
        patch_sha256=package_proof["patch_sha256"],
        generated_package_header_sha256=package_proof["generated_header_sha256"],
        native_required_companions=[
            "techsets_<zone>",
            "<current-region>_<zone>",
            "<current-language>_<zone>",
            "srv_<zone>",
        ],
        companions_contain_no_assets=True,
        generator_sha256=sha(Path(__file__).read_bytes()),
        game_modified=False,
        game_run_performed=False,
    )
    write_private(
        snapshot / "generated/bot-style-zone-integration.json",
        json.dumps(receipt, indent=2) + "\n",
    )
    return receipt


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("snapshot", type=Path)
    p.add_argument("--replace-owned", action="store_true")
    a = p.parse_args()
    print(json.dumps(prepare(a.snapshot, a.replace_owned), indent=2))
