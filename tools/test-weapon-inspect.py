"""Deferred read-only gate for frozen, compiled and linked inspection ownership.

This checker never compiles, assembles, generates a zone or modifies the game.
--self-test exercises its byte/relocation checks with synthetic metadata only.
"""

import argparse
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "DW_WeaponInspect_UpdateSprint": 0x1128160,
    "DW_WeaponInspect_PMove": 0x1141160,
    "DW_WeaponInspectInput_Capture": 0x19F9810,
    "DW_WeaponInspectInput_Unbind": 0x19F99E0,
    "DW_WeaponInspectInput_Reset": 0x19F9C00,
    "DW_WeaponInspectInput_GetDefault": 0x19FA720,
    "DW_WeaponInspectInput_GetBound": 0x19FAC70,
    "DW_WeaponInspectInput_HandleKey": 0x19D1A80,
}


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def literal(path, name):
    values = [
        ast.literal_eval(node.value)
        for node in ast.parse(Path(path).read_text()).body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        )
    ]
    assert len(values) == 1, ("Missing/duplicate generator declaration", name)
    return values[0]


def branch_to(obj, owner, target):
    """Require an actual direct call/tail-call relocation in this COFF owner."""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64

    rows = [
        symbol
        for symbol in obj["symbols"].values()
        if symbol["name"] == owner and symbol["section"] > 0 and symbol["storage"] == 2
    ]
    assert len(rows) == 1, ("Missing direct branch owner", owner)
    section = obj["sections"][rows[0]["section"] - 1]
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    offsets = {
        instruction.address + instruction.imm_offset
        for instruction in decoder.disasm(bytes(section["data"]), 0)
        if instruction.mnemonic in ("call", "jmp") and instruction.imm_size == 4
    }
    sites = [
        offset
        for offset, index, kind in section["relocations"]
        if 4 <= kind <= 9
        and offset in offsets
        and obj["symbols"][index]["name"] == target
    ]
    assert sites, ("Missing direct reliable inspection branch", owner, target)
    return sites


def linked_object(pe, obj, symbols, roots, ranges=()):
    """Match complete reachable COFF sections and every relocation destination."""
    anchors, pending, checked, relocations = {}, [], {}, 0

    def anchor(index, start):
        assert 0 < start < pe.OPTIONAL_HEADER.SizeOfImage
        if index in anchors:
            assert anchors[index] == start, ("Conflicting linked section owner", index)
        else:
            anchors[index] = start
            pending.append(index)

    for name in roots:
        rows = [
            symbol
            for symbol in obj["symbols"].values()
            if symbol["name"] == name
            and symbol["section"] > 0
            and symbol["storage"] == 2
        ]
        assert len(rows) == 1 and name in symbols, (
            "Missing/duplicate COFF owner",
            name,
        )
        anchor(rows[0]["section"], symbols[name] - rows[0]["value"])
    while pending:
        index = pending.pop()
        section, start = obj["sections"][index - 1], anchors[index]
        expected = bytearray(section["data"])
        actual = bytearray(pe.get_data(start, len(expected)))
        assert len(actual) == len(expected), ("Truncated linked section", index)
        for offset, symbol_index, kind in section["relocations"]:
            if kind == 0:
                continue
            target = obj["symbols"][symbol_index]
            visited = set()
            while "weak" in target and target["name"] not in symbols:
                assert symbol_index not in visited, "Cyclic weak COFF fallback"
                visited.add(symbol_index)
                symbol_index = target["weak"]["fallback"]
                target = obj["symbols"][symbol_index]
            absolute = target["section"] == -1
            if 4 <= kind <= 9:
                width = 4
                value = (
                    start
                    + offset
                    + kind
                    + struct.unpack_from("<i", actual, offset)[0]
                    - struct.unpack_from("<i", expected, offset)[0]
                )
            elif kind in (1, 2, 3):
                width = 8 if kind == 1 else 4
                unsigned, signed = ("<Q", "<q") if width == 8 else ("<I", "<i")
                value = (
                    struct.unpack_from(unsigned, actual, offset)[0]
                    - struct.unpack_from(signed, expected, offset)[0]
                )
                if kind in (1, 2) and not absolute:
                    value -= pe.OPTIONAL_HEADER.ImageBase
            else:
                raise AssertionError(("Unsupported reachable relocation schema", kind))
            if target["section"] > 0:
                anchor(target["section"], value - target["value"])
            elif absolute:
                assert value == target["value"], (
                    "Changed absolute operand",
                    target["name"],
                )
            else:
                if target["name"] in symbols:
                    destination = symbols[target["name"]]
                else:
                    assert re.fullmatch(r"replay_rva_[0-9a-fA-F]{8}", target["name"]), (
                        "Unresolved linked operand",
                        target["name"],
                    )
                    original = int(target["name"][11:], 16)
                    mapped = [
                        row for row in ranges if row["begin"] <= original < row["end"]
                    ]
                    assert len(mapped) == 1, (
                        "Missing/duplicate native RVA mapping",
                        target["name"],
                    )
                    destination = (
                        mapped[0]["mapped_begin"] + original - mapped[0]["begin"]
                    )
                assert value == destination, ("Wrong linked operand", target["name"])
            expected[offset : offset + width] = actual[offset : offset + width] = bytes(
                width
            )
            relocations += 1
        assert actual == expected, (
            "Compiled section differs from linked bytes",
            section["name"],
            index,
        )
        checked[index] = dict(rva=start, bytes=len(expected))
    return dict(sections=checked, relocations=relocations)


def verify(build):
    import pefile

    build = Path(build).resolve(strict=True)
    report = read(build / "build-report.json")
    snapshot = Path(report["source_root"]).resolve(strict=True)
    assert snapshot.is_relative_to(ROOT / "data"), "Different private source root"
    image = Path(report["executable"])
    image = (image if image.is_absolute() else build / image).resolve(strict=True)
    assert (
        image.is_relative_to(build)
        and sha(image) == report["sha256"]
        and not report["unresolved_symbols"]
    )
    verification = read(build / "verification-report.json")
    assert (
        verification["sha256"] == report["sha256"]
        and not verification["unresolved_symbols"]
    )
    catalog = read(snapshot / "generated/function-catalog.json")
    assert (
        report["input_sha256"]
        == catalog["image_sha256"]
        == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
    )
    by_rva = {row["rva"]: row for row in catalog["functions"]}
    pe = pefile.PE(str(image))
    original = Path("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe")
    assert sha(original) == catalog["image_sha256"]
    native = pefile.PE(str(original))
    spec = importlib.util.spec_from_file_location(
        "inspect_frozen_coff", snapshot / "tools/coff.py"
    )
    coff = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(coff)
    associations = read(snapshot / "source-units.json")["units"]
    revisions = read(snapshot / "source-workstation/units.json")["units"]
    symbols = report["symbols"]
    objects, object_receipts = {}, {}

    def unit(name, required=()):
        source = snapshot / ("src/" + name)
        rows = [
            row
            for row in report["cpp"]
            if Path(row["source"]).as_posix() == "src/" + name
        ]
        assert len(rows) == 1 and rows[0]["source_sha256"] == sha(source), (
            "Missing/changed compiled owner",
            name,
        )
        row = rows[0]
        objpath = Path(row["object"]).resolve(strict=True)
        assert objpath.is_relative_to(build) and sha(objpath) == row["object_sha256"]
        dependencies = {
            Path(item["path"]).resolve(): item["sha256"] for item in row["dependencies"]
        }
        assert len(dependencies) == len(row["dependencies"])
        for path, digest in dependencies.items():
            assert sha(path) == digest, ("Changed compiler input", str(path))
        for path in [source, *(snapshot / "src" / item for item in required)]:
            assert dependencies[path.resolve()] == sha(path), (
                "Untracked generated dependency",
                path.name,
            )
        objects[name] = coff.read(objpath)
        object_receipts[name] = dict(
            source_sha256=sha(source),
            object_sha256=row["object_sha256"],
            dependencies=len(dependencies),
        )
        return objects[name]

    owners, linked_checks, clone_checks = {}, {}, []
    for stem, preparation, generator in (
        (
            "DW_WeaponInspect",
            "weapon-inspect-integration.json",
            "prepare-weapon-inspect.py",
        ),
        (
            "DW_WeaponInspectInput",
            "weapon-inspect-input-integration.json",
            "prepare-weapon-inspect-input.py",
        ),
    ):
        proof = read(snapshot / "generated" / preparation)
        assert (
            proof["passed"]
            and proof["original_bodies_assembled"]
            and proof["image_sha256"] == report["input_sha256"]
        )
        assert proof["generator_sha256"] == sha(snapshot / "tools" / generator)
        assert proof["clone_tool_sha256"] == sha(
            snapshot / "tools/replay_owned_clone.py"
        )
        for relative, digest in proof["dependencies"].items():
            assert sha(snapshot / relative) == digest, (
                "Changed preparation dependency",
                relative,
            )
        owner_rows = literal(snapshot / "tools" / generator, "OWNERS")
        required = [stem + ".h", stem + "Bindings.h"] + (
            ["DW_WeaponInspectAssets.h"] if stem == "DW_WeaponInspect" else []
        )
        obj = unit(stem + ".cpp", required)
        unit(stem + "_Native.cpp")
        assert proof["source_sha256"] == sha(snapshot / proof["source"])
        assert {row[1] for row in owner_rows} == set(proof["owners"])
        for rva, symbol, helper, signature, size, digest in owner_rows:
            assert EXPECTED[symbol] == rva
            identity = by_rva[rva]["id"]
            expected_association = dict(
                source=proof["source"], symbol=symbol, function_id=identity
            )
            assert [row for row in associations if row["function_id"] == identity] == [
                expected_association
            ]
            rows = [row for row in revisions if row["function_id"] == identity]
            assert (
                len(rows) == 1
                and rows[0]["source"] == proof["source"]
                and rows[0]["symbol"] == symbol
            )
            assert rows[0]["sha256"] == proof["source_sha256"]
            assert symbols[identity] == symbols[symbol] != symbols[helper], (
                "Wrong linked replacement/clone owner",
                symbol,
            )
            owners[symbol] = dict(
                original_rva=rva,
                identity=identity,
                linked_rva=symbols[symbol],
                clone_rva=symbols[helper],
            )
            clone = next(row for row in proof["clones"] if row["helper"] == helper)
            assert (
                clone["identity"] == identity
                and clone["bytes"] == size
                and clone["preserved_outside_fixups"]
                and clone["gs_unwind_preserved"]
            )
            directory = (
                snapshot
                / "generated"
                / (
                    "weapon-inspect"
                    if stem == "DW_WeaponInspect"
                    else "weapon-inspect-input"
                )
            )
            assert sha(directory / (helper + ".cpp")) == clone["source_sha256"]
            assert sha(directory / (helper + ".obj")) == clone["object_sha256"]
            gs = clone["gs_unwind"]
            assert gs == proof["owners"][symbol]["unwind"]
            expected = bytearray(
                b"".join(
                    native.get_data(row["begin"], row["end"] - row["begin"])
                    for row in gs
                )
            )
            assert (
                len(expected) == size and hashlib.sha256(expected).hexdigest() == digest
            )
            actual = bytearray(pe.get_data(symbols[helper], size))
            for fixup in clone["external_fixups"]:
                if fixup.get("section", ".text") != ".text":
                    continue
                offset, kind = fixup["offset"], fixup["kind"]
                if kind == 3:
                    target = struct.unpack_from("<I", actual, offset)[0]
                else:
                    assert 4 <= kind <= 9
                    target = (
                        symbols[helper]
                        + offset
                        + 4
                        + fixup["trailing_instruction_bytes"]
                        + struct.unpack_from("<i", actual, offset)[0]
                    )
                assert target == symbols[fixup["stable_id"]], (
                    "Wrong native clone reference",
                    helper,
                    fixup,
                )
                actual[offset : offset + 4] = expected[offset : offset + 4] = bytes(4)
            assert actual == expected, ("Retained original fallback changed", helper)
            runtime = sorted(
                [
                    row.struct
                    for row in pe.DIRECTORY_ENTRY_EXCEPTION
                    if row.struct.BeginAddress < symbols[helper] + size
                    and row.struct.EndAddress > symbols[helper]
                ],
                key=lambda row: row.BeginAddress,
            )
            assert len(runtime) == len(gs)
            for index, (old, new) in enumerate(zip(gs, runtime)):
                assert (
                    new.BeginAddress - symbols[helper],
                    new.EndAddress - symbols[helper],
                ) == (old["begin"] - rva, old["end"] - rva)
                before = bytes.fromhex(old["bytes"])
                after = pe.get_data(new.UnwindData, len(before))
                flags = before[0] >> 3
                prefix = 4 + ((before[2] + 1) & ~1) * 2
                assert after[:prefix] == before[:prefix], (
                    "Changed native unwind opcodes",
                    helper,
                )
                if flags == 4:
                    chain = struct.unpack_from("<III", before, prefix)
                    parent = next(
                        i
                        for i, row in enumerate(gs[:index])
                        if chain == (row["begin"], row["end"], row["unwind_rva"])
                    )
                    target = runtime[parent]
                    assert struct.unpack_from("<III", after, prefix) == (
                        target.BeginAddress,
                        target.EndAddress,
                        target.UnwindData,
                    )
                elif flags == 3:
                    fixup = next(
                        row
                        for row in clone["external_fixups"]
                        if row.get("section") == ".xdata"
                        and row["original_site_rva"] == old["unwind_rva"] + prefix
                    )
                    assert (
                        struct.unpack_from("<I", after, prefix)[0]
                        == symbols[fixup["stable_id"]]
                    )
                    assert after[prefix + 4 :] == before[prefix + 4 :]
                else:
                    assert flags == 0 and after == before
            clone_checks.append(
                dict(
                    helper=helper,
                    original_bytes=size,
                    unwind_records=len(runtime),
                    source_sha256=clone["source_sha256"],
                )
            )
        linked_checks[stem] = linked_object(
            pe,
            obj,
            symbols,
            [row[1] for row in owner_rows]
            + (
                ["DW_WeaponInspect_Request", "DW_WeaponInspect_ServerRequest"]
                if stem == "DW_WeaponInspect"
                else []
            ),
            report["rva_map"]["ranges"],
        )
        for alias, identity in proof["imports"].items():
            assert symbols[alias] == symbols[identity], (
                "Changed inspection ABI binding",
                alias,
            )
    assert set(owners) == set(EXPECTED)
    finish_identity = by_rva[0x15B8050]["id"]
    assert not any(
        row["function_id"] == finish_identity
        and row["source"] == "src/DW_WeaponInspect.cpp"
        for row in associations
    ), "Inspection must not replace FinishCmdButtons"
    for name in ("DW_WeaponInspect.cpp", "DW_WeaponInspect_Native.cpp"):
        assert not any(
            symbol["section"] > 0
            and symbol["name"]
            in ("DW_WeaponInspect_FinishButtons", "WIR_OriginalFinishButtons")
            for symbol in objects[name]["symbols"].values()
        ), "Removed button transport remains compiled"
    noclip_obj = unit("DW_Noclip.cpp", ["DW_WeaponInspect.h"])
    linked_checks["DW_Noclip_ClientCommand"] = linked_object(
        pe,
        noclip_obj,
        symbols,
        ["DW_Noclip_ClientCommand"],
        report["rva_map"]["ranges"],
    )
    reliable_dispatch = branch_to(
        noclip_obj, "DW_Noclip_ClientCommand", "DW_WeaponInspect_ServerRequest"
    )
    reliable_request = branch_to(
        objects["DW_WeaponInspect.cpp"],
        "DW_WeaponInspect_Request",
        "WIR_AddReliableCommand",
    )
    runtime_proof = read(snapshot / "generated/weapon-inspect-integration.json")
    assert runtime_proof.get(
        "reliable_transport"
    ), "Missing verified reliable-command transport proof"
    assert runtime_proof["imports"]["WIR_AddReliableCommand"] == by_rva[0x15E03E0]["id"]
    ui_obj = unit("DW_PlaylistUI.cpp", ["DW_WeaponInspectUI_Source.h"])
    linked_checks["DW_PlaylistUI_Frame"] = linked_object(
        pe, ui_obj, symbols, ["DW_PlaylistUI_Frame"], report["rva_map"]["ranges"]
    )
    ui_text = (snapshot / "src/DW_WeaponInspectUI.lua").read_text(encoding="utf-8")
    chunk = (
        "local state=MenuBuilder.m_types.replaydwplaylistfillstate(); "
        "if not state.InstallWeaponInspect then state.InstallWeaponInspect=(function()\n"
        + ui_text
        + "\nend)() end; return state.InstallWeaponInspect() and 1 or 0\n"
    ).encode()
    header = (snapshot / "src/DW_WeaponInspectUI_Source.h").read_bytes()
    match = re.fullmatch(
        rb'#pragma once\ninline constexpr char dwWeaponInspectUISource\[\] = R"REPLAYDW_UI\((.*)\)REPLAYDW_UI";\n',
        header,
        re.S,
    )
    assert (
        match and match[1] == chunk and chunk + b"\0" in image.read_bytes()
    ), "Missing/changed embedded inspection UI"
    package = read(snapshot / "generated/weapon-inspect-assets/package-proof.json")
    assert (
        package["schema"] == "replay120-weapon-inspect-native-package-v1"
        and package["gates"]["native_reader_validated"]
    )
    spec = importlib.util.spec_from_file_location(
        "inspect_frozen_assets", snapshot / "tools/dw_update_assets.py"
    )
    asset_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(asset_module)
    group = asset_module.package_group(snapshot, 2)
    manifest = asset_module.extract(image.read_bytes())
    assert asset_module.decode_groups(manifest)[1] == {
        key: group[key] for key in ("owner", "bundle_sha256", "entries")
    }
    assert (
        read(snapshot / "generated/update-assets.json")["manifest_sha256"]
        == hashlib.sha256(manifest).hexdigest()
    )
    zone_obj = unit("DW_BotStyleZone.cpp", ["DW_WeaponInspectPackage.h"])
    linked_checks["DW_BotStyleZone_LoadFastfiles"] = linked_object(
        pe,
        zone_obj,
        symbols,
        ["DW_BotStyleZone_LoadFastfiles"],
        report["rva_map"]["ranges"],
    )
    package_header = (snapshot / "src/DW_WeaponInspectPackage.h").read_bytes()
    linked_bytes = image.read_bytes()
    for array in ("Fastfile", "Patch", "EmptyFastfile", "EmptyPatch"):
        match = re.search(
            rb"inline const uint8_t " + array.encode() + rb"\[\] = \{(.*?)\};",
            package_header,
            re.S,
        )
        assert match, ("Missing inspection embedded resource", array)
        data = bytes(
            int(value, 16) for value in re.findall(rb"0x([0-9a-f]{2})", match[1])
        )
        assert data and data in linked_bytes, (
            "Missing inspection resource bytes in full EXE",
            array,
        )
        candidates = [
            entry
            for entry in group["entries"]
            if entry["sha256"] == hashlib.sha256(data).hexdigest()
            and entry["size"] == len(data)
        ]
        assert candidates, (
            "Embedded inspection resources differ from update manifest",
            array,
        )
    pe.close()
    native.close()
    return dict(
        passed=True,
        executable_sha256=report["sha256"],
        source_root=str(snapshot),
        owners=owners,
        objects=object_receipts,
        linked_sections=linked_checks,
        native_clones=clone_checks,
        transport="native reliable dw_inspect command; normal scripted-state snapshots",
        reliable_dispatch_coff_offsets=reliable_dispatch,
        reliable_request_coff_offsets=reliable_request,
        usercmd_buttons_owner_replaced=False,
        ui_sha256=hashlib.sha256(chunk).hexdigest(),
        native_package_proof_sha256=sha(
            snapshot / "generated/weapon-inspect-assets/package-proof.json"
        ),
        compiled_image_verified=True,
        verifier_compiled_nothing=True,
        generated_fastfiles=False,
        game_launched=False,
        runtime_behavior_tested=False,
    )


def self_test():
    class PE:
        OPTIONAL_HEADER = type(
            "Header", (), dict(ImageBase=0x140000000, SizeOfImage=0x10000)
        )
        data = bytearray(0x10000)

        def get_data(self, start, size):
            return bytes(self.data[start : start + size])

    pe = PE()
    # A complete synthetic CALL/RET section, with an actual REL32 operand.
    obj = dict(
        sections=[
            dict(name=".text", data=b"\xe8\0\0\0\0\xc3", relocations=[(1, 1, 4)])
        ],
        symbols={
            0: dict(name="owner", section=1, storage=2, value=0),
            1: dict(name="target", section=0, storage=2, value=0),
        },
    )
    pe.data[0x100:0x106] = b"\xe8" + struct.pack("<i", 0x200 - 0x105) + b"\xc3"
    assert (
        linked_object(pe, obj, dict(owner=0x100, target=0x200), ["owner"])[
            "relocations"
        ]
        == 1
    )
    checks = ["Complete compiled section and linked REL32 destination accepted"]
    assert branch_to(obj, "owner", "target") == [1]
    checks.append("Actual direct call relocation identified in the compiled owner")
    try:
        branch_to(obj, "owner", "missing_target")
    except AssertionError:
        checks.append("Rejected missing authenticated server callback branch")
    else:
        raise AssertionError("Accepted missing authenticated server callback branch")
    for label, mutate in [
        ("changed code byte", lambda: pe.data.__setitem__(0x105, 0x90)),
        ("wrong linked call target", lambda: pe.data.__setitem__(0x101, 0)),
    ]:
        original = bytes(pe.data)
        mutate()
        try:
            linked_object(pe, obj, dict(owner=0x100, target=0x200), ["owner"])
        except AssertionError:
            checks.append("Rejected " + label)
        else:
            raise AssertionError("Checker accepted " + label)
        pe.data[:] = original
    return dict(
        passed=True,
        self_test_only=True,
        checks=checks,
        compiled_image_verified=False,
        verifier_compiled_nothing=True,
        generated_fastfiles=False,
        game_launched=False,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert bool(args.build) != args.self_test, "Select --build or --self-test"
    result = self_test() if args.self_test else verify(args.build)
    result["checker_sha256"] = sha(Path(__file__))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(
        "PASS inspection verifier self-test"
        if args.self_test
        else "PASS eight linked inspection runtime/input owners, reliable dispatch, native clones, UI and owned package"
    )
