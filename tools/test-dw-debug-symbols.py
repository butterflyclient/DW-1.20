"""Reopen each linked image/PDB/MAP and prove all public addresses agree."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import uuid

import pefile
from dw_debug_symbols import (
    compiler_identity_inputs,
    digest,
    extra_sqlite_symbols,
    known_symbols,
)


def verify(build):
    report_path = Path(build) / "build-report.json"
    report = json.loads(report_path.read_bytes())
    debug = report["debug_symbols"]
    sqlite_snapshot = report["debug_sqlite_snapshot"]
    assert debug["sqlite_global_snapshot"] == sqlite_snapshot
    assert (
        sqlite_snapshot["program_md5"]
        == report["function_catalog_snapshot"]["sqlite"]["program_md5"]
    )
    extra_symbols, unproven = extra_sqlite_symbols(report)
    assert unproven == debug["sqlite_names_without_address_proof"]
    image = Path(report["executable"])
    assert digest(image) == report["sha256"], "EXE hash differs"
    for kind in ("pdb", "map"):
        assert digest(debug[kind]) == debug[kind + "_sha256"], kind + " hash differs"
    pe = pefile.PE(str(image), fast_load=True)
    identity, manifest, identity_path, manifest_path = compiler_identity_inputs(report)
    assert digest(identity_path) == debug["compiler_identity"]["sha256"]
    assert digest(manifest_path) == debug["compiler_identity"]["manifest_sha256"]
    header = image.read_bytes()[:0x80]
    identity.verify(header, manifest, pe.OPTIONAL_HEADER.SizeOfImage, report)
    assert bytes.fromhex(debug["pre_debug_compiler_stamp"]) == identity.encode(
        manifest, debug["pre_debug_image_size"]
    )
    assert len(pe.sections) == len(debug["preserved_sections"]) + 1
    for section, before in zip(pe.sections, debug["preserved_sections"]):
        assert section.Name.rstrip(b"\0").decode("ascii") == before["name"]
        assert section.VirtualAddress == before["rva"]
        assert section.PointerToRawData == before["raw_offset"]
        assert section.SizeOfRawData == before["raw_size"]
        assert (
            hashlib.sha256(section.get_data()).hexdigest() == before["sha256"]
        ), "Existing section bytes changed"
    pe.parse_data_directories(directories=[6])
    records = [entry for entry in pe.DIRECTORY_ENTRY_DEBUG if entry.struct.Type == 2]
    assert len(records) == 1, "Expected exactly one CodeView association"
    record = records[0].struct
    codeview = pe.get_data(record.AddressOfRawData, record.SizeOfData)
    assert codeview[:4] == b"RSDS"
    assert str(uuid.UUID(bytes_le=codeview[4:20])).upper() == debug["guid"]
    assert struct.unpack_from("<I", codeview, 20)[0] == debug["age"]
    assert codeview[24:].rstrip(b"\0").decode() == Path(debug["pdb"]).name
    assert Path(debug["pdb"]).name == "game_dx12_ship_replay_dw.pdb"
    headers = subprocess.run(
        [
            debug["llvm_pdbutil"],
            "pdb2yaml",
            "--pdb-stream",
            "--dbi-stream",
            "--section-headers",
            debug["pdb"],
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert debug["guid"] in headers.upper(), "PDB GUID differs from RSDS"
    assert re.search(r"Age:\s+" + str(debug["age"]) + r"\b", headers)
    section_rvas = [
        int(value) for value in re.findall(r"VirtualAddress:\s+(\d+)", headers)
    ]
    assert section_rvas == [section.VirtualAddress for section in pe.sections]
    expected = set()
    omitted = {(entry["name"], entry["rva"]) for entry in debug["omitted_symbols"]}
    for name, rva in known_symbols(report):
        if (name, rva) in omitted:
            assert not any(
                s.VirtualAddress
                <= rva
                < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)
                for s in pe.sections
            ), "Mapped symbol was incorrectly omitted"
        else:
            expected.add((name, rva))
    map_symbols = set()
    with Path(debug["map"]).open(encoding="utf-8") as source:
        for line in source:
            match = re.match(
                r" ([0-9A-F]{4}):([0-9A-F]{8}) (.*) ([0-9A-F]{16}) [fd]$",
                line.rstrip("\n"),
            )
            if match:
                segment, offset = int(match[1], 16), int(match[2], 16)
                rva = section_rvas[segment - 1] + offset
                assert rva + pe.OPTIONAL_HEADER.ImageBase == int(match[4], 16)
                map_symbols.add((match[3], rva))
    assert map_symbols == expected, "MAP does not cover all verified public symbols"
    dump = Path(build) / "debug-publics.pending.txt"
    try:
        with dump.open("w", encoding="utf-8") as output:
            subprocess.run(
                [debug["llvm_pdbutil"], "dump", "--publics", debug["pdb"]],
                stdout=output,
                check=True,
            )
        publics = set()
        name = None
        with dump.open(encoding="utf-8") as source:
            for line in source:
                if " | S_PUB32 " in line:
                    name = line.split("`", 1)[1].rsplit("`", 1)[0]
                elif name is not None and "addr = " in line:
                    segment, offset = line.split("addr = ", 1)[1].strip().split(":")
                    publics.add((name, section_rvas[int(segment) - 1] + int(offset)))
                    name = None
        assert publics == expected, "PDB does not cover all verified public symbols"
    finally:
        dump.unlink(missing_ok=True)
        pe.close()
    catalog = json.loads(Path(report["function_catalog_snapshot"]["path"]).read_bytes())
    moved = []
    for row in catalog["functions"]:
        final = report["symbols"].get(row["id"])
        if final is not None and final != row["rva"]:
            moved.append(
                dict(name=row["name"], original_rva=row["rva"], final_rva=final)
            )
            if len(moved) == 8:
                break
    result = dict(
        passed=True,
        executable_sha256=report["sha256"],
        compiler_stamp_verified=True,
        pre_debug_compiler_stamp_verified=True,
        pre_debug_image_size=debug["pre_debug_image_size"],
        final_image_size=pe.OPTIONAL_HEADER.SizeOfImage,
        preserved_section_count=len(debug["preserved_sections"]),
        preserved_section_bytes_verified=True,
        public_count=len(expected),
        sqlite_global_inventory_count=sqlite_snapshot["inventory_count"],
        sqlite_named_inventory_count=sqlite_snapshot["named_inventory_count"],
        sqlite_ida_event_count=sqlite_snapshot["event_count"],
        sqlite_proven_name_address_count=len(extra_symbols),
        sqlite_names_without_address_proof_count=len(unproven),
        omitted_count=len(omitted),
        moved_address_examples=moved,
        guid=debug["guid"],
        age=debug["age"],
        scope="Public code/data names only; no source lines, local variables, or types",
    )
    (Path(build) / "debug-symbol-verification.json").write_text(
        json.dumps(result, indent=2) + "\n"
    )
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = verify(args.build)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
