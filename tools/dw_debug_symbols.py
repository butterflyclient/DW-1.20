"""Emit debugger public symbols for the custom-linked image, without inventing types.

The linker's final symbol table is the authority for relocated addresses. Its
build-owned SQLite catalog supplies naming provenance; it is never reopened here
after linking, which could pair newer names with an older image.
"""

import bisect
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import subprocess
import uuid

import pefile


def public_symbol_yaml(llvm, yaml_path, pdb, guid, pe, symbols, starts):
    """Use compact YAML for the existing LLVM public-symbol writer."""
    with yaml_path.open('w',encoding='utf-8',newline='\n') as out:
        out.write('---\nPdbStream:\n  Age: 1\n  Guid: "{'+str(guid).upper()+'}"\n  Features: [ VC140 ]\n  Version: VC70\n')
        out.write('DbiStream:\n  VerHeader: V70\n  Age: 1\n  MachineType: Amd64\n  SectionHeaders:\n')
        for section in pe.sections:
            out.write('    - Name: '+json.dumps(section.Name.rstrip(b'\0').decode('ascii'))+'\n')
            for key in ('VirtualAddress','SizeOfRawData','PointerToRawData','PointerToRelocations',
                        'PointerToLinenumbers','NumberOfRelocations','NumberOfLinenumbers','Characteristics'):
                out.write(f'      {key}: {getattr(section,key)}\n')
            out.write(f'      VirtualSize: {section.Misc_VirtualSize}\n')
        out.write('PublicsStream:\n  Records:\n')
        for rva,name,segment,function in symbols:
            out.write('    - { Kind: S_PUB32, PublicSym32: { Flags: '+('[ Code ]' if function else '[]')+
                f', Offset: {rva-starts[segment-1]}, Segment: {segment}, Name: '+json.dumps(name,ensure_ascii=True)+' } }\n')
        out.write('...\n')
    subprocess.run([llvm,'yaml2pdb',str(yaml_path),'--pdb='+str(pdb)],check=True)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def compiler_identity_inputs(report):
    """Use the exact frozen compiler's identity contract and recovered manifest."""
    root = Path(report["source_root"])
    module_path = root / "tools/compiler_identity.py"
    manifest_path = root / "generated/manifest.json"
    spec = importlib.util.spec_from_file_location(
        "dw_frozen_compiler_identity", module_path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    manifest = json.loads(manifest_path.read_bytes())
    if manifest["input_sha256"] != report["input_sha256"]:
        raise ValueError("Compiler manifest does not match linked input identity")
    linked = dict(
        manifest, rva_map=report["rva_map"], linked_entry_rva=report["entry_rva"]
    )
    return module, linked, module_path, manifest_path


def prepare_audit(source_root):
    """Replace the obsolete no-debug policy only in a fresh compiler snapshot."""
    path = Path(source_root) / "tools/audit_relocations.py"
    text = path.read_text(encoding="utf-8")
    old = """        if index == 6:
            if new.VirtualAddress or new.Size:
                raise ValueError("Fresh build advertises the original compiler's debug directory")
            continue"""
    new = """        if index == 6:
            from dw_debug_symbols import verify_debug_directory
            debug_directory_proof = verify_debug_directory(report, rebuilt, original)
            continue"""
    if text.count(old) != 1:
        raise ValueError("Relocation audit debug-directory policy anchor drift")
    text = text.replace(old, new)
    # Include the accepted association in the normal audit receipt.
    anchor = "    result = dict("
    if text.count(anchor) != 1:
        raise ValueError("Relocation audit result anchor drift")
    text = text.replace(
        anchor, "    result = dict(debug_directory=debug_directory_proof,"
    )
    compile(text, str(path), "exec")
    path.write_text(text, encoding="utf-8")


def verify_debug_directory(report, rebuilt, original):
    """Accept only this build's new, independently verified public-symbol PDB."""
    debug = report.get("debug_symbols")
    if (
        not debug
        or debug.get("schema") != 1
        or debug.get("kind") != "public-symbols-no-source-lines-or-types"
    ):
        raise ValueError("Fresh debug directory lacks generated-symbol provenance")
    image = Path(report["executable"])
    if digest(image) != report["sha256"]:
        raise ValueError("Debug-directory image hash differs from the link report")
    for kind in ("pdb", "map"):
        if digest(debug[kind]) != debug[kind + "_sha256"]:
            raise ValueError("Debug-directory artifact hash differs: " + kind)
        if Path(debug[kind]).name != "game_dx12_ship_replay_dw." + kind:
            raise ValueError("Unexpected debugger artifact basename")
    catalog = report["function_catalog_snapshot"]
    for path, expected in (
        (catalog["path"], catalog["sha256"]),
        (
            catalog["sqlite"]["catalog_rows_path"],
            catalog["sqlite"]["catalog_rows_sha256"],
        ),
        (
            report["debug_sqlite_snapshot"]["path"],
            report["debug_sqlite_snapshot"]["sha256"],
        ),
    ):
        if digest(path) != expected:
            raise ValueError("Debug symbol naming snapshot changed")
    if (
        debug["catalog"] != catalog
        or debug["sqlite_global_snapshot"] != report["debug_sqlite_snapshot"]
    ):
        raise ValueError("Debug directory uses another naming snapshot")
    section = rebuilt.sections[-1]
    previous = debug["preserved_sections"]
    if (
        len(rebuilt.sections) != len(previous) + 1
        or section.Name.rstrip(b"\0") != b".debug"
        or section.Characteristics != 0x42000040
    ):
        raise ValueError("Debug directory is not the new generated read-only section")
    directory = rebuilt.OPTIONAL_HEADER.DATA_DIRECTORY[6]
    if directory.VirtualAddress != section.VirtualAddress or directory.Size != 28:
        raise ValueError("Debug directory is outside its newly generated section")
    old = original.OPTIONAL_HEADER.DATA_DIRECTORY[6]
    if old.VirtualAddress and directory.VirtualAddress == old.VirtualAddress:
        raise ValueError("Original compiler debug directory was retained")
    expected_codeview = (
        b"RSDS"
        + uuid.UUID(debug["guid"]).bytes_le
        + struct.pack("<I", debug["age"])
        + Path(debug["pdb"]).name.encode("utf-8")
        + b"\0"
    )
    if debug["age"] != 1:
        raise ValueError("Unexpected generated PDB age")
    expected = (
        struct.pack(
            "<IIHHIIII",
            0,
            0,
            0,
            0,
            2,
            len(expected_codeview),
            section.VirtualAddress + 28,
            section.PointerToRawData + 28,
        )
        + expected_codeview
    )
    if section.Misc_VirtualSize != len(
        expected
    ) or section.get_data() != expected.ljust(section.SizeOfRawData, b"\0"):
        raise ValueError(
            "Debug directory/RSDS payload differs from the generated PDB identity"
        )
    identity, manifest, _module, _path = compiler_identity_inputs(report)
    identity.verify(
        image.read_bytes()[:0x80], manifest, rebuilt.OPTIONAL_HEADER.SizeOfImage, report
    )
    for old_section, proof in zip(rebuilt.sections, previous):
        if (
            old_section.VirtualAddress != proof["rva"]
            or old_section.PointerToRawData != proof["raw_offset"]
            or old_section.SizeOfRawData != proof["raw_size"]
            or hashlib.sha256(old_section.get_data()).hexdigest() != proof["sha256"]
        ):
            raise ValueError("Generated debug directory changed an existing section")
    pdb_identity = subprocess.run(
        [debug["llvm_pdbutil"], "pdb2yaml", "--pdb-stream", debug["pdb"]],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    import re

    if debug["guid"] not in pdb_identity.upper() or not re.search(
        r"Age:\s+1\b", pdb_identity
    ):
        raise ValueError("PDB GUID/age does not match the fresh RSDS association")
    proof_path = image.parent / "debug-symbol-verification.json"
    proof = json.loads(proof_path.read_bytes())
    if (
        not proof.get("passed")
        or proof.get("executable_sha256") != report["sha256"]
        or proof.get("guid") != debug["guid"]
        or proof.get("age") != debug["age"]
        or proof.get("public_count") != debug["symbol_count"]
    ):
        raise ValueError(
            "Independent debug-symbol verification belongs to another image"
        )
    return dict(
        kind="generated-public-symbols",
        guid=debug["guid"],
        age=debug["age"],
        pdb_sha256=debug["pdb_sha256"],
        map_sha256=debug["map_sha256"],
        symbol_verification=str(proof_path),
        symbol_verification_sha256=digest(proof_path),
        naming_snapshot_sha256=report["debug_sqlite_snapshot"]["sha256"],
    )


def snapshot_sqlite_names(database, manifest, sqlite_provenance, destination):
    """Freeze current IDA data labels in one read transaction before linking."""
    database = Path(database).resolve()
    base = manifest["image_base"]
    limit = manifest["optional"]["SizeOfImage"]
    expected_md5 = sqlite_provenance["program_md5"].lower()
    named = []
    events = []
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        connection.execute("BEGIN")
        meta_row = connection.execute(
            "SELECT scope,executable_md5,captured_at,digest,total FROM replay_global_inventory_meta WHERE id=1"
        ).fetchone()
        if (
            not meta_row
            or meta_row[0] != "ida-data-heads-v1"
            or meta_row[1].lower() != expected_md5
        ):
            raise ValueError(
                "Latest global inventory does not match verified Replay MD5"
            )

        def validate(rva, address, name):
            if not 0 <= rva < limit or int(address, 0) != base + rva:
                raise ValueError(
                    "SQLite symbol address/RVA is outside verified Replay image"
                )
            if "\0" in name or "\n" in name or "\r" in name:
                raise ValueError(
                    "SQLite symbol contains invalid debugger-name characters"
                )

        total = 0
        for rva, address, name, segment in connection.execute(
            "SELECT rva,address,name,segment FROM replay_global_inventory ORDER BY rva"
        ):
            validate(rva, address, name)
            total += 1
            if name:
                named.append(dict(rva=rva, name=name, segment=segment))
        if total != meta_row[4]:
            raise ValueError("Latest global inventory count differs from metadata")
        for row in connection.execute(
            "SELECT rva,address,kind,name,previous_name,idb_path,updated,event_id FROM replay_ida_symbols ORDER BY rva"
        ):
            rva, address, kind, name, previous, idb, updated, event = row
            validate(rva, address, name)
            if kind not in ("function", "global"):
                raise ValueError("Unknown SQLite IDA symbol kind")
            events.append(
                dict(
                    rva=rva,
                    name=name,
                    kind=kind,
                    previous_name=previous,
                    idb_path=idb,
                    updated=updated,
                    event_id=event,
                )
            )
    document = dict(
        schema=1,
        database=str(database),
        program_md5=expected_md5,
        input_sha256=manifest["input_sha256"],
        image_base=base,
        inventory_meta=dict(
            zip(("scope", "executable_md5", "captured_at", "digest", "total"), meta_row)
        ),
        unnamed_inventory_count=total - len(named),
        inventory=named,
        events=events,
    )
    destination = Path(destination)
    destination.write_text(
        json.dumps(document, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    return dict(
        path=str(destination),
        sha256=digest(destination),
        named_inventory_count=len(named),
        event_count=len(events),
        inventory_count=total,
        program_md5=expected_md5,
    )


def extra_sqlite_symbols(report):
    snapshot = report.get("debug_sqlite_snapshot")
    if not snapshot:
        raise ValueError("Missing prelink SQLite global/IDA-name snapshot")
    if digest(snapshot["path"]) != snapshot["sha256"]:
        raise ValueError("Prelink SQLite symbol snapshot changed")
    document = json.loads(Path(snapshot["path"]).read_bytes())
    if document["input_sha256"] != report["input_sha256"]:
        raise ValueError("SQLite global snapshot belongs to another executable")
    _identity, manifest, _module, _path = compiler_identity_inputs(report)
    catalog = json.loads(Path(report["function_catalog_snapshot"]["path"]).read_bytes())
    entries = {
        row["rva"]: report["symbols"][row["id"]]
        for row in catalog["functions"]
        if not row.get("quarantined")
    }
    ranges = report["rva_map"]["ranges"]
    starts = [row["begin"] for row in ranges]
    result = set()
    skipped = []
    for row in document["inventory"] + document["events"]:
        rva = row["rva"]
        name = row["name"]
        if not name:
            continue
        if rva in entries:
            result.add((name, entries[rva]))
            continue
        section = next(
            (
                s
                for s in manifest["sections"]
                if s["rva"] <= rva < s["rva"] + s["virtual_size"]
            ),
            None,
        )
        if (
            section is None
            or section["flags"] & 0x20000000
            or row.get("kind") == "function"
        ):
            skipped.append(
                dict(
                    name=name,
                    rva=rva,
                    reason="no exact function-entry identity or non-code data proof",
                )
            )
            continue
        index = bisect.bisect_right(starts, rva) - 1
        if index < 0 or not rva < ranges[index]["end"]:
            raise ValueError("Known SQLite data address has no final RVA-map range")
        result.add((name, ranges[index]["mapped_begin"] + rva - starts[index]))
    return result, skipped


def known_symbols(report):
    """Keep ambiguous spellings at every proven identity, as debuggers permit."""
    result = {(name, int(rva)) for name, rva in report["symbols"].items()}
    result.update(extra_sqlite_symbols(report)[0])
    catalog = json.loads(Path(report["function_catalog_snapshot"]["path"]).read_bytes())
    for group in ("functions", "symbols"):
        for row in catalog.get(group, []):
            if row.get("quarantined"):
                continue
            final = report["symbols"].get(row["id"])
            if final is None:
                raise ValueError(
                    "Catalog identity has no final linked address: " + row["id"]
                )
            for name in set(row.get("aliases", [])) | {
                row.get("name"),
                row.get("sqlite_name"),
            }:
                if name:
                    result.add((name, int(final)))
    return result


def emit(report_path):
    report_path = Path(report_path)
    report = json.loads(report_path.read_bytes())
    image = Path(report["executable"])
    if digest(image) != report["sha256"]:
        raise ValueError("Debug symbols require the unchanged linked executable")
    if report.get("debug_symbols"):
        raise ValueError("Debug symbols already emitted for this build")
    catalog = report["function_catalog_snapshot"]
    if digest(catalog["path"]) != catalog["sha256"]:
        raise ValueError("Build-owned name catalog changed")
    sqlite = catalog["sqlite"]
    if digest(sqlite["catalog_rows_path"]) != sqlite["catalog_rows_sha256"]:
        raise ValueError("Build-owned SQLite names changed")
    llvm = shutil.which("llvm-pdbutil") or r"C:\Program Files\LLVM\bin\llvm-pdbutil.exe"
    if not Path(llvm).is_file():
        raise FileNotFoundError("llvm-pdbutil is required for every executable build")
    pe = pefile.PE(str(image), fast_load=True)
    sections = list(pe.sections)
    header_offset = sections[-1].get_file_offset() + 40
    if header_offset + 40 > min(s.PointerToRawData for s in sections):
        raise ValueError("No PE section-header room for debugger association")
    if pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size:
        raise ValueError("Refusing to overwrite an existing PE debug directory")
    pdb = image.with_name("game_dx12_ship_replay_dw.pdb")
    map_path = image.with_name("game_dx12_ship_replay_dw.map")
    yaml_path = image.with_suffix(".pdb.yaml.pending")
    symbol_pairs = known_symbols(report)
    symbol_cache = None
    cache_folder = None
    cache_key = None
    if os.environ.get("REPLAY_OBJECT_CACHE"):
        cache_key = hashlib.sha256(json.dumps(["public-symbol-layout-v1", digest(__file__), digest(llvm),
            image.name, pe.OPTIONAL_HEADER.ImageBase, pe.OPTIONAL_HEADER.SectionAlignment,
            pe.OPTIONAL_HEADER.FileAlignment, pe.OPTIONAL_HEADER.SizeOfImage,
            [section.__pack__().hex() for section in sections], sorted(symbol_pairs)],
            separators=(",", ":")).encode()).hexdigest()
        cache_folder = Path(os.environ["REPLAY_OBJECT_CACHE"]) / "debug-symbols" / cache_key
        metadata = cache_folder / "proof.json"
        try:
            previous = json.loads(metadata.read_bytes())
            if (previous["key"] == cache_key and digest(cache_folder / "symbols.pdb") == previous["pdb_sha256"]):
                uuid.UUID(previous["guid"])
                symbol_cache = previous
        except (OSError, ValueError, KeyError):
            pass
    guid = uuid.UUID(symbol_cache["guid"]) if symbol_cache else uuid.uuid4()
    age = 1
    align = lambda value, size: (value + size - 1) // size * size
    raw = bytearray(image.read_bytes())
    pe.close()
    identity, manifest, identity_path, manifest_path = compiler_identity_inputs(report)
    identity.verify(raw[:0x80], manifest, pe.OPTIONAL_HEADER.SizeOfImage, report)
    pre_debug_stamp = bytes(raw[identity.OFFSET : identity.OFFSET + identity.SIZE])
    preserved_sections = [
        dict(
            name=s.Name.rstrip(b"\0").decode("ascii"),
            rva=s.VirtualAddress,
            raw_offset=s.PointerToRawData,
            raw_size=s.SizeOfRawData,
            sha256=hashlib.sha256(
                raw[s.PointerToRawData : s.PointerToRawData + s.SizeOfRawData]
            ).hexdigest(),
        )
        for s in sections
    ]
    raw_offset = align(len(raw), pe.OPTIONAL_HEADER.FileAlignment)
    debug_rva = align(
        max(
            s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)
            for s in sections
        ),
        pe.OPTIONAL_HEADER.SectionAlignment,
    )
    codeview = (
        b"RSDS"
        + guid.bytes_le
        + struct.pack("<I", age)
        + pdb.name.encode("utf-8")
        + b"\0"
    )
    payload = (
        struct.pack(
            "<IIHHIIII", 0, 0, 0, 0, 2, len(codeview), debug_rva + 28, raw_offset + 28
        )
        + codeview
    )
    raw_size = align(len(payload), pe.OPTIONAL_HEADER.FileAlignment)
    new_header = struct.pack(
        "<8sIIIIIIHHI",
        b".debug\0\0",
        len(payload),
        debug_rva,
        raw_size,
        raw_offset,
        0,
        0,
        0,
        0,
        0x42000040,
    )
    raw[header_offset : header_offset + 40] = new_header
    struct.pack_into(
        "<H",
        raw,
        pe.FILE_HEADER.get_field_absolute_offset("NumberOfSections"),
        len(sections) + 1,
    )
    struct.pack_into(
        "<I",
        raw,
        pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfImage"),
        align(debug_rva + len(payload), pe.OPTIONAL_HEADER.SectionAlignment),
    )
    struct.pack_into(
        "<I",
        raw,
        pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfInitializedData"),
        pe.OPTIONAL_HEADER.SizeOfInitializedData + raw_size,
    )
    struct.pack_into(
        "<II",
        raw,
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].get_file_offset(),
        debug_rva,
        28,
    )
    struct.pack_into(
        "<I", raw, pe.OPTIONAL_HEADER.get_field_absolute_offset("CheckSum"), 0
    )
    raw.extend(b"\0" * (raw_offset - len(raw)))
    raw.extend(payload + b"\0" * (raw_size - len(payload)))
    final_size = align(debug_rva + len(payload), pe.OPTIONAL_HEADER.SectionAlignment)
    raw[identity.OFFSET : identity.OFFSET + identity.SIZE] = identity.encode(
        manifest, final_size
    )
    identity.verify(raw[:0x80], manifest, final_size, report)
    for section in preserved_sections:
        begin = section["raw_offset"]
        if (
            hashlib.sha256(raw[begin : begin + section["raw_size"]]).hexdigest()
            != section["sha256"]
        ):
            raise ValueError(
                "Debug association altered existing section: " + section["name"]
            )
    # Parse the final headers, including the new debug section, for PDB section RVAs.
    final_pe = pefile.PE(data=bytes(raw), fast_load=True)
    starts = [s.VirtualAddress for s in final_pe.sections]
    symbols = []
    omitted = []
    for name, rva in symbol_pairs:
        index = bisect.bisect_right(starts, rva) - 1
        if index < 0 or rva >= starts[index] + max(
            final_pe.sections[index].Misc_VirtualSize,
            final_pe.sections[index].SizeOfRawData,
        ):
            omitted.append(
                {"name": name, "rva": rva, "reason": "outside mapped image sections"}
            )
            continue
        symbols.append(
            (
                rva,
                name,
                index + 1,
                bool(final_pe.sections[index].Characteristics & 0x20000000),
            )
        )
    symbols.sort()
    if symbol_cache:
        shutil.copyfile(cache_folder / "symbols.pdb", pdb)
    else:
        public_symbol_yaml(llvm, yaml_path, pdb, guid, final_pe, symbols, starts)
    check = subprocess.run(
        [llvm, "pdb2yaml", "--pdb-stream", "--dbi-stream", str(pdb)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if str(guid).upper() not in check.upper() or "Age:             1" not in check:
        raise ValueError("PDB GUID/age verification failed")
    with map_path.open("w", encoding="utf-8", newline="\n") as out:
        out.write(
            f"{image.name}\n Preferred load address is {final_pe.OPTIONAL_HEADER.ImageBase:016X}\n\n Address         Publics by Value              Rva+Base\n\n"
        )
        for rva, name, segment, function in symbols:
            out.write(
                f' {segment:04X}:{rva - starts[segment - 1]:08X} {name} {final_pe.OPTIONAL_HEADER.ImageBase + rva:016X} {"f" if function else "d"}\n'
            )
    # Commit the association only after LLVM successfully reopens the PDB.
    temporary = image.with_suffix(".exe.debug.pending")
    temporary.write_bytes(raw)
    temporary.replace(image)
    yaml_path.unlink(missing_ok=True)
    if cache_folder and not symbol_cache:
        cache_folder.mkdir(parents=True, exist_ok=True)
        pending = cache_folder / "symbols.pdb.pending"
        shutil.copyfile(pdb, pending)
        os.replace(pending, cache_folder / "symbols.pdb")
        pending = cache_folder / "proof.json.pending"
        pending.write_text(json.dumps(dict(key=cache_key, guid=str(guid).upper(),
            pdb_sha256=digest(pdb), public_count=len(symbols)), indent=2)+"\n", encoding="utf-8")
        os.replace(pending, cache_folder / "proof.json")
    report["debug_symbols"] = dict(
        schema=1,
        kind="public-symbols-no-source-lines-or-types",
        pdb=str(pdb),
        pdb_sha256=digest(pdb),
        map=str(map_path),
        map_sha256=digest(map_path),
        guid=str(guid).upper(),
        age=age,
        symbol_count=len(symbols),
        symbol_cache_hit=bool(symbol_cache),
        symbol_cache_key=cache_key,
        omitted_symbols=omitted,
        pre_debug_image_sha256=report["sha256"],
        pre_debug_image_size=pe.OPTIONAL_HEADER.SizeOfImage,
        pre_debug_compiler_stamp=pre_debug_stamp.hex(),
        preserved_sections=preserved_sections,
        compiler_identity=dict(
            path=str(identity_path),
            sha256=digest(identity_path),
            manifest=str(manifest_path),
            manifest_sha256=digest(manifest_path),
        ),
        catalog=catalog,
        sqlite_global_snapshot=report["debug_sqlite_snapshot"],
        sqlite_names_without_address_proof=extra_sqlite_symbols(report)[1],
        generator_sha256=digest(__file__),
        llvm_pdbutil=str(llvm),
        llvm_pdbutil_sha256=digest(llvm),
    )
    report["sha256"] = digest(image)
    report["image_size"] = final_pe.OPTIONAL_HEADER.SizeOfImage
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report["debug_symbols"]
