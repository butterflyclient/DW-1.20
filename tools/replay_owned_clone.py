"""Assemble a complete original body and prove its symbolic COFF fixups."""

import hashlib
import re
import struct
import subprocess

import capstone
from capstone.x86 import X86_OP_MEM, X86_REG_RIP


def assemble(workspace, pe, catalog, row, helper, output, llvm, read_coff,
             *, gs_unwind=None):
    original = workspace._assembly_source(row)
    if gs_unwind is None:
        assert original["editable"] and original["compilable"]
        assert ".seh_proc " + row["id"] in original["content"]
    else:
        limit = original['provenance'].get('editability_limit')
        assert limit is None or limit.startswith('Handler metadata at ')
        spans = original['provenance']['ranges']
        assert spans[0][0] == gs_unwind[0]['begin'] and spans[-1][1] == gs_unwind[-1]['end']
        assert all(a['end'] == b['begin'] for a, b in zip(gs_unwind, gs_unwind[1:]))
        assert sum(b-a for a,b in spans) == sum(r['end']-r['begin'] for r in gs_unwind)
    content = re.sub(r"\b" + row["id"] + r"\b", helper, original["content"])
    content = re.sub(
        r"\bL_([0-9a-f]{8})\b", lambda match: helper + "_L_" + match.group(1), content
    )
    if gs_unwind is not None:
        content = '\n'.join(line for line in content.splitlines()
                            if not line.startswith('.seh_'))
        content = content.replace(helper + ':', helper + ':\n' +
                                  helper + '_L_%08x:' % row['rva'], 1)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    encoded, fixups = [], {}
    address = row["rva"]
    for line in content.splitlines():
        label = re.fullmatch(re.escape(helper) + "_L_([0-9a-f]{8}):", line)
        if label:
            next_address = int(label.group(1), 16)
            assert next_address >= address
            if next_address > address:
                encoded.append(
                    ".byte "
                    + ", ".join(
                        hex(value)
                        for value in pe.get_data(address, next_address - address)
                    )
                )
            address = next_address
        if line.startswith(".") or line.endswith(":") or not line.strip():
            encoded.append(line)
            continue
        size = workspace._instruction_size(address)
        raw = pe.get_data(address, size)
        instruction = next(decoder.disasm(raw, address))
        assert instruction.size == size
        references = re.findall(r"\b(?:fn|sym)_[0-9a-f]{16}\b", line)
        if references:
            assert len(references) == 1
            image_relative = references[0] + "@IMGREL" in line
            rip_relative = any(
                operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP
                for operand in instruction.operands
            )
            # RIP-relative addressing always encodes disp32. Capstone reports
            # disp_size2 for some operand-size-prefixed word stores; verify the
            # raw signed32 target against the catalog below instead.
            field = (
                instruction.disp_offset
                if rip_relative or image_relative
                else instruction.imm_offset
            )
            width = 4 if rip_relative or image_relative else instruction.imm_size
            assert width == 4 and field > 0, (line, hex(address), instruction.op_str)
            tail = size - field - 4
            encoded.append(".byte " + ", ".join(hex(value) for value in raw[:field]))
            encoded.append(
                ".long " + references[0] + "@IMGREL"
                if image_relative
                else ".long " + references[0] + " - . - " + str(4 + tail)
            )
            if tail:
                encoded.append(
                    ".byte " + ", ".join(hex(value) for value in raw[field + 4 :])
                )
            fixups[address - row["rva"] + field] = dict(
                stable_id=references[0],
                original_site_rva=address + field,
                trailing_instruction_bytes=tail,
                original_relative_value=struct.unpack_from("<i", raw, field)[0],
                kind=3 if image_relative else 4,
            )
        else:
            encoded.append(".byte " + ", ".join(hex(value) for value in raw))
        address += size
    assembly = "\n".join(encoded) + "\n"
    unwind_fixups = []
    unwind_expected, unwind_symbols = bytearray(), {}
    if gs_unwind is not None:
        by_rva = {r['rva']: r for r in catalog['functions'] + catalog['symbols']}
        handler = by_rva[next(r for r in catalog['functions']
            if r['id'] == 'fn_3da1e16560231243')['rva']]
        assert hashlib.sha256(pe.get_data(handler['rva'], 29)).hexdigest() == \
            '53989c4a3df823fa742c0bebda04d4729c810916a7f81899cc2b885ae9c8997c'
        primary = gs_unwind[0]
        assembly += helper + '_L_%08x:\n' % gs_unwind[-1]['end']
        assembly += '.section .xdata,"dr"\n.p2align 2\n'
        for index, record in enumerate(gs_unwind):
            blob = bytes.fromhex(record['bytes'])
            assert pe.get_data(record['unwind_rva'], len(blob)) == blob
            flags = blob[0] >> 3
            header_size = 4 + ((blob[2] + 1) & ~1) * 2
            assembly += helper + '_Unwind_%u:\n' % index
            assembly += '.byte ' + ','.join(hex(x) for x in blob[:header_size]) + '\n'
            offset = len(unwind_expected)
            unwind_expected.extend(blob)
            if index == 0:
                assert flags in (0, 3)
                assert len(blob) == header_size + (8 if flags == 3 else 0)
                if flags == 3:
                    assert struct.unpack_from('<I', blob, header_size)[0] == handler['rva']
                    assembly += '.rva ' + handler['id'] + '\n.long ' + \
                        str(struct.unpack_from('<I', blob, header_size + 4)[0]) + '\n'
                    unwind_fixups.append(dict(stable_id=handler['id'], section='.xdata',
                        offset=header_size, kind=3, original_site_rva=record['unwind_rva']+header_size))
                    unwind_symbols[offset + header_size] = handler['id']
            else:
                assert flags == 4 and len(blob) == header_size + 12
                chain = struct.unpack_from('<III', blob, header_size)
                parents = [(i, r) for i, r in enumerate(gs_unwind[:index])
                    if chain == (r['begin'], r['end'], r['unwind_rva'])]
                assert len(parents) == 1
                parent_index, parent = parents[0]
                assembly += '.rva %s_L_%08x\n.rva %s_L_%08x\n.rva %s_Unwind_%u\n' % \
                    (helper, parent['begin'], helper, parent['end'], helper, parent_index)
                for at, symbol in enumerate((helper + '_L_%08x' % parent['begin'],
                        helper + '_L_%08x' % parent['end'],
                        helper + '_Unwind_%u' % parent_index)):
                    unwind_symbols[offset + header_size + at * 4] = symbol
        assembly += '.section .pdata,"dr"\n.p2align 2\n'
        for index, record in enumerate(gs_unwind):
            assembly += '.rva %s_L_%08x\n.rva %s_L_%08x\n.rva %s_Unwind_%u\n' % \
                (helper, record['begin'], helper, record['end'], helper, index)
    assembly = assembly.replace(
        ".globl " + helper,
        ".globl " + helper + "\n.def " + helper + "; .scl 2; .type 32; .endef",
    )
    source = output / (helper + ".cpp")
    source.write_text('asm(R"NATIVEBODY(\n' + assembly + ')NATIVEBODY");\n')
    obj_path = output / (helper + ".obj")
    subprocess.run(
        [
            str(llvm / "clang++.exe"),
            "--target=x86_64-pc-windows-msvc",
            "-c",
            str(source),
            "-o",
            str(obj_path),
            "-ffreestanding",
            "-fno-stack-protector",
            "-funwind-tables",
            "-O2",
            "-std=c++20",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fno-exceptions",
            "-fno-rtti",
        ],
        check=True,
    )
    obj = read_coff(obj_path)
    text = next(section for section in obj["sections"] if section["name"] == ".text")
    expected = bytearray(
        b"".join(
            pe.get_data(begin, end - begin)
            for begin, end in original["provenance"]["ranges"]
        )
    )
    actual = bytearray(text["data"])
    assert len(expected) == len(actual)
    by_id = {
        entry["id"]: entry
        for entry in catalog["functions"] + catalog.get("symbols", [])
    }
    external = []
    for offset, index, kind in text["relocations"]:
        symbol = obj["symbols"][index]["name"]
        derived = fixups[offset]
        assert kind == derived["kind"] and symbol == derived["stable_id"]
        if kind == 3:
            assert derived["original_relative_value"] == by_id[symbol]["rva"]
            assert struct.unpack_from("<i", actual, offset)[0] == 0
        else:
            assert (
                derived["original_relative_value"]
                + derived["original_site_rva"]
                + 4
                + derived["trailing_instruction_bytes"]
                == by_id[symbol]["rva"]
            )
            assert (
                struct.unpack_from("<i", actual, offset)[0]
                == -derived["trailing_instruction_bytes"]
            )
        expected[offset : offset + 4] = actual[offset : offset + 4] = bytes(4)
        external.append(dict(offset=offset, **derived))
    assert expected == actual
    if gs_unwind is not None:
        xdata = next(section for section in obj['sections'] if section['name'] == '.xdata')
        actual_unwind = bytearray(xdata['data'])
        assert len(actual_unwind) == len(unwind_expected)
        assert len(xdata['relocations']) == len(unwind_symbols)
        for offset, index, kind in xdata['relocations']:
            assert kind == 3 and obj['symbols'][index]['name'] == unwind_symbols[offset]
            assert actual_unwind[offset:offset+4] == bytes(4)
            unwind_expected[offset:offset+4] = bytes(4)
        assert unwind_expected == actual_unwind
        pdata = next(section for section in obj['sections'] if section['name'] == '.pdata')
        assert len(pdata['data']) == 12 * len(gs_unwind)
        wanted = [symbol for index, r in enumerate(gs_unwind) for symbol in (
            helper + '_L_%08x' % r['begin'], helper + '_L_%08x' % r['end'],
            helper + '_Unwind_%u' % index)]
        assert len(pdata['relocations']) == len(wanted)
        for offset, index, kind in pdata['relocations']:
            assert kind == 3 and obj['symbols'][index]['name'] == wanted[offset // 4]
            assert pdata['data'][offset:offset+4] == bytes(4)
    unwind_records = sum(
        len(section["data"]) // 12
        for section in obj["sections"]
        if section["name"] == ".pdata"
    )
    assert unwind_records and any(
        section["data"] for section in obj["sections"] if section["name"] == ".xdata"
    )
    proof = dict(
        identity=row["id"],
        helper=helper,
        bytes=len(expected),
        preserved_outside_fixups=True,
        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        object_sha256=hashlib.sha256(obj_path.read_bytes()).hexdigest(),
        unwind_records=unwind_records,
        external_fixups=external + unwind_fixups,
        gs_unwind=gs_unwind,
        gs_unwind_preserved=gs_unwind is not None,
    )
    return source.read_text(), proof
