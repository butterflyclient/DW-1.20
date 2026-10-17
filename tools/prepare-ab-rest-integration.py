"""Derive a private AB REST replacement's native imports and layout at compile time.

No RVA or function extent is supplied by engine C++. The same-image catalog
identifies candidates, original instructions determine callees and offsets,
and the standard compiler resolves their stable identities to linked symbols.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RBX, X86_REG_RDI, X86_REG_RDX

ROOT = Path(__file__).resolve().parents[1]


def prepare(snapshot):
    snapshot = snapshot.resolve()
    assert snapshot.is_relative_to(ROOT / "data")
    catalog_path = snapshot / "generated/function-catalog.json"
    catalog = json.loads(catalog_path.read_bytes())
    manifest = json.loads((snapshot / "generated/manifest.json").read_bytes())
    image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
    raw = image.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    assert digest == manifest["input_sha256"] == catalog["image_sha256"]
    assert digest == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
    pe = pefile.PE(data=raw, fast_load=True)
    pe.parse_data_directories(directories=[3])
    base = pe.OPTIONAL_HEADER.ImageBase

    def named(name):
        rows = [row for row in catalog["functions"] if name in (row["id"], row["name"], *row["aliases"])]
        assert len(rows) == 1 and not rows[0].get("quarantined"), name
        return rows[0]

    writer = named("bdABTestingEnrollRequest::restSerializeRequest")
    entries = {row.struct.BeginAddress: row for row in pe.DIRECTORY_ENTRY_EXCEPTION}
    entry = entries[writer["rva"]]
    assert not entry.unwindinfo.UNW_FLAG_CHAININFO
    code = pe.get_data(writer["rva"], entry.struct.EndAddress - writer["rva"])
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(code, base + writer["rva"]))
    assert sum(row.size for row in instructions) == len(code)
    calls = [row for row in instructions if row.mnemonic == "call" and row.operands[0].type == X86_OP_IMM]
    # Validate the original formatter's entire repeated-call topology, rather
    # than treating a named decompiler function or a positional call as proof.
    assert len(calls) == 20
    targets = [row.operands[0].imm for row in calls]
    assert all(targets[index] == targets[3] for index in (5, 7, 9, 11, 13))
    assert targets[8] == targets[10] == targets[12]
    assert targets[14] == targets[15]
    assert len(set(targets)) == 12
    dummy = pe.get_data(targets[8] - base, 4)
    assert [(row.mnemonic, row.op_str) for row in decoder.disasm(dummy, targets[8])] == [("mov", "rax, rcx"), ("ret", "")]
    imports = dict(DW_AB_BuilderLobby=targets[0], DW_AB_BuilderAuth=targets[1],
                   DW_AB_BuilderURI=targets[2], DW_AB_AppendBlock=targets[3],
                   DW_AB_AppendString=targets[4], DW_AB_AppendNumber=targets[6],
                   DW_AB_URIIsOK=targets[14], DW_AB_SetMethod=targets[16],
                   DW_AB_BuilderHeaders=targets[17], DW_AB_SetAccept=targets[18],
                   DW_AB_SetResource=targets[19])
    by_address = {base + row["rva"]: row for row in catalog["functions"] if not row.get("quarantined")}
    service = named("q_bdRESTRequestBuilder::setServiceName")
    imports["DW_AB_SetService"] = base + service["rva"]
    assert imports["DW_AB_SetService"] not in targets

    resets = []
    for row in instructions:
        if row.address >= calls[3].address:
            break
        if row.mnemonic == "mov" and row.operands[0].type == X86_OP_MEM and row.operands[1].type == X86_OP_IMM:
            destination = row.operands[0]
            if destination.mem.base == X86_REG_RDI and destination.mem.index == 0 and row.operands[1].imm == 0:
                resets.append((destination.size, destination.mem.disp))
    assert len(resets) == 2 and sorted(size for size, _ in resets) == [1, 4]
    reset_offsets = dict(resets)

    def auth_operand(call_index, operation):
        before = [row for row in instructions if row.address < calls[call_index].address][-3:]
        matches = [row for row in before if row.mnemonic == operation and
                   row.operands[0].type == X86_OP_REG and row.operands[0].reg == X86_REG_RDX and
                   row.operands[1].type == X86_OP_MEM and row.operands[1].mem.base == X86_REG_RBX and
                   row.operands[1].mem.index == 0]
        assert len(matches) == 1
        return matches[0].operands[1].mem.disp

    account_offset, user_offset = auth_operand(4, "lea"), auth_operand(6, "mov")
    # Wire enums are also extracted from the writer rather than copied into the
    # C++ replacement. The target constants remain recorded as evidence.
    def integer_argument(call_index):
        before = [row for row in instructions if row.address < calls[call_index].address][-3:]
        matches = [row for row in before if row.mnemonic == "mov" and row.operands[0].type == X86_OP_REG and
                   row.reg_name(row.operands[0].reg) == "edx" and row.operands[1].type == X86_OP_IMM]
        assert len(matches) == 1
        return matches[0].operands[1].imm

    method, mime = integer_argument(16), integer_argument(18)
    header = ["#pragma once", "#include <cstdint>", "",
              "// Generated from original Replay instructions during private compilation.",
              f"// Original image SHA256 {digest}",
              'extern "C" {',
              "void *DW_AB_BuilderLobby(void *);", "void *DW_AB_BuilderAuth(void *);",
              "void *DW_AB_BuilderURI(void *);", "void *DW_AB_BuilderHeaders(void *);",
              "void DW_AB_AppendBlock(void *, const char **);", "void *DW_AB_AppendString(void *, const char *);",
              "void *DW_AB_AppendNumber(void *, uint64_t);", "bool DW_AB_URIIsOK(void *);",
              "bool DW_AB_SetMethod(void *, uint32_t);", "bool DW_AB_SetAccept(void *, uint32_t);",
              "bool DW_AB_SetResource(void *, const char *, const char *);", "bool DW_AB_SetService(void *, const char *);", "}",
              f"inline constexpr uint32_t DW_AB_PostMethod = {method};",
              f"inline constexpr uint32_t DW_AB_JsonMime = {mime};",
              "inline void DW_AB_ResetPath(void *uri)", "{",
              f"    *reinterpret_cast<uint8_t *>(static_cast<uint8_t *>(uri) + {reset_offsets[1]}) = 0;",
              f"    *reinterpret_cast<uint32_t *>(static_cast<uint8_t *>(uri) + {reset_offsets[4]}) = 0;", "}",
              "inline const char *DW_AB_AccountType(const void *auth)", "{",
              f"    return static_cast<const char *>(auth) + {account_offset};", "}",
              "inline uint64_t DW_AB_UserID(const void *auth)", "{",
              f"    return *reinterpret_cast<const uint64_t *>(static_cast<const uint8_t *>(auth) + {user_offset});", "}", ""]
    generated = snapshot / "src/DW_ABTestingEnrollBindings.h"
    generated.write_text("\n".join(header), encoding="utf-8")
    sys.path.insert(0, str(snapshot / "tools"))
    spec = importlib.util.spec_from_file_location("private_ab_source_catalog", snapshot / "tools/source_catalog.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    shim = importlib.util.spec_from_file_location("dw_catalog", Path(__file__).resolve().with_name("dw_catalog.py"))
    shim_module = importlib.util.module_from_spec(shim)
    shim.loader.exec_module(shim_module)
    shim_module.share_catalog(module)  # one catalog parse, not one per binding
    module.bind(writer["id"], Path("src/DW_ABTestingEnroll.cpp"), "bdABTestingEnrollRequest_RestSerializeRequest")
    bindings = []
    for alias, address in imports.items():
        assert address in by_address, alias
        row = by_address[address]
        module.bind_import(row["id"], alias)
        bindings.append(dict(symbol=alias, function_id=row["id"], original_rva=row["rva"]))
    units_path = snapshot / "source-workstation/units.json"
    units = json.loads(units_path.read_bytes())
    assert not any(row["function_id"] == writer["id"] for row in units["units"])
    source = snapshot / "src/DW_ABTestingEnroll.cpp"
    source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    units["units"].append(dict(function_id=writer["id"], kind="cpp", source="src/DW_ABTestingEnroll.cpp",
                              symbol="bdABTestingEnrollRequest_RestSerializeRequest", sha256=source_digest,
                              revision=source_digest, language="cpp"))
    units_path.write_text(json.dumps(units, indent=2) + "\n")
    receipt = dict(passed=True, original_image_sha256=digest,
        generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        original_writer=dict(function_id=writer["id"], rva=writer["rva"], code_size=len(code),
                             code_sha256=hashlib.sha256(code).hexdigest()),
        source_sha256=source_digest, generated_header_sha256=hashlib.sha256(generated.read_bytes()).hexdigest(),
        derived_layout=dict(path_byte=reset_offsets[1], path_length=reset_offsets[4], account_type=account_offset,
                            user_id=user_offset, method=method, mime=mime), bindings=bindings,
        calls=[dict(site=row.address, target=row.operands[0].imm) for row in calls],
        no_manual_source_rvas_or_layouts=True, shared_workstation_modified=False)
    (snapshot / "generated/ab-rest-integration.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    args = parser.parse_args()
    result = prepare(args.snapshot)
    print("Derived AB REST replacement and", len(result["bindings"]), "native imports")
