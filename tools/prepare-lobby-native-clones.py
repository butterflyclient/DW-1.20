"""Prepare byte-faithful PartyHost native clones and guarded-root bindings in a fresh private DW snapshot."""

from workstation_preparation_context import cached_input_json, shared_original_pe, source_context
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import struct
import pefile
import capstone

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--snapshot", type=Path, required=True, help="Fresh private compiler source under the DW root")
parser.add_argument("--output", type=Path, required=True, help="Preparation provenance receipt outside compiler-source/src")
parser.add_argument("--wrapper-source", default="src/DW_LobbyControls.cpp")
parser.add_argument("--original-image", type=Path, default=Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe"))
parser.add_argument("--emit-only", action="store_true", help="Component proof only: do not change root/import/unit metadata")
args = parser.parse_args()
SNAPSHOT = args.snapshot.resolve(strict=True)
assert SNAPSHOT.is_relative_to(ROOT) and SNAPSHOT != ROOT, "Private compiler source must remain under E DW"
assert not (SNAPSHOT.parent / "client-readiness.json").exists(), "Never regenerate a sealed completed client snapshot"
OUTPUT = args.output.resolve()
assert OUTPUT.is_relative_to(ROOT) and not OUTPUT.is_relative_to(SNAPSHOT / "src")
HERE = OUTPUT.parent
HERE.mkdir(parents=True, exist_ok=True)
wrapper = (SNAPSHOT / args.wrapper_source).resolve()
assert wrapper.is_relative_to(SNAPSHOT / "src")
if not args.emit_only:
    assert wrapper.is_file()
    wrapper_text = wrapper.read_text()
    assert all(re.search(r"\b" + symbol + r"\s*\([^;]*\)\s*\{", wrapper_text) for symbol in ("func_14119E3D0", "func_14119B0E0")), "Both guarded wrappers must exist before preparation"
sys.path.insert(0, str(SNAPSHOT / "tools"))
from workstation_sources import SourceWorkspace
from coff import read
from build import LLVM

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

catalog = cached_input_json(SNAPSHOT / 'generated/function-catalog.json')
workspace = SourceWorkspace(SNAPSHOT, HERE / "cache")
workspace._catalog = catalog
workspace._state = lambda: {"sources": {}}
targets = (
    ("fn_d77ce7965aec9acf", "DW_LobbyControls_StartMatchInternalNative"),
    ("fn_1fc040042c6dcd2c", "DW_LobbyControls_ReadyToLaunchNative"),
)
results, rendered, derived_fixups = [], [], {}
assert catalog["image_sha256"] == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
original_path = args.original_image.resolve(strict=True)
assert digest(original_path) == catalog["image_sha256"]
original_pe = shared_original_pe(str(original_path), fast_load=True)
decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
decoder.detail = True
for identity, helper in targets:
    row = next(r for r in catalog["functions"] if r["id"] == identity and not r.get("quarantined"))
    rva = row["rva"]
    original = workspace._assembly_source(row)
    assert original["compilable"] and original["editable"], original["provenance"]
    content = original["content"]
    assert ".seh_proc " + row["id"] in content
    renamed = re.sub(r"\b" + re.escape(row["id"]) + r"\b", helper, content)
    renamed = re.sub(r"\bL_([0-9a-f]{8})\b", lambda m: helper + "_L_" + m.group(1), renamed)
    # Keep the exact pinned native instruction encoding. Compiler-rendered
    # semantic references supply the symbolic relocation field; assembler
    # directives continue to derive the real Win64 unwind records.
    encoded, address = [], rva
    for line in renamed.splitlines():
        label = re.fullmatch(re.escape(helper) + r"_L_([0-9a-f]{8}):", line)
        if label:
            address = int(label.group(1), 16)
        if line.startswith(".") or line.endswith(":") or not line.strip():
            encoded.append(line)
            continue
        size = workspace._instruction_size(address)
        raw = original_pe.get_data(address, size)
        instruction = next(decoder.disasm(raw, address))
        assert instruction.size == size
        references = re.findall(r"\b(?:fn|sym)_[0-9a-f]{16}\b", line)
        if references:
            assert len(references) == 1
            field = instruction.disp_offset if instruction.disp_size == 4 else instruction.imm_offset
            width = instruction.disp_size if instruction.disp_size == 4 else instruction.imm_size
            assert width == 4 and field > 0, (line, instruction.op_str)
            if field:
                encoded.append(".byte " + ", ".join(hex(b) for b in raw[:field]))
            tail = len(raw) - field - 4
            derived_fixups[(helper, address - rva + field)] = {"original_site_rva": address + field, "trailing_instruction_bytes": tail, "stable_id": references[0],
                "original_relative_value": struct.unpack_from("<i", raw, field)[0]}
            encoded.append(".long " + references[0] + " - . - " + str(4 + tail))
            if tail:
                encoded.append(".byte " + ", ".join(hex(b) for b in raw[field + 4:]))
        else:
            encoded.append(".byte " + ", ".join(hex(b) for b in raw))
        address += size
    renamed = "\n".join(encoded) + "\n"
    # Give the fresh helper a real external function type without assigning an
    # original native RVA. Its references keep their original stable IDs.
    renamed = renamed.replace(".globl " + helper, ".globl " + helper + "\n.def " + helper + "; .scl 2; .type 32; .endef")
    (HERE / (helper + ".s")).write_text(renamed)
    rendered.append('asm(R"NATIVEBODY(\n' + renamed + ')NATIVEBODY");\n')
    results.append({"original_id": row["id"], "original_rva": rva, "original_name": row["name"],
                    "helper_symbol": helper, "provenance": original["provenance"],
                    "original_rendered_sha256": hashlib.sha256(content.encode()).hexdigest(),
                    "clone_assembly_sha256": hashlib.sha256(renamed.encode()).hexdigest()})
source = SNAPSHOT / "src/DW_LobbyControls_Native.cpp"
source.parent.mkdir(parents=True, exist_ok=True)
assert not source.exists() or source.stat().st_nlink == 1, "Detach inherited clone source before regeneration"
source.write_text("// Generated from verified complete native PE-owned bodies; no decompiler input.\n" + "\n".join(rendered))
target = HERE / "DW_LobbyControls_Native.obj"
command = [str(LLVM / "clang++.exe"), "--target=x86_64-pc-windows-msvc", "-c", str(source), "-o", str(target),
           "-ffreestanding", "-fno-stack-protector", "-funwind-tables", "-ffunction-sections", "-fdata-sections",
           "-O2", "-std=c++20", "-Wall", "-Wextra", "-Werror", "-fno-exceptions", "-fno-rtti"]
subprocess.run(command, check=True)
obj = read(target)
for result in results:
    definitions = [s for s in obj["symbols"].values() if s["name"] == result["helper_symbol"] and s["section"] > 0 and s["storage"] == 2]
    assert len(definitions) == 1 and definitions[0]["kind"] & 0x20
    result["coff_definition"] = definitions[0]
pdata = [s for s in obj["sections"] if s["name"] == ".pdata"]
xdata = [s for s in obj["sections"] if s["name"] == ".xdata"]
assert sum(len(s["data"]) for s in pdata) == 24 and xdata
original_bytes = bytearray()
for result in results:
    for begin, end in result["provenance"]["ranges"]:
        original_bytes.extend(original_pe.get_data(begin, end - begin))
code = next(s for s in obj["sections"] if s["name"] == ".text")
cloned_bytes = bytearray(code["data"])
assert len(original_bytes) == len(cloned_bytes)
external_fixups = []
catalog_by_id = {r["id"]: r for r in catalog["functions"] + catalog.get("symbols", [])}
for offset, index, kind in code["relocations"]:
    assert kind == 4, "All native body fixups must be real REL32 source references"
    symbol = obj["symbols"][index]["name"]
    assert symbol.startswith(("fn_", "sym_")), symbol
    owner = max((r for r in results if r["coff_definition"]["value"] <= offset), key=lambda r: r["coff_definition"]["value"])
    derived = derived_fixups[(owner["helper_symbol"], offset - owner["coff_definition"]["value"])]
    assert derived["stable_id"] == symbol
    target_rva = catalog_by_id[symbol]["rva"]
    assert derived["original_relative_value"] + derived["original_site_rva"] + 4 + derived["trailing_instruction_bytes"] == target_rva
    assert struct.unpack_from("<i", cloned_bytes, offset)[0] == -derived["trailing_instruction_bytes"], "COFF REL32 addend must account for trailing immediate bytes"
    original_bytes[offset:offset + 4] = cloned_bytes[offset:offset + 4] = bytes(4)
    external_fixups.append({"offset": offset, "stable_id": symbol, "kind": kind, "native_target_rva": target_rva, **derived})
assert original_bytes == cloned_bytes, "Assembler changed verified native bytes outside symbolic fixups"
receipt = {"schema": 1, "passed": True, "snapshot": str(SNAPSHOT), "image_sha256": catalog["image_sha256"],
           "catalog_sha256": digest(SNAPSHOT / "generated/function-catalog.json"),
           "renderer_sha256": digest(SNAPSHOT / "tools/workstation_sources.py"),
           "source": str(source), "source_sha256": digest(source), "object": str(target), "object_sha256": digest(target),
           "compiler_command": command, "compiler_sha256": digest(Path(command[0])), "clones": results,
           "coff_unwind_records": 2, "new_helper_symbols_have_no_original_native_mapping": True,
           "native_bytes_preserved_outside_derived_external_fixups": True,
           "body_bytes": len(cloned_bytes), "external_fixups": external_fixups,
           "required_build_changes": "None: ordinary src CPP file-scope asm, existing compiler and linker place helpers and consume real pdata/xdata",
           "game_runs_performed": False, "full_engine_build_performed": False}
if not args.emit_only:
    associations_path = SNAPSHOT / "source-units.json"
    associations = json.loads(associations_path.read_text())
    units_path = SNAPSHOT / "source-workstation/units.json"
    units = json.loads(units_path.read_text())
    assert units["image_sha256"] == catalog["image_sha256"]
    plan = []
    for result, symbol in zip(results, ("func_14119E3D0", "func_14119B0E0")):
        expected = {"source": args.wrapper_source, "symbol": symbol, "function_id": result["original_id"]}
        existing = [u for u in associations["units"] if u["function_id"] == result["original_id"] or u["symbol"] == symbol]
        assert not existing or existing == [expected], "Existing original root ownership differs"
        if not existing:
            plan.append((result["original_id"], symbol))
        record = {"function_id": result["original_id"], "kind": "cpp", "source": args.wrapper_source,
                  "symbol": symbol, "sha256": digest(wrapper), "revision": digest(wrapper), "language": "cpp"}
        old = [u for u in units["units"] if u["function_id"] == result["original_id"]]
        assert not old or len(old) == 1 and old[0].get("source") == args.wrapper_source and old[0].get("symbol") == symbol
        units["units"] = [u for u in units["units"] if u["function_id"] != result["original_id"]] + [record]
    symbols = sorted({f["stable_id"] for f in external_fixups})
    import_plan = []
    for symbol in symbols:
        existing = [u for u in associations.get("imports", []) if u["symbol"] == symbol]
        expected = {"symbol": symbol, "symbol_id": symbol}
        assert not existing or existing == [expected], "Existing native stable-ID import differs"
        if not existing:
            import_plan.append(symbol)
    # All ownership conflicts are checked before mutation. Authored/mutable
    # files are independent; never write through a shared hardlink.
    assert associations_path.stat().st_nlink == units_path.stat().st_nlink == 1
    # Persist the same normal source_catalog schema in one validated transaction.
    # Repeated bind_import calls each reload the 94 MB catalog; all identities,
    # exact targets and conflicts have already been proved against this catalog.
    for identity, symbol in plan:
        associations["units"].append({"source": args.wrapper_source, "symbol": symbol, "function_id": identity})
    for symbol in import_plan:
        associations.setdefault("imports", []).append({"symbol": symbol, "symbol_id": symbol})
    associations_path.write_text(json.dumps(associations, indent=2) + "\n")
    units_path.write_text(json.dumps(units, indent=2) + "\n")
    receipt["guarded_root_bindings"] = [{"function_id": r["original_id"], "symbol": s, "source": args.wrapper_source}
                                        for r, s in zip(results, ("func_14119E3D0", "func_14119B0E0"))]
    receipt["native_stable_id_imports"] = symbols
    receipt["wrapper_source_sha256"] = digest(wrapper)
receipt["generator_sha256"] = digest(Path(__file__))
receipt["component_proof_only"] = args.emit_only
OUTPUT.write_text(json.dumps(receipt, indent=2) + "\n")
print("PASS two complete native body clones, independent helper globals, stable external fixups and two real COFF unwind records")
