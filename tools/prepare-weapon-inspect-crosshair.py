"""Prepare Replay's shared crosshair eligibility owner for inspection playback.

--inspect-only is read-only. Compilation/assembly of the original fallback is
deferred to an authorized future canonical source preparation/build.
"""

from workstation_preparation_context import cached_input_json, shared_original_pe, source_context

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

import capstone
import pefile

ROOT = Path(__file__).resolve().parents[1]
IMAGE = Path("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe")
IMAGE_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
OWNER_RVA = 0x1698A70
OWNER_SIZE = 435
OWNER_SHA = "d46a6777f2bef92d82c3b68593f65b2c52772db22f754efb022cdc151953aeb9"
UNWIND = "011a0a001a7409001a6408001a5407001a3406001a3216e0"
SOURCE = "src/DW_WeaponInspectCrosshair.cpp"
SYMBOL = "DW_WeaponInspectCrosshair_Allowed"
HELPER = "WIC_OriginalAllowed"
CALLERS = {0x169AA86: "legacy_crosshair_draw", 0x169AE7D: "crosshair_visibility_and_alpha"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def workspace_for(snapshot, catalog, cache):
    sys.path.insert(0, str(snapshot / "tools"))
    from workstation_sources import SourceWorkspace

    workspace = SourceWorkspace(snapshot, cache)
    workspace._catalog = catalog
    workspace._state = lambda: {"sources": {}}
    return workspace


def inspect(snapshot):
    raw = IMAGE.read_bytes()
    assert sha(raw) == IMAGE_SHA
    catalog = cached_input_json(snapshot / 'generated/function-catalog.json')
    assert catalog["image_sha256"] == IMAGE_SHA
    functions = {row["rva"]: row for row in catalog["functions"]}
    row = functions[OWNER_RVA]
    assert row["id"] == "fn_f964a37b43ace2fa" and not row.get("quarantined")
    pe = shared_original_pe(data=raw, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]])
    assert sha(pe.get_data(OWNER_RVA, OWNER_SIZE)) == OWNER_SHA
    records = [entry.struct for entry in pe.DIRECTORY_ENTRY_EXCEPTION
               if entry.struct.BeginAddress <= OWNER_RVA < entry.struct.EndAddress]
    assert len(records) == 1 and records[0].BeginAddress == OWNER_RVA
    assert records[0].EndAddress == OWNER_RVA + OWNER_SIZE
    assert pe.get_data(records[0].UnwindData, len(bytes.fromhex(UNWIND))).hex() == UNWIND

    text = next(section for section in pe.sections if section.Name.rstrip(b"\0") == b".text")
    code = text.get_data()
    sites = []
    position = code.find(b"\xE8")
    while position >= 0:
        if position + 5 <= len(code):
            address = text.VirtualAddress + position
            if address + 5 + struct.unpack_from("<i", code, position + 1)[0] == OWNER_RVA:
                sites.append(address)
        position = code.find(b"\xE8", position + 1)
    assert set(sites) == set(CALLERS)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for site, start in ((0x169AA86, 0x169AA80), (0x169AE7D, 0x169AE77)):
        arguments = list(decoder.disasm(pe.get_data(start, site + 5 - start), start))
        assert arguments[0].mnemonic == "lea" and arguments[0].op_str.endswith("+ 8]")
        assert arguments[0].op_str.startswith("rdx, ")
        assert arguments[1].mnemonic == "mov" and arguments[1].op_str.startswith("ecx, ")
        assert arguments[-1].mnemonic == "call" and arguments[-1].op_str == hex(OWNER_RVA)

    workspace = workspace_for(snapshot, catalog, snapshot / "generated/weapon-inspect-crosshair-inspect-cache")
    original = workspace._assembly_source(row)
    assert original["editable"] and original["compilable"]
    assert original["provenance"]["ranges"] == [[OWNER_RVA, OWNER_RVA + OWNER_SIZE]]
    assert f".seh_proc {row['id']}" in original["content"]
    proof = dict(
        passed=True, image_sha256=IMAGE_SHA, source=SOURCE,
        source_sha256=sha((ROOT / "integration/replay/DW_WeaponInspectCrosshair.cpp").read_bytes()),
        source_header_sha256=sha((ROOT / "integration/replay/DW_WeaponInspectCrosshair.h").read_bytes()),
        owners={SYMBOL: dict(identity=row["id"], rva=OWNER_RVA, bytes=OWNER_SIZE,
                            sha256=OWNER_SHA, unwind_rva=records[0].UnwindData, unwind=UNWIND)},
        imports={}, native_signature="bool(uint32_t, const DWInspectPlayerState *)",
        original_predicate_runs_first=True,
        crosshair_rule="Native allowed AND NOT (DW enabled AND viewed state owns inspection AND primary weaponTime > 800)",
        final_visible_tail_ms=800,
        direct_callers=[dict(rva=site, purpose=CALLERS[site], viewed_state="cg + 8") for site in sorted(sites)],
        runtime_contract=dict(symbol="DW_WeaponInspect_IsActive", passed_state_unchanged=True,
            ownership="Runtime verifies SCRIPTED62, script flag and our animation index; never state62 alone"),
        observer_policy="Preserve original killcam/spectator/MLG rules and use the actual viewed predicted playerState",
        later_build_reference=dict(database_id=55914, rva=0x52B9F60,
            rule="predicted primary weaponState == 78 and weaponTime > 800",
            pseudocode_sha256="1a773c6f2806b3e5a123fddc19948e55f8255bcbdbecc8a22535b187a5afc0e4"),
        compiler_source_sha256=sha(original["content"].encode()),
        cpp_compiled=False, original_bodies_assembled=False, game_runs_performed=False,
    )
    return pe, catalog, row, proof


def prepare(snapshot, *, replace_owned=False):
    snapshot = Path(snapshot).resolve(strict=True)
    assert snapshot.is_relative_to(ROOT / "data")
    for parent in (snapshot, snapshot.parent):
        for marker in ("client-readiness.json", "readiness.json", "local-readiness.json", "source-receipt.json"):
            assert not (parent / marker).exists(), "Cannot modify a sealed snapshot"
    assert not list(snapshot.parent.glob("builds/*/build-report.json"))
    dependencies = [SOURCE, "src/DW_WeaponInspectCrosshair.h", "src/DW_WeaponInspectCrosshairBindings.h",
                    "src/DW_WeaponInspectCrosshair_Native.cpp", "src/DW_WeaponInspect.h"]
    for relative in dependencies + ["source-units.json", "source-workstation/units.json"]:
        path = snapshot / relative
        assert not path.exists() or path.stat().st_nlink == 1
    pe, catalog, row, proof = inspect(snapshot)
    from replay_owned_clone import assemble
    from coff import read

    output = snapshot / "generated/weapon-inspect-crosshair"
    output.mkdir(parents=True, exist_ok=True)
    workspace = workspace_for(snapshot, catalog, output / "cache")
    # Preserve equal-offset unwind operation ordering exactly. Re-emitting
    # .seh directives lets the assembler reorder the pinned native record.
    owner = proof["owners"][SYMBOL]
    unwind = [dict(begin=OWNER_RVA, end=OWNER_RVA + OWNER_SIZE,
                   unwind_rva=owner["unwind_rva"], bytes=owner["unwind"])]
    native_source, clone = assemble(workspace, pe, catalog, row, HELPER, output,
                                    Path(r"C:\Program Files\LLVM\bin"), read,
                                    gs_unwind=unwind)
    assert clone["bytes"] == OWNER_SIZE and clone["unwind_records"] == 1
    for fixup in clone["external_fixups"]:
        proof["imports"][fixup["stable_id"]] = fixup["stable_id"]
    for name in ("DW_WeaponInspectCrosshair.cpp", "DW_WeaponInspectCrosshair.h"):
        (snapshot / "src" / name).write_bytes((ROOT / "integration/replay" / name).read_bytes())
    (snapshot / "src/DW_WeaponInspectCrosshairBindings.h").write_text(
        '#pragma once\n#include "DW_WeaponInspectCrosshair.h"\nextern "C" {\n' +
        'bool WIC_OriginalAllowed(uint32_t, const DWInspectPlayerState *);\n}\n')
    (snapshot / "src/DW_WeaponInspectCrosshair_Native.cpp").write_text(native_source)
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
    assert not prior or (replace_owned and len(prior) == 1 and
                         prior[0]["source"] == SOURCE and prior[0]["symbol"] == SYMBOL)
    units["units"] = [unit for unit in units["units"] if unit["function_id"] != row["id"]]
    digest = sha((snapshot / SOURCE).read_bytes())
    units["units"].append(dict(function_id=row["id"], kind="cpp", source=SOURCE,
                               symbol=SYMBOL, sha256=digest, revision=digest, language="cpp"))
    for symbol, identity in proof["imports"].items():
        wanted = dict(symbol=symbol, symbol_id=identity)
        prior = [item for item in associations.get("imports", []) if item["symbol"] == symbol]
        assert not prior or prior == [wanted]
        if not prior:
            associations.setdefault("imports", []).append(wanted)
    association_path.write_text(json.dumps(associations, indent=2) + "\n")
    units_path.write_text(json.dumps(units, indent=2) + "\n")
    proof.update(clones=[clone], original_bodies_assembled=True,
        generator_sha256=sha(Path(__file__).read_bytes()),
        clone_tool_sha256=sha((ROOT / "tools/replay_owned_clone.py").read_bytes()),
        dependencies={relative: sha((snapshot / relative).read_bytes()) for relative in dependencies})
    (snapshot / "generated/weapon-inspect-crosshair-integration.json").write_text(json.dumps(proof, indent=2) + "\n")
    return proof


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--inspect-only", action="store_true")
    parser.add_argument("--replace-owned", action="store_true")
    args = parser.parse_args()
    snapshot = args.snapshot.resolve(strict=True)
    result = inspect(snapshot)[3] if args.inspect_only else prepare(snapshot, replace_owned=args.replace_owned)
    print(json.dumps(result, indent=2))
