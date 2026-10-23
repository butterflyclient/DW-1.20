"""Preserve native weapon-cycle input with a client-side BR armor decision."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

import capstone
from capstone.x86 import X86_OP_MEM, X86_REG_RIP
from workstation_preparation_context import cached_input_json, shared_original_pe

ROOT = Path(__file__).resolve().parents[1]
IMAGE = Path("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe")
IMAGE_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
OWNER = "fn_734f3db7aa4f5af2"
OWNER_RVA = 0x15B5CE0
OWNER_SIZE = 921
OWNER_SHA = "5efcd86011b2c0cdfa7ba3f56031a788a37919ccf548c001ae016cb218f0fea7"
PREDICATE = "fn_1ebefa58678ed127"
DVAR = "sym_6e0342869bc8aa0a"
DVAR_SITES = (0x15B5E96, 0x15B5F34)
SYMBOL = "DW_ControllerArmor_CycleWeapon"
SOURCE = "src/DW_ControllerArmor.cpp"
LLVM = Path("C:/Program Files/LLVM/bin")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def generate(snapshot, output):
    """Read frozen evidence; write only the specified output directory."""
    catalog = cached_input_json(snapshot / "generated/function-catalog.json")
    raw = IMAGE.read_bytes()
    assert sha(raw) == catalog["image_sha256"] == IMAGE_SHA
    pe = shared_original_pe(data=raw, fast_load=True)
    pe.parse_data_directories(directories=[3])
    by_id = {r["id"]: r for r in catalog["functions"] + catalog["symbols"]}
    row = by_id[OWNER]
    assert row["rva"] == OWNER_RVA and not row.get("quarantined")
    operators = load(ROOT / "tools/prepare-custom-operators.py", "armor_unwind")
    unwind = operators.unwind_family(pe, OWNER_RVA)
    body = b"".join(pe.get_data(r["begin"], r["end"] - r["begin"]) for r in unwind)
    assert len(body) == OWNER_SIZE and sha(body) == OWNER_SHA
    assert by_id[PREDICATE]["rva"] == 0xEFCD40
    assert sha(pe.get_data(0xEFCD40, 26)) == "46ab72ca03484127463287727e54ea53dcf14595312ca13a715a48a090c49606"
    assert by_id[DVAR]["rva"] == 0xC6E20F8
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    refs = [i.address + i.disp_offset for i in decoder.disasm(body, OWNER_RVA)
            if any(o.type == X86_OP_MEM and o.mem.base == X86_REG_RIP and
                   i.address + i.size + o.mem.disp == 0xC6E20F8 for o in i.operands)]
    assert tuple(refs) == DVAR_SITES
    sys.path.insert(0, str(snapshot / "tools"))
    from workstation_sources import SourceWorkspace
    from replay_owned_clone import assemble
    from coff import read
    output.mkdir(parents=True, exist_ok=True)
    workspace = SourceWorkspace(snapshot, output / "cache")
    workspace._catalog = catalog
    workspace._state = lambda: {"sources": {}}
    sources, clones = [], []
    for helper in ("DCA_CycleWeaponNative", "DCA_CycleWeaponBR"):
        source, proof = assemble(workspace, pe, catalog, row, helper, output, LLVM,
                                 read, gs_unwind=unwind)
        assert proof["bytes"] == OWNER_SIZE
        if helper.endswith("BR"):
            changes = [r for r in proof["external_fixups"] if r["stable_id"] == DVAR]
            assert tuple(r["original_site_rva"] for r in changes) == DVAR_SITES
            assert len(re.findall(r"\b" + DVAR + r"\b", source)) == 2
            source = re.sub(r"\b" + DVAR + r"\b", "DCA_ArmorInput", source)
            cpp, obj = output / (helper + ".cpp"), output / (helper + ".obj")
            before = read(obj)
            cpp.write_text(source)
            subprocess.run([str(LLVM / "clang++.exe"), "--target=x86_64-pc-windows-msvc",
                            "-c", str(cpp), "-o", str(obj), "-ffreestanding",
                            "-fno-stack-protector", "-funwind-tables", "-O2",
                            "-fno-exceptions", "-fno-rtti"], check=True)
            after = read(obj)
            assert len(before["sections"]) == len(after["sections"])
            for a, b in zip(before["sections"], after["sections"]):
                assert (a["name"], a["data"]) == (b["name"], b["data"])
                def relocations(section, coff):
                    return [(off, coff["symbols"][idx]["name"], kind)
                            for off, idx, kind in section["relocations"]]
                expected = [(off, "DCA_ArmorInput" if symbol == DVAR else symbol, kind)
                            for off, symbol, kind in relocations(a, before)]
                assert expected == relocations(b, after)
            proof.update(source_sha256=sha(cpp.read_bytes()), object_sha256=sha(obj.read_bytes()),
                         redirects={DVAR: "DCA_ArmorInput"})
        sources.append(source)
        clones.append(proof)
    imports = {r["stable_id"]: r["stable_id"] for c in clones for r in c["external_fixups"]}
    imports["DCA_PlayingBR"] = PREDICATE
    return "\n".join(sources), dict(passed=True, image_sha256=IMAGE_SHA,
        owner=OWNER, owner_rva=OWNER_RVA, owner_bytes=OWNER_SIZE, owner_sha256=OWNER_SHA,
        imports=imports, clones=clones, predicate_rva=0xEFCD40,
        predicate_sha256=sha(pe.get_data(0xEFCD40, 26)), dvar_sites=list(DVAR_SITES),
        native_unwind=unwind, game_launched=False)


def prepare(snapshot, *, replace_owned=False):
    snapshot = Path(snapshot).resolve(strict=True)
    assert snapshot.is_relative_to(ROOT / "data")
    for parent in (snapshot, snapshot.parent):
        for marker in ("client-readiness.json", "local-readiness.json", "source-receipt.json"):
            assert not (parent / marker).exists(), "Cannot modify a sealed source"
    assert not list(snapshot.parent.glob("builds/*/build-report.json"))
    native, proof = generate(snapshot, snapshot / "generated/controller-armor")
    paths = [SOURCE, "src/DW_ControllerArmor_Native.cpp", "source-units.json",
             "source-workstation/units.json"]
    for relative in paths:
        path = snapshot / relative
        assert not path.exists() or path.stat().st_nlink == 1
    (snapshot / SOURCE).write_bytes((ROOT / "integration/replay/DW_ControllerArmor.cpp").read_bytes())
    (snapshot / "src/DW_ControllerArmor_Native.cpp").write_text(native)
    associations = json.loads((snapshot / "source-units.json").read_bytes())
    units = json.loads((snapshot / "source-workstation/units.json").read_bytes())
    wanted = dict(function_id=OWNER, source=SOURCE, symbol=SYMBOL)
    old = [r for r in associations["units"] if r["function_id"] == OWNER]
    assert not old or (replace_owned and old == [wanted]), "Different input owner"
    if not old:
        associations["units"].append(wanted)
    old = [r for r in units["units"] if r["function_id"] == OWNER]
    assert not old or (replace_owned and old[0]["source"] == SOURCE)
    units["units"] = [r for r in units["units"] if r["function_id"] != OWNER]
    digest = sha((snapshot / SOURCE).read_bytes())
    units["units"].append(dict(**wanted, kind="cpp", sha256=digest, revision=digest, language="cpp"))
    for symbol, identity in proof["imports"].items():
        wanted_import = dict(symbol=symbol, symbol_id=identity)
        old = [r for r in associations.setdefault("imports", []) if r["symbol"] == symbol]
        assert not old or old == [wanted_import]
        if not old:
            associations["imports"].append(wanted_import)
    (snapshot / "source-units.json").write_text(json.dumps(associations, indent=2) + "\n")
    (snapshot / "source-workstation/units.json").write_text(json.dumps(units, indent=2) + "\n")
    proof.update(generator_sha256=sha(Path(__file__).read_bytes()),
                 clone_tool_sha256=sha((ROOT / "tools/replay_owned_clone.py").read_bytes()),
                 dependencies={p: sha((snapshot / p).read_bytes()) for p in paths[:2] + ["src/replay_dvar.h"]})
    (snapshot / "generated/controller-armor-integration.json").write_text(json.dumps(proof, indent=2) + "\n")
    return proof


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--replace-owned", action="store_true")
    args = parser.parse_args()
    print(json.dumps(prepare(args.snapshot, replace_owned=args.replace_owned), indent=2))
