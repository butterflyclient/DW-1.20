"""Derive bot customization imports and layout from the pinned Replay image."""

import hashlib
import csv
import importlib.util
import json
from pathlib import Path
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP

ROOT = Path(__file__).resolve().parents[1]


def prepare(snapshot):
    snapshot = snapshot.resolve()
    assert snapshot.is_relative_to(ROOT / "data")
    catalog = json.loads((snapshot / "generated/function-catalog.json").read_bytes())
    raw = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe").read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    assert digest == catalog["image_sha256"]
    pe = pefile.PE(data=raw, fast_load=True)
    pe.parse_data_directories(directories=[3])
    base = pe.OPTIONAL_HEADER.ImageBase
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    entries = {row.struct.BeginAddress: row for row in pe.DIRECTORY_ENTRY_EXCEPTION}

    def one(rows):
        assert len(rows) == 1, rows
        return rows[0]

    def named(name):
        return one([r for r in catalog["functions"] if not r.get("quarantined")
                    and name in (r["name"], *r["aliases"])])

    proofs = []

    def instructions(name):
        row = named(name)
        def owner(entry):
            seen = set()
            while entry.unwindinfo.UNW_FLAG_CHAININFO:
                assert entry.struct.BeginAddress not in seen
                seen.add(entry.struct.BeginAddress)
                entry = entry.unwindinfo._chained_entry
            return entry.struct.BeginAddress
        chunks = sorted((e.struct.BeginAddress, e.struct.EndAddress)
                        for e in entries.values() if owner(e) == row["rva"])
        assert chunks and chunks[0][0] == row["rva"]
        assert all(a[1] == b[0] for a, b in zip(chunks, chunks[1:]))
        code = pe.get_data(chunks[0][0], chunks[-1][1] - chunks[0][0])
        result = list(decoder.disasm(code, base + chunks[0][0]))
        assert sum(i.size for i in result) == len(code)
        proofs.append(dict(identity=row["id"], name=name, sha256=hashlib.sha256(code).hexdigest()))
        return result

    update = instructions("BG_Customization_UpdatePackageBindings")

    def rip_lea(rows, register):
        return one([i.address + i.size + i.operands[1].mem.disp for i in rows
                    if i.mnemonic == "lea" and i.operands[0].type == X86_OP_REG
                    and i.reg_name(i.operands[0].reg) == register
                    and i.operands[1].type == X86_OP_MEM and i.operands[1].mem.base == X86_REG_RIP])

    packages = rip_lea(update, "r12")
    group = rip_lea(update, "rbp") - 4
    enabled = one([i.address + i.size + i.operands[0].mem.disp for i in update
                   if i.mnemonic == "cmp" and i.operands[0].type == X86_OP_MEM
                   and i.operands[0].mem.base == X86_REG_RIP])
    category = instructions("BG_Customization_SetPackageCategory")
    assert group in [i.address + i.size + i.operands[1].mem.disp for i in category
                     if i.mnemonic == "lea" and i.operands[0].type == X86_OP_REG
                     and i.reg_name(i.operands[0].reg) == "rdx"
                     and i.operands[1].type == X86_OP_MEM and i.operands[1].mem.base == X86_REG_RIP]
    assert packages in [i.address + i.size + o.mem.disp for i in category for o in i.operands
                        if o.type == X86_OP_MEM and o.mem.base == X86_REG_RIP]
    primary = instructions("sub_1410E4300")
    # Full package stride and both lifecycle/category fields are independently
    # confirmed by registration and the native binding validator.
    def has(rows, mnemonic, operand):
        assert any(i.mnemonic == mnemonic and i.op_str == operand for i in rows), operand
    has(update, "lea", "rcx, [rax + rax*4]")
    has(update, "lea", "rsi, [rcx*8]")
    has(update, "add", "rbp, 0x10")
    has(update, "movzx", "eax, word ptr [rbp - 4]")
    has(update, "mov", "byte ptr [rsi + r12 + 0x23], 1")
    has(category, "cmp", "byte ptr [rdi + 0x22], 0")
    has(category, "mov", "dword ptr [rdi + 0x1c], ebx")
    assert rip_lea(primary, "rbp") - packages == 22
    has(primary, "mov", "word ptr [r14 + rbp], di")
    header = '''#pragma once
#include <stdint.h>
#include <stddef.h>
// Derived and checked against native registration/binding instructions.
struct DWBotCustomizationPackage
{
    const char *model, *fallback;
    uint32_t hash;
    uint16_t next, primary, secondary, padding;
    uint32_t category;
    uint16_t viewhands;
    uint8_t randomEligible, invalid;
    uint32_t tail;
};
struct DWBotCustomizationGroup
{
    uint16_t first, padding;
    uint32_t count, maleCount, femaleCount;
};
static_assert(sizeof(DWBotCustomizationPackage) == 40);
static_assert(offsetof(DWBotCustomizationPackage, primary) == 22);
static_assert(offsetof(DWBotCustomizationPackage, category) == 28);
static_assert(offsetof(DWBotCustomizationPackage, randomEligible) == 34);
static_assert(offsetof(DWBotCustomizationPackage, invalid) == 35);
static_assert(sizeof(DWBotCustomizationGroup) == 16);
inline constexpr unsigned DWBotCustomizationPackageLimit = 8192;
extern "C" {
extern uint8_t DW_Bot_CustomizationPackages[], DW_Bot_CustomizationGroups[];
extern int DW_Bot_CustomizationEnabled;
}
'''
    assets = Path(r"E:\replay-compiler\evidence\workstation-stringtable-actsexport-fixed\mw19replay\code_post_gfx\mw19replay\code_post_gfx\assets\stringtable")
    asset_proofs = []

    def table(pattern):
        path = one(list(assets.glob(pattern)))
        content = path.read_bytes()
        asset_proofs.append(dict(path=str(path), sha256=hashlib.sha256(content).hexdigest()))
        return list(csv.reader(content.decode("utf-8-sig").splitlines()))

    heads = {r[1]: int(r[0]) for r in table("mp/cac/heads.csv.*.csv") if r[0].isdigit()}
    bodies = {r[1]: int(r[0]) for r in table("mp/cac/bodies.csv.*.csv") if r[0].isdigit()}
    skins = table("operatorskins.csv.*.csv") + table("defaultoperatorskins.csv.*.csv")
    pairs = sorted({(heads[r[5]], bodies[r[4]]) for r in skins
                    if len(r) > 5 and r[5] in heads and r[4] in bodies
                    and heads[r[5]] and bodies[r[4]]})
    assert len(pairs) > 100
    header += "struct DWBotOperatorSkin { uint16_t head, body; };\ninline constexpr DWBotOperatorSkin DWBotOperatorSkins[] = {\n"
    header += "".join(f"    {{{h}, {b}}},\n" for h, b in pairs) + "};\n"
    ids = table("loot/weapon_ids.csv.*.csv")
    by_variant = {r[6]: (int(r[0]), r[1]) for r in ids if len(r) > 6 and r[0].isdigit()}
    camos = [r[1] for r in table("loot/camo_ids.csv.*.csv") if len(r) > 1 and r[1].startswith("camo_")]
    header += "inline constexpr const char *DWBotCamos[] = {\n" + "".join("    " + json.dumps(c) + ",\n" for c in camos) + "};\n"
    header += "struct DWBotWeapon { unsigned loot; bool secondary; const char *attachments[5]; unsigned variants[5]; };\ninline constexpr DWBotWeapon DWBotWeapons[] = {\n"
    weapons = []
    for pattern in ("mp/gunsmith/ar_*_variants.csv.*.csv", "mp/gunsmith/sm_*_variants.csv.*.csv", "mp/gunsmith/pi_*_variants.csv.*.csv"):
        for path in sorted(assets.glob(pattern)):
            content = path.read_bytes()
            asset_proofs.append(dict(path=str(path), sha256=hashlib.sha256(content).hexdigest()))
            for row in csv.reader(content.decode("utf-8-sig").splitlines()):
                if len(row) < 14 or row[1] not in by_variant:
                    continue
                loot, reference = by_variant[row[1]]
                # Five original functional attachment slots. Receiver cosmetic
                # pieces remain supplied by the stock blueprint variant itself.
                attachments = []
                for cell in row[5:14]:
                    if cell:
                        fields = cell.split("|")
                        if len(fields) == 2 and fields[1].isdigit() and " " not in fields[0]:
                            attachments.append((fields[0], int(fields[1])))
                if not attachments or len(attachments) > 5:
                    continue
                attachments += [("", 0)] * (5 - len(attachments))
                weapons.append((loot, reference.startswith("iw8_pi_"), attachments))
    assert len(weapons) > 50 and any(w[1] for w in weapons)
    for loot, secondary, attachments in weapons:
        refs = ", ".join(json.dumps(a) for a, v in attachments)
        variants = ", ".join(str(v) for a, v in attachments)
        header += f"    {{{loot}, {'true' if secondary else 'false'}, {{{refs}}}, {{{variants}}}}},\n"
    header += "};\n"
    decoder_code = instructions("sub_140CA2140")
    decode_calls = [i.operands[0].imm for i in decoder_code if i.mnemonic == "call"
                    and i.operands[0].type == X86_OP_IMM]
    by_address = {base + r["rva"]: r for r in catalog["functions"] if not r.get("quarantined")}
    assert by_address[decode_calls[0]]["id"] == named("StringTable_GetAsset")["id"]
    assert len(decode_calls) == 6 and decode_calls[1] == decode_calls[3]
    assert by_address[decode_calls[2]]["id"] == named("q_StringTable_GetRowCount")["id"]
    native_imports = dict(DW_Bot_StringTableAsset=decode_calls[0],
                          DW_Bot_StringTableRows=decode_calls[2],
                          DW_Bot_StringTableColumn=decode_calls[4])
    name_pointer = one([i.address + i.size + i.operands[1].mem.disp for i in decoder_code
                        if i.mnemonic == "mov" and i.operands[0].type == X86_OP_REG
                        and i.reg_name(i.operands[0].reg) == "rcx"
                        and i.operands[1].type == X86_OP_MEM and i.operands[1].mem.base == X86_REG_RIP])
    header += '''extern "C" {
extern const char *DW_Bot_NameTable;
void DW_Bot_StringTableAsset(const char *, const void **);
int DW_Bot_StringTableRows(const void *);
const char *DW_Bot_StringTableColumn(const void *, unsigned, unsigned);
}
'''
    (snapshot / "src/DW_BotBindings.h").write_text(header)
    spec = importlib.util.spec_from_file_location("private_bot_catalog", snapshot / "tools/source_catalog.py")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(snapshot / "tools"))
    spec.loader.exec_module(module)
    shim = importlib.util.spec_from_file_location("dw_catalog", Path(__file__).resolve().with_name("dw_catalog.py"))
    shim_module = importlib.util.module_from_spec(shim)
    shim.loader.exec_module(shim_module)
    shim_module.share_catalog(module)  # one catalog parse, not one per binding
    bindings = []
    for alias, address in dict(DW_Bot_CustomizationPackages=packages,
                               DW_Bot_CustomizationGroups=group,
                               DW_Bot_CustomizationEnabled=enabled,
                               DW_Bot_NameTable=name_pointer).items():
        symbol = one([r for r in catalog["symbols"] if r["rva"] == address - base
                      and r.get("kind") == "data-address" and not r.get("quarantined")])
        module.bind_import(symbol["id"], alias)
        bindings.append(dict(symbol=alias, identity=symbol["id"]))
    for alias, address in native_imports.items():
        module.bind_import(by_address[address]["id"], alias)
        bindings.append(dict(symbol=alias, identity=by_address[address]["id"]))
    # An unnamed native predicate is identified by its retained catalog alias;
    # source associations still contain only stable IDs, never RVAs/extents.
    predicate = named("sub_140CA2270")
    module.bind(predicate["id"], Path("src/DW_BotRoster.cpp"), "BG_GameStateInfo_IsBotMemberPresent")
    units_path = snapshot / "source-workstation/units.json"
    units = json.loads(units_path.read_bytes())
    sha = hashlib.sha256((snapshot / "src/DW_BotRoster.cpp").read_bytes()).hexdigest()
    units["units"].append(dict(function_id=predicate["id"], kind="cpp",
                              source="src/DW_BotRoster.cpp", symbol="BG_GameStateInfo_IsBotMemberPresent",
                              sha256=sha, revision=sha, language="cpp"))
    decoder_row = named("sub_140CA2140")
    module.bind(decoder_row["id"], Path("src/DW_BotRoster.cpp"), "BG_GameStateInfo_ExpandBotData")
    units["units"].append(dict(function_id=decoder_row["id"], kind="cpp",
                              source="src/DW_BotRoster.cpp", symbol="BG_GameStateInfo_ExpandBotData",
                              sha256=sha, revision=sha, language="cpp"))
    units_path.write_text(json.dumps(units, indent=2) + "\n")
    result = dict(passed=True, image_sha256=digest, source_sha256=sha,
                  header_sha256=hashlib.sha256(header.encode()).hexdigest(),
                  original_instructions=proofs, bindings=bindings, replacement=predicate["id"],
                  asset_inputs=asset_proofs, operator_pairs=len(pairs), weapon_variants=len(weapons),
                  game_launched=False, native_runtime_verified=False)
    (snapshot / "generated/bot-integration.json").write_text(json.dumps(result, indent=2) + "\n")
    return result
