"""Bind custom operators to Replay native package registration and local profile selection."""
from workstation_preparation_context import cached_input_json, shared_original_pe
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
import sys
import capstone
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

ROOT = Path(__file__).resolve().parents[1]
IMAGE = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
TARGET = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
SOURCE = "src/DW_CustomOperators.cpp"
OWNERS = (
    ("fn_8f2e3d3208dda332", "DW_CustomOperators_ShouldRecreateLegs", "CO_ShouldRecreateLegsNative", 434,
     "662db0d1fdb1a9a3a73c7ff76d73caa47cfc53b0cd7c1f0896783c495d56aafc"),
    ("fn_bf107f1928376acc", "DW_CustomOperators_UpdateLegs", "CO_UpdateLegsNative", 825,
     "1d5028b8203fc36ec9934c7626636d3c169da3ffc1b831b35c900119a9e624de"),
    ("fn_2a33c7cfe7c02d31", "DW_CustomOperators_GetActiveModel", "CO_GetActiveModelNative", 629,
     "d9a87511d002e8a0e0c7fb25d67354f7a40a858a305c170b6fb2b490c71b6560"),
    ("fn_8dc0265545dc880f", "DW_CustomOperators_RegisterHeads", "CO_RegisterHeadsNative", 639,
     "cc06ca637348f8848c518d5d39e78b2938eb923aa82db8368d8d4656787e346c"),
    ("fn_c3a34ec1242428c2", "DW_CustomOperators_RegisterBodies", "CO_RegisterBodiesNative", 688,
     "d154d7e03ca37c0c6613d607e724b485e3b97d77b39fc665c33bcfeb72c282d8"),
    ("fn_de3590aa3258cac0", "DW_CustomOperators_BuildCustomization", "CO_BuildCustomizationNative", 345,
     "9809b1f14b04c63b72f847d825df71a46f86a51b1f2600959936eaabcbdf631b"),
    ("fn_44ef274a897b16f0", "DW_CustomOperators_CardModels", "CO_CardModelsNative", 980,
     "48496e4caf5847accf13e6e91b6fb36ce719ad8180b9563977c86dd320713aa3"),
    ("fn_1a9d7b641743b9a0", "DW_CustomOperators_GetPlayercard", "CO_GetPlayercardNative", 174,
     "dabe0dca63b233ccfacb4cde5b8a17fc82eed8c2371d937be41e255d009308cc"),
    ("fn_242276f67e018a51", "DW_CustomOperators_TableRow", "CO_TableRowNative", 297,
     "e625da94577de5790ab67c051ff875a0cd3a7628e6f60616c2baeec44ed9d4f0"),
    ("fn_bedabe7eae6ddf57", "DW_CustomOperators_TableColumn", None, 65,
     "a4cb475744f67749bad6a9fb8f2aee5b6c83700de129b141d6b1c8adf0214aaa"),
    ("fn_84b0cc51647d6a31", "DW_CustomOperators_TableRows", None, 4,
     "2e339cdc5de837ec151dbde90057caeabba18ac3ea32e7c2cffc8f95df41a6ff"),
    ("fn_aab332faa4f9b9fa", "DW_CustomOperators_SetCustomization", "CO_SetCustomizationNative", 470,
     "b08e77dcb91e9f18f325f68dd13393c94033e14b851925a101e4bacde44bc2c5"),
    ("fn_bd01e16dff8e3ad1", "DW_CustomOperators_GetTable", "CO_GetTableNative", 36,
     "793cf44c6bbfc967e526f4bf32ef7aaf4d1b44faef7b8415d1aec228f702f232"),
    ("fn_aba66b7810318d77", "DW_CustomOperators_TableMultiRow", "CO_TableMultiRowNative", 484,
     "cb4006dae359657a4b377ecc863becb1afbdc2f0570c450a39b3664b2df11607"),
)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def unwind_family(pe, rva):
    rows = []
    for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
        owner = entry
        while owner.unwindinfo and owner.unwindinfo.UNW_FLAG_CHAININFO:
            owner = owner.unwindinfo._chained_entry
        if owner.struct.BeginAddress != rva:
            continue
        head = pe.get_data(entry.struct.UnwindData, 4)
        flags = head[0] >> 3
        assert flags in (0, 3, 4), flags
        size = 4 + ((head[2] + 1) & ~1) * 2
        size += 12 if flags == 4 else 8 if flags == 3 else 0
        rows.append(dict(begin=entry.struct.BeginAddress, end=entry.struct.EndAddress,
                         unwind_rva=entry.struct.UnwindData,
                         bytes=pe.get_data(entry.struct.UnwindData, size).hex()))
    rows.sort(key=lambda row: row["begin"])
    assert rows and all(a["end"] == b["begin"] for a, b in zip(rows, rows[1:]))
    return rows


def operator_data(path):
    manifest = json.loads(path.read_bytes())
    rows = manifest["operators"]
    zone = manifest["zone"]
    assert re.fullmatch(r"dw_custom_operators_[0-9a-f]{16}", zone)
    assert 0 < len(rows) <= 2
    assert [row["id"] for row in rows] == ["nicky", "bo2"][:len(rows)]
    names = [row[key] for row in rows for key in ("head", "body")]
    assert len(set(names)) == len(names)
    assert all(name.startswith("dw_operator_") and all(c.isalnum() or c == "_" for c in name)
               for name in names)
    text = "#pragma once\n#include <stdint.h>\nnamespace DWCustomOperators {\n"
    text += "inline constexpr const char *ZoneName = " + json.dumps(zone) + ";\n"
    text += "struct Operator { const char *head, *body; uint16_t primary; };\n"
    text += "inline constexpr Operator Operators[] = {\n"
    for index, row in enumerate(rows):
        text += "    {%s, %s, %d},\n" % (json.dumps(row["head"]), json.dumps(row["body"]), 60000 + index)
    text += "};\ninline constexpr unsigned Count = sizeof(Operators) / sizeof(*Operators);\n}\n"
    return rows, text


def inspect(snapshot):
    catalog = cached_input_json(snapshot / "generated/function-catalog.json")
    raw = IMAGE.read_bytes()
    assert sha(raw) == catalog["image_sha256"] == TARGET
    pe = shared_original_pe(data=raw, fast_load=True)
    pe.parse_data_directories(directories=[3])
    base = pe.OPTIONAL_HEADER.ImageBase
    by_id = {row["id"]: row for row in catalog["functions"] if not row.get("quarantined")}
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    proof = dict(image_sha256=TARGET, owners={}, imports={}, game_launched=False,
                 native_runtime_verified=False)
    for identity, symbol, helper, size, digest in OWNERS:
        row = by_id[identity]
        records = unwind_family(pe, row["rva"]) if helper else []
        body = b"".join(pe.get_data(r["begin"], r["end"] - r["begin"]) for r in records) if records else pe.get_data(row["rva"], size)
        assert len(body) == size and sha(body) == digest
        proof["owners"][symbol] = dict(identity=identity, bytes=size, sha256=digest, unwind=records)
    # The native local profile update embeds its controller storage address as
    # an image-relative LEA, then scales controller * 3 * 8 before BuildCustomization.
    update = by_id["fn_39dc9477c47dbbcb"]
    records = unwind_family(pe, update["rva"])
    body = b"".join(pe.get_data(r["begin"], r["end"] - r["begin"]) for r in records)
    assert len(body) == 622 and sha(body) == "f6f36357a69528c80ab8653148426f14cf3bc4e44952e526b54aa18b0a61e521"
    code = list(decoder.disasm(body, update["rva"]))
    assert any(i.mnemonic == "lea" and i.op_str == "rax, [r14 + r14*2]" for i in code)
    assert any(i.mnemonic == "lea" and i.op_str == "rcx, [rcx + rax*8]" for i in code)
    storage = [i.operands[1].mem.disp for i in code if i.mnemonic == "lea" and
               i.op_str.startswith("rcx, [r12 +")]
    assert len(storage) == 1
    data = [r for r in catalog["symbols"] if r["rva"] == storage[0] and
            r.get("kind") == "data-address" and not r.get("quarantined")]
    assert len(data) == 1
    proof["imports"].update(CO_LocalCustomization=data[0]["id"],
        CO_UpdateLocalCustomization=update["id"], CO_RegisterPackage="fn_d9afebe5262146cc",
        CO_GetLocalXuid="fn_61640056ba171252", CO_RequestCardUpload="fn_12c9e75ec598e3c3",
        CO_TableHash="fn_71ac63e4764a9a62", CO_Format="fn_f51f47f51d0b8c6a",
        CO_Entities="sym_530069cc5d44c7c2", CO_ServerGlobals="sym_a6ecc74906cfc78d",
        CO_SetBody="fn_e86289555b21deb8", CO_SetHead="fn_7f0f2602a8e89043",
        CO_PartyXuid="fn_ee843f490c599816", CO_ServerLobby="fn_509bc371a05c0e2b",
        CO_IsBot="fn_ea95710a6b2bb5fd", CO_CardSelections="fn_9e9f7d8588e3ae73",
        CO_UploadCard="fn_6028f98a52da540d",
        CO_UpdatePackageBindings="fn_78dc121d537a1631",
        CO_GenerateActiveModel="fn_9b30b5ec59dc1003",
        CO_DObjGetModel="fn_ef8bc74e30ba356f", CO_FindAsset="fn_2c80329c0d908f5c",
        CO_LocalClientGlobals="sym_4f763e1a5b9da09c")
    print_rows = [r for r in by_id.values() if "Com_Printf" in r["aliases"]]
    assert len(print_rows) == 1
    proof["imports"]["CO_Print"] = print_rows[0]["id"]
    proof["local_profile"] = dict(identity=update["id"], sha256=sha(body),
                                   storage_identity=data[0]["id"], controller_stride=24, selected_controller=0)
    register = by_id["fn_d9afebe5262146cc"]
    records = unwind_family(pe, register["rva"])
    body = b"".join(pe.get_data(r["begin"], r["end"] - r["begin"]) for r in records)
    assert sha(body) == "0db6a231e46285214b0a9f9b77c3bcb70decc54bf1783368305641805538170e"
    binding = by_id["fn_78dc121d537a1631"]
    records = unwind_family(pe, binding["rva"])
    binding_body = b"".join(pe.get_data(r["begin"], r["end"] - r["begin"]) for r in records)
    assert len(binding_body) == 395 and sha(binding_body) == "0f99cd4098012d06b41a09bcd797fe3bf626d21ef21bc05eb2c9edf1f1cba3a7"
    proof["package_rebinding"] = dict(identity=binding["id"], bytes=len(binding_body),
        sha256=sha(binding_body), after_dependency_completion=True)
    # Native ComFastFileLoadModule::Frame_Loading advances only when every
    # poll returns state two. Keep that dependency-readiness contract linked
    # to the exact Replay poll identity and original instruction comparison.
    poll = by_id["fn_898aab2c422c379f"]
    proof["imports"]["DWBSZ_PollFastfileState"] = poll["id"]
    assert sha(pe.get_data(poll["rva"], 320)) == "5a03a11cbb1f705cafcb93348bfaa9d32abe76ba1433f4cf75f7ebdd5a7a7911"
    loading = [by_id["fn_2e8ce8e48261f3bf"]]
    records = unwind_family(pe, loading[0]["rva"])
    body = b"".join(pe.get_data(r["begin"], r["end"] - r["begin"]) for r in records)
    code = list(decoder.disasm(body, base + loading[0]["rva"]))
    assert any(i.mnemonic == "call" and i.op_str == hex(base + poll["rva"]) and
               code[index + 1].mnemonic == "cmp" and code[index + 1].op_str == "eax, 2"
               for index, i in enumerate(code[:-1]))
    proof["zone_readiness"] = dict(complete_state=2, dependency_zones=["global_stream_mp", "common_mp"],
        custom_zone_flags=8, placement="after last MP common/dependency record",
        poll_identity=poll["id"], native_completion_caller=loading[0]["id"],
        native_completion_caller_sha256=sha(body))
    # Additional native contracts used by the appearance source and the
    # authoritative player customization setter. Numeric offsets are grounded
    # in these exact Replay helpers and the entity command's original owner.
    contracts = {
        "CO_DObjGetModel": (15, "72312d6c9abac0aaf47af7af19653436d4ae1e33dee10d911ff8192379513725"),
        "CO_GenerateActiveModel": (268, "86be3ff2a7acf0f3e6a893a8ba46c7781d0f0fd5b3ea93c3f667dfcf84b157c3"),
        "CO_SetBody": (92, "de45f43a040b46e6fd0c579ae69a100b3e05cc0f79549f3387ce759d26f2441c"),
        "CO_SetHead": (28, "62bdeb244197cae74f15b1d86f97df7e5e51e769f9b3c3abcc420a1d351d08a3"),
        "CO_PartyXuid": (25, "51f6d2e2b800d21c6017c1619c45625cb8c48d252016f007b6027a2a9920bf19"),
        "CO_IsBot": (85, "037174836b04b1ee5b45b8e7bef0c03a0a38a810769195dd8daf4df4f2396d78"),
        "CO_ServerLobby": (38, "3811ffd9f3df087d0a7fac2df12f7e15b8c1bc207eef9bcee975f7b975d60a54"),
        "CO_UploadCard": (719, "e4c08cfff596069f96387530dbbd16281229effbb51cdc0402207a176682398b"),
        "CO_TableHash": (67, "d5ae463fb2844e3d255ff7f517dcb121f6ab7b20389555d180f73e659c7d36ac"),
    }
    proof["appearance_contracts"] = {}
    for alias, (size, digest) in contracts.items():
        row = by_id[proof["imports"][alias]]
        assert sha(pe.get_data(row["rva"], size)) == digest, alias
        proof["appearance_contracts"][alias] = dict(identity=row["id"], rva=row["rva"], bytes=size, sha256=digest)
    proof["appearance_layout"] = dict(string_table_size=48,
        string_table_offsets=dict(columns=8, rows=12, unique_strings=16, padding=20, cells=24, hashes=32, strings=40),
        card_public_offsets=[80, 104], card_private_offsets=[92, 116], faction_record_size=24,
        entity_stride=0x5A0, entity_client_offset=0x150, client_party_member_offset=0x55FC,
        client_customization_offset=0x56D8, front_end_server_offset=0x72,
        card_refresh="native upload returns 1 for updated/unchanged local cache, 0 before prerequisites; request flag retries normally")
    spectator = by_id["fn_5a00cd01fe2f3a1a"]
    spectator_body = pe.get_data(spectator["rva"], 99)
    assert sha(spectator_body) == "510cea9aa26f3c432bf262543dcb1d74b5faf5e925db4799c8e0bf17eb0901f0"
    proof["local_cosmetic_contract"] = dict(
        active_model_owner="fn_2a33c7cfe7c02d31", native_selection="fn_9b30b5ec59dc1003",
        client_info_customization_offset=100, character_client_offset=0,
        force_default_argument_bytes=4,
        predicted_client_offset=456, local_client_offset=25632,
        spectator_gate=dict(identity=spectator["id"], sha256=sha(spectator_body),
                            movement_type_offset=20, spectator_flags_offset=36, killcam_offset=533720),
        server_setter_forwarded_unchanged=True, uploaded_playercards_stock=True,
        shared_network_strings_added=False)
    return pe, catalog, by_id, proof


def prepare(snapshot, *, manifest=None, replace_owned=False):
    snapshot = Path(snapshot).resolve(strict=True)
    assert snapshot.is_relative_to(ROOT / "data")
    assert not (snapshot.parent / "client-readiness.json").exists()
    manifest = Path(manifest or ROOT / "data/custom-operators/manifest.json").resolve(strict=True)
    rows, data_header = operator_data(manifest)
    # Reserve a separate primary ID range from all shipped head/body tables.
    import csv
    tables = Path(r"E:\replay-compiler\evidence\workstation-stringtable-actsexport-fixed\mw19replay\code_post_gfx\mw19replay\code_post_gfx\assets\stringtable")
    for kind in ("heads", "bodies", "alt_heads", "alt_bodies"):
        for path in tables.glob("mp/cac/" + kind + ".csv.*.csv"):
            table = list(csv.reader(path.read_text(encoding="utf-8-sig").splitlines()))
            assert all(not row[0].isdigit() or int(row[0]) < 60000 for row in table)
    pe, catalog, by_id, proof = inspect(snapshot)
    sys.path.insert(0, str(snapshot / "tools"))
    from workstation_sources import SourceWorkspace
    from coff import read
    from replay_owned_clone import assemble
    output = snapshot / "generated/custom-operators"
    output.mkdir(parents=True, exist_ok=True)
    workspace = SourceWorkspace(snapshot, output / "cache")
    workspace._catalog = catalog
    workspace._state = lambda: {"sources": {}}
    clone_sources, clones = [], []
    for identity, symbol, helper, size, digest in OWNERS:
        if not helper:
            continue
        source, clone = assemble(workspace, pe, catalog, by_id[identity], helper, output,
            Path(r"C:\Program Files\LLVM\bin"), read,
            gs_unwind=proof["owners"][symbol]["unwind"])
        assert clone["bytes"] == size
        if helper in ("CO_ShouldRecreateLegsNative", "CO_UpdateLegsNative"):
            # Redirect the world-model read only. The cache's second read must
            # still see the existing legs model, including a previous selection.
            native_model = "fn_ef8bc74e30ba356f"
            sites = [r for r in clone["external_fixups"] if r["stable_id"] == native_model]
            expected = [0x16DF415, 0x16DF47E] if helper == "CO_ShouldRecreateLegsNative" else [0x16DF60B]
            assert [r["original_site_rva"] for r in sites] == expected
            source = re.sub(r"\b" + native_model + r"\b", "CO_GetLegsSourceModel", source, count=1)
            source_path, object_path = output / (helper + ".cpp"), output / (helper + ".obj")
            before = read(object_path)
            source_path.write_text(source)
            subprocess.run([r"C:\Program Files\LLVM\bin\clang++.exe", "--target=x86_64-pc-windows-msvc",
                "-c", str(source_path), "-o", str(object_path), "-ffreestanding", "-fno-stack-protector",
                "-funwind-tables", "-fno-exceptions", "-fno-rtti"], check=True)
            after = read(object_path)
            assert len(before["sections"]) == len(after["sections"])
            redirected = 0
            for old, new in zip(before["sections"], after["sections"]):
                assert old["name"] == new["name"] and old["data"] == new["data"]
                def relocations(section, obj):
                    return [(offset, obj["symbols"][index]["name"], kind)
                            for offset, index, kind in section["relocations"]]
                wanted = []
                for offset, name, kind in relocations(old, before):
                    if old["name"] == ".text" and name == native_model and not redirected:
                        name = "CO_GetLegsSourceModel"
                        redirected += 1
                    wanted.append((offset, name, kind))
                assert relocations(new, after) == wanted
            assert redirected == 1
            clone.update(source_sha256=sha(source_path.read_bytes()), object_sha256=sha(object_path.read_bytes()),
                         source_model_redirect_site=expected[0])
        clone_sources.append(source)
        clones.append(clone)
        for fixup in clone["external_fixups"]:
            proof["imports"][fixup["stable_id"]] = fixup["stable_id"]
    for name in ("DW_CustomOperators.cpp", "DW_CustomOperators.h"):
        destination = snapshot / "src" / name
        assert not destination.exists() or destination.stat().st_nlink == 1
        destination.write_bytes((ROOT / "integration/replay" / name).read_bytes())
    header = """#pragma once
#include <stdint.h>
extern "C" {
uint64_t CO_RegisterHeadsNative(const char *);
uint64_t CO_RegisterBodiesNative(const char *);
uint64_t CO_BuildCustomizationNative(void *, unsigned, unsigned, unsigned, bool);
uint16_t CO_RegisterPackage(const char *, const char *, unsigned);
void CO_UpdateLocalCustomization(unsigned);
void CO_Print(int, const char *, ...);
extern uint8_t CO_LocalCustomization[];
uint64_t CO_CardModelsNative(unsigned, uint8_t *, uint32_t *, uint32_t *, void *, void *);
uint64_t CO_GetPlayercardNative(uint64_t, const char *, void *);
void *CO_GetLocalXuid(uint64_t *, unsigned);
void CO_RequestCardUpload(unsigned);
bool CO_UploadCard(unsigned);
void CO_UpdatePackageBindings(const char *);
int CO_TableRowNative(const void *, int, const char *);
const void *CO_GetTableNative(const char *, const void **);
int CO_TableMultiRowNative(const void *, const int *, const char *const *, int);
uint32_t CO_TableHash(const char *);
int CO_Format(char *, uint64_t, const char *, ...);
uint64_t CO_SetCustomizationNative(void *, uint64_t);
extern uint8_t *CO_Entities, *CO_ServerGlobals;
uint64_t CO_SetBody(void *, unsigned);
uint64_t CO_SetHead(void *, unsigned);
uint64_t *CO_PartyXuid(uint64_t *, const void *, int);
void *CO_ServerLobby();
bool CO_IsBot(const void *);
bool CO_CardSelections(uint64_t, const char *, uint8_t *, uint32_t *, uint32_t *);
extern const uint8_t *CO_LocalClientGlobals[];
const char *CO_GetActiveModelNative(unsigned, const void *, const void *, unsigned, bool *);
int CO_GenerateActiveModel(unsigned, const char **, const void *, const void *, unsigned, int);
const void *CO_DObjGetModel(const void *, unsigned);
const void *CO_FindAsset(int, const char *, int);
bool CO_ShouldRecreateLegsNative(unsigned, unsigned);
void CO_UpdateLegsNative(unsigned, const void *);
}
"""
    (snapshot / "src/DW_CustomOperatorsBindings.h").write_text(header)
    (snapshot / "src/DW_CustomOperatorsData.h").write_text(data_header)
    (snapshot / "src/DW_CustomOperators_Native.cpp").write_text("\n".join(clone_sources))
    associations_path = snapshot / "source-units.json"
    units_path = snapshot / "source-workstation/units.json"
    associations = json.loads(associations_path.read_bytes())
    units = json.loads(units_path.read_bytes())
    # Native lookup already belongs to map availability. Earlier custom
    # snapshots claimed it separately; retire only that exact obsolete claim.
    retired = dict(function_id="fn_cdf2d126fdf66569", source=SOURCE, symbol="DW_CustomOperators_TableLookup")
    for collection in (associations["units"], units["units"]):
        obsolete = [r for r in collection if r.get("function_id") == retired["function_id"] and r.get("source") == SOURCE]
        assert not obsolete or (replace_owned and all(r.get("symbol") == retired["symbol"] for r in obsolete)), "Unexpected native lookup ownership"
        collection[:] = [r for r in collection if r not in obsolete]
    digest = sha((snapshot / SOURCE).read_bytes())
    for identity, symbol, helper, size, body_digest in OWNERS:
        wanted = dict(function_id=identity, source=SOURCE, symbol=symbol)
        prior = [r for r in associations["units"] if r["function_id"] == identity]
        assert not prior or (replace_owned and prior == [wanted]), "Different root owner"
        if not prior:
            associations["units"].append(wanted)
        prior = [r for r in units["units"] if r["function_id"] == identity]
        assert not prior or (replace_owned and prior[0]["source"] == SOURCE)
        units["units"] = [r for r in units["units"] if r["function_id"] != identity]
        units["units"].append(dict(function_id=identity, kind="cpp", source=SOURCE, symbol=symbol,
                                  sha256=digest, revision=digest, language="cpp"))
    for alias, identity in proof["imports"].items():
        wanted = dict(symbol=alias, symbol_id=identity)
        prior = [r for r in associations.setdefault("imports", []) if r["symbol"] == alias]
        assert not prior or prior == [wanted]
        if not prior:
            associations["imports"].append(wanted)
    associations_path.write_text(json.dumps(associations, indent=2) + "\n")
    units_path.write_text(json.dumps(units, indent=2) + "\n")
    proof["dependencies"] = {name: sha((snapshot / "src" / name).read_bytes()) for name in (
        "DW_CustomOperators.cpp", "DW_CustomOperators.h", "DW_CustomOperatorsBindings.h",
        "DW_CustomOperatorsData.h", "DW_CustomOperators_Native.cpp")}
    proof.update(passed=True, source=SOURCE, source_sha256=digest, clones=clones, operators=rows,
                 manifest=str(manifest), manifest_sha256=sha(manifest.read_bytes()),
                 generator_sha256=sha(Path(__file__).read_bytes()))
    (snapshot / "generated/custom-operators-integration.json").write_text(json.dumps(proof, indent=2) + "\n")
    return proof


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--inspect-only", action="store_true")
    parser.add_argument("--replace-owned", action="store_true")
    args = parser.parse_args()
    result = inspect(args.snapshot)[-1] if args.inspect_only else prepare(
        args.snapshot, manifest=args.manifest, replace_owned=args.replace_owned)
    print(json.dumps(result, indent=2))
