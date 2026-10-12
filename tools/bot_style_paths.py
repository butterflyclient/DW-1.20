"""Replay-owned zone directory policy derived from the original native image."""

import hashlib
import json
from pathlib import Path
import struct

import capstone
from capstone.x86_const import X86_OP_MEM, X86_REG_RIP
import pefile

IMAGE = Path("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe")
IMAGE_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
FUNCTIONS = (
    ("fn_eccc2e99b655b10d", "DB_File_OpenDBFile", 145, "f4f4cd96f7a2dab5d6ba15aa091c468e8315c870a31127de978b7f351510fd49"),
    ("fn_295fbdf66c9d5e2f", "DWBSZ_IsLocalized", 227, "db2ca12f627f6198ddb0eb83c23de3c1e3d9ac4219d261025a66dda2fc4995f8"),
    ("fn_8fd709e23efbafa5", "DWBSZ_IsRegional", 195, "72f2319c91423fb5e9bb14f93904452043ad02059bf9496f21a35c244d39d9ad"),
    ("fn_24314f52a57ba15d", "DWBSZ_BuildAbsPath", 159, "8b9eecebca3f282d3448f9de2e8dae6b469ee2d6d6b59e4d0ae4be55412de52c"),
    ("fn_bf31d033940921cb", "Sys_SetFolders", 358, "6ae2777979dc6a7ed8bce7f5c60153f372d24c4615848786d192dd276f0ac381"),
    ("fn_da779bcd6dfc5413", "Sys_SetRegionalFolders", 199, "2678179bdcb2ee66b3e2c3e904e520e551ed29ea2d6cefecb94a905577b22ee4"),
    ("fn_ee36c67856385722", "SEH_GetCurrentLanguageName", 40, "02f7526247c1348155aca930c1dfe8cef9025bd9d8d0dbbaceef57a2afac89f3"),
    ("fn_bf545b7e5b6b90dc", "RG_GetCurrentRegionName", 78, "227cf5c31e023063c198a07a581e391383c985a0abc96fdc9df738f5aa78b7c7"),
    ("fn_169bad9b2d259b4e", "Sys_DefaultInstallPath", 267, "84dc843fe73cf7a370e510b8fff15fe5f48838429a1c1641542872bcd99385f2"),
    ("fn_7d3c68d083bb7a1d", "RG_GetCurrentRegionCode", 78, "9211fe667e5f5b8165d0ba6f6e340a3750d809a55167fc037ad241a27661ecfb"),
    ("fn_f7e7b34c60acdbed", "SEH_GetCurrentLanguageCode", 40, "e5fc19d19870e79517f49b3f3177d0de195d68fb1ecdbe5b16d39bcbe4d58e55"),
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def derive(snapshot):
    catalog = json.loads((Path(snapshot) / "generated/function-catalog.json").read_bytes())
    if catalog["image_sha256"] != IMAGE_SHA or sha(IMAGE.read_bytes()) != IMAGE_SHA:
        raise ValueError("Native zone path image changed")
    pe = pefile.PE(str(IMAGE), fast_load=True)
    byid = {row["id"]: row for row in catalog["functions"]}
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    proof, rows = [], {}
    for identity, role, size, digest in FUNCTIONS:
        row = byid[identity]
        body = pe.get_data(row["rva"], size)
        if row.get("quarantined") or sha(body) != digest:
            raise ValueError("Native zone path function changed: " + role)
        rows[role] = list(decoder.disasm(body, row["rva"]))
        proof.append(dict(identity=identity, role=role, rva=row["rva"], bytes=size, sha256=digest))

    def string(rva):
        value = pe.get_data(rva, 64).split(b"\0", 1)[0].decode("ascii")
        if len(value) >= 64 or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_" for c in value):
            raise ValueError("Unbounded native locale directory")
        return value

    def addresses(role):
        return [i.address + i.size + i.operands[1].mem.disp for i in rows[role]
                if i.mnemonic == "lea" and len(i.operands) == 2 and
                i.operands[1].type == X86_OP_MEM and i.operands[1].mem.base == X86_REG_RIP]

    region_codes = [string(at) for at in addresses("RG_GetCurrentRegionCode")]
    region_names = [string(at) for at in addresses("RG_GetCurrentRegionName")]
    if sorted(region_codes) != ["", "cn", "jp", "kr15", "sa", "ww"] or len(region_names) != len(region_codes):
        raise ValueError("Native regional branches changed")
    # Both pinned getters have the same switch structure and branch order.
    regions = dict(zip(region_codes, region_names))
    name_addresses, code_addresses = addresses("SEH_GetCurrentLanguageName"), addresses("SEH_GetCurrentLanguageCode")
    if len(name_addresses) != 1 or code_addresses != [name_addresses[0] + 8]:
        raise ValueError("Native language table fields changed")
    table = pe.get_data(name_addresses[0], 21 * 24)
    languages = {}
    for index in range(21):
        name, code, _flags = struct.unpack_from("<QQQ", table, index * 24)
        languages[string(code - pe.OPTIONAL_HEADER.ImageBase)] = string(name - pe.OPTIONAL_HEADER.ImageBase)
    if len(languages) != 21:
        raise ValueError("Native language codes are duplicated")
    # Retain the complete target ABI as evidence. Only English is delivered;
    # regional companions are independent of the selected language.
    supported_languages = {"eng": languages["eng"]}
    if supported_languages != {"eng": "english"}:
        raise ValueError("Native English language identity changed")
    rule_directories = {code + "_": directory for code, directory in {**regions, **languages}.items()}
    rule_directories.update({"": "", "srv_": "", "techsets_": ""})
    rules = [dict(name_prefix=prefix, directory=directory)
             for prefix, directory in sorted(rule_directories.items())]
    installation_directories = {
        code + "_": directory
        for code, directory in {**regions, **supported_languages}.items()
    }
    installation_directories.update({"": "", "srv_": "", "techsets_": ""})
    installation_rules = [dict(name_prefix=prefix, directory=directory)
                          for prefix, directory in sorted(installation_directories.items())]
    return dict(regions=list(regions), languages=list(languages), region_directories=regions,
                language_directories=languages, native=proof, image_sha256=IMAGE_SHA,
                native_folder_rules=rules,
                supported_languages=list(supported_languages),
                supported_language_directories=supported_languages,
                installation_folder_rules=installation_rules,
                language_table_sha256=sha(table), language_record_bytes=24,
                language_name_offset=0, language_code_offset=8,
                folder_ids=dict(zone=0, localized=1, regional=7),
                native_classifier="current language prefix first, then current region prefix, case insensitive",
                relative_root="zone", policy_generator_sha256=sha(Path(__file__).read_bytes()))


def directory_for_name(name, zone, policy):
    if name == zone or name in ("techsets_" + zone, "srv_" + zone):
        return ""
    suffix = "_" + zone
    if not name.endswith(suffix):
        raise ValueError("Overlay installation name is not owned")
    prefix = name[:-len(suffix)]
    if prefix in policy["language_directories"]:
        return policy["language_directories"][prefix]
    if prefix in policy["region_directories"]:
        return policy["region_directories"][prefix]
    raise ValueError("Overlay prefix has no native directory")
