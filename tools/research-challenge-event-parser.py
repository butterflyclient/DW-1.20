"""Execute the original challenge parameter parser with explicit CRT boundaries.

Uses enabled upload dvars, a fixed match-ID input and retained asset-table
lookups. Proves parser output only; ingestion, context flags, mission predicates
and client callbacks are separate contracts.
"""
import hashlib
import json
from pathlib import Path
import struct
import argparse
import csv
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_RSP, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RAX, UC_X86_REG_RIP)

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
assert args.output.resolve().is_relative_to(ROOT)
extra_tables = {}
for filename in ("20261010-challenge-asset-tables.json", "20261010-challenge-br-asset-tables.json"):
    table_manifest = ROOT / "validation" / filename
    if not table_manifest.is_file():
        continue
    manifest = json.loads(table_manifest.read_bytes())
    assert manifest["passed"] and manifest["target_image_sha256"] == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
    for source in (manifest["source"], *manifest["source"]["patches"]):
        assert hashlib.sha256(Path(source["path"]).read_bytes()).hexdigest() == source["sha256"]
    for row in manifest["tables"]:
        path = (ROOT / row["path"]).resolve()
        assert path.is_relative_to(ROOT) and row["type_id"] == 54
        assert hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"]
        extra_tables[row["name"]] = path
image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
raw = image.read_bytes()
assert hashlib.sha256(raw).hexdigest() == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
pe = pefile.PE(data=raw, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
entry, end = 0x140F35980, 0x140F385DC
code = pe.get_data(entry - base, end - entry)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]])
helper_entry = 0x140F358D0
helper_rows = [row.struct for row in pe.DIRECTORY_ENTRY_EXCEPTION
               if base + row.struct.BeginAddress == helper_entry]
assert len(helper_rows) == 1
helper_end = base + helper_rows[0].EndAddress
assert helper_entry < helper_end <= entry
helper_bytes = pe.get_data(helper_entry - base, helper_end - helper_entry)
decoder = Cs(CS_ARCH_X86, CS_MODE_64)
decoder.detail = True
instructions = list(decoder.disasm(code, entry))
flags = set()
for left, right in zip(instructions, instructions[1:]):
    if (left.mnemonic == "mov" and left.op_str.startswith("rax, qword ptr [rip")
            and ((right.mnemonic == "cmp" and right.op_str == "byte ptr [rax + 0x28], 0")
                 or (right.mnemonic == "movzx" and "byte ptr [rax + 0x28]" in right.op_str))):
        operand = left.operands[1]
        flags.add(left.address + left.size + operand.mem.disp)


def case(name, params):
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    for section in pe.sections:
        size = (max(section.Misc_VirtualSize, section.SizeOfRawData) + 4095) & ~4095
        if size:
            vm.mem_map(base + section.VirtualAddress, size)
            vm.mem_write(base + section.VirtualAddress, section.get_data())
    scratch, stack, stop = 0x60000000, 0x70000000, 0x71000000
    vm.mem_map(scratch, 0x20000)
    vm.mem_map(stack, 0x20000)
    vm.mem_map(stop, 4096)
    for index, pointer in enumerate(sorted(flags)):
        value = scratch + 0x2000 + index * 64
        vm.mem_write(pointer, struct.pack("<Q", value))
        vm.mem_write(value + 40, b"\x01")
    name_ptr, params_ptr, output = scratch + 0x100, scratch + 0x200, scratch + 0x1000
    vm.mem_write(name_ptr, name.encode() + b"\0")
    vm.mem_write(params_ptr, params.encode() + b"\0")
    rsp = stack + 0x1F008
    vm.mem_write(rsp, struct.pack("<Q", stop))
    for register, value in ((UC_X86_REG_RSP, rsp), (UC_X86_REG_RCX, scratch),
                            (UC_X86_REG_RDX, name_ptr), (UC_X86_REG_R8, params_ptr),
                            (UC_X86_REG_R9, output)):
        vm.reg_write(register, value)
    global_token = 0
    calls = []
    tables = {}
    table_hashes = {}
    allocated = scratch + 0x5000

    def allocate(string):
        nonlocal allocated
        pointer = allocated
        payload = string.encode() + b"\0"
        allocated += (len(payload) + 7) & ~7
        assert allocated < scratch + 0x1F000
        vm.mem_write(pointer, payload)
        return pointer

    def text(pointer):
        out = bytearray()
        while pointer and len(out) < 1024:
            byte = bytes(vm.mem_read(pointer + len(out), 1))
            if byte == b"\0":
                break
            out.extend(byte)
        return out.decode("ascii")

    def tokenize(pointer, delimiter, context):
        nonlocal global_token
        if not pointer:
            pointer = struct.unpack("<Q", vm.mem_read(context, 8))[0] if context else global_token
        if not pointer:
            return 0
        while bytes(vm.mem_read(pointer, 1)) in delimiter and bytes(vm.mem_read(pointer, 1)) != b"\0":
            pointer += 1
        if bytes(vm.mem_read(pointer, 1)) == b"\0":
            result, following = 0, 0
        else:
            result = pointer
            while bytes(vm.mem_read(pointer, 1)) != b"\0" and bytes(vm.mem_read(pointer, 1)) not in delimiter:
                pointer += 1
            if bytes(vm.mem_read(pointer, 1)) == b"\0":
                following = 0
            else:
                vm.mem_write(pointer, b"\0")
                following = pointer + 1
        if context:
            vm.mem_write(context, struct.pack("<Q", following))
        else:
            global_token = following
        return result

    def hook(uc, address, size, _):
        nonlocal allocated
        if entry <= address < end or helper_entry <= address < helper_end:
            return
        if address == stop:
            uc.emu_stop()
            return
        rcx, rdx, r8 = (uc.reg_read(r) for r in (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8))
        calls.append(hex(address))
        value = 0
        if address == 0x1421F6CC0:  # memset
            uc.mem_write(rcx, bytes([rdx & 255]) * r8)
            value = rcx
        elif address == 0x142036A10:  # bounded Core_strcpy
            string = text(r8).encode()
            assert len(string) < rdx
            uc.mem_write(rcx, string + b"\0")
        elif address == 0x1421FB0E4:  # CRT atoi, signed 32-bit return
            prefix = re.match(r"\s*([+-]?[0-9]+)", text(rcx))
            parsed = int(prefix.group(1)) if prefix else 0
            # Model only defined in-range atoi inputs; do not invent this CRT's
            # overflow/errno behavior. Native floats serialize as decimal text.
            assert -(1 << 31) <= parsed < (1 << 31)
            value = parsed & 0xFFFFFFFF
        elif address == 0x142225F88:  # CRT strtok
            value = tokenize(rcx, text(rdx).encode(), 0)
        elif address == 0x142036F40:  # I_strtok_r
            value = tokenize(rcx, text(rdx).encode(), r8)
        elif address == 0x1421CCF60:  # security-cookie boundary preserves result
            value = uc.reg_read(UC_X86_REG_RAX)
        elif address == 0x1412B0820:  # Com_Printf
            pass
        elif address == 0x140D38D50:  # I_strnicmp
            left, right = text(rcx)[:r8].lower(), text(rdx)[:r8].lower()
            value = (0 if left == right else (-1 if left < right else 1)) & 0xFFFFFFFF
        elif address == 0x140E60C20:  # I_stricmp
            left, right = text(rcx).lower(), text(rdx).lower()
            value = (0 if left == right else (-1 if left < right else 1)) & 0xFFFFFFFF
        elif address == 0x141042BC0:  # OnlineMatchId::GetMatchId fixture boundary
            value = 987654321
        elif address == 0x1413E2B00:  # native StringTable asset boundary
            asset = text(rcx)
            root = Path(r"E:\replay-compiler\evidence\workstation-stringtable-actsexport-fixed\mw19replay\code_post_gfx\mw19replay\code_post_gfx\assets\stringtable")
            paths = ([extra_tables[asset]] if asset in extra_tables else
                     list((root / Path(asset).parent).glob(Path(asset).name + ".*.csv")))
            assert len(paths) == 1, asset
            rows = list(csv.reader(paths[0].read_text(encoding="utf-8-sig").splitlines()))
            table_hashes[asset] = hashlib.sha256(paths[0].read_bytes()).hexdigest()
            pointer = allocate("" * 32)
            allocated += 64
            tables[pointer] = rows
            uc.mem_write(rdx, struct.pack("<Q", pointer))
        elif address == 0x1413E2B90:
            value = len(tables[rcx])
        elif address == 0x1413E2B40:
            value = allocate(tables[rcx][rdx][r8])
        elif address == 0x1413E2BA0:
            rows = tables[rcx]
            selected = text(r8)
            column = uc.reg_read(UC_X86_REG_R9)
            value = allocate(next((row[column] for row in rows if row[rdx] == selected), ""))
        else:
            raise RuntimeError(f"Unmodeled call {address:#x} for {name}")
        uc.reg_write(UC_X86_REG_RAX, value)
        sp = uc.reg_read(UC_X86_REG_RSP)
        destination = struct.unpack("<Q", uc.mem_read(sp, 8))[0]
        uc.reg_write(UC_X86_REG_RSP, sp + 8)
        uc.reg_write(UC_X86_REG_RIP, destination)

    vm.hook_add(UC_HOOK_CODE, hook)
    try:
        vm.emu_start(entry, stop, count=500000)
    except Exception as error:
        raise RuntimeError(f"{error}; rip={vm.reg_read(UC_X86_REG_RIP):#x}; rax={vm.reg_read(UC_X86_REG_RAX):#x}") from error
    assert vm.reg_read(UC_X86_REG_RIP) == stop
    data = bytes(vm.mem_read(output, 88))
    count = data[80]
    assert count <= 10
    return dict(name=name, input=params, accepted=bool(vm.reg_read(UC_X86_REG_RAX) & 255),
                parameter_count=count, values=list(struct.unpack("<10Q", data[:80]))[:count],
                external_boundaries=sorted(set(calls)), asset_sha256=table_hashes)


rows = []
for name, params in (("start_match", "11,22,33,44,55"),
                     ("end_match", "11,22,33,44,55"),
                     ("mp_addxp", "101,202,303,404,505"),
                     ("kill", "101|202,iw8_ar_mike4,11,22,33,44,55"),
                     ("end_match", "-1,-2,-3,-4,-5"),
                     ("kill", "101|202,iw8_pi_golf21_mp,11,22,33,44,55"),
                     ("not_a_native_challenge_event", "11,22")):
    try:
        rows.append(case(name, params))
    except Exception as error:
        rows.append(dict(name=name, error=str(error)))
assert rows[0]["values"] == [987654321, 11]
assert rows[1]["values"] == [11, 22, 33, 44, 55]
assert rows[2]["values"] == [101, 0, 0, 404, 505]
assert rows[4]["values"] == [0xFFFFFFFF, 0xFFFFFFFFFFFFFFFE,
                              0xFFFFFFFFFFFFFFFD, 0xFFFFFFFFFFFFFFFC,
                              0xFFFFFFFFFFFFFFFB]
assert rows[5]["parameter_count"] == 7 and rows[5]["values"][0] & 0xFFFF == 1, rows[5]
assert rows[5]["values"][5] >> 48 == 129  # Native pistol class mask.
assert not rows[6]["accepted"] and rows[6]["parameter_count"] == 0

# Full producer strings, including attachment/perk/operator and death-cause
# slots. Expected semantics come from shipped tables; all packed numbers below
# are computed by executing the original image, never by a backend encoder.
def kill_input(weapon, attachments="no_attachments", cause="MOD_RIFLE_BULLET", target_type=1,
               perks="no_perks"):
    return f"1|2,{weapon},3,4,unknown_operator,0,{attachments},{perks},{target_type},no_super,0,{cause},0,0"

fixtures = (
    ("assault", "iw8_ar_mike4_mp", "no_attachments", "MOD_RIFLE_BULLET", 15, 3),
    ("smg", "iw8_sm_mpapa5_mp", "no_attachments", "MOD_RIFLE_BULLET", 6, 5),
    ("shotgun", "iw8_sh_dpapa12_mp", "no_attachments", "MOD_RIFLE_BULLET", 34, 9),
    ("lmg", "iw8_lm_kilo121_mp", "no_attachments", "MOD_RIFLE_BULLET", 38, 17),
    ("sniper", "iw8_sn_alpha50_mp", "no_attachments", "MOD_RIFLE_BULLET", 30, 65),
    ("marksman", "iw8_sn_mike14_mp", "no_attachments", "MOD_RIFLE_BULLET", 27, 65),
    ("pistol", "iw8_pi_golf21_mp", "no_attachments", "MOD_PISTOL_BULLET", 1, 129),
    ("frag", "equip_frag", "no_attachments", "MOD_GRENADE_SPLASH", 50000, 3072),
    ("semtex", "equip_semtex", "no_attachments", "MOD_GRENADE_SPLASH", 50001, 3072),
    ("molotov", "equip_molotov", "no_attachments", "MOD_FIRE", 50002, 3072),
    ("proximity_mine", "equip_at_mine", "no_attachments", "MOD_EXPLOSIVE", 50007, 3072),
    ("throwing_knife", "equip_throwing_knife", "no_attachments", "MOD_PROJECTILE", 50004, 3072),
    ("thermite", "equip_thermite", "no_attachments", "MOD_FIRE", 50006, 3072),
    ("tactical", "equip_concussion", "no_attachments", "MOD_IMPACT", 50010, 1024),
    ("finishing_move", "iw8_knife_mp", "no_attachments", "MOD_EXECUTION", 14, 513),
    ("one_attachment", "iw8_ar_mike4_mp", "reflex", "MOD_RIFLE_BULLET", 15, 3),
    ("lmg_five", "iw8_lm_kilo121_mp", "acog|acoglight|acog2|acog2light|reflex", "MOD_RIFLE_BULLET", 38, 17),
    ("fr556", "iw8_ar_falpha_mp", "no_attachments", "MOD_RIFLE_BULLET", 18, 3),
    ("sniper_head_five", "iw8_sn_alpha50_mp", "acog|acoglight|acog2|acog2light|reflex", "MOD_HEAD_SHOT", 30, 65),
    ("marksman_head_five", "iw8_sn_mike14_mp", "acog|acoglight|acog2|acog2light|reflex", "MOD_HEAD_SHOT", 27, 65),
    ("magnum_three", "iw8_pi_cpapa_mp", "acog|acoglight|reflex", "MOD_PISTOL_BULLET", 5, 129),
)
for label, weapon, attachments, cause, expected_id, expected_class in fixtures:
    row = case("kill", kill_input(weapon, attachments, cause))
    assert row["accepted"] and row["parameter_count"] == 7, row
    assert row["values"][0] & 0xFFFF == expected_id, row
    assert row["values"][5] >> 48 == expected_class, row
    row["fixture_label"] = label
    rows.append(row)
for label, target_type in (("equipment_target", 64), ("vehicle_target", 32),
                           ("killstreak_target", 2), ("unknown_target", 0)):
    row = case("kill", kill_input("iw8_pi_golf21_mp", target_type=target_type))
    assert row["values"][5] >> 16 & 0xFFFF == target_type
    row["fixture_label"] = label
    rows.append(row)
assert next(row for row in rows if row.get("fixture_label") == "finishing_move")["values"][6] >> 16 & 0xFFFF == 21
assert next(row for row in rows if row.get("fixture_label") == "sniper_head_five")["values"][6] >> 16 & 0xFFFF == 9
assert next(row for row in rows if row.get("fixture_label") == "lmg_five")["values"][5] & 255 == 5
# Original instruction execution establishes the perk slots, five packed
# attachment slots and optic family independently of the backend predicates.
kill_contexts = (
    ("ghost_first", "iw8_pi_golf21_mp", "no_attachments", "MOD_PISTOL_BULLET", "specialty_ghost"),
    ("ghost_second", "iw8_pi_golf21_mp", "no_attachments", "MOD_PISTOL_BULLET", "specialty_tracker|specialty_ghost"),
    ("ghost_third", "iw8_pi_golf21_mp", "no_attachments", "MOD_PISTOL_BULLET", "specialty_tracker|specialty_extra_shrapnel|specialty_ghost"),
    ("br_ghost", "iw8_pi_golf21_mp", "no_attachments", "MOD_PISTOL_BULLET", "specialty_br_ghost"),
    ("shrapnel_frag", "equip_frag", "no_attachments", "MOD_GRENADE_SPLASH", "specialty_extra_shrapnel"),
    ("shrapnel_pistol", "iw8_pi_golf21_mp", "no_attachments", "MOD_PISTOL_BULLET", "specialty_extra_shrapnel"),
    ("tracker_smg", "iw8_sm_mpapa5_mp", "no_attachments", "MOD_RIFLE_BULLET", "specialty_tracker"),
    ("tracker_pistol", "iw8_pi_golf21_mp", "no_attachments", "MOD_PISTOL_BULLET", "specialty_tracker"),
    ("br_tracker_smg", "iw8_sm_mpapa5_mp", "no_attachments", "MOD_RIFLE_BULLET", "specialty_br_tracker"),
    ("smg_head", "iw8_sm_mpapa5_mp", "no_attachments", "MOD_HEAD_SHOT", "no_perks"),
    ("ak47_head", "iw8_ar_akilo47_mp", "no_attachments", "MOD_HEAD_SHOT", "no_perks"),
    ("ak47_body", "iw8_ar_akilo47_mp", "no_attachments", "MOD_RIFLE_BULLET", "no_perks"),
    ("reflex_head", "iw8_pi_golf21_mp", "reflex", "MOD_HEAD_SHOT", "no_perks"),
    ("reflex_pistol", "iw8_pi_golf21_mp", "reflex", "MOD_PISTOL_BULLET", "no_perks"),
    ("reflex_assault", "iw8_ar_mike4_mp", "reflex", "MOD_RIFLE_BULLET", "no_perks"),
    ("acog_head", "iw8_pi_golf21_mp", "acog", "MOD_HEAD_SHOT", "no_perks"),
    ("zoom_head", "iw8_sn_alpha50_mp", "vzscope", "MOD_HEAD_SHOT", "no_perks"),
    ("zoom_body", "iw8_sn_alpha50_mp", "vzscope", "MOD_RIFLE_BULLET", "no_perks"),
    ("sks_five", "iw8_sn_sksierra_mp", "acog|acoglight|acog2|acog2light|reflex", "MOD_RIFLE_BULLET", "no_perks"),
    ("crossbow_five", "iw8_sn_crossbow_mp", "acog|acoglight|acog2|acog2light|reflex", "MOD_RIFLE_BULLET", "no_perks"),
    ("marksman_four", "iw8_sn_mike14_mp", "acog|acoglight|acog2|reflex", "MOD_RIFLE_BULLET", "no_perks"),
    ("unknown_attachments", "iw8_sn_mike14_mp", "unknown_attachment|unknown_attachment2|unknown_attachment3|unknown_attachment4|unknown_attachment5", "MOD_RIFLE_BULLET", "no_perks"),
    ("double_time_smg", "iw8_sm_mpapa5_mp", "no_attachments", "MOD_RIFLE_BULLET", "specialty_hustle"),
    ("double_time_second", "iw8_sm_mpapa5_mp", "no_attachments", "MOD_RIFLE_BULLET", "specialty_ghost|specialty_hustle"),
    ("double_time_third", "iw8_sm_mpapa5_mp", "no_attachments", "MOD_RIFLE_BULLET", "specialty_ghost|specialty_tracker|specialty_hustle"),
    ("double_time_assault", "iw8_ar_mike4_mp", "no_attachments", "MOD_RIFLE_BULLET", "specialty_hustle"),
)
for label, weapon, attachments, cause, perks in kill_contexts:
    row = case("kill", kill_input(weapon, attachments, cause, perks=perks))
    assert row["accepted"] and row["parameter_count"] == 7, row
    row["fixture_label"] = label
    rows.append(row)
context = {row["fixture_label"]: row["values"] for row in rows if "fixture_label" in row}
for label, slot in (("ghost_first", 0), ("ghost_second", 1), ("ghost_third", 2)):
    assert (context[label][4] >> (16 * slot)) & 0xFFFF == 52
assert context["shrapnel_frag"][4] & 0xFFFF == 12
for label, slot in (("double_time_smg", 0), ("double_time_second", 1), ("double_time_third", 2)):
    assert (context[label][4] >> (16 * slot)) & 0xFFFF == 7
assert context["tracker_smg"][4] & 0xFFFF == 56
assert context["reflex_head"][6] & 0xFFFF == 1
assert context["zoom_head"][6] & 0xFFFF == 6
assert context["sks_five"][0] & 0xFFFF == 536
assert context["crossbow_five"][0] & 0xFFFF == 33
assert context["unknown_attachments"][5] & 0xFF == 0
for label, name, params in (
    ("ping_enemy", "ping", "enemy, "),
    ("ping_object", "ping", "object, "),
    ("ping_danger", "ping", "danger, "),
    ("ping_unknown", "ping", "unknown, "),
    ("pickup_totals", "pickup", "2,3,4, "),
    ("pickup_weapons", "pickup", "2,0,0, "),
    ("pickup_cash", "pickup", "0,3,0, "),
    ("pickup_caches", "pickup", "0,0,4, "),
    ("driving_ms", "driving", "45000, "),
    ("gas_ms", "alive_in_gas", "1250, "),
    ("not_downed_ms", "alive_not_downed", "61000, "),
    ("gas_partial_ms", "alive_in_gas", "250, "),
    ("gas_remaining_ms", "alive_in_gas", "750, "),
    ("driving_remaining_ms", "driving", "15000, "),
    ("not_downed_partial_ms", "alive_not_downed", "45000, "),
    ("not_downed_remaining_ms", "alive_not_downed", "15000, "),
    ("self_revive", "revive", "1,1, "),
    ("teammate_revive", "revive", "0,1, "),
    ("being_revived", "revive", "1,0, "),
    ("invalid_revive_flags", "revive", "2,2, "),
    ("gulag_win", "gulag_end_match", "1, "),
    ("gulag_loss", "gulag_end_match", "2, "),
    ("placement_15", "match_placement", "5,15, "),
    ("loadout", "loadout", "1, "),
    ("contract_locales", "contract_start", "4|33,4|33, ,1"),
    ("stim_health", "stim", "17.500000"),
    ("stim_fraction", "stim", "0.750000"),
    ("stim_zero", "stim", "0"),
    ("stim_remaining_health", "stim", "2483.999"),
):
    try:
        row = case(name, params)
        row["fixture_label"] = label
        rows.append(row)
    except Exception as error:
        rows.append(dict(name=name, input=params, fixture_label=label, error=str(error)))
for label, expected in {"pickup_totals": [2, 3, 4, 0], "driving_ms": [45000, 0],
                         "ping_enemy": [9, 0], "ping_object": [13, 0],
                         "ping_danger": [10, 0], "ping_unknown": [0, 0],
                         "gas_ms": [1250, 0], "not_downed_ms": [61000, 0],
                         "self_revive": [1, 1, 0], "teammate_revive": [0, 1, 0],
                         "being_revived": [1, 0, 0], "invalid_revive_flags": [2, 2, 0],
                         "gulag_win": [1, 0], "gulag_loss": [2, 0],
                         "placement_15": [5, 15, 0], "loadout": [1, 0],
                         "contract_locales": [4, 4, 0], "stim_health": [17],
                         "stim_fraction": [0], "stim_zero": [0],
                         "stim_remaining_health": [2483]}.items():
    row = next(row for row in rows if row.get("fixture_label") == label)
    assert row.get("values") == expected, row
for locale in range(1, 34):
    row = case("contract_start", f"0,{locale}, ,1")
    assert row["values"] == [0, locale, 0], row
    row["fixture_label"] = f"contract_card_{locale}"
    rows.append(row)
    row = case("contract_start", f"{locale},0, ,1")
    assert row["values"] == [locale, 0, 0], row
    row["fixture_label"] = f"contract_player_{locale}"
    rows.append(row)
for label, params, expected in (
    ("contract_player_only", "4,0, ,1", [4, 0, 0]),
    ("contract_no_locale", "0,0, ,1", [0, 0, 0]),
):
    row = case("contract_start", params)
    assert row["values"] == expected, row
    row["fixture_label"] = label
    rows.append(row)
for label, name, params in (
    ("use_armor", "use_item", "armor_plate, "),
    ("use_respawn_token", "use_item", "respawn_token, "),
    ("use_unknown", "use_item", "unknown, "),
    ("collect_armor", "collect_item", "armor_plate, "),
    ("loadout_preset", "loadout", "0, "),
    ("loadout_invalid", "loadout", "2, "),
    ("contract_success_alive", "contract_end", "scavenger,1,1,1, "),
    ("contract_success_dead", "contract_end", "scavenger,1,0,1, "),
    ("contract_failed", "contract_end", "scavenger,2,1,1, "),
    ("contract_target_survived", "contract_end", "assassination,1,1,2, "),
    ("contract_invalid_alive", "contract_end", "scavenger,1,2,1, "),
    ("contract_invalid_role", "contract_end", "scavenger,1,1,3, "),
    ("contract_unknown_result", "contract_end", "scavenger,0,1,1, "),
    ("contract_unknown_category", "contract_end", "unknown,1,1,1, "),
    ("placement_br_15", "match_placement", "24,15, "),
    ("placement_br_16", "match_placement", "24,16, "),
):
    row = case(name, params)
    assert row["accepted"], row
    row["fixture_label"] = label
    rows.append(row)
names = set()
for instruction in instructions:
    for operand in instruction.operands:
        if instruction.mnemonic == "lea" and operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
            address = instruction.address + instruction.size + operand.mem.disp
            data = pe.get_data(address - base, 160).split(b"\0", 1)[0]
            if data and all(97 <= byte <= 122 or 48 <= byte <= 57 or byte == 95 for byte in data):
                names.add(data.decode("ascii"))
for name in sorted(names):
    try:
        rows.append(case(name, ""))
    except Exception as error:
        rows.append(dict(name=name, input="", error=str(error)))
result = dict(target_image_sha256=hashlib.sha256(raw).hexdigest(),
              tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              function=dict(address=entry, end=end, bytes_sha256=hashlib.sha256(code).hexdigest()),
              executed_helpers=[dict(address=helper_entry,end=helper_end,
                                    bytes_sha256=hashlib.sha256(helper_bytes).hexdigest(),
                                    boundary_source="Original PE unwind entry")],
              enabled_dvar_pointers=sorted(flags), cases=rows,
              scope="Original parser instructions; enabled dvars and explicit CRT/log/cookie boundaries. No event delivery or earning predicate claim.")
assert all("error" not in row for row in rows), [row for row in rows if "error" in row]
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(result, indent=2) + "\n")
print("PASS:", len(rows), "original challenge parser cases;", len({row["name"] for row in rows if row["accepted"]}), "accepted event names")
