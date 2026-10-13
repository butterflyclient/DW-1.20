"""Reconstruct the complete Replay Bot_Think through verified native boundaries."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

ROOT = Path(__file__).resolve().parents[1]
IMAGE_HASH = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
IDENTITY = "fn_4d36d641c4b352d6"
BODY_HASH = "dd9853932dab5fab9bdd03ccfdddfec5705e580f4a06cdb65abb8330da86543b"
# Ordinal in the complete, digest-verified native direct-call sequence. Repeated
# calls are checked too, protecting semantic names from accidental retargeting.
CALLS = [
    (0, "PlayerState", "void *", "int"), (1, "RoundRobin", "void", "void *"),
    (2, "NavSetPos", "void", "void *, const void *"), (3, "EntityData", "void *", "const void *"),
    (4, "LocalPaused", "bool", ""), (5, "ViewWeapon", "void *", "const void *"),
    (6, "WeaponNone", "int", "const void *"), (7, "WeaponUpdate", "void", "void *, void *"),
    (8, "Direction", "void", "void *, void *"), (9, "ArchiveTime", "int", "int"),
    (10, "PrintError", "void", "int, const char *, ..."),
    (12, "NearestNode", "void *", "const void *"), (13, "NearestTac", "void *", "void *"),
    (14, "Strafe", "void", "void *"), (15, "OffGridMove", "void", "void *, void *"),
    (16, "ScriptedScene", "bool", "const void *"), (18, "ClearWeapon", "void", "void *, const void *"),
    (19, "PlayerExcluded", "int", "const void *"), (20, "BotExcluded", "int", "const void *"),
    (21, "RadarEvent", "void", "void *, const void *, float, uint8_t"),
    (23, "RandomInt", "int", "int, int"), (24, "XRay", "void", "void *"),
    (25, "Sight", "void", "void *, void *"), (26, "Threat", "void", "void *"),
    (27, "EnemyTrack", "void", "void *"), (28, "RiotShield", "void", "void *"),
    (30, "Movement", "void", "void *, void *"), (31, "Doors", "void", "void *"),
    (34, "ADSDesire", "int", "const void *"), (35, "ADSAllowed", "int", "void *, const void *"),
    (37, "NodeDistance", "float", "const void *, float, int"), (38, "SniperADS", "int", "const void *"),
    (39, "WeaponRange", "float", "const void *, const void *"), (40, "CanFire", "int", "void *"),
    (42, "Combat", "void", "void *, void *"), (43, "Reload", "int", "void *, void *"),
    (44, "WeaponMap", "void *", ""), (45, "MapViewWeapon", "void *", "const void *, const void *"),
    (46, "Underbarrel", "bool", "const void *"), (48, "PressADS", "int", "const void *"),
    (49, "CanHoldBreath", "int", "const void *"), (51, "RandomFloat", "float", ""),
    (52, "BreathTime", "int", "const void *"), (53, "ScriptButtons", "void", "void *, void *"),
    (55, "IsFiring", "int", "void *, const void *"), (56, "IsSkydiving", "bool", "const void *"),
    (57, "DualWield", "bool", "const void *"),
    (58, "Gesture", "void *", "const void *, const void *, const void *, bool, bool, unsigned"),
    (60, "GesturePlaying", "bool", "const void *, const void *, void *, void *"),
    (62, "ScreenTargets", "void", "void *"), (63, "MeleeCharge", "void", "void *, void *"),
    (64, "VariableZoom", "bool", "const void *"), (65, "InADS", "bool", "const void *"),
    (66, "Feature", "bool", "unsigned"), (69, "Hybrid", "void", "void *, void *"),
    (72, "ActiveUnderbarrel", "bool", "const void *"), (73, "UnderbarrelAmmo", "bool", "const void *"),
    (75, "Compare", "int", "const void *, const void *, size_t"),
    (76, "PathClear", "void", "void *"), (77, "ClientNotifies", "void", "void *, void *"),
    (78, "InvalidateNode", "void", "void *"), (79, "InvalidateTac", "void", "void *"),
]
REPEATS = {11: 10, 17: 7, 22: 21, 29: 7, 32: 5, 33: 6, 36: 12, 41: 39,
           47: 43, 50: 23, 54: 5, 59: 58, 61: 60, 67: 66, 68: 23, 70: 5,
           71: 6, 74: 55, 80: 18}
POLICY_CALLS = [(3, "WeaponFireType", "int", "const void *, bool"),
                (7, "IsWeaponClass", "int", "const void *, const void *, int")]
POLICY_DIRECT_CALLS = [("fn_295cb67a71ccce97", "IsRanged", "bool", "const void *, const void *")]


def prepare(snapshot, replace_owned=False):
    snapshot = Path(snapshot).resolve()
    assert snapshot.is_relative_to(ROOT / "data")
    assert not (snapshot.parent / "client-readiness.json").exists(), "Finished snapshot"
    assert not list(snapshot.parent.glob("builds/*/build-report.json")), "Built snapshot"
    for relative in ("source-units.json", "source-workstation/units.json", "src/Bot_Think.cpp",
                     "src/SV_BotThinkBindings.h"):
        path = snapshot / relative
        assert not path.exists() or path.stat().st_nlink == 1, "Shared immutable snapshot file"
    catalog = json.loads((snapshot / "generated/function-catalog.json").read_bytes())
    raw = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == IMAGE_HASH == catalog["image_sha256"]
    pe = pefile.PE(data=raw, fast_load=True)
    pe.parse_data_directories(directories=[3])
    base = pe.OPTIONAL_HEADER.ImageBase
    functions = {f["id"]: f for f in catalog["functions"] if not f.get("quarantined")}
    by_address = {base + f["rva"]: f for f in functions.values()}
    function = functions[IDENTITY]
    chunks = []
    for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
        owner = entry
        while owner.unwindinfo and owner.unwindinfo.UNW_FLAG_CHAININFO:
            owner = owner.unwindinfo._chained_entry
        if owner.struct.BeginAddress == function["rva"]:
            chunks.append((entry.struct.BeginAddress, entry.struct.EndAddress))
    chunks.sort()
    assert chunks and all(a[1] == b[0] for a, b in zip(chunks, chunks[1:]))
    code = pe.get_data(chunks[0][0], chunks[-1][1] - chunks[0][0])
    assert hashlib.sha256(code).hexdigest() == BODY_HASH
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    rows = list(decoder.disasm(code, base + function["rva"]))
    assert sum(r.size for r in rows) == len(code)
    calls = [r.operands[0].imm for r in rows if r.mnemonic == "call" and r.operands[0].type == X86_OP_IMM]
    assert len(calls) == 81
    assert {ordinal for ordinal, *_ in CALLS} | set(REPEATS) == set(range(len(calls)))
    for repeated, first in REPEATS.items():
        assert calls[repeated] == calls[first]

    policy_proofs = []
    for identity, label, expected in (
        ("fn_e4ec3a303778947b", "Bot_UpdateCombat", "14fd884970328c9feed3838a118305fa017d7586394e1e33e759d0be8684ed02"),
        ("fn_00d949a0e1ebefca", "Bot_CombatStateFire", "8651f2051d111d845c505038f603a0c5d00ab8dd9d81e8eaf006d21bff6b6135"),
        ("fn_a5608aae19108a45", "Bot_ShouldADS", "ff5b135b17ee65c7cd013ff7be7056c7594d94cce69252898be8713a2f6e5bd3"),
        ("fn_295cb67a71ccce97", "Bot_Weap_IsRanged", "30bca501476c98f4148fbe3baf32593d0dbfb5db0019af64b87ba7389750d053"),
        ("fn_a7d1c4643723c645", "Bot_ADSButtonEligibility", "31cf873965d4db36e42ccb2c18ae90c50ae0fbbfffcfc2fc0c45b6f5875e3f76"),
        ("fn_b5b36aabb516f88e", "Bot_CurrentEntityEligibility", "7f6d7082bf00e1cd932e62f882f4207ea08e9e09e451c259cf14f832cd806054"),
        ("fn_c917a8bce82b2fb5", "Bot_ThinkCaller", "0ed5163c27cf8a60beb758211c7ab1d56fdd5cdf01d1157f79aacc0f4742e91b"),
        ("fn_d0ec61d8b5fa5c02", "Bot_GrenadeAction", "42d804acda844355a194ee7a85240c21903b4ade88a47a09d3af651cbc896fc3"),
        ("fn_21cdf08c7165f1a4", "Bot_GrenadeEligibility", "c37335595f73949648ff63f2e4fe51e2da19f3e7a01d1d38adfbeaa441005a59"),
        ("fn_b7989c2dc4ad4175", "Bot_OwnedOffhandSelection", "26029e3b0b58c4cddaf12d352f0d68b661c2f6715088f48d8a258063bb25cada"),
        ("fn_435703bd63df4fa0", "Bot_GrenadeThrowArc", "206dc890a602e3aa6f93493bf479c39a6314f5c65840ef1e89931ddb3c8d1802"),
        ("fn_096db323e550f7e2", "Bot_OffhandButtonDecision", "a5d674b5e9bd19499021435659520fd95c95c25a64790e4ffd00cf3cb67a6667"),
        ("fn_7baf9f44fec9fcbc", "Bot_GrenadeCookingState", "07075db6b3e2459a0a89fb4ddcd89ecbffe2ca6417778cb2f0226d882ca74905"),
    ):
        row = functions[identity]
        pieces = []
        for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
            owner = entry
            while owner.unwindinfo and owner.unwindinfo.UNW_FLAG_CHAININFO:
                owner = owner.unwindinfo._chained_entry
            if owner.struct.BeginAddress == row["rva"]:
                pieces.append((entry.struct.BeginAddress, entry.struct.EndAddress))
        pieces.sort()
        assert pieces and all(a[1] == b[0] for a, b in zip(pieces, pieces[1:]))
        body = pe.get_data(pieces[0][0], pieces[-1][1] - pieces[0][0])
        assert hashlib.sha256(body).hexdigest() == expected, label
        instructions = list(decoder.disasm(body, base + row["rva"]))
        assert sum(i.size for i in instructions) == len(body)
        if label == "Bot_CombatStateFire":
            fire_rows = instructions
            fire_calls = [i.operands[0].imm for i in fire_rows if i.mnemonic == "call" and i.operands[0].type == X86_OP_IMM]
            assert len(fire_calls) == 27
            assert fire_calls[0] == calls[5] and fire_calls[9] == calls[35]
            assert any(i.mnemonic == "mov" and i.op_str == "edx, dword ptr [rdi + 0x7fb0]" for i in fire_rows)
            assert any(i.mnemonic == "mov" and i.op_str == "edx, dword ptr [rdi + 0x6cd8]" for i in fire_rows)
            assert any(i.mnemonic == "mov" and i.op_str == "eax, dword ptr [rdi + 0x6cdc]" for i in fire_rows)
            assert any(i.mnemonic == "mov" and i.op_str == "dword ptr [rdi + 0x7218], ecx" for i in fire_rows)
        if label == "Bot_ShouldADS":
            assert any(i.mnemonic == "test" and i.op_str == "byte ptr [rbx + 0x7ee4], 2" for i in instructions)
        if label == "Bot_ADSButtonEligibility":
            assert row["rva"] + base == calls[48]
            assert any(i.mnemonic == "mov" and i.op_str == "eax, dword ptr [rbx + 0x704]" for i in instructions)
            assert any(i.mnemonic == "shr" and i.op_str == "eax, 5" for i in instructions)
        if label == "Bot_ThinkCaller":
            assert any(i.mnemonic == "cmp" and i.op_str == "dword ptr [r8 + 0x346e4], 2" for i in instructions)
            assert any(i.mnemonic == "imul" and i.op_str == "rdx, rax, 0x108" for i in instructions)
            assert any(i.mnemonic == "lea" and i.op_str == "rax, [rsp + 0x20]" for i in instructions)
            assert any(i.mnemonic == "call" and i.operands[0].type == X86_OP_IMM and i.operands[0].imm == base + function["rva"] for i in instructions)
        policy_proofs.append(dict(identity=identity, symbol=label, original_rva=row["rva"], original_bytes=len(body), original_sha256=expected))

    def rip(mnemonic, prefix, occurrence=0):
        matches = [r for r in rows if r.mnemonic == mnemonic and r.op_str.startswith(prefix)]
        row = matches[occurrence]
        operands = [op for op in row.operands if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP]
        assert len(operands) == 1
        return row.address + row.size + operands[0].mem.disp

    globals_ = {
        "BT_ClientBase": (rip("sub", "rdx, qword ptr [rip"), "void *"),
        "BT_Entities": (rip("add", "rcx, qword ptr [rip"), "uint8_t *"),
        "BT_PausedDvar": (rip("mov", "rax, qword ptr [rip", 0), "void *"),
        "BT_Persistent": (rip("mov", "rax, qword ptr [rip", 1), "void *"),
        "BT_DisableNearest": (rip("cmp", "byte ptr [rip"), "uint8_t"),
        "BT_DisableRepulsorsDvar": (rip("mov", "rax, qword ptr [rip", 3), "void *"),
        "BT_RadarDvar": (rip("mov", "rax, qword ptr [rip", 4), "void *"),
        "BT_EntityInUse": (rip("mov", "r9, qword ptr [rip"), "uint8_t *"),
        "BT_RadarEntities": (rip("lea", "rbx, [rip"), "int16_t", "[64]"),
    }
    # Native current-area view and TLS aliases are already validated by the
    # host integration. Cross-check the aliases against this complete body.
    host = json.loads((snapshot / "generated/host-scale-integration.json").read_bytes())
    host_bindings = {b["name"]: b for b in host["bindings"]}
    assert host_bindings["SVHS_BotThink"]["identity"] == IDENTITY
    assert host_bindings["SVHS_BotTlsIndex"]["original_rva"] == rip("mov", "r12d, dword ptr [rip") - base
    assert host_bindings["SVHS_GameStatics"]["original_rva"] == rip("mov", "rax, qword ptr [rip", 2) - base
    assert host_bindings["SVHS_LevelTime"]["original_rva"] == rip("mov", "eax, dword ptr [rip") - base
    assert host_bindings["SVHS_IsBotEntity"]["identity"] == "fn_b5b36aabb516f88e"
    assert host_bindings["SVHS_Clients"]["original_rva"] == globals_["BT_ClientBase"][0] - base
    playing = functions[host_bindings["SVHS_IsBotPlaying"]["identity"]]
    assert playing["id"] == "fn_df6dfec79ee6ace8"
    # This leaf has no unwind row. Both exits delimit its complete 108-byte
    # semantic body; the following four bytes are native alignment padding.
    playing_code = pe.get_data(playing["rva"], 108)
    playing_hash = "ae2eed75d2cfec44a6ebb1239a7587090d2ba8e0224446db177fb98d0a003db3"
    assert hashlib.sha256(playing_code).hexdigest() == playing_hash
    playing_rows = list(decoder.disasm(playing_code, base + playing["rva"]))
    assert playing_rows[-1].mnemonic == "ret" and sum(i.size for i in playing_rows) == 108
    assert any(i.mnemonic == "cmp" and i.op_str == "byte ptr [rax + 8], 5" for i in playing_rows)
    assert any(i.mnemonic == "mov" and i.op_str == "rax, qword ptr [rcx + 0x118]" for i in playing_rows)
    assert any(i.mnemonic == "mov" and i.op_str == "rcx, qword ptr [rax + 0x150]" for i in playing_rows)
    assert any(i.mnemonic == "cmp" and i.op_str == "dword ptr [rcx + 0x1c0], eax" for i in playing_rows)
    policy_proofs.append(dict(identity=playing["id"], symbol="Bot_CurrentPlayingEligibility",
                              original_rva=playing["rva"], original_bytes=108,
                              original_sha256=playing_hash, leaf_body_excludes_alignment=True))
    header = ['#pragma once', '#include <stddef.h>', '#include <stdint.h>', 'extern "C" {']
    imports = []
    for ordinal, name, return_type, parameters in CALLS:
        row = by_address[calls[ordinal]]
        symbol = "BT_" + name
        header.append(f"{return_type} {symbol}({parameters});")
        imports.append(dict(name=symbol, identity=row["id"], original_rva=row["rva"], kind="function", call_ordinal=ordinal))
    for ordinal, name, return_type, parameters in POLICY_CALLS:
        row = by_address[fire_calls[ordinal]]
        symbol = "BT_" + name
        header.append(f"{return_type} {symbol}({parameters});")
        imports.append(dict(name=symbol, identity=row["id"], original_rva=row["rva"], kind="function",
                            call_ordinal=ordinal, containing_function="Bot_CombatStateFire"))
    for identity, name, return_type, parameters in POLICY_DIRECT_CALLS:
        row = functions[identity]
        symbol = "BT_" + name
        header.append(f"{return_type} {symbol}({parameters});")
        imports.append(dict(name=symbol, identity=identity, original_rva=row["rva"], kind="function"))
    for name, value in globals_.items():
        address, type_ = value[:2]
        matches = [r for r in catalog["symbols"] if r["rva"] == address - base and r.get("kind") == "data-address" and not r.get("quarantined")]
        assert len(matches) == 1, name
        row = matches[0]
        header.append(f"extern {type_} {name}{value[2] if len(value) == 3 else ''};")
        imports.append(dict(name=name, identity=row["id"], original_rva=row["rva"], kind="data"))
    header.append('}')
    header = '\n'.join(header) + '\n'
    (snapshot / "src/SV_BotThinkBindings.h").write_text(header)
    shutil.copy2(ROOT / "integration/host-scale/Bot_Think.cpp", snapshot / "src/Bot_Think.cpp")
    spec = importlib.util.spec_from_file_location("bot_think_catalog", snapshot / "tools/source_catalog.py")
    sys.path.insert(0, str(snapshot / "tools"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    associations = json.loads((snapshot / "source-units.json").read_bytes())
    existing = {r["symbol"]: r["symbol_id"] for r in associations.get("imports", [])}
    for imported in imports:
        if imported["name"] in existing:
            assert replace_owned and existing[imported["name"]] == imported["identity"]
        else:
            module.bind_import(imported["identity"], imported["name"])
    units_path = snapshot / "source-workstation/units.json"
    units = json.loads(units_path.read_bytes())
    prior = [u for u in units["units"] if u["function_id"] == IDENTITY]
    assert len(prior) <= 1
    if prior:
        assert replace_owned and prior[0]["source"] == "src/Bot_Think.cpp" and prior[0]["symbol"] == "Bot_Think"
        units["units"].remove(prior[0])
    previous_sources = [u for u in associations["units"] if u["function_id"] == IDENTITY]
    assert len(previous_sources) <= 1
    if previous_sources:
        assert replace_owned and previous_sources[0]["source"] == "src/Bot_Think.cpp" and previous_sources[0]["symbol"] == "Bot_Think"
    else:
        module.bind(IDENTITY, Path("src/Bot_Think.cpp"), "Bot_Think")
    source_digest = hashlib.sha256((snapshot / "src/Bot_Think.cpp").read_bytes()).hexdigest()
    units["units"].append(dict(function_id=IDENTITY, kind="cpp", source="src/Bot_Think.cpp", symbol="Bot_Think", sha256=source_digest, revision=source_digest, language="cpp"))
    units_path.write_text(json.dumps(units, indent=2) + '\n')
    proof = dict(schema=1, image_sha256=IMAGE_HASH, function_id=IDENTITY, original_rva=function["rva"],
                 original_bytes=len(code), original_sha256=BODY_HASH, source="src/Bot_Think.cpp",
                 source_sha256=source_digest, bindings=imports, game_run_performed=False)
    proof["combat_policy_proofs"] = policy_proofs
    proof["ads_policy"] = dict(mapped_dw_bots_only=True, all_game_modes=True,
                              native_last_ads_offset=29208, native_window_ms=500,
                              preference_mask=2, native_eligibility_preserved=True,
                              native_button_emission_preserved=True,
                              burst_cadence_br_only=False, burst_all_mapped_dw_modes=True,
                              burst_requires_native_can_fire=True)
    proof["equipment_policy"] = dict(mapped_dw_bots_only=True, all_game_modes=True,
                                    preference_mask=1, minimum_target_distance=128,
                                    maximum_target_distance=2048, br_gulag_mask=0x600,
                                    native_owned_inventory_ammo_preserved=True,
                                    native_throw_arc_and_cooldowns_preserved=True,
                                    native_throw_cook_states_preserved=True,
                                    lethal_button=0x1000, tactical_button=0x2000,
                                    buttons_forced=False)
    proof["current_bot_guard"] = dict(native_client_type_offset=214756, native_bot_type=2,
                                     client_entity_offset=280, bot_info_offset=1368,
                                     bot_entity_offset=0, bot_player_offset=448,
                                     bot_sentient_offset=8, entity_stride=1440,
                                     entity_client_offset=336, entity_sentient_offset=344,
                                     native_slot_and_table_checked=True,
                                     native_entity_and_playing_checks=True,
                                     rejects_before_native_brain=True,
                                     output_command_owner="caller local 200-entry UserCmd264 array")
    proof["dependencies"] = {name: hashlib.sha256((snapshot / "src" / name).read_bytes()).hexdigest()
                             for name in ("Bot_Think.cpp", "SV_BotThinkBindings.h", "DW_BotStyleProfile.h",
                                          "sv_host_navigation.h", "sv_host_scale.h", "SV_HostScaleBindings.h")}
    (snapshot / "generated/bot-think-integration.json").write_text(json.dumps(proof, indent=2) + '\n')
    return proof


if __name__ == "__main__":
    print(json.dumps(prepare(sys.argv[1], "--replace-owned" in sys.argv), indent=2))
