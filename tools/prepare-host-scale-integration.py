"""Bind the opt-in host-scaling replacements to verified Replay instructions."""

import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

ROOT = Path(__file__).resolve().parents[1]
IMAGE_HASH = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
REPLACEMENTS = (
    ("fn_fbf1da5e8975f775", "AICommon_UpdateSight", "944ab3ec0f35a001ee5b1a613fcdd04eb22cd0bbe77f6ae2864d199b6a006250"),
    ("fn_4a270f7cad270ed9", "SV_BotApplyCommands", "57c5e7f6bcee351a0ec1c5e2bb84b35c99054eb216e255204068cf11e0bd127a"),
    ("fn_ffb27c3e0123ed72", "SV_UserMoveWorkersMP_TryQueueClientThinkCmd", "e6a424cdc4db32405e984b9d9234bef490adbf53e5fb26c9a81b217f1d52e3b5"),
    ("fn_c917a8bce82b2fb5", "SV_BotUpdateBots", "0ed5163c27cf8a60beb758211c7ab1d56fdd5cdf01d1157f79aacc0f4742e91b"),
    ("fn_2a7e1c58bb783b7a", "CL_TransientsCollisionMP_UpdateTransientTileFlags", "58089fb2a18bcad26484596e8aa67c92ea16240885dc2b0e6300a25718fb75a5"),
    ("fn_c987395ab461fc56", "CL_TransientsCollisionMP_UpdateTransientFlags", "4f62d2c67ac749cb9549ddd93307c6ee3275b6aab84e62257c908548ea6b7f06"),
    ("fn_a4c0221cfc32c8ba", "Scr_GetClosestReachablePointOnNavmesh", "f51f339eedabcb0c728569e43a6e22e6c5814114285567454edda2e6752ef35b"),
    ("fn_b04550f09a430f17", "Bfx_ClosestReachableTreeStep", "620c099cc8e3fb7f995ea3be228374bd4b9f2ac2784c7779b611efb2b24e83b4"),
    ("fn_bd90054f36a2d719", "Bfx_ClosestReachableSearchStep", "6aa50f1f8717d5fa4145e0b9b71bd1d17db396030a52d403cfbf1ccd6c4187f5"),
    ("fn_63be27bde9d7b86c", "Bfx_IncrementalSearchToIsland", "8032184c10b84de2db6b6432c701d7aca98b8105e5c28cceb518ab87314a8a47"),
    ("fn_52282ba9de7c27ad", "Bfx_GetClosestArea", "8bacbce48b3608d6cf3cf84e06507fc7ef2a1e626f6ed4ddfdfb4570f2e5bb78"),
    ("fn_8c399c4d7d3e1836", "Bfx_ClosestAreaTreeStep", "0fead1cff23e729a1e7b5f1b07992ab541b538be4f36fcd1bc2fbf430d5a7d67"),
    ("fn_4bdeea2a50a7d8d0", "Bfx_ClosestAreaCollect", "b9c0f3c1437372073ed51b2776f181dd9fd141d6d02c379d6bbe49d63ac80bbd"),
    ("fn_6d3e9047613805c4", "Bot_UpdateMove_OffPathGrid", "5aff2a15b5d8055f1ceab91a6b75fd44ffca1695a9fb9be9f8060325dde37c7a"),
    ("fn_e25d88059e9ad6af", "Sentient_NearestTacPoint", "4916e26e5374b2e6ed5f791c81c424de9e1459c8507eb296e0b9de948254b9a6"),
    ("fn_80990981f58ec6f4", "G_Glass_PieceStateChanged", "395b4f1a084f34fadd59d5948602b574fa7cbcc84ff18860834a0fc6e45aedf9"),
)


def prepare(snapshot, replace_owned=False):
    snapshot = Path(snapshot).resolve()
    if not snapshot.is_relative_to(ROOT / "data"):
        raise ValueError("Host-scaling integration requires a private DW compiler snapshot")
    catalog = json.loads((snapshot / "generated/function-catalog.json").read_bytes())
    image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
    raw = image.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == IMAGE_HASH == catalog["image_sha256"]
    pe = pefile.PE(data=raw, fast_load=True)
    pe.parse_data_directories(directories=[3])
    base = pe.OPTIONAL_HEADER.ImageBase
    entries = {e.struct.BeginAddress: e for e in pe.DIRECTORY_ENTRY_EXCEPTION}
    by_id = {f["id"]: f for f in catalog["functions"] if not f.get("quarantined")}
    by_address = {base + f["rva"]: f for f in by_id.values()}
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True

    def one(values):
        assert len(values) == 1, values
        return values[0]

    def instructions(identity):
        row = by_id[identity]
        chunks = []
        for entry in entries.values():
            owner = entry
            while owner.unwindinfo and owner.unwindinfo.UNW_FLAG_CHAININFO:
                owner = owner.unwindinfo._chained_entry
            if owner.struct.BeginAddress == row["rva"]:
                chunks.append((entry.struct.BeginAddress, entry.struct.EndAddress))
        chunks.sort()
        assert chunks and all(a[1] == b[0] for a, b in zip(chunks, chunks[1:]))
        code = pe.get_data(chunks[0][0], chunks[-1][1] - chunks[0][0])
        decoded = list(decoder.disasm(code, base + row["rva"]))
        assert sum(i.size for i in decoded) == len(code)
        return code, decoded

    proof = []
    decoded = {}
    for identity, name, expected in REPLACEMENTS:
        code, rows = instructions(identity)
        assert hashlib.sha256(code).hexdigest() == expected, name
        decoded[name] = rows
        proof.append(dict(identity=identity, symbol=name, original_rva=by_id[identity]["rva"],
                          original_bytes=len(code), original_sha256=expected))
    sight, apply, queue = (decoded[name] for _, name, _ in REPLACEMENTS[:3])
    bots, tile, all_tiles = (decoded[name] for _, name, _ in REPLACEMENTS[3:6])

    def rip(rows, mnemonic, prefix):
        targets = {i.address + i.size + op.mem.disp for i in rows
                   if i.mnemonic == mnemonic and i.op_str.startswith(prefix)
                   for op in i.operands if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP}
        return one(list(targets))

    def direct_calls(rows):
        return [i.operands[0].imm for i in rows if i.mnemonic == "call" and
                i.operands[0].type == X86_OP_IMM]

    # These sequences and field positions are protected by the complete native
    # body digests above. Imported addresses are derived afresh, never entered
    # into C++ or source-unit layout definitions.
    sight_calls = direct_calls(sight)
    # First call probes the stack; last checks its security cookie.
    assert len(sight_calls) == 16
    funcs = dict(zip(("SVHS_SupportsFeature", "SVHS_SupportsFeature_again",
                     "SVHS_AllCombatTeamsSP", "SVHS_AllTeamsMP", "SVHS_EnemyTeamFlags",
                     "SVHS_SupportsFeature_neutral", "SVHS_FirstSentient",
                     "SVHS_SupportsFeature_client", "SVHS_SentientOrigin",
                     "SVHS_UpdateThreatSight", "SVHS_NextSentient", "SVHS_Sort",
                     "SVHS_CanSeeEntity", "SVHS_IsBotEntity"), sight_calls[1:-1]))
    for key in list(funcs):
        if key.startswith("SVHS_SupportsFeature_"):
            assert funcs.pop(key) == funcs["SVHS_SupportsFeature"]
    funcs["SVHS_CompareSight"] = rip(sight, "lea", "r9,")
    apply_calls = direct_calls(apply)
    assert len(apply_calls) == 4
    assert apply_calls[0] == funcs["SVHS_SupportsFeature"]
    funcs.update(zip(("SVHS_AcknowledgeBotCommands", "SVHS_ClientThink", "SVHS_GetUsercmd"), apply_calls[1:]))
    queue_calls = direct_calls(queue)
    assert len(queue_calls) == 4
    funcs.update(zip(("SVHS_UserMoveBegin", "SVHS_ClientPreThink", "SVHS_AddWorker"),
                     (queue_calls[0], queue_calls[1], queue_calls[3])))
    funcs["SVHS_Sleep"] = queue_calls[2]
    finish = one([f for f in by_id.values() if "sub_1412E40E0" in (f["name"], *f["aliases"])])
    _, finish_code = instructions(finish["id"])
    waits = direct_calls(finish_code)
    assert len(waits) == 2 and waits[0] == waits[1]
    funcs["SVHS_FinishClientThinkCmds"] = base + finish["rva"]
    funcs["SVHS_WaitWorkerType"] = waits[0]
    globals_ = {
        "SVHS_TeamMode": rip(sight, "cmp", "dword ptr [rip"),
        "SVHS_LevelTime": rip(sight, "add", "r8d,"),
        "SVHS_FrameDuration": rip(sight, "mov", "r8d, dword ptr [rip"),
        "SVHS_Sentients": rip(sight, "sub", "rcx, qword ptr [rip"),
        "SVHS_ClientCount": rip(apply, "cmp", "dword ptr [rip"),
        "SVHS_Clients": rip(apply, "lea", "r15,"),
        "SVHS_WorkersEnabled": rip(queue, "cmp", "byte ptr [rip"),
        "SVHS_ThinkQueues": rip(queue, "mov", "rdi, qword ptr [rip"),
    }
    assert globals_["SVHS_Clients"] == rip(queue, "lea", "rcx,")
    bot_calls = direct_calls(bots)
    assert len(bot_calls) == 10 and bot_calls[1] == funcs["SVHS_SupportsFeature"]
    assert bot_calls[-2] == base + by_id[REPLACEMENTS[1][0]]["rva"]
    funcs.update(zip(("SVHS_IsBotPlaying", "SVHS_BotThink", "SVHS_AdvanceBotPriority",
                      "SVHS_IsBotSpectator", "SVHS_BotScriptActions", "SVHS_ReleaseBotPing"),
                     bot_calls[2:8]))
    bot_guards = [i.address + i.size + i.operands[0].mem.disp for i in bots
                  if i.mnemonic == "cmp" and i.operands[0].type == X86_OP_MEM
                  and i.operands[0].mem.base == X86_REG_RIP and i.op_str.endswith(", 0")]
    assert len(bot_guards) == 2
    globals_.update(zip(("SVHS_BotSystemAllocated", "SVHS_LevelClientsAllocated"), bot_guards))
    server_global = [i.address + i.size + i.operands[1].mem.disp for i in bots
                     if i.mnemonic == "mov" and i.op_str.startswith("rax, qword ptr [rip")][-1]
    globals_.update(SVHS_ServerGlobals=server_global,
                    SVHS_ActiveBotCount=rip(bots, "inc", "dword ptr [rip"),
                    SVHS_BotPingAnchor=rip(bots, "lea", "rbx,"))
    assert rip(bots, "mov", "eax, dword ptr [rip") == globals_["SVHS_LevelTime"]

    tile_calls = direct_calls(tile)
    assert len(tile_calls) == 3
    funcs.update(zip(("SVHS_TransientFileLoaded", "SVHS_WorldTileReady", "SVHS_StaticTileReady"), tile_calls))
    # Original tile flags use image-relative indexed operands through R15.
    assert rip(tile, "lea", "r15,") == base
    flag_addresses = [base + i.operands[0].mem.disp for i in tile
                      if i.mnemonic == "test" and i.operands[0].type == X86_OP_MEM]
    assert len(flag_addresses) == 4 and all(b - a == 128 for a, b in zip(flag_addresses, flag_addresses[1:]))
    globals_.update(zip(("SVHS_TileLoadRequested", "SVHS_TileLoaded",
                        "SVHS_TileSetupRequested", "SVHS_TileSetup"), flag_addresses))
    globals_["SVHS_TileFileIndices"] = base + one([i.operands[1].mem.disp for i in tile
        if i.mnemonic == "movzx" and i.operands[1].type == X86_OP_MEM])
    for function, name in (("SVHS_WorldTileReady", "SVHS_WorldTileSetup"),
                           ("SVHS_StaticTileReady", "SVHS_StaticTileSetup")):
        _, rows = instructions(by_address[funcs[function]]["id"])
        globals_[name] = rip(rows, "lea", "r15,")
        # Both target-build routines cover two server and three client worlds.
        assert any(i.mnemonic == "mov" and i.op_str == "r9d, 3" for i in rows)
        assert any(i.mnemonic == "lea" and i.op_str == "r8, [r15 + 0x200]" for i in rows)
    all_calls = direct_calls(all_tiles)
    assert all_calls[:3] == tile_calls and all_calls[3] == base + by_id[REPLACEMENTS[4][0]]["rva"]
    all_flags = [i.address + i.size + i.operands[1].mem.disp for i in all_tiles
                 if i.mnemonic == "movzx" and i.op_str.startswith("eax, byte ptr [rip")]
    assert len(all_flags) == 2 and all_flags[1] - all_flags[0] == 2
    globals_.update(SVHS_AllTilesLoaded=all_flags[0], SVHS_AllTilesSetup=all_flags[1])
    requested_flags = [i.address + i.size + i.operands[0].mem.disp for i in all_tiles
                       if i.mnemonic == "cmp" and i.operands[0].type == X86_OP_MEM]
    assert len(requested_flags) == 2
    globals_.update(zip(("SVHS_AllTilesLoadRequested", "SVHS_AllTilesSetupRequested"), requested_flags))
    globals_.update(SVHS_CollisionTileCount=rip(all_tiles, "mov", "eax, dword ptr [rip"),
                    SVHS_AllTilesFileIndex=rip(all_tiles, "movzx", "ecx, word ptr [rip"))
    script_calls = direct_calls(decoded["Scr_GetClosestReachablePointOnNavmesh"])
    assert len(script_calls) == 8 and script_calls[1] == script_calls[4]
    funcs.update(zip(("SVHS_ScriptEntity", "SVHS_ScriptError", "SVHS_Navigator", "SVHS_NavFormat"),
                     script_calls[:4]))
    funcs.update(zip(("SVHS_ScriptGetVector", "SVHS_ScriptAddVector"), script_calls[5:7]))
    # The virtual target determines which exact navigator layout may be read.
    nav_body, nav_code = instructions("fn_31502f181b618d40")
    assert hashlib.sha256(nav_body).hexdigest() == "615a04549eeb81b9f840d4759439379e28eb6b28306d270823bc4d213bba61f3"
    funcs["SVHS_Nav2DClosest"] = base + by_id["fn_31502f181b618d40"]["rva"]
    nav_calls = direct_calls(nav_code)
    assert len(nav_calls) == 3
    funcs.update(zip(("SVHS_NavClosestArea", "SVHS_NavProjectArea", "SVHS_NavDestroyArea"), nav_calls))
    tree_calls = direct_calls(decoded["Bfx_ClosestReachableTreeStep"])
    assert len(tree_calls) == 2 and tree_calls[0] == tree_calls[1]
    funcs["SVHS_NavCollectArea"] = tree_calls[0]
    graph = decoded["Bfx_IncrementalSearchToIsland"]
    graph_calls = direct_calls(graph)
    assert len(graph_calls) == 4
    funcs.update(zip(("SVHS_NavMalloc", "SVHS_NavAllocationFailure", "SVHS_NavMemmove", "SVHS_NavFree"), graph_calls))
    globals_.update(SVHS_NavSystem=rip(graph, "mov", "rax, qword ptr [rip"),
                    SVHS_NavAllocationTag=rip(graph, "mov", "r8d, dword ptr [rip"))
    planner = decoded["Bfx_GetClosestArea"]
    planner_calls = direct_calls(planner)
    assert len(planner_calls) == 2 and planner_calls[1] == funcs["SVHS_NavFree"]
    funcs["SVHS_NavGetClosestAreas"] = planner_calls[0]
    globals_["SVHS_NavUnlimitedRadius"] = rip(planner, "movss", "xmm3,")
    closest_tree_calls = direct_calls(decoded["Bfx_ClosestAreaTreeStep"])
    assert len(closest_tree_calls) == 2 and closest_tree_calls[0] == closest_tree_calls[1]
    funcs["SVHS_NavCollectClosest"] = closest_tree_calls[0]
    assert funcs["SVHS_NavCollectClosest"] == base + by_id["fn_4bdeea2a50a7d8d0"]["rva"]
    closest_collector_calls = direct_calls(decoded["Bfx_ClosestAreaCollect"])
    assert len(closest_collector_calls) == 3
    funcs.update(zip(("SVHS_NavProjectClosest", "SVHS_NavInsertClosest", "SVHS_NavFarthestClosest"),
                     closest_collector_calls))
    off_grid_calls = direct_calls(decoded["Bot_UpdateMove_OffPathGrid"])
    assert len(off_grid_calls) == 4
    funcs.update(zip(("SVHS_BotCanFire", "SVHS_NavHasPath", "SVHS_BotYawVectors"), off_grid_calls[:3]))
    tac_calls = direct_calls(decoded["Sentient_NearestTacPoint"])
    assert len(tac_calls) == 10 and tac_calls[-1] == off_grid_calls[-1]
    assert tac_calls[5] == funcs["SVHS_NavDestroyArea"]
    funcs.update(zip(("SVHS_PathNodePosition", "SVHS_TacPointForNode", "SVHS_NavConstructArea",
                      "SVHS_NavClosestVerticalDefault", "SVHS_TacClosestWithLos", "SVHS_NavDestroyArea",
                      "SVHS_TacClosest", "SVHS_TacSetReference", "SVHS_TacGetReference"), tac_calls[:-1]))
    tac_leaf = pe.get_data(funcs["SVHS_TacClosest"] - base, 32)
    assert hashlib.sha256(tac_leaf).hexdigest() == "bc879b4e8b2cac812d7c6588622c67150c1401e5c5f8f4396b32fa7a8921c551"
    tac_lookup = list(decoder.disasm(tac_leaf, funcs["SVHS_TacClosest"]))
    globals_["SVHS_TacGraphCount"] = rip(tac_lookup, "cmp", "dword ptr [rip")
    for identity, name, expected in (
        ("fn_3f50a363d8067a21", "SVHS_BotPathToGoal", "b40927630208b1f77fdf9b4b464d7b04601df9f6b4465f5c41e7430632718159"),
        ("fn_705c7024190158b3", "SVHS_BotMovePathing", "ad584145f14723429419e6c72871c93173b06901e91cc93bd8c1070e34305464"),
    ):
        body, rows = instructions(identity)
        assert hashlib.sha256(body).hexdigest() == expected, name
        funcs[name] = base + by_id[identity]["rva"]
        if name == "SVHS_BotMovePathing":
            # Last real call is the native route-steering/avoidance leaf. Its
            # containing body is hash checked above; derive the target each build.
            calls = direct_calls(rows)
            assert calls[-1] == off_grid_calls[-1]
            funcs["SVHS_BotSteerPath"] = calls[-2]
    think_prefix = pe.get_data(funcs["SVHS_BotThink"] - base, 750)
    assert hashlib.sha256(think_prefix).hexdigest() == "d0123e3e923dc409bf1548398f5aeaef4916aab3d72cbeb5a7ea452da8743322"
    tls_tail = pe.get_data(funcs["SVHS_BotThink"] - base + len(think_prefix), 32)
    assert hashlib.sha256(tls_tail).hexdigest() == "45342c2b9d701b78adec2d70a400ce287d9a99e4c4c504576744b83ab307e24d"
    think_rows = list(decoder.disasm(think_prefix + tls_tail, funcs["SVHS_BotThink"]))
    tls_setup = one([i for i, row in enumerate(think_rows) if "gs:[0x58]" in row.op_str])
    globals_["SVHS_BotTlsIndex"] = rip([think_rows[tls_setup + 2]], "mov", "r12d,")
    globals_["SVHS_GameStatics"] = rip([think_rows[tls_setup + 5]], "mov", "rax,")
    glass = decoded["G_Glass_PieceStateChanged"]
    glass_calls = direct_calls(glass)
    assert len(glass_calls) == 15 and glass_calls[-1] == off_grid_calls[-1]
    funcs.update(zip(("SVHS_GlassDirectionByte", "SVHS_GlassSystem", "SVHS_GlassCenter",
                      "SVHS_GlassAxis", "SVHS_GlassPackImpact"), glass_calls[:5]))
    assert glass_calls[4] == glass_calls[5] and glass_calls[6] == glass_calls[7]
    funcs["SVHS_GlassRemoveObstacle"] = glass_calls[6]
    assert glass_calls[8] == glass_calls[9] == glass_calls[10]
    funcs["SVHS_GlassRandom"] = glass_calls[8]
    funcs.update(zip(("SVHS_GlassScriptContext", "SVHS_GlassAddInt", "SVHS_GlassNotify"), glass_calls[11:14]))
    rax_loads = [row for row in glass if row.mnemonic == "mov" and
                 row.op_str.startswith("rax, qword ptr [rip")]
    globals_["SVHS_GlassData"] = rip(rax_loads[1:2], "mov", "rax,")
    globals_["SVHS_GlassDestroyDvar"] = rip(rax_loads[3:4], "mov", "rax,")
    globals_["SVHS_GlassWeakenDvar"] = rip(rax_loads[4:5], "mov", "rax,")
    assert rip(glass, "mov", "eax, dword ptr [rip") == globals_["SVHS_LevelTime"]
    globals_["SVHS_GlassDestroyedString"] = rip(glass, "mov", "edx, dword ptr [rip")
    header = '''#pragma once
#include <stddef.h>
#include <stdint.h>
// Generated during the private compile from the pinned original Replay image.
extern "C" {
extern int32_t SVHS_TeamMode, SVHS_LevelTime, SVHS_FrameDuration;
extern void *SVHS_Sentients, *SVHS_ThinkQueues, *SVHS_Clients[200];
extern uint32_t SVHS_ClientCount;
extern uint8_t SVHS_WorkersEnabled;
bool SVHS_SupportsFeature(unsigned);
const void *SVHS_AllCombatTeamsSP();
const void *SVHS_AllTeamsMP();
void SVHS_EnemyTeamFlags(void *, unsigned);
void *SVHS_FirstSentient(const void *);
void *SVHS_NextSentient(const void *, const void *);
void SVHS_SentientOrigin(const void *, void *);
void SVHS_UpdateThreatSight(void *, void *, float);
int SVHS_CompareSight(const void *, const void *);
void SVHS_Sort(void *, size_t, size_t, int (*)(const void *, const void *));
int SVHS_CanSeeEntity(void *, void *, float, float, float);
bool SVHS_IsBotEntity(const void *);
void SVHS_AcknowledgeBotCommands(void *);
void SVHS_ClientThink(void *, const void *);
void SVHS_GetUsercmd(unsigned, void *);
void SVHS_UserMoveBegin();
bool SVHS_ClientPreThink(void *, const void *);
void SVHS_AddWorker(unsigned, const void *);
void SVHS_FinishClientThinkCmds();
void SVHS_WaitWorkerType(unsigned);
void SVHS_Sleep(unsigned);
extern uint32_t SVHS_BotSystemAllocated, SVHS_LevelClientsAllocated, SVHS_ActiveBotCount;
extern void *SVHS_ServerGlobals;
extern uint8_t SVHS_BotPingAnchor[];
bool SVHS_IsBotPlaying(void *);
void SVHS_BotThink(void *, void *);
void SVHS_AdvanceBotPriority(int);
bool SVHS_IsBotSpectator(void *);
void SVHS_BotScriptActions(void *, void *);
void SVHS_ReleaseBotPing(unsigned);
extern uint32_t SVHS_TileLoadRequested[32], SVHS_TileLoaded[32];
extern uint32_t SVHS_TileSetupRequested[32], SVHS_TileSetup[32];
extern uint32_t SVHS_WorldTileSetup[5][32], SVHS_StaticTileSetup[5][32];
extern uint16_t SVHS_TileFileIndices[1024], SVHS_AllTilesFileIndex;
extern uint32_t SVHS_CollisionTileCount;
extern uint8_t SVHS_AllTilesLoadRequested, SVHS_AllTilesLoaded;
extern uint8_t SVHS_AllTilesSetupRequested, SVHS_AllTilesSetup;
bool SVHS_TransientFileLoaded(unsigned);
bool SVHS_WorldTileReady(unsigned);
bool SVHS_StaticTileReady(unsigned);
void *SVHS_ScriptEntity(uint32_t);
void SVHS_ScriptError(unsigned, void *, const char *);
void *SVHS_Navigator(void *);
const char *SVHS_NavFormat(const char *, ...);
void SVHS_ScriptGetVector(void *, unsigned, void *);
void SVHS_ScriptAddVector(void *, const void *);
void SVHS_Nav2DClosest(void *, const void *, void *);
void SVHS_NavClosestArea(void *, const void *, const void *, const void *);
void SVHS_NavProjectArea(const void *, void *, const void *, void *);
void SVHS_NavDestroyArea(void *);
void SVHS_NavCollectArea(void *, void *, const void *);
extern void *SVHS_NavSystem;
extern uint32_t SVHS_NavAllocationTag;
void *SVHS_NavMalloc(void *, size_t, unsigned, unsigned);
void SVHS_NavAllocationFailure();
void *SVHS_NavMemmove(void *, const void *, size_t);
void SVHS_NavFree(void *, void *);
void SVHS_NavGetClosestAreas(void *, const void *, const void *, float, int, void *);
extern const float SVHS_NavUnlimitedRadius;
void SVHS_NavCollectClosest(void *, void *, const void *);
void SVHS_NavProjectClosest(void *, const void *, const void *, const void *);
void SVHS_NavInsertClosest(void *, const void *, float);
float SVHS_NavFarthestClosest(void *);
bool SVHS_BotCanFire(void *);
bool SVHS_NavHasPath(void *);
void SVHS_BotYawVectors(float, void *, void *);
unsigned SVHS_BotPathToGoal(void *, const void *, float, const char *);
unsigned SVHS_BotMovePathing(void *, void *);
void SVHS_BotSteerPath(void *, void *, int);
extern uint32_t SVHS_BotTlsIndex;
extern void *SVHS_GameStatics;
extern int32_t SVHS_TacGraphCount;
void SVHS_PathNodePosition(const void *, void *);
void *SVHS_TacPointForNode(const void *);
void SVHS_NavConstructArea(void *);
bool SVHS_NavClosestVerticalDefault(const void *, void *, void *);
void *SVHS_TacClosestWithLos(const void *, const void *, const void *);
void *SVHS_TacClosest(const void *);
void SVHS_TacSetReference(void *, const void *);
void *SVHS_TacGetReference(const void *);
extern void *SVHS_GlassData, *SVHS_GlassWeakenDvar, *SVHS_GlassDestroyDvar;
extern uint32_t SVHS_GlassDestroyedString;
float SVHS_GlassRandom();
uint8_t SVHS_GlassDirectionByte(const void *);
void *SVHS_GlassSystem(unsigned, unsigned *);
void SVHS_GlassCenter(const void *, unsigned, void *);
void SVHS_GlassAxis(const void *, unsigned, void *);
uint8_t SVHS_GlassPackImpact(float);
void SVHS_GlassRemoveObstacle(unsigned);
void *SVHS_GlassScriptContext();
void SVHS_GlassAddInt(void *, unsigned);
void SVHS_GlassNotify(void *, uint32_t, unsigned);
}
'''
    equipment_spec = importlib.util.spec_from_file_location(
        "host_bot_equipment_preparation", ROOT / "tools/prepare-host-bot-equipment.py")
    equipment_module = importlib.util.module_from_spec(equipment_spec)
    equipment_spec.loader.exec_module(equipment_module)
    equipment_proof = equipment_module.configure(pe, by_id, funcs, snapshot)
    (snapshot / "src/SV_HostScaleBindings.h").write_text(header, encoding="utf-8")
    sys.path.insert(0, str(snapshot / "tools"))
    spec = importlib.util.spec_from_file_location("private_host_scale_catalog", snapshot / "tools/source_catalog.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    associations = json.loads((snapshot / "source-units.json").read_bytes())
    existing_imports = {row["symbol"]: row["symbol_id"] for row in associations.get("imports", [])}
    existing_sources = {row["function_id"]: row for row in associations["units"]}
    def bind_import(identity, name):
        if replace_owned and name in existing_imports:
            assert existing_imports[name] == identity, "Prior native alias differs: " + name
        else:
            module.bind_import(identity, name)
    bindings = []
    for name, address in funcs.items():
        row = by_address[address]
        bind_import(row["id"], name)
        bindings.append(dict(name=name, identity=row["id"], original_rva=row["rva"], kind="function"))
    for name, address in globals_.items():
        row = one([s for s in catalog["symbols"] if s["rva"] == address - base
                   and s.get("kind") == "data-address" and not s.get("quarantined")])
        bind_import(row["id"], name)
        bindings.append(dict(name=name, identity=row["id"], original_rva=row["rva"], kind="data"))
    units_path = snapshot / "source-workstation/units.json"
    units = json.loads(units_path.read_bytes())
    # The latest authored DW helper selects the auth host at the first address
    # read. Older shared workstation metadata owns only its port getter. Carry
    # the verified new getter binding into this private build without changing
    # the shared editor or replacing a binding it has already acquired.
    auth = one([f for f in by_id.values()
                if "sub_14212B100" in (f["name"], *f.get("aliases", []))])
    if not any(u["function_id"] == auth["id"] for u in units["units"]):
        body = pe.get_data(auth["rva"], 5)
        assert body == bytes.fromhex("48 8d 41 24 c3"), "Native auth getter ABI changed"
        assert any("DW_LocalBackend_GetAuthAddress(const void *" in f.read_text()
                   for f in (snapshot / "src").glob("workstation_user_*.cpp")), "Updated DW auth helper absent"
        proof.append(dict(identity=auth["id"], symbol="DW_GetAuthAddress",
                          original_rva=auth["rva"], original_bytes=5,
                          original_sha256=hashlib.sha256(body).hexdigest()))
    for item in proof:
        identity, symbol = item["identity"], item["symbol"]
        source = "src/" + symbol + ".cpp"
        if replace_owned:
            prior_units = [u for u in units["units"] if u["function_id"] == identity]
            assert len(prior_units) <= 1
            if prior_units:
                prior = prior_units[0]
                assert prior["kind"] == "cpp" and prior["source"] == source and prior["symbol"] == symbol
                units["units"].remove(prior)
        assert not any(u["function_id"] == identity for u in units["units"])
        if replace_owned and identity in existing_sources:
            prior = existing_sources[identity]
            assert prior["source"] == source and prior["symbol"] == symbol
        else:
            module.bind(identity, Path(source), symbol)
        digest = hashlib.sha256((snapshot / source).read_bytes()).hexdigest()
        units["units"].append(dict(function_id=identity, kind="cpp", source=source, symbol=symbol,
                                  sha256=digest, revision=digest, language="cpp"))
        item.update(source=source, source_sha256=digest)
    units_path.write_text(json.dumps(units, indent=2) + "\n")
    result = dict(schema=1, image_sha256=IMAGE_HASH, replacements=proof, bindings=bindings,
                  generated_header_sha256=hashlib.sha256(header.encode()).hexdigest(),
                  generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  usercmd_bytes=264, queue_bytes=1600, queue_capacity=6, client_bytes=321192,
                  entity_bytes=1440, sentient_bytes=184, sentient_info_bytes=64,
                  team_bit_count=160, sight_capacity=272, client_capacity=200,
                  equipment_bindings=equipment_proof, game_run_performed=False)
    (snapshot / "generated/host-scale-integration.json").write_text(json.dumps(result, indent=2) + "\n")
    for filename, module_name in (("prepare-bot-think-integration.py", "native_bot_think"),
                                  ("prepare-br-bot-loot-integration.py", "native_bot_loot")):
        child_spec = importlib.util.spec_from_file_location(module_name, ROOT / "tools" / filename)
        child_module = importlib.util.module_from_spec(child_spec)
        child_spec.loader.exec_module(child_module)
        child_module.prepare(snapshot, replace_owned=replace_owned)
    return result
