"""Bind BR bot looting to the original Replay player-use/scriptable ABI."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ROOT = Path(__file__).resolve().parents[1]
IMAGE_HASH = '68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0'
# Full unwind-owned bodies, or an exact aligned leaf extent. Hashes include
# padding for leaves so unsupported changes fail before a native import binds.
IMPORTS = (
    ('G_PlayerUse_GetUseList', 'SVHBL_GetUseList', 0, 'ed4c7b63caf4653fc141a74eddf26af27192ac957556a296c0138884c0fc0e46'),
    ('G_PlayerUse_UseScriptable', 'SVHBL_UseScriptable', 0, 'a39fdef095b0783d351a4d10fb52d6ff0db9ae0213f78db9e59f33edfa366ce2'),
    ('sub_14130B090', 'SVHBL_LootDefinition', 0, '88f3fc289e4d40af4206d0b272987f618ef00ad32773853964f3c1799ae64ca4'),
    ('sub_14130B320', 'SVHBL_LootTable', 16, '2bdbd746b0a31d68877e83c8bed550a37178d1e52addd184590a3564c302c0cb'),
    ('sub_141310DA0', 'SVHBL_UseCount', 32, 'e84fbb6fa23e4d3bbf4fde4b958d575e3dbfe15e465ffb9bf73a153daa11eaef'),
    ('q_ScriptableSv_GetInstanceInUse', 'SVHBL_InstanceInUse', 32, '116057b99ed06f0ac472c8e0a115405b3bda86a2de76950d4cdaacf3e0afb49f'),
    ('UsableRef_GetUseTracePos', 'SVHBL_UsePosition', 0, '734a168adc89df88eb502e8ba1fb9f3206e9d06a52dea2c008a533e0ccbf42ed'),
    ('BG_Skydive_IsSkydiving', 'SVHBL_IsSkydiving', 32, '74dc03ddd32206b7beb9a48192853ac58260883a348c18326d3914076d3f9b0d'),
    ('sub_1413430F0', 'SVHBL_LookAtPoint', 128, '38ba6dc0488a3abd7a54ca926a246c30e484b8ea8bc3ad0cb53a223baf3b2831'),
    ('sub_14134BF00', 'SVHBL_UpdateDirection', 0, '365e66bf819b54b275474dec17b1ccc310208d123c83aa8dcd469865e8fd46fa'),
)
HEADER = '''#pragma once
#include "sv_host_bot_loot.h"
// Generated from the pinned original Replay image; aliases may be unnamed.
extern "C" {
int SVHBL_GetUseList(HostScale::Entity *, HostScale::LootUsableList *, int);
void SVHBL_UseScriptable(const HostScale::Entity *, unsigned, uint8_t, unsigned, bool);
const HostScale::LootItemDefinition *SVHBL_LootDefinition(unsigned);
const void *SVHBL_LootTable();
unsigned SVHBL_UseCount(unsigned);
bool SVHBL_InstanceInUse(unsigned);
void SVHBL_UsePosition(const HostScale::LootUsableRef *, HostScale::Vec3 *);
bool SVHBL_IsSkydiving(const void *);
void SVHBL_LookAtPoint(void *, const HostScale::Vec3 *, int, int);
void SVHBL_UpdateDirection(void *, HostScale::UserCmd *);
}
'''

def inspect(snapshot):
    snapshot = Path(snapshot).resolve()
    assert snapshot.is_relative_to(ROOT / 'data')
    catalog = json.loads((snapshot / 'generated/function-catalog.json').read_bytes())
    raw = Path('E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == catalog['image_sha256'] == IMAGE_HASH
    pe = pefile.PE(data=raw, fast_load=True)
    pe.parse_data_directories(directories=[3])
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    groups = {}
    for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
        owner = entry
        while owner.unwindinfo and owner.unwindinfo.UNW_FLAG_CHAININFO:
            owner = owner.unwindinfo._chained_entry
        groups.setdefault(owner.struct.BeginAddress, []).append((entry.struct.BeginAddress, entry.struct.EndAddress))
    by_name = {}
    for row in catalog['functions']:
        if not row.get('quarantined'):
            for name in set((row['name'], *row.get('aliases', []))):
                by_name.setdefault(name, []).append(row)
    proofs, bodies = [], {}
    def one(rows):
        assert len(rows) == 1, rows
        return rows[0]
    def body(name, extent=0):
        row = one(by_name[name])
        if extent:
            code = pe.get_data(row['rva'], extent)
        else:
            chunks = sorted(groups[row['rva']])
            assert chunks[0][0] == row['rva']
            assert all(a[1] == b[0] for a, b in zip(chunks, chunks[1:]))
            code = pe.get_data(row['rva'], chunks[-1][1] - row['rva'])
        decoded = list(decoder.disasm(code, pe.OPTIONAL_HEADER.ImageBase + row['rva']))
        assert sum(i.size for i in decoded) == len(code)
        return row, code, decoded
    for name, symbol, extent, expected in IMPORTS:
        row, code, decoded = body(name, extent)
        digest = hashlib.sha256(code).hexdigest()
        assert digest == expected, name
        proofs.append(dict(name=name, symbol=symbol, identity=row['id'], rva=row['rva'], bytes=len(code), sha256=digest))
        bodies[symbol] = decoded
    # Separate target-build proof for the item row identity prefix and flags.
    for name, expected in (
        ('BG_SpawnGroup_Loot_ParseItemDef', 'f0692062458e4b921c6a92ac87b3aed4f7836a2c3c94040bdf2223eecc1b6e2b'),
        ('sub_1412847B0', '9e86b1e0c85e1050ae518444463dc9f3d017067c7727012c71793a70a6932a18'),
        ('G_CombatMP_PlayerDie', 'da587ac28529b93c1ffcba4284c8d6f3a63afe2f9a23b6d0e4da2c760765f77d'),
        ('sub_141356140', '93f0935ad4da0a3df8d68d159f1b7a03093d76d33d8960f90ffacfdcd5d0a6da'),
        ('sub_14134F340', 'c307294e654b5f3b44deacfce90c02d243db2b046137f48c355c0dacc5be57fd'),
    ):
        row, code, decoded = body(name)
        digest = hashlib.sha256(code).hexdigest()
        assert digest == expected, name
        if name == 'BG_SpawnGroup_Loot_ParseItemDef':
            text = {(i.mnemonic, i.op_str) for i in decoded}
            assert ('mov', 'qword ptr [rbx + 0x1d8], rcx') in text
            assert ('mov', 'byte ptr [rbx + 0x1e4], al') in text
            assert ('mov', 'word ptr [rbx + 0x1e6], ax') in text
        elif name == 'sub_1412847B0':
            text = {(i.mnemonic, i.op_str) for i in decoded}
            assert ('or', 'byte ptr [rax + 0x10], 1') in text
        elif name == 'G_CombatMP_PlayerDie':
            text = {(i.mnemonic, i.op_str) for i in decoded}
            assert ('cmp', 'dword ptr [rcx + 0xc], 1') in text
            assert ('mov', 'edx, dword ptr [rcx + 0x1c]') in text
            assert ('shr', 'edx, 0xb') in text
        elif name == 'sub_141356140':
            text = {(i.mnemonic, i.op_str) for i in decoded}
            assert ('call', '0x14134f340') in text
            assert ('lea', 'edx, [rax + 3]') in text
        else:
            text = {(i.mnemonic, i.op_str) for i in decoded}
            assert ('cmp', 'dword ptr [rcx + 0x6e34], edx') in text
            assert ('movss', 'xmm3, dword ptr [rbx + 0x6e20]') in text
        proofs.append(dict(name=name, identity=row['id'], rva=row['rva'], bytes=len(code), sha256=digest))
    use_list = {(i.mnemonic, i.op_str) for i in bodies['SVHBL_GetUseList']}
    assert ('cmp', 'r12w, word ptr [rsi + 0x4e20]') in use_list
    assert ('lea', 'rdi, [rsi + rcx*4]') in use_list
    assert ('or', 'byte ptr [rdi + 0x10], 4') in use_list
    look = {(i.mnemonic, i.op_str) for i in bodies['SVHBL_LookAtPoint']}
    assert ('mov', 'dword ptr [rcx + 0x6e34], r9d') in look
    assert ('mov', 'dword ptr [rcx + 0x6e2c], eax') in look
    direction = {(i.mnemonic, i.op_str) for i in bodies['SVHBL_UpdateDirection']}
    assert ('call', '0x141356140') in direction
    return dict(schema=1, image_sha256=IMAGE_HASH, proofs=proofs,
                usable_ref_bytes=8, usable_item_bytes=20, usable_capacity=1000,
                usable_list_bytes=20004, loot_item_bytes=256, server_thread_only=True,
                native_script_used_callback=True, native_loot_look_encoding=True,
                look_request_offset=28192, look_request_bytes=24, game_test_performed=False)

def prepare(snapshot, replace_owned=False):
    snapshot = Path(snapshot).resolve()
    result = inspect(snapshot)
    source = ROOT / 'integration/host-scale'
    for name in ('SV_HostBot_Loot.cpp', 'sv_host_bot_loot.h'):
        (snapshot / 'src' / name).write_bytes((source / name).read_bytes())
    (snapshot / 'src/SV_HostBotLootBindings.h').write_text(HEADER, encoding='utf-8')
    sys.path.insert(0, str(snapshot / 'tools'))
    spec = importlib.util.spec_from_file_location('private_br_loot_catalog', snapshot / 'tools/source_catalog.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    shim = importlib.util.spec_from_file_location("dw_catalog", Path(__file__).resolve().with_name("dw_catalog.py"))
    shim_module = importlib.util.module_from_spec(shim)
    shim.loader.exec_module(shim_module)
    shim_module.share_catalog(module)  # one catalog parse, not one per binding
    associations = json.loads((snapshot / 'source-units.json').read_bytes())
    existing = {row['symbol']: row['symbol_id'] for row in associations.get('imports', [])}
    for proof in result['proofs']:
        if 'symbol' not in proof:
            continue
        symbol, identity = proof['symbol'], proof['identity']
        if replace_owned and symbol in existing:
            assert existing[symbol] == identity
        else:
            module.bind_import(identity, symbol)
    result['source_sha256'] = hashlib.sha256((source / 'SV_HostBot_Loot.cpp').read_bytes()).hexdigest()
    result['header_sha256'] = hashlib.sha256(HEADER.encode()).hexdigest()
    result['generator_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    (snapshot / 'generated/br-bot-loot-integration.json').write_text(json.dumps(result, indent=2) + '\n')
    return result

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('snapshot', type=Path)
    parser.add_argument('--inspect-only', action='store_true')
    args = parser.parse_args()
    result = inspect(args.snapshot) if args.inspect_only else prepare(args.snapshot)
    print(json.dumps(result, indent=2))
