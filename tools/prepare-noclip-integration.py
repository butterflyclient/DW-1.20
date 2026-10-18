"""Prepare a server-authoritative noclip command and complete native ABI clone."""

from workstation_preparation_context import cached_input_json, shared_original_pe, source_context
import argparse, hashlib, json, struct, subprocess, sys, tempfile, os
from pathlib import Path
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

ROOT = Path(__file__).resolve().parents[1]
IMAGE = Path('E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe')
TARGET = '68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0'
OUTER = 'fn_9adeadab00498aa8'
HELPER = 'NC_StringCommandNative'
BODY = '98bc163e9d712e86240170100d839dd5c437b8d1c0d74c4eef1f5622a0276c26'
BODIES = {
    OUTER: (548, BODY),
    'fn_695afa6f3e7f3edb': (2919, 'ce367df891cc441719abe7f9062dae390dc25081d5e794e9e2dfce41ca16ca98'),
    'fn_96f41f09cbad0bad': (37, 'c21d57cdc3683025fe9f9c0a5510400b441953515d41e38e92043c1bed2cb5f4'),
    'fn_4a73e02f1e16ae4c': (136, 'e233f3bbc4a8498d7d03bb0f538e661ffd120ad89f91d4de20e3bef29823ec7c'),
    'fn_da8002fdcbe756cf': (3492, '507bf230c7862f05340d87d77bc29633f7744afa9fe38d73ea598cbbf05af4a8'),
    'fn_3da1e16560231243': (29, '53989c4a3df823fa742c0bebda04d4729c810916a7f81899cc2b885ae9c8997c'),
    'fn_04583a98e3aa8c51': (11, '20f10646e8dcacd78732d57756ec8e2a8549c0685d868a20fe25ffede566e90c'),
    'fn_15b0e8e680376717': (20, 'afbb6e085339ff416bcafec8e0323e4594b0049fb953e63e7ab4a9c38147e550'),
}
# Complete known GS-cookie-only UNWIND_INFO graph. Every byte is checked;
# unknown handler families, scopes or additional records are rejected.
UNWIND = (
    '192006000e018b0007f005e00360025058ce1c0240040000',
    '2113040013748a0008349300d03837016e393701f80a8802',
    '21000000d03837016e393701f80a8802',
)

def sha(data): return hashlib.sha256(data).hexdigest()

def validate_unwind(records, handler_rva):
    if len(records) != 3 or records[-1]['end'] - records[0]['begin'] != 548:
        raise ValueError('Unknown native runtime-function scope')
    for record, expected in zip(records, UNWIND):
        if record['bytes'] != expected or record['begin'] >= record['end']:
            raise ValueError('Unknown native unwind/GS metadata family')
    if any(a['end'] != b['begin'] for a, b in zip(records, records[1:])):
        raise ValueError('Native runtime-function scopes are not contiguous')
    if struct.unpack_from('<I', bytes.fromhex(records[0]['bytes']), 16)[0] != handler_rva:
        raise ValueError('GS handler identity changed')
    for record in records[1:]:
        if struct.unpack('<III', bytes.fromhex(record['bytes'])[-12:]) != (
            records[0]['begin'], records[0]['end'], records[0]['unwind_rva']):
            raise ValueError('Native chain does not point to its complete primary scope')

def write(path, data):
    path = Path(path)
    data = data.encode() if isinstance(data, str) else data
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        stream.write(data); temporary = Path(stream.name)
    os.replace(temporary, path)  # Detach any inherited hardlink.

def prepare(snapshot, replace_owned=False):
    snapshot = Path(snapshot).resolve(strict=True)
    if not snapshot.is_relative_to(ROOT / 'data'):
        raise ValueError('Noclip preparation needs a private DW snapshot')
    for parent in (snapshot, snapshot.parent):
        for marker in ('client-readiness.json', 'readiness.json', 'local-readiness.json', 'source-receipt.json'):
            if (parent / marker).exists(): raise ValueError('Noclip snapshot is sealed: ' + marker)
    catalog = cached_input_json(snapshot / 'generated/function-catalog.json')
    raw = IMAGE.read_bytes()
    assert sha(raw) == catalog['image_sha256'] == TARGET
    pe = shared_original_pe(data=raw)
    byid = {r['id']: r for r in catalog['functions'] + catalog.get('symbols', [])}
    rows = {r['rva']: r for r in catalog['functions'] if not r.get('quarantined')}
    decoder = Cs(CS_ARCH_X86, CS_MODE_64); decoder.detail = True
    sys.path.insert(0, str(snapshot / 'tools'))
    from workstation_sources import SourceWorkspace
    from coff import read
    output = snapshot / 'generated/noclip'; output.mkdir(parents=True, exist_ok=True)
    workspace = SourceWorkspace(snapshot, output / 'cache'); workspace._catalog = catalog
    native = []
    for identity, (size, expected) in BODIES.items():
        r = byid[identity]; assert not r.get('quarantined')
        assert sha(pe.get_data(r['rva'], size)) == expected
        native.append(dict(identity=identity, rva=r['rva'], size=size, sha256=expected))
    row = byid[OUTER]; begin = row['rva']; end = begin + 548
    entries = [e.struct for e in pe.DIRECTORY_ENTRY_EXCEPTION if begin <= e.struct.BeginAddress < end]
    assert len(entries) == 3 and entries[0].BeginAddress == begin and entries[-1].EndAddress == end
    assert all(a.EndAddress == b.BeginAddress for a, b in zip(entries, entries[1:]))
    unwind_records = []
    for entry, expected in zip(entries, UNWIND):
        blob = pe.get_data(entry.UnwindData, len(bytes.fromhex(expected)))
        assert blob.hex() == expected, 'Unknown native unwind/GS metadata'
        unwind_records.append(dict(begin=entry.BeginAddress, end=entry.EndAddress,
                                   unwind_rva=entry.UnwindData, bytes=blob.hex(), sha256=sha(blob)))
    # __GSHandlerCheck is a single cookie-only record: DWORD cookie stack offset
    # 0x440. Its two secondary RUNTIME_FUNCTION entries chain to the first.
    handler = byid['fn_3da1e16560231243']
    validate_unwind(unwind_records, handler['rva'])
    body = pe.get_data(begin, 548)
    instructions = list(decoder.disasm(body, begin))
    assert sum(i.size for i in instructions) == 548
    imports, fixups, assembly = {}, [], ['.intel_syntax noprefix', '.text', '.p2align 4',
        '.globl ' + HELPER, '.def ' + HELPER + '; .scl 2; .type 32; .endef', HELPER + ':']
    redirected = 0
    for instruction in instructions:
        assembly.append('NC_L_%08x:' % instruction.address)
        data = instruction.bytes; target = None; field = None
        for operand in instruction.operands:
            if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                target = instruction.address + instruction.size + operand.mem.disp
                field = instruction.disp_offset
        if instruction.mnemonic.startswith(('call', 'j')) and instruction.operands and instruction.operands[0].type == X86_OP_IMM:
            destination = instruction.operands[0].imm
            if not begin <= destination < end:
                assert instruction.imm_size == 4
                target, field = destination, instruction.imm_offset
        if target is None or begin <= target < end:
            assembly.append('.byte ' + ','.join(hex(x) for x in data)); continue
        assert field and (instruction.disp_size == 4 or instruction.imm_size == 4)
        symbol = workspace._catalog_symbol(target)
        assert symbol in byid and byid[symbol]['rva'] == target
        replacement = symbol
        if target == byid['fn_695afa6f3e7f3edb']['rva']:
            assert instruction.mnemonic == 'call'
            replacement = 'DW_Noclip_ClientCommand'; redirected += 1
        else: imports[symbol] = symbol
        tail = instruction.size - field - 4
        assembly.append('.byte ' + ','.join(hex(x) for x in data[:field]))
        assembly.append('.long %s - . - %u' % (replacement, 4 + tail))
        if tail: assembly.append('.byte ' + ','.join(hex(x) for x in data[field + 4:]))
        fixups.append(dict(offset=instruction.address - begin + field, symbol=replacement,
                           native_target=target, trailing_bytes=tail, redirected=replacement != symbol))
    assert redirected == 1
    assembly.append('NC_L_%08x:' % end)
    assembly.extend(['.section .xdata,"dr"', '.p2align 2'])
    for index, blob in enumerate(UNWIND):
        data = bytes.fromhex(blob); assembly.append('NC_Unwind_%u:' % index)
        prefix = data[:-8] if index == 0 else data[:-12]
        assembly.append('.byte ' + ','.join(hex(x) for x in prefix))
        if index == 0:
            imports[handler['id']] = handler['id']
            assembly.extend(['.rva ' + handler['id'], '.long 0x440'])
        else:
            assembly.extend(['.rva NC_L_%08x' % entries[0].BeginAddress,
                             '.rva NC_L_%08x' % entries[0].EndAddress, '.rva NC_Unwind_0'])
    assembly.extend(['.section .pdata,"dr"', '.p2align 2'])
    for index, entry in enumerate(entries):
        assembly.extend(['.rva NC_L_%08x' % entry.BeginAddress, '.rva NC_L_%08x' % entry.EndAddress, '.rva NC_Unwind_%u' % index])
    clone = snapshot / 'src/DW_Noclip_Native.cpp'
    write(clone, '// Complete original native body and typed GS/unwind graph.\nasm(R"NATIVE(\n' + '\n'.join(assembly) + '\n)NATIVE");\n')
    objpath = output / 'native.obj'
    command = [r'C:\Program Files\LLVM\bin\clang++.exe', '--target=x86_64-pc-windows-msvc', '-c', str(clone), '-o', str(objpath), '-ffreestanding', '-fno-stack-protector', '-funwind-tables', '-O2', '-std=c++20']
    subprocess.run(command, check=True, capture_output=True)
    obj = read(objpath); text = next(s for s in obj['sections'] if s['name'] == '.text')
    expected, actual = bytearray(body), bytearray(text['data'])
    assert len(actual) == len(expected)
    for fixup in fixups:
        offset = fixup['offset']; expected[offset:offset + 4] = actual[offset:offset + 4] = bytes(4)
    assert actual == expected
    assert len(next(s for s in obj['sections'] if s['name'] == '.pdata')['data']) == 36
    assert len(next(s for s in obj['sections'] if s['name'] == '.xdata')['data']) == 64
    # Imports are derived from named verified bodies or original native operand
    # addresses, then bound to stable IDs. Authored C++ contains no RVAs.
    argv = next(r for r in catalog['functions'] if r['name'] == 'q_SV_Cmd_Argv')
    imports.update(NC_Argv=argv['id'], NC_ClientCommandNative='fn_695afa6f3e7f3edb',
        NC_ServerLoaded='fn_04583a98e3aa8c51', NC_IsLocalClient='fn_96f41f09cbad0bad', NC_FindDvar='fn_15b0e8e680376717')
    host = list(decoder.disasm(pe.get_data(byid['fn_96f41f09cbad0bad']['rva'], 37), byid['fn_96f41f09cbad0bad']['rva']))
    clients = next(i for i in host if i.mnemonic == 'lea' and i.operands[1].type == X86_OP_MEM)
    clients_rva = clients.address + clients.size + clients.operands[1].mem.disp
    imports['NC_Clients'] = workspace._catalog_symbol(clients_rva)
    # Reuse the preceding style preparer's instruction-derived native count
    # proof. Verify its original bodies and stable catalog identities again.
    ownership_path = snapshot / 'generated/bot-profile-ownership.json'
    ownership = json.loads(ownership_path.read_bytes())
    assert ownership['passed'] and ownership['image_sha256'] == TARGET
    for evidence in ownership['original_instructions']:
        native_row = byid[evidence['identity']]
        assert native_row['rva'] == evidence['rva']
        assert sha(pe.get_data(native_row['rva'], evidence['bytes'])) == evidence['sha256']
    count = next(r for r in ownership['imports'] if r['name'] == 'DW_Bot_ClientCount')
    assert byid[count['identity']]['rva'] == count['original_rva']
    assert byid[count['identity']]['kind'] == 'data-address'
    imports['NC_ClientCount'] = count['identity']
    dispatcher = list(decoder.disasm(pe.get_data(byid['fn_695afa6f3e7f3edb']['rva'], 48), byid['fn_695afa6f3e7f3edb']['rva']))
    entity = next(i for i in dispatcher if i.mnemonic == 'mov' and i.op_str.startswith('r15, qword ptr [rip'))
    imports['NC_Entities'] = workspace._catalog_symbol(entity.address + entity.size + entity.operands[1].mem.disp)
    header = '''#pragma once
#include "DW_Noclip.h"
extern "C" {
const char *NC_Argv(int);
void NC_ClientCommandNative(int);
bool NC_StringCommandNative(DWNoclip::ServerClient *, void *, int, bool);
bool NC_ServerLoaded();
bool NC_IsLocalClient(int);
const dvar_t *NC_FindDvar(const char *);
extern DWNoclip::ServerClient *NC_Clients[200];
extern uint32_t NC_ClientCount;
extern HostScale::Entity *NC_Entities;
}
'''
    write(snapshot / 'src/DW_NoclipBindings.h', header)
    for name in ('DW_Noclip.cpp', 'DW_Noclip.h'):
        write(snapshot / 'src' / name, (ROOT / 'integration/replay' / name).read_bytes())
    associations_path = snapshot / 'source-units.json'; associations = json.loads(associations_path.read_bytes())
    unit = dict(source='src/DW_Noclip.cpp', symbol='DW_Noclip_StringCommand', function_id=OUTER)
    prior = [u for u in associations['units'] if u['function_id'] == OUTER]
    assert not prior or replace_owned and prior == [unit]
    if not prior: associations['units'].append(unit)
    for symbol, identity in imports.items():
        wanted = dict(symbol=symbol, symbol_id=identity)
        prior = [r for r in associations.setdefault('imports', []) if r['symbol'] == symbol]
        assert not prior or prior == [wanted]
        if not prior: associations['imports'].append(wanted)
    units_path = snapshot / 'source-workstation/units.json'; units = json.loads(units_path.read_bytes())
    prior = [u for u in units['units'] if u['function_id'] == OUTER]
    assert not prior or replace_owned and len(prior) == 1 and prior[0]['source'] == unit['source']
    units['units'] = [u for u in units['units'] if u['function_id'] != OUTER]
    digest = sha((snapshot / unit['source']).read_bytes())
    units['units'].append(dict(unit, kind='cpp', sha256=digest, revision=digest, language='cpp'))
    write(associations_path, json.dumps(associations, indent=2) + '\n'); write(units_path, json.dumps(units, indent=2) + '\n')
    proof = dict(schema=1, passed=True, image_sha256=TARGET, native=native,
        imports=imports, fixups=fixups, unwind=unwind_records, clone_bytes=548,
        gs_handler_family='__GSHandlerCheck cookie-only DWORD offset, exact target schema',
        clone_source_sha256=sha(clone.read_bytes()), clone_object_sha256=sha(objpath.read_bytes()),
        header_sha256=sha(header.encode()), source_sha256=digest,
        layout_header_sha256=sha((snapshot / 'src/DW_Noclip.h').read_bytes()),
        generator_sha256=sha(Path(__file__).read_bytes()), native_unwind_records=3,
        count_proof_sha256=sha(ownership_path.read_bytes()),
        original_bytes_identical_except_symbolic_fixups=True, redirected_native_dispatch_calls=1,
        native_command_authentication_retained=True, game_runs=False)
    write(snapshot / 'generated/noclip-integration.json', json.dumps(proof, indent=2) + '\n')
    return proof

if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--replace-owned', action='store_true'); args = parser.parse_args()
    print(json.dumps(prepare(args.snapshot, args.replace_owned), indent=2))
