"""Execute linked playlist installer instructions with modeled native Lua boundaries."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

import pefile
import unicorn
import unicorn.x86_const as x


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--lua-source', type=Path,
                        default=Path(__file__).resolve().parents[1] / 'integration/replay/DW_PlaylistUI.lua')
    args = parser.parse_args()
    report_path = args.build / 'build-report.json' if args.build.is_dir() else args.build
    report = json.loads(report_path.read_bytes())
    image = Path(report['executable'])
    if not image.is_absolute():
        image = report_path.parent / image
    raw = image.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == report['sha256']
    pe = pefile.PE(data=raw, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    symbols = {key: base + value for key, value in report['symbols'].items()}
    # The ordinary source RVA alias resolves to the native timer; reports expose
    # its named symbol rather than every replay_rva spelling used by source.
    if 'replay_rva_0148fce0' not in symbols:
        symbols['replay_rva_0148fce0'] = symbols['Sys_Milliseconds']
    machine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    for section in pe.sections:
        size = (max(section.Misc_VirtualSize, section.SizeOfRawData) + 4095) & -4096
        if size:
            machine.mem_map(base + section.VirtualAddress, size)
            machine.mem_write(base + section.VirtualAddress, section.get_data())
    arena = 0x100000000
    machine.mem_map(arena, 0x20000)
    stack, stop = arena + 0x10000 - 8, arena + 0x1F000
    source = args.lua_source.read_bytes().replace(b'\r\n', b'\n')
    state = dict(enabled=True, main=True, now=1000, locked=False, top=7,
                 installed=False, eligible=True, load_error=0, call_error=0, error_kind='probe',
                 vm=arena + 0x1000, loads=[], prints=[], events=[])
    names = ('DW_LocalBackend_IsEnabled', 'Sys_IsMainThread', 'replay_rva_0148fce0',
             'DW_Progression_LUILock', 'DW_Progression_LUIUnlock',
             'DW_Progression_LuaTop', 'DW_Progression_LuaSetTop',
             'DW_Progression_LuaLoad', 'DW_Progression_LuaCall', 'func_142084A10', 'Com_Printf')
    boundaries = {symbols[name]: name for name in names}

    def returned(value=0):
        rsp = machine.reg_read(x.UC_X86_REG_RSP)
        target = struct.unpack('<Q', machine.mem_read(rsp, 8))[0]
        machine.reg_write(x.UC_X86_REG_RAX, value)
        machine.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        machine.reg_write(x.UC_X86_REG_RIP, target)

    def hook(vm, address, size, context):
        name = boundaries.get(address)
        if not name:
            return
        state['events'].append(name)
        if name == 'DW_LocalBackend_IsEnabled':
            returned(int(state['enabled']))
        elif name == 'Sys_IsMainThread':
            returned(int(state['main']))
        elif name == 'replay_rva_0148fce0':
            returned(state['now'])
        elif name == 'DW_Progression_LUILock':
            assert not state['locked']
            state['locked'] = True
            returned()
        elif name == 'DW_Progression_LUIUnlock':
            assert state['locked'] and state['top'] == 7
            state['locked'] = False
            returned()
        elif name == 'Com_Printf':
            state['prints'].append(state['now'])
            returned()
        else:
            assert state['locked'], name
            assert vm.reg_read(x.UC_X86_REG_RCX) == state['vm'], name
            if name == 'DW_Progression_LuaTop':
                returned(state['top'])
            elif name == 'DW_Progression_LuaSetTop':
                state['top'] = vm.reg_read(x.UC_X86_REG_RDX) & 0xFFFFFFFF
                returned()
            elif name == 'DW_Progression_LuaLoad':
                text = bytes(vm.mem_read(vm.reg_read(x.UC_X86_REG_RDX), vm.reg_read(x.UC_X86_REG_R8)))
                if text.startswith(b'local ready=MenuBuilder'):
                    kind = 'probe'
                    assert text == (b'local ready=MenuBuilder and MenuBuilder.IsTypeRegistered and '
                                    b"MenuBuilder.IsTypeRegistered('ReplayDWPlaylistFillState'); "
                                    b'if ready then MenuBuilder.m_types.replaydwplaylistfillstate().Refresh() end; '
                                    b'return ready and 1 or 0')
                else:
                    kind = 'installer'
                    assert text == source, 'Linked embedded Lua differs from supplied source'
                state['kind'] = kind
                state['loads'].append(kind)
                state['top'] += 1
                returned(state['load_error'] if kind == state['error_kind'] else 0)
            elif name == 'DW_Progression_LuaCall':
                error = state['call_error'] if state['kind'] == state['error_kind'] else 0
                assert vm.reg_read(x.UC_X86_REG_RDX) == 0
                assert vm.reg_read(x.UC_X86_REG_R8) == 1
                assert vm.reg_read(x.UC_X86_REG_R9) == 0
                if not error and state['kind'] == 'installer' and state['eligible']:
                    state['installed'] = True
                returned(error)
            elif name == 'func_142084A10':
                number = float(state['installed'])
                vm.reg_write(x.UC_X86_REG_XMM0, int.from_bytes(struct.pack('<d', number), 'little'))
                returned()

    machine.hook_add(unicorn.UC_HOOK_CODE, hook)
    checks = []

    def frame(label, advance=1000):
        state['now'] += advance
        machine.mem_write(symbols['gl_151868880'], struct.pack('<Q', state['vm']))
        machine.mem_write(stack, struct.pack('<Q', stop))
        machine.reg_write(x.UC_X86_REG_RSP, stack)
        machine.emu_start(symbols['DW_PlaylistUI_Frame'], stop, count=100000)
        assert not state['locked'] and state['top'] == 7
        checks.append(label)

    state['enabled'] = False
    frame('DW disabled early return')
    assert state['events'] == ['DW_LocalBackend_IsEnabled']
    state['enabled'], state['main'] = True, False
    state['events'].clear()
    frame('off-thread early return')
    assert state['events'] == ['DW_LocalBackend_IsEnabled', 'Sys_IsMainThread']
    state['main'], state['vm'] = True, 0
    frame('absent VM unlocks safely')
    state['vm'], state['load_error'] = arena + 0x1000, 1
    frame('load error restores stack')
    assert state['loads'] == ['probe'] and len(state['prints']) == 1
    state['load_error'], state['call_error'] = 0, 1
    frame('pcall error restores stack and suppresses repeated error log')
    assert len(state['prints']) == 1
    state['error_kind'], state['call_error'], state['load_error'] = 'installer', 0, 1
    frame('installer load error restores stack')
    assert state['loads'][-2:] == ['probe', 'installer'] and not state['installed']
    state['load_error'], state['call_error'] = 0, 1
    frame('installer pcall error restores stack')
    assert not state['installed'] and len(state['prints']) == 1
    state['call_error'], state['eligible'] = 0, False
    frame('ineligible installer remains retryable')
    assert state['loads'][-2:] == ['probe', 'installer'] and not state['installed']
    state['eligible'] = True
    frame('retry installs exact compiled Lua')
    assert state['installed'] and len(state['prints']) == 2
    before = len(state['loads'])
    frame('one-second throttle', advance=1)
    assert len(state['loads']) == before
    frame('marker idempotence')
    assert state['loads'][before:] == ['probe'] and len(state['prints']) == 2
    state['installed'] = False
    frame('VM reload at reused address reinstalls')
    assert state['loads'][-2:] == ['probe', 'installer']
    state['vm'], state['installed'] = arena + 0x2000, False
    frame('replacement VM installs and reports success')
    assert state['installed'] and len(state['prints']) == 3
    result = dict(passed=True, image_sha256=report['sha256'], checks=checks,
                  checker_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  lua_source=str(args.lua_source), lua_source_sha256=hashlib.sha256(args.lua_source.read_bytes()).hexdigest(),
                  embedded_lua_sha256=hashlib.sha256(source).hexdigest(),
                  evidence='Actual linked frame instructions; modeled native Lua and locking boundaries',
                  game_launched=False)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
