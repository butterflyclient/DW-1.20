"""Read custom operator state from a matching running client without changing it."""
import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import importlib.util
import json
from pathlib import Path
import struct


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', required=True, type=int)
    parser.add_argument('--job', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    ready = json.loads((args.job / 'local-readiness.json').read_bytes())
    report = json.loads(Path(ready['build_report']).read_bytes())
    gate = json.loads((args.job / 'custom-operators.json').read_bytes())
    assert gate['passed'] and gate['executable_sha256'] == ready['sha256']
    spec = importlib.util.spec_from_file_location('operator_live_coff', Path(report['source_root']) / 'tools/coff.py')
    coff = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(coff)
    row = next(row for row in report['cpp'] if row['source'] == 'src/DW_CustomOperators.cpp')
    objpath = Path(row['object'])
    assert hashlib.sha256(objpath.read_bytes()).hexdigest() == row['object_sha256']
    obj = coff.read(objpath)
    anchors = gate['linked']['callback_sections']['sections']
    k = c.WinDLL('kernel32', use_last_error=True)
    ps = c.WinDLL('psapi', use_last_error=True)
    k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    k.OpenProcess.restype = w.HANDLE
    k.ReadProcessMemory.argtypes = [w.HANDLE, c.c_void_p, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t)]
    k.CloseHandle.argtypes = [w.HANDLE]
    k.QueryFullProcessImageNameW.argtypes = [w.HANDLE, w.DWORD, w.LPWSTR, c.POINTER(w.DWORD)]
    ps.EnumProcessModulesEx.argtypes = [w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), w.DWORD]
    handle = k.OpenProcess(0x410, False, args.pid)
    if not handle:
        raise c.WinError(c.get_last_error())
    total = 0
    try:
        name = c.create_unicode_buffer(32768)
        length = w.DWORD(len(name))
        assert k.QueryFullProcessImageNameW(handle, 0, name, c.byref(length))
        with Path(name.value).open('rb') as stream:
            assert hashlib.file_digest(stream, 'sha256').hexdigest() == ready['sha256']
        modules = (w.HMODULE * 1024)()
        needed = w.DWORD()
        assert ps.EnumProcessModulesEx(handle, modules, c.sizeof(modules), c.byref(needed), 3)
        base = modules[0]

        def raw(at, size):
            nonlocal total
            buf = c.create_string_buffer(size)
            done = c.c_size_t()
            if not k.ReadProcessMemory(handle, at, buf, size, c.byref(done)) or done.value != size:
                raise OSError(hex(at), c.get_last_error())
            total += size
            return buf.raw

        def read(at, fmt):
            values = struct.unpack(fmt, raw(at, struct.calcsize(fmt)))
            return values[0] if len(values) == 1 else list(values)

        def string(at):
            return raw(at, 128).split(b'\0', 1)[0].decode('ascii', errors='replace') if at else None

        static = {}
        for symbol in obj['symbols'].values():
            if not symbol or not symbol.get('name', '').startswith('?s_'):
                continue
            section = anchors.get(str(symbol['section']))
            if section:
                at = base + section['rva'] + symbol['value']
                count = min(section['bytes'] - symbol['value'], 24)
                static[symbol['name']] = dict(address=hex(at), raw=raw(at, count).hex())
        selection = next((v for n, v in static.items() if n.startswith('?s_selection@')), None)
        dvar = None
        if selection:
            at = int.from_bytes(bytes.fromhex(selection['raw'])[:8], 'little')
            if at:
                dvar = dict(name=string(read(at, '<Q')), current=read(at+40, '<i'),
                            latched=read(at+56, '<i'), flags=read(at+24, '<I'))
        symbols = report['symbols']
        local_views = []
        for local in range(1):
            pointer = read(base + symbols['CO_LocalClientGlobals'] + 8 * local, '<Q')
            if pointer:
                local_views.append(dict(index=local, address=hex(pointer),
                    movement_type=read(pointer+20,'<i'), other_flags=read(pointer+36,'<I'),
                    predicted_client=read(pointer+456,'<I'),
                    local_client=read(pointer+25632,'<I'), in_killcam=read(pointer+533720,'<i')))
        groups = []
        packages = []
        for kind in range(3):
            first, _, count, male, female = read(base+symbols['DW_Bot_CustomizationGroups']+kind*16, '<HHIII')
            groups.append(dict(kind=kind, first=first, count=count, male=male, female=female))
            assert first+count <= 8192
            for slot in range(first, first+count):
                at = base+symbols['DW_Bot_CustomizationPackages']+slot*40
                value = raw(at, 40)
                primary = struct.unpack_from('<H', value, 22)[0]
                if not 60000 <= primary <= 60001:
                    continue
                packages.append(dict(slot=slot, model=string(struct.unpack_from('<Q',value,0)[0]),
                    fallback=string(struct.unpack_from('<Q',value,8)[0]), primary=primary,
                    secondary=struct.unpack_from('<H',value,24)[0], category=struct.unpack_from('<I',value,28)[0],
                    hands=struct.unpack_from('<H',value,32)[0], random=value[34], invalid=value[35]))
        output = dict(read_only=True, atomic_snapshot=False, pid=args.pid, base=hex(base),
            executable_sha256=ready['sha256'], bytes_read=total, statics=static, dvar=dvar,
            groups=groups, packages=packages, local_views=local_views,
            local_customization=read(base+symbols['CO_LocalCustomization'], '<6I'))
        output['server_players'] = []
        entity_base = read(base+symbols['CO_Entities'],'<Q')
        for index in range(200):
            if not entity_base:
                break
            entity = entity_base+0x5a0*index
            client = read(entity+0x150,'<Q')
            if client:
                player = dict(index=index,entity_type=read(entity+8,'<H'),
                              model_index=read(entity+1044,'<H'),client=hex(client))
                try:
                    player.update(customization=read(client+0x56d8,'<3I'),
                                  party_member=read(client+0x55fc,'<i'))
                except OSError:
                    player['unreadable_client'] = True
                output['server_players'].append(player)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(output, indent=2)+'\n')
        print(json.dumps(output, indent=2))
    finally:
        k.CloseHandle(handle)


if __name__ == '__main__':
    main()
