"""Read the resident Replay custom operator assets without changing game state."""
import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import re
from pathlib import Path
import struct


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pid', type=int, required=True)
    p.add_argument('--job', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--entity', type=int, action='append', default=[])
    a = p.parse_args()
    ready = json.loads((a.job/'local-readiness.json').read_bytes())
    report = json.loads(Path(ready['build_report']).read_bytes())
    symbols = report['symbols']
    k = c.WinDLL('kernel32', use_last_error=True)
    ps = c.WinDLL('psapi', use_last_error=True)
    k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    k.OpenProcess.restype = w.HANDLE
    k.ReadProcessMemory.argtypes = [w.HANDLE, c.c_void_p, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t)]
    k.CloseHandle.argtypes = [w.HANDLE]
    k.QueryFullProcessImageNameW.argtypes = [w.HANDLE, w.DWORD, w.LPWSTR, c.POINTER(w.DWORD)]
    ps.EnumProcessModulesEx.argtypes = [w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), w.DWORD]
    h = k.OpenProcess(0x410, False, a.pid)
    if not h:
        raise c.WinError(c.get_last_error())
    try:
        filename = c.create_unicode_buffer(32768)
        length = w.DWORD(len(filename))
        if not k.QueryFullProcessImageNameW(h, 0, filename, c.byref(length)):
            raise c.WinError(c.get_last_error())
        with Path(filename.value).open('rb') as f:
            if hashlib.file_digest(f, 'sha256').hexdigest() != ready['sha256']:
                raise ValueError('Running executable does not match the supplied build')
        modules = (w.HMODULE * 1024)()
        needed = w.DWORD()
        if not ps.EnumProcessModulesEx(h, modules, c.sizeof(modules), c.byref(needed), 3):
            raise c.WinError(c.get_last_error())
        base = modules[0]
        total = 0

        def raw(at, size):
            nonlocal total
            if not 0 < size <= 8*1024*1024:
                raise ValueError(size)
            b = c.create_string_buffer(size)
            done = c.c_size_t()
            if not k.ReadProcessMemory(h, at, b, size, c.byref(done)) or done.value != size:
                raise OSError(hex(at), size, c.get_last_error())
            total += size
            return b.raw

        def read(at, fmt):
            values = struct.unpack(fmt, raw(at, struct.calcsize(fmt)))
            return values[0] if len(values) == 1 else list(values)

        def text(at):
            return raw(at, 160).split(b'\0', 1)[0].decode('ascii', 'replace') if at else ''

        # Replay DB_AssetEntryTable::FindAsset, 0x140F5E010: hashed chains
        # of 20-byte entries, with the asset type at byte 17.
        table = base+symbols['sym_bb9f033016e1b7da']

        def asset(kind, name):
            hashed = kind
            for v in name.encode('ascii'):
                hashed = (hashed*31+v) & 0xffffffff
            index = read(table+7212808+(hashed % 0x57800)*4, '<I')
            visited = set()
            while index:
                if index in visited or len(visited) >= 4096:
                    raise ValueError('Invalid asset chain')
                visited.add(index)
                root, next_index, _, _, entry_kind, _ = read(table+20*index, '<QIIBBH')
                if entry_kind == kind and text(read(root, '<Q')) == name:
                    return root
                index = next_index
            return None

        result = dict(read_only=True, atomic_snapshot=False, pid=a.pid, base=hex(base), models=[])
        for name in ('dw_operator_nicky_body', 'dw_operator_nicky_head',
                     'dw_operator_bo2_body', 'dw_operator_bo2_head', 'body_mp_western_dday_1_1_lod1'):
            root = asset(9, name)
            if not root:
                result['models'].append(dict(name=name, resident=False))
                continue
            n, roots, client = read(root+0x14, '<BBH')
            parents, quats, trans, classification, bind = read(root+0xa0, '<5Q')
            model = dict(name=name, resident=True, address=hex(root), bones=n, roots=roots, client_bones=client,
                         flags=read(root+0x1c,'<I'),
                         baseMat=[read(bind+i*32, '<8f') for i in range(n)],
                         parents=list(raw(parents,n-roots)) if n>roots else [],
                         quats=[read(quats+i*8, '<4h') for i in range(n-roots)],
                         trans=[read(trans+i*12, '<3f') for i in range(n-roots)], surfaces=[])
            staging, surfaces, _, count, _ = read(root+0xe0, '<QQfHH')
            model['staging'] = hex(staging)
            model['lod_surfaces'] = hex(surfaces)
            for i in range(count):
                at = surfaces+192*i
                flags, verts, tris = read(at, '<3H')
                counts = read(at+16, '<8H')
                size = read(at+32, '<I')
                shared, _, rigid, blend = read(at+0x48, '<4Q')
                ptr, data_size, shared_flags = read(shared, '<QII')
                offsets = read(at+0x24, '<8I')
                words = read(blend, '<'+'H'*(size//2)) if size else []
                model['surfaces'].append(dict(index=i, flags=flags, vertices=verts, triangles=tris,
                    blend_counts=counts, blend_words=words, blend_size=size,
                    bounds=read(at+0x90, '<6f'), part_bits=read(at+0x70, '<8I'),
                    shared_flags=shared_flags, shared_size=data_size, offsets=offsets,
                    geometry_sha256=hashlib.sha256(raw(ptr,data_size)).hexdigest()))
            result['models'].append(model)
        # Complete native frontend request extent is 0x9f8; inspect names only.
        result['ui_requests'] = []
        for i in range(40):
            at = base+symbols['sym_c1e16c4eb28cb01f']+i*0x9f8
            count = read(at+0x6f0, '<I')
            if 0 < count <= 8:
                result['ui_requests'].append(dict(index=i, entity=read(at,'<h'),
                    models=[text(at+0x4f0+j*64) for j in range(count)],
                    strings=[dict(offset=m.start(), value=m.group().decode('ascii'))
                             for m in re.finditer(rb'[ -~]{5,}', raw(at, 0x9f8))]))
        # Replay Com_ClientDObjCreate uses a 16-bit handle table and 0x150-byte
        # DObjs. DObjCreateDuplicateParts stores model/bone counts at 15/16,
        # client bones at 18, and the model pointer array at 240.
        result['dobjs'] = []
        obj_buffer = read(base+symbols['sym_e3e7bb08359b2565'], '<Q')
        handles = read(base+symbols['sym_2fc19dbe25f87ddc'], '<2533H')
        result['active_dobj_handles'] = [[i,v] for i,v in enumerate(handles) if v]
        entities = {r['entity'] for r in result['ui_requests']} | set(a.entity)
        for entity in sorted(entities):
            if not 0 <= entity < 2533:
                continue
            index = read(base+symbols['sym_2fc19dbe25f87ddc']+2*entity, '<H')
            if not index:
                continue
            obj = obj_buffer+336*index
            models, bones, flags, clients = read(obj+15, '<BBBH')
            if not 0 < models <= 32 or bones+clients > 768:
                continue
            model_array = read(obj+240, '<Q')
            model_ptrs = read(model_array, '<'+'Q'*models)
            if models == 1:
                model_ptrs = [model_ptrs]
            mat = read(obj+192, '<Q')
            tree = read(obj, '<Q')
            result['dobjs'].append(dict(entity=entity, index=index, address=hex(obj),
                models=[dict(address=hex(m),name=text(read(m,'<Q')),
                    bones=read(m+20,'<B'),client_bones=read(m+22,'<H')) for m in model_ptrs],
                bones=bones, clients=clients, flags=flags, mat=hex(mat),
                tree=hex(tree), tree_header_hex=raw(tree,64).hex() if tree else None,
                pose=[read(mat+32*b,'<8f') for b in range(bones+clients)] if mat else [],
                header_hex=raw(obj,336).hex()))
        result['bytes_read'] = total
        a.output.parent.mkdir(parents=True,exist_ok=True)
        a.output.write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(dict(output=str(a.output), bytes_read=total,
            models=[{k:v for k,v in m.items() if k in ('name','resident','bones','roots','client_bones')} for m in result['models']],
            ui_requests=result['ui_requests']),indent=2))
    finally:
        k.CloseHandle(h)


if __name__ == '__main__':
    main()
