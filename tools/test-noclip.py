"""Offline source callback and complete native Win64 GS/unwind gate."""
import argparse, ctypes as c, hashlib, json, struct, subprocess, sys, tempfile, copy, importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def verify_linked(snapshot, proof, build):
    """Verify production bytes, rather than treating --build as a receipt label."""
    import pefile
    from coff import read
    build = build.resolve()
    report = json.loads((build / 'build-report.json').read_bytes())
    assert Path(report['source_root']).resolve() == snapshot, 'Different linked source snapshot'
    assert report['input_sha256'] == proof['image_sha256'] and report['unresolved_symbols'] == 0
    executable = Path(report['executable']).resolve()
    assert executable.is_relative_to(build) and sha(executable) == report['sha256']
    objects = {}
    expected_sources = {'DW_Noclip.cpp': 'source_sha256', 'DW_Noclip_Native.cpp': 'clone_source_sha256'}
    required = {'DW_Noclip.cpp': proof['source_sha256'], 'DW_Noclip.h': proof['layout_header_sha256'],
                'DW_NoclipBindings.h': proof['header_sha256']}
    for name, key in expected_sources.items():
        rows = [r for r in report['cpp'] if Path(r['source']).as_posix() == 'src/' + name]
        assert len(rows) == 1, ('Missing/duplicate linked C++ unit', name)
        row = rows[0]
        assert row['source_sha256'] == proof[key] == sha(snapshot / 'src' / name)
        objpath = Path(row['object']).resolve()
        assert objpath.is_relative_to(build) and sha(objpath) == row['object_sha256']
        dependencies = {Path(d['path']).resolve(): d['sha256'] for d in row['dependencies']}
        assert len(dependencies) == len(row['dependencies']), 'Duplicate dependency records'
        for path, digest in dependencies.items():
            assert sha(path) == digest, ('Changed linked dependency', str(path))
        own = required if name == 'DW_Noclip.cpp' else {name: proof[key]}
        for dependency, digest in own.items():
            assert dependencies[(snapshot / 'src' / dependency).resolve()] == digest
        objects[name] = dict(sha256=row['object_sha256'], dependency_count=len(dependencies))
        if name == 'DW_Noclip_Native.cpp':
            linked_object = read(objpath)
        else:
            callback_object = read(objpath)
    reference = read(snapshot / 'generated/noclip/native.obj')
    def section_signature(obj, name):
        rows = [s for s in obj['sections'] if s['name'] == name]
        assert len(rows) == 1, ('Missing/duplicate native COFF section', name)
        row = rows[0]
        relocations = []
        for offset, index, kind in row['relocations']:
            symbol = obj['symbols'][index]
            relocations.append((offset, symbol['name'], symbol['section'], symbol['value'], kind))
        # Section numbers can change with compiler directives; normalize the
        # referenced section identity, while retaining every relocation field.
        relocations = [(off, label, obj['sections'][sec - 1]['name'] if sec > 0 else sec, value, kind)
                       for off, label, sec, value, kind in relocations]
        return bytes(row['data']), relocations
    for section in ('.text', '.xdata', '.pdata'):
        assert section_signature(linked_object, section) == section_signature(reference, section), section
    symbols = report['symbols']
    for alias, identity in proof['imports'].items():
        assert alias in symbols and identity in symbols and symbols[alias] == symbols[identity], alias
    assert symbols['fn_9adeadab00498aa8'] == symbols['DW_Noclip_StringCommand']
    assert symbols['NC_ClientCommandNative'] != symbols['DW_Noclip_ClientCommand']
    start = symbols['NC_StringCommandNative']; size = proof['clone_bytes']
    pe = pefile.PE(str(executable))
    exported = [s for s in linked_object['symbols'].values() if s['name'] == 'NC_StringCommandNative']
    assert len(exported) == 1 and exported[0]['storage'] == 2 and exported[0]['value'] == 0
    assert linked_object['sections'][exported[0]['section'] - 1]['name'] == '.text'
    callback_sizes = {}
    for name in ('DW_Noclip_StringCommand', 'DW_Noclip_ClientCommand'):
        exported = [s for s in callback_object['symbols'].values() if s['name'] == name]
        assert len(exported) == 1 and exported[0]['storage'] == 2 and exported[0]['value'] == 0
        section = callback_object['sections'][exported[0]['section'] - 1]
        assert section['name'] == '.text' and section['data']
        expected_cpp = bytearray(section['data'])
        linked_cpp = bytearray(pe.get_data(symbols[name], len(expected_cpp)))
        assert len(linked_cpp) == len(expected_cpp)
        for offset, index, kind in section['relocations']:
            assert 4 <= kind <= 9, ('Unexpected callback relocation schema', kind)
            target = callback_object['symbols'][index]
            if target['name'].startswith('NC_'):
                actual_target = symbols[name] + offset + 4 + kind - 4 + struct.unpack_from('<i', linked_cpp, offset)[0]
                assert actual_target == symbols[target['name']] + struct.unpack_from('<i', expected_cpp, offset)[0]
            expected_cpp[offset:offset + 4] = linked_cpp[offset:offset + 4] = bytes(4)
        assert linked_cpp == expected_cpp, ('Linked callback differs from recorded C++ object', name)
        callback_sizes[name] = len(expected_cpp)
    expected = bytearray(section_signature(reference, '.text')[0]); actual = bytearray(pe.get_data(start, size))
    assert len(expected) == len(actual) == size == 548
    for fixup in proof['fixups']:
        offset = fixup['offset']
        target = start + offset + 4 + fixup['trailing_bytes'] + struct.unpack_from('<i', actual, offset)[0]
        assert target == symbols[fixup['symbol']], ('Incorrect linked native operand', fixup)
        expected[offset:offset + 4] = actual[offset:offset + 4] = bytes(4)
    assert actual == expected, 'Retained native command body changed'
    runtime = [e.struct for e in pe.DIRECTORY_ENTRY_EXCEPTION
               if e.struct.BeginAddress < start + size and e.struct.EndAddress > start]
    runtime.sort(key=lambda r: r.BeginAddress)
    original = proof['unwind']; native_start = original[0]['begin']
    assert len(runtime) == 3
    assert [(r.BeginAddress - start, r.EndAddress - start) for r in runtime] == [
        (r['begin'] - native_start, r['end'] - native_start) for r in original]
    primary = runtime[0]
    records = []
    for index, (entry, native) in enumerate(zip(runtime, original)):
        data = pe.get_data(entry.UnwindData, len(bytes.fromhex(native['bytes'])))
        prefix = (16, 12, 4)[index]
        assert data[:prefix] == bytes.fromhex(native['bytes'])[:prefix], 'Changed unwind opcodes/schema'
        if index == 0:
            assert struct.unpack_from('<II', data, 16) == (symbols['fn_3da1e16560231243'], 0x440)
        else:
            assert struct.unpack_from('<III', data, prefix) == (
                primary.BeginAddress, primary.EndAddress, primary.UnwindData), 'Incorrect chained RuntimeFunction'
        records.append(dict(begin=entry.BeginAddress, end=entry.EndAddress, unwind_rva=entry.UnwindData,
                            bytes=data.hex()))
    linked_unwind = linked_unwind_cases(pe, start, runtime, original)
    pe.close()
    return dict(sha256=report['sha256'], objects=objects, native_bytes=548,
                linked_callback_bytes=callback_sizes,
                native_operand_count=len(proof['fixups']), runtime_functions=records,
                actual_windows_RtlVirtualUnwind_cases=linked_unwind)

def linked_unwind_cases(pe, start, runtime, original):
    # Reserve a sparse image at an arbitrary private address. Commit only the
    # linked code and unwind pages; no game instructions or handlers execute.
    kernel = c.WinDLL('kernel32', use_last_error=True)
    alloc = kernel.VirtualAlloc; alloc.argtypes = [c.c_void_p, c.c_size_t, c.c_uint32, c.c_uint32]
    alloc.restype = c.c_void_p
    free = kernel.VirtualFree; free.argtypes = [c.c_void_p, c.c_size_t, c.c_uint32]; free.restype = c.c_int
    base = alloc(None, pe.OPTIONAL_HEADER.SizeOfImage, 0x2000, 4)
    assert base, ('VirtualAlloc reserve', c.get_last_error())
    try:
        ranges = [(start, pe.get_data(start, 548))] + [
            (r.UnwindData, pe.get_data(r.UnwindData, len(bytes.fromhex(n['bytes']))))
            for r, n in zip(runtime, original)]
        pages = {page for at, data in ranges for page in range(at & ~4095, (at + len(data) + 4095) & ~4095, 4096)}
        for page in sorted(pages):
            assert alloc(base + page, 4096, 0x1000, 4) == base + page
        for at, data in ranges: c.memmove(base + at, data, len(data))
        table = (c.c_uint32 * 9)(*[value for r in runtime for value in (r.BeginAddress, r.EndAddress, r.UnwindData)])
        return exercise_unwind(base, start, c.addressof(table), original)
    finally:
        assert free(base, 0, 0x8000)

def malformed_metadata_cases(proof):
    spec = importlib.util.spec_from_file_location('noclip_prepare', ROOT / 'tools/prepare-noclip-integration.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    handler = next(r['rva'] for r in proof['native'] if r['identity'] == 'fn_3da1e16560231243')
    module.validate_unwind(proof['unwind'], handler)
    for case in range(8):
        records = copy.deepcopy(proof['unwind']); target = handler
        if case == 0: records.pop()
        elif case == 1: records[0]['bytes'] = '09' + records[0]['bytes'][2:]
        elif case == 2: records[0]['bytes'] = records[0]['bytes'][:-8] + '00000000'
        elif case == 3: records[1]['bytes'] = '01' + records[1]['bytes'][2:]
        elif case == 4: records[1]['begin'] += 1
        elif case == 5: records[-1]['end'] += 1
        elif case == 6: records[0]['unwind_rva'] += 4
        else: target += 1
        try: module.validate_unwind(records, target)
        except ValueError: pass
        else: raise AssertionError(('Malformed native metadata accepted', case))
    return 8

def unwind_cases(snapshot, proof):
    sys.path.insert(0, str(snapshot / 'tools'))
    from coff import read
    objpath = snapshot / 'generated/noclip/native.obj'
    assert hashlib.sha256(objpath.read_bytes()).hexdigest() == proof['clone_object_sha256']
    obj = read(objpath)
    image = c.create_string_buffer(0x10000); base = c.addressof(image)
    sections = {}
    for index, section in enumerate(obj['sections'], 1):
        if section['name'] in ('.text', '.xdata', '.pdata'):
            sections[index] = {'.text': 0x1000, '.xdata': 0x2000, '.pdata': 0x3000}[section['name']]
            c.memmove(base + sections[index], bytes(section['data']), len(section['data']))
    def symbol(index):
        row = obj['symbols'][index]
        if row['section'] > 0:
            return sections[row['section']] + row['value']
        return 0x5000 # Never called; RtlVirtualUnwind only reads code/unwind data.
    for index, section in enumerate(obj['sections'], 1):
        if index not in sections: continue
        for offset, target, kind in section['relocations']:
            at = base + sections[index] + offset
            value = c.c_uint32.from_address(at).value
            if kind == 3: value += symbol(target) # IMAGE_REL_AMD64_ADDR32NB.
            elif kind == 4: value += symbol(target) - sections[index] - offset - 4
            else: raise AssertionError(('Unexpected native relocation', kind))
            c.c_uint32.from_address(at).value = value & 0xffffffff
    runtime = (c.c_uint32 * 9).from_address(base + 0x3000)
    original = proof['unwind']; first = original[0]['begin']
    assert [(runtime[i * 3], runtime[i * 3 + 1]) for i in range(3)] == [
        (0x1000 + row['begin'] - first, 0x1000 + row['end'] - first) for row in original]
    # Native GS-only record followed by two exact chain records. Metadata
    # cannot quietly become a plain/unprotected unwind record.
    assert bytes(image[0x2000:0x2010]).hex() == '192006000e018b0007f005e003600250'
    assert struct.unpack_from('<I', image, 0x2014)[0] == 0x440
    assert bytes(image[0x2018:0x2024]).hex() == '2113040013748a0008349300'
    assert bytes(image[0x2030:0x2034]).hex() == '21000000'
    for at in (0x2024, 0x2034):
        assert struct.unpack_from('<III', image, at) == (runtime[0], runtime[1], runtime[2])
    return exercise_unwind(base, 0x1000, base + 0x3000, original)

def exercise_unwind(base, code_rva, table_address, original):
    first = original[0]['begin']
    rtl = c.WinDLL('ntdll').RtlVirtualUnwind
    rtl.argtypes = [c.c_uint32, c.c_uint64, c.c_uint64, c.c_void_p, c.c_void_p,
                    c.POINTER(c.c_void_p), c.POINTER(c.c_uint64), c.c_void_p]
    rtl.restype = c.c_void_p
    stack = c.create_string_buffer(0x4000); top = (c.addressof(stack) + 0x2000) & ~15
    values = dict(rbp=0x1111222233334444, rsi=0x2222333344445555,
                  r14=0x3333444455556666, r15=0x4444555566667777,
                  rbx=0x5555666677778888, rdi=0x6666777788889999)
    return_address = 0x1122334455667788
    c.c_uint64.from_address(top).value = return_address
    for delta, reg in [(8, 'rbp'), (16, 'rsi'), (24, 'r14'), (32, 'r15')]:
        c.c_uint64.from_address(top - delta).value = values[reg]
    bottom = top - 0x478
    c.c_uint64.from_address(bottom + 0x450).value = values['rdi']
    c.c_uint64.from_address(bottom + 0x498).value = values['rbx']
    offsets = dict(rbx=144, rsp=152, rbp=160, rsi=168, rdi=176, r14=232, r15=240, rip=248)
    cases = [(0, 0, top), (2, 0, top - 8), (3, 0, top - 16), (5, 0, top - 24),
             (7, 0, top - 32), (14, 0, bottom), (32, 0, bottom),
             (original[1]['begin'] - first + 19, 1, bottom),
             (original[1]['end'] - first - 1, 1, bottom),
             (original[2]['begin'] - first, 2, bottom),
             (original[2]['end'] - first - 1, 2, top)]
    for control, entry, rsp in cases:
        context = c.create_string_buffer(1232)
        for reg, value in values.items(): struct.pack_into('<Q', context, offsets[reg], value)
        struct.pack_into('<Q', context, 152, rsp)
        struct.pack_into('<Q', context, 248, base + code_rva + control)
        handler = c.c_void_p(); frame = c.c_uint64()
        rtl(0, base, base + code_rva + control, table_address + entry * 12,
            c.addressof(context), c.byref(handler), c.byref(frame), None)
        assert struct.unpack_from('<Q', context, 248)[0] == return_address, (control, 'Return address')
        assert struct.unpack_from('<Q', context, 152)[0] == top + 8, (control, 'Stack restore')
        for reg, value in values.items():
            assert struct.unpack_from('<Q', context, offsets[reg])[0] == value, (control, reg)
    return len(cases)

def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--build', type=Path)
    parser.add_argument('--output', type=Path, required=True); args = parser.parse_args()
    snapshot = args.snapshot.resolve()
    assert snapshot.is_relative_to(ROOT / 'data')
    proof = json.loads((snapshot / 'generated/noclip-integration.json').read_bytes())
    assert proof['schema'] == 1 and proof['passed']
    assert proof['generator_sha256'] == sha(ROOT / 'tools/prepare-noclip-integration.py')
    assert proof['count_proof_sha256'] == sha(snapshot / 'generated/bot-profile-ownership.json')
    associations = json.loads((snapshot / 'source-units.json').read_bytes())
    assert [u for u in associations['units'] if u['function_id'] == 'fn_9adeadab00498aa8'] == [
        dict(source='src/DW_Noclip.cpp', symbol='DW_Noclip_StringCommand', function_id='fn_9adeadab00498aa8')]
    for alias, identity in proof['imports'].items():
        assert [r for r in associations['imports'] if r['symbol'] == alias] == [dict(symbol=alias, symbol_id=identity)]
    malformed = malformed_metadata_cases(proof)
    for name, key in [('DW_Noclip.cpp', 'source_sha256'), ('DW_Noclip.h', 'layout_header_sha256'),
                      ('DW_NoclipBindings.h', 'header_sha256'), ('DW_Noclip_Native.cpp', 'clone_source_sha256')]:
        assert hashlib.sha256((snapshot / 'src' / name).read_bytes()).hexdigest() == proof[key]
    unwind = unwind_cases(snapshot, proof)
    linked = verify_linked(snapshot, proof, args.build) if args.build else None
    with tempfile.TemporaryDirectory(prefix='noclip-', dir=ROOT / 'data') as temporary:
        exe = Path(temporary) / 'noclip-test.exe'
        command = [r'C:\Program Files\LLVM\bin\clang++.exe', '-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror',
                   '-I' + str(snapshot / 'src'), str(snapshot / 'src/DW_Noclip.cpp'),
                   str(ROOT / 'tools/noclip_harness.cpp'), '-o', str(exe)]
        subprocess.run(command, check=True, capture_output=True)
        run = subprocess.run([str(exe)], check=True, capture_output=True, text=True)
    report = dict(passed=True, native_unwind_cases=unwind, callback_output=run.stdout.strip(),
                  malformed_native_metadata_rejected=malformed,
                  native_authenticated_outer_bytes=548, native_gs_chain_records=3,
                  linked_build=linked,
                  source_hashes={name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in (
                      'integration/replay/DW_Noclip.cpp', 'integration/replay/DW_Noclip.h',
                      'tools/prepare-noclip-integration.py', 'tools/test-noclip.py', 'tools/noclip_harness.cpp')},
                  game_run=False, native_body_executed=False, actual_windows_RtlVirtualUnwind=True,
                  modeled_boundaries=['Native packet parsing/delegation', 'Server local connection and dvar lookup', 'Native command response'])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(run.stdout.strip(), 'RtlVirtualUnwind cases:', unwind)

if __name__ == '__main__': main()
