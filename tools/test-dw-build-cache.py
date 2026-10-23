"""Exercise object reuse, input invalidation and native comparison reuse."""
from contextlib import closing
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace

import dw_build_cache as cache
import dw_sqlite_snapshot as snapshots

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'data/dw-client/compiler-base/tools'))
import coff

CALLS = []


def compile_input(source, target, cpp=False, previous=None, optimized=False):
    CALLS.append(str(source))
    command = [r'C:\Program Files\LLVM\bin\clang++.exe', '--target=x86_64-pc-windows-msvc',
               '-c', str(source), '-o', str(target), '-O2', '-DOPT='+str(int(optimized)),
               '-fmacro-prefix-map='+str(source.parent.parent)+'=.']
    subprocess.run(command, check=True, capture_output=True)
    return dict(source=str(source), source_sha256=cache.digest(source), object=str(target),
                object_sha256=cache.digest(target), command=command, compiler=dict(path=command[0], sha256='compiler'),
                cache_key='original', dependencies=[dict(path=str(p), sha256=cache.digest(p))
                    for p in (source, source.with_name('value.h'))])


def objects(folder):
    os.environ['REPLAY_OBJECT_CACHE'] = str(folder/'objects')
    for name in ('first', 'second'):
        root = folder/name
        (root/'src').mkdir(parents=True)
        (root/'src/sample.cpp').write_text('#include "value.h"\nextern "C" int value(){return VALUE+OPT;}\nextern "C" const char *file(){return __FILE__;}\n')
        (root/'src/value.h').write_text('#define VALUE 17\n')
        namespace = dict(ROOT=root, compile_one=compile_input, MASM=Path('unused'), LLVM=Path(r'C:\Program Files\LLVM\bin'),
            tool_identity=lambda p:dict(path=str(p), sha256='compiler'), _reported_path=lambda p:str(p), read=coff.read,
            source_catalog=SimpleNamespace(refresh=lambda *a,**k:None),
            native_functions=SimpleNamespace(branch_references=lambda *a:None))
        cache.install(namespace)
        result = namespace['compile_one'](root/'src/sample.cpp', root/'sample.obj', cpp=True)
        assert result['object_cache_hit'] == (name == 'second')
    assert len(CALLS) == 1, CALLS
    compile_input(root/'src/sample.cpp',root/'fresh.obj',cpp=True)
    assert cache.digest(root/'sample.obj') == cache.digest(root/'fresh.obj'), 'Cached __FILE__ differs from a fresh compile'
    header = root/'src/value.h'
    times = header.stat()
    header.write_text('#define VALUE 19\n')
    os.utime(header, ns=(times.st_atime_ns, times.st_mtime_ns))
    assert not namespace['compile_one'](root/'src/sample.cpp', root/'sample.obj', cpp=True)['object_cache_hit']
    assert not namespace['compile_one'](root/'src/sample.cpp', root/'sample.obj', cpp=True, optimized=True)['object_cache_hit']
    assert namespace['compile_one'](root/'src/sample.cpp', root/'sample.obj', cpp=True, optimized=True)['object_cache_hit']
    for path in (folder/'objects').glob('*.obj'):
        path.write_bytes(b'corrupt')
    assert not namespace['compile_one'](root/'src/sample.cpp', root/'sample.obj', cpp=True)['object_cache_hit']
    assert len(CALLS) == 5


def layout_lookups():
    import layout
    spans = [dict(begin=i*11,end=i*11+7) for i in range(30)]
    mapping = dict(ranges=[dict(begin=i*11,end=i*11+7,mapped_begin=i*19) for i in range(30)],
        interior_reference_resolutions=[dict(original_rva=4,mapped_rva=400)])
    obj = SimpleNamespace(replacements=spans)
    cache.install_layout_lookups()
    for rva in range(-1,342):
        expected = next((row for row in spans if row['begin'] <= rva < row['end']),None)
        assert layout.Layout.replaced(obj,rva) is expected
        expected = rva
        for row in mapping['ranges']:
            if row['begin'] <= rva < row['end'] or (row is mapping['ranges'][-1] and rva == row['end']):
                expected = row['mapped_begin']+rva-row['begin']
                break
        if rva == 4:
            expected = 400
        assert layout.from_report(rva,dict(rva_map=mapping)) == expected


def bootstrap(folder):
    root = folder/'bootstrap'
    (root/'tools').mkdir(parents=True)
    (root/'workstation').mkdir()
    (root/'tools/build.py').write_text('def compile_one():\n    options = ["-O2", "-std=c17" if c_language else "-std=c++20"]\n\nif __name__ == "__main__":\n    pass\n')
    (root/'workstation/project.py').write_text('class Project:\n    def build(self):\n        def run(arguments, phase):\n            update(phase=phase)\n')
    (root/'tools/native_linker.py').write_text("def place(objects):\n        for obj in objects:\n            for index, section in enumerate(obj['sections'], 1):\n                definitions = [s for s in obj['symbols'].values() if s['section'] == index and s['storage'] == 2]\n")
    cache.prepare(root)
    paths = [root/'tools/build.py',root/'tools/native_linker.py',root/'workstation/project.py']
    expected = [cache.digest(p) for p in paths]
    cache.prepare(root)
    assert expected == [cache.digest(p) for p in paths]
    for p in paths:
        compile(p.read_text(),str(p),'exec')


def native_text(folder):
    root = folder/'native'
    (root/'generated').mkdir(parents=True)
    verifier = root/'verify.py'
    verifier.write_text('verifier identity')
    for name in ('instruction-lengths.bin','instruction-confidence.bin','data-fixups.bin','metadata-fixups.bin'):
        (root/'generated'/name).write_bytes(b'input')
    calls = []
    data = bytearray(range(16))
    original = SimpleNamespace(sections=[SimpleNamespace(Name=b'.text', VirtualAddress=0x1000, SizeOfRawData=16)])
    rebuilt = SimpleNamespace(get_data=lambda at,size:bytes(data[at-0x1000:at-0x1000+size]))
    report = dict(input_sha256='native',cpp_region_rva=0x1010,script_opaque_limit=0xe2c0,
        rva_map=dict(ranges=[dict(begin=0x1000,end=0x1010,mapped_begin=0x1000)]),
        replacements=[dict(begin=0x1004,end=0x1008,symbol='replacement')],symbols=dict(replacement=0x1004))
    namespace = dict(ROOT=root,__file__=str(verifier),check_text=lambda *a:(calls.append(1) or dict(instructions=16)),
                     verify_protected_callbacks=lambda *a:[])
    cache.install_text_verification(namespace)
    check = lambda:namespace['check_text'](original,rebuilt,report,root)
    check()
    data[5] ^= 1  # Changed C++ replacement is checked by the compiled-code verifier.
    check()
    assert len(calls) == 1
    data[2] ^= 1  # Retained native byte changes invalidate the complete comparison.
    check()
    assert len(calls) == 2
    report['rva_map']['ranges'][0]['mapped_begin'] += 1
    check()
    assert len(calls) == 3


def dependencies(folder):
    root = folder/'dependencies'
    (root/'tools').mkdir(parents=True)
    (root/'tools/test-a.py').write_text('# UnitA.cpp common.h\n')
    (root/'tools/test-unknown.py').write_text('# no declared owner\n')
    units = [dict(source='src/Unit'+name+'.cpp',object_sha256=name,defined_symbols=['function'+name],
                  undefined_symbols=['functionB'] if name=='A' else [],
                  dependencies=[dict(path='common.h',sha256='shared')]) for name in 'ABC']
    report = dict(source_root=str(root),cpp=units,symbols={})
    receipt = dict(source_inputs=[],tool_inputs=[],sqlite_snapshot=dict(sha256='sqlite'))
    key, selected = cache.check_dependencies('test-a.py',report,receipt,root)
    assert selected == ['src/UnitA.cpp','src/UnitB.cpp']
    report['cpp'][2]['object_sha256'] = 'unrelated change'
    assert cache.check_dependencies('test-a.py',report,receipt,root)[0] == key
    report['cpp'][1]['object_sha256'] = 'called unit change'
    assert cache.check_dependencies('test-a.py',report,receipt,root)[0] != key
    assert len(cache.check_dependencies('test-unknown.py',report,receipt,root)[1]) == 3


def preparation_metadata(folder):
    source = folder/'metadata'
    source.mkdir()
    origin = folder/'previous/source'
    old_cpp, new_cpp = 'old-source-hash', 'new-source-hash'
    a = source/'binding.json'
    a.write_text(json.dumps(dict(path=str(origin/'body.cpp'),source_sha256=old_cpp)))
    b = source/'package.json'
    b.write_text(json.dumps(dict(path=str(origin/'binding.json'),sha256=cache.digest(a))))
    c = source/'manifest.json'
    c.write_text(json.dumps(dict(path=str(origin/'package.json'),sha256=cache.digest(b))))
    cache.rebase_metadata(source,[origin],{old_cpp:new_cpp})
    assert json.loads(a.read_bytes()) == dict(path=str(source/'body.cpp'),source_sha256=new_cpp)
    assert json.loads(b.read_bytes()) == dict(path=str(source/'binding.json'),sha256=cache.digest(a))
    assert json.loads(c.read_bytes()) == dict(path=str(source/'package.json'),sha256=cache.digest(b))
    before = [cache.digest(p) for p in (a,b,c)]
    cache.rebase_metadata(source,[origin],{old_cpp:new_cpp})
    assert before == [cache.digest(p) for p in (a,b,c)]
    records, destination = folder/'records',folder/'new-job'
    records.mkdir(); destination.mkdir()
    for name in ('lobby-native-clones.json','playlist-ui-preparation.json','map-images-package.json'):
        (records/name).write_text(json.dumps(dict(passed=True)))
    copied = cache.copy_preparation_records(records,destination)
    assert len(copied) == 3
    assert all(cache.digest(destination/row['path']) == row['sha256'] for row in copied)


def validation_dependencies(folder):
    import dw_client as client
    original_loader = client.load_module
    fixture = folder/'validation-dependencies'
    source = fixture/'data/dw-client/jobs/fixture/source'
    source.mkdir(parents=True)
    receipt_path = source.parent/'source-receipt.json'
    receipt = dict(snapshot=str(source),files=[],source_inputs=[],tool_inputs=[])
    receipt_path.write_text(json.dumps(receipt))
    def fixture_loader(name,path):
        module = original_loader(name,path)
        module.ROOT = fixture
        return module
    client.load_module = fixture_loader
    try:
        client.prepare_validation_dependencies(source)
        destination = source/'tools/test-host-scale.py'
        assert destination.read_bytes() == (ROOT/'tools/test-host-scale.py').read_bytes()
        before = cache.digest(destination)
        client.prepare_validation_dependencies(source)
        assert before == cache.digest(destination)
        receipt['files'] = [dict(path='tools/test-host-scale.py',sha256=before)]
        receipt_path.write_text(json.dumps(receipt))
        try:
            client.prepare_validation_dependencies(source)
            raise AssertionError('Validation setup accepted a frozen compiler input')
        except ValueError as error:
            assert 'frozen input' in str(error)
    finally:
        client.load_module = original_loader


def sqlite_snapshots(folder):
    source = folder/'live.sqlite'
    with closing(sqlite3.connect(source)) as connection:
        connection.execute('CREATE TABLE names(id INTEGER PRIMARY KEY, name TEXT)')
        connection.execute("INSERT INTO names VALUES(1,'original')")
        connection.commit()
    first = snapshots.create_snapshot(source,folder/'snapshot1/analysis.sqlite',cache_directory=folder/'sqlite-cache')
    second = snapshots.create_snapshot(source,folder/'snapshot2/analysis.sqlite',cache_directory=folder/'sqlite-cache')
    assert first['sha256'] == second['sha256']
    assert 'reused_from' in json.loads(Path(second['proof']).read_bytes())
    with closing(sqlite3.connect(source)) as connection:
        connection.execute("UPDATE names SET name='updated' WHERE id=1")
        connection.commit()
    third = snapshots.create_snapshot(source,folder/'snapshot3/analysis.sqlite',cache_directory=folder/'sqlite-cache')
    assert third['sha256'] != first['sha256']
    assert snapshots.verify_binding(third)
    if os.name == 'nt':
        path = Path(third['path'])
        os.chmod(path,0o666)
        try:
            with path.open('r+b'):
                raise AssertionError('Frozen snapshot accepted a concurrent writer')
        except PermissionError:
            pass
    snapshots.close_snapshot_locks()
    path = Path(third['path'])
    os.chmod(path,0o666)
    with path.open('r+b') as stream:
        stream.seek(500)
        stream.write(b'changed')
    try:
        snapshots.verify_binding(third)
        raise AssertionError('Changed snapshot was accepted')
    except ValueError:
        pass


def main():
    before = dict(os.environ)
    folder = Path(tempfile.mkdtemp(prefix='dw-build-cache-',dir=ROOT/'data/build-performance'))
    try:
        database = folder/'analysis.sqlite'
        database.write_bytes(b'fixture')
        database.with_name('analysis-snapshot.json').write_text(json.dumps(dict(sha256='sqlite')))
        os.environ['REPLAY_SQLITE'] = str(database)
        objects(folder)
        layout_lookups()
        bootstrap(folder)
        native_text(folder)
        dependencies(folder)
        preparation_metadata(folder)
        validation_dependencies(folder)
        sqlite_snapshots(folder)
        raw = b'inline const uint8_t Bytes[] = {\n1,2,3,\n};\n'
        masked, arrays = cache.declaration_header(raw)
        assert b'Bytes[3]' in masked and arrays == [dict(name='Bytes',bytes=3)]
        try:
            cache.declaration_header(raw.replace(b'1,2,3,',b'function(),'))
            raise AssertionError('Nonliteral initializer was accepted')
        except ValueError:
            pass
        print('PASS object reuse across jobs, exact header/option/corruption invalidation, native-byte reuse, transitive check ownership, SQLite reuse/commit/write-lock/corruption checks')
    finally:
        snapshots.close_snapshot_locks()
        os.environ.clear()
        os.environ.update(before)
        for path in folder.rglob('*'):
            if path.is_file():
                os.chmod(path,0o666)
        shutil.rmtree(folder)


if __name__ == '__main__':
    main()
