"""Historical shipping helper catch-up using signed fixtures and harmless EXEs.

No game, production key, public host or installed game folder is used. The old
helper implementations come from retained private build snapshots; only their
public trust key is replaced with a fresh test key. Real Windows wait/replace/
relaunch then exercises the new embedded helper and asset-only repair.
"""

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import http.server
import importlib.util
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import threading
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


ROOT = Path(__file__).resolve().parents[1]
FLAGS = subprocess.CREATE_NO_WINDOW
# The original jobs/ snapshots were pruned; data/dw-client/historical-helpers/
# reconstruct.py rebuilds both projects from git (see its docstring).
HISTORICAL = {
    "pre-assets": ROOT / "data/dw-client/historical-helpers/pre-assets",
    "release29": ROOT / "data/dw-client/historical-helpers/release29",
}


def sha(data):
    return hashlib.sha256(data).digest()


def command(argv, timeout=180):
    result = subprocess.run([str(x) for x in argv], capture_output=True, text=True,
                            creationflags=FLAGS, timeout=timeout)
    assert result.returncode == 0, (argv, result.returncode, result.stdout, result.stderr)
    return result


def trust(path, public_blob):
    text = path.read_text()
    text, count = re.subn(r"(s_dwLocalPlatformPublicKey\[\]\s*=\s*\{).*?(\};)",
                        lambda m: m[1] + ",".join(f"0x{x:02x}" for x in public_blob) + m[2], text, flags=re.S)
    assert count == 1
    path.write_text(text)


def cmake(project, build):
    command(["cmake", "-S", project, "-B", build, "-G", "Visual Studio 18 2026", "-A", "x64"])
    command(["cmake", "--build", build, "--config", "Release", "--parallel", "2"])


def byte_header(path, symbol, value):
    path.write_text("#pragma once\ninline const unsigned char " + symbol + "[] = {\n" +
                    "\n".join(",".join(f"0x{x:02x}" for x in value[at:at + 32]) + ","
                              for at in range(0, len(value), 32)) + "\n};\n")


def compressed(data):
    cabinet = ctypes.WinDLL("cabinet", use_last_error=True)
    cabinet.CreateCompressor.argtypes = [wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    cabinet.Compress.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                               ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    cabinet.CloseCompressor.argtypes = [ctypes.c_void_p]
    handle = ctypes.c_void_p()
    assert cabinet.CreateCompressor(4, None, ctypes.byref(handle))
    try:
        source = ctypes.create_string_buffer(data)
        count = ctypes.c_size_t()
        assert not cabinet.Compress(handle, source, len(data), None, 0, ctypes.byref(count))
        assert ctypes.get_last_error() == 122 and count.value
        target = ctypes.create_string_buffer(count.value)
        assert cabinet.Compress(handle, source, len(data), target, len(target), ctypes.byref(count))
        return target.raw[:count.value]
    finally:
        assert cabinet.CloseCompressor(handle)


def map_fixture():
    files, chunks, payloads, installed = bytearray(), bytearray(), {}, {}
    names = ["mp_fixture.ff", "srv_mp_fixture.ff", "eng_mp_fixture.ff",
             "ww_mp_fixture.ff", "techsets_mp_fixture.ff", "map.json"]
    total = 0
    for index, name in enumerate(sorted(names)):
        relative = "mods/mw120r/maps/mp_fixture/" + name
        data = (b"synthetic native map fixture " + bytes([index])) * (512 + index)
        packed = compressed(data)
        files += struct.pack("<128s32sQII", relative.encode(), sha(data), len(data), index, 1)
        chunks += struct.pack("<32s32sII", sha(data), sha(packed), len(data), len(packed))
        payloads[sha(packed).hex()] = packed
        installed[relative] = data
        total += len(data)
    package = sha(files)
    manifest = struct.pack("<16sIIIIQ32s32s", b"REPLAYDWMAP01\0\0\0", 1,
                           104 + len(files) + len(chunks), 6, 6, total,
                           sha(package + files + chunks), package) + files + chunks
    return manifest, payloads, installed


def owned_fixture(folder_rules):
    """Metadata-only v1 catch-up plus v2 bot/inspection resources; no real FF."""
    from dw_update_assets import encode, encode_groups, native_folder_policy, OWNERS
    directories = {rule['name_prefix']: rule['directory'] for rule in folder_rules}
    assert '' in directories and 'eng_' in directories
    groups, payloads, installed, owners = [], {}, {}, {}
    for owner in (1, 2):
        resources = [f'harmless owned fixture group {owner} resource {index}\n'.encode() for index in range(4)]
        bundle = sha(b''.join(resources)).hex()
        zone = OWNERS[owner] + bundle[:16]
        entries, policy_entries = [], []
        for prefix, first in (('', 0), ('eng_', 2)):
            for offset, suffix in enumerate(('.ff', '.fp')):
                data = resources[first + offset]
                digest, name = sha(data).hex(), prefix + zone + suffix
                relative = (directories[prefix] + '/' if directories[prefix] else '') + name
                entries.append(dict(name=name, sha256=digest, size=len(data)))
                policy_entries.append(dict(name=name, relative_path=relative))
                payloads[digest] = data
                installed['zone/' + relative] = data
                owners['zone/' + relative] = owner
        native_folder_policy(dict(native_folder_rules=folder_rules, installation_manifest=policy_entries), owner)
        groups.append(dict(owner=owner, entries=sorted(entries, key=lambda item: item['name']), bundle_sha256=bundle))
    legacy = encode(groups[0]['entries'], groups[0]['bundle_sha256'])
    aggregate = encode_groups(groups)
    return legacy + aggregate, payloads, installed, owners, groups


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, help="Canonical build directory or build-report.json")
    parser.add_argument("--source-root", type=Path, help="Prepared native source headers; derived from --build when omitted")
    parser.add_argument("--pre-assets-source", type=Path, default=HISTORICAL["pre-assets"], help="Retained pre-assets helper-source project")
    parser.add_argument("--release29-source", type=Path, default=HISTORICAL["release29"], help="Retained release29 helper-source project")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build_proof = None
    if args.build:
        report_path = args.build / "build-report.json" if args.build.is_dir() else args.build
        report = json.loads(report_path.read_bytes())
        image = Path(report["executable"])
        if not image.is_absolute():
            image = report_path.parent / image
        with image.open("rb") as stream:
            assert hashlib.file_digest(stream,"sha256").hexdigest() == report["sha256"]
        assert report["unresolved_symbols"] == 0
        source = Path(report["source_root"])
        if args.source_root is None:
            args.source_root = source / "src"
        frozen_helper = source / "generated-updater/helper-source/tools"
        for name in ("replay-update-client.cpp","replay-update-assets.h","replay-update-maps.h"):
            assert sha((frozen_helper/name).read_bytes()) == sha((ROOT/"tools"/name).read_bytes()), ("Helper source differs from compiled client",name)
        build_proof = {"image_sha256":report["sha256"],"build_report_sha256":sha(report_path.read_bytes()).hex(),
                       "frozen_helper_sources_match":True}
    if args.source_root is None:
        parser.error("Pass --build or --source-root")
    historical_sources = {"pre-assets":args.pre_assets_source,"release29":args.release29_source}
    checks, old_proofs = [], []
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = key.public_key().public_numbers()
    public_blob = struct.pack("<6I", 0x31415352, 2048, 3, 256, 0, 0) + public.e.to_bytes(3, "big") + public.n.to_bytes(256, "big")
    with tempfile.TemporaryDirectory(prefix="historical-update-", dir=ROOT / "data") as temporary:
        root = Path(temporary)
        map_manifest, map_payloads, map_files = map_fixture()
        frozen = root / "current-src"
        frozen.mkdir()
        for name in ("dw_local_trust.h", "dw_update_protocol.h", "dw_update_assets_protocol.h",
                     "DW_UpdateAssetManifest.h", "DW_UpdateAssetPaths.h", "dw_update_maps_protocol.h"):
            source = args.source_root / name
            if name == "dw_update_maps_protocol.h" and not source.exists():
                source = ROOT / "integration/replay" / name
            shutil.copyfile(source, frozen / name)
        trust(frozen / "dw_local_trust.h", public_blob)
        # Freeze both versions in the same referenced array. Historical helpers
        # see one bot-only v1 record; the new helper must validate the aggregate
        # and download the separately owned inspection group as well.
        from dw_update_assets import extract, decode_groups, folder_header
        metadata = json.loads((args.source_root.parent / 'generated/update-assets.json').read_bytes())
        assert (frozen / 'DW_UpdateAssetPaths.h').read_bytes() == folder_header(metadata['native_folder_rules'])
        owned_manifest, owned_payloads, owned_files, owned_owners, owned_groups = owned_fixture(metadata['native_folder_rules'])
        assert decode_groups(extract(owned_manifest)) == owned_groups
        byte_header(frozen / 'DW_UpdateAssetManifest.h', 's_dwUpdateAssetManifest', owned_manifest)
        byte_header(frozen / "DW_UpdateMapManifest.h", "s_dwUpdateMapManifest", map_manifest)
        spec = importlib.util.spec_from_file_location("fixture_embed", ROOT / "tools/embed-update-helper.py")
        embed = importlib.util.module_from_spec(spec); spec.loader.exec_module(embed)
        current_helper = embed.build(frozen, root / "current/DW_UpdateHelper.h")
        historical = {}
        for version, original in historical_sources.items():
            project = root / version / "project"
            shutil.copytree(original, project)
            source = project / "tools/replay-update-client.cpp"
            before = hashlib.sha256(source.read_bytes()).hexdigest()
            assert ("update_assets" not in source.read_text()) == (version == "pre-assets")
            trust(project / "integration/replay/dw_local_trust.h", public_blob)
            build = root / version / "build"
            cmake(project, build)
            assert hashlib.sha256(source.read_bytes()).hexdigest() == before
            historical[version] = build / "Release/replay-update-client.exe"
            old_proofs.append({"version": version, "retained_source": str(original), "source_sha256": before,
                               "fixture_helper_sha256": hashlib.sha256(historical[version].read_bytes()).hexdigest(),
                               "public_trust_replaced_only": True})
        # The launcher contains the actual new helper. Its first relaunch runs
        # the helper extracted from this new image, as the native worker does.
        launcher = root / "launcher"
        launcher.mkdir()
        byte_header(launcher / "helper.h", "fixtureHelper", current_helper.read_bytes())
        (launcher / "main.cpp").write_text(r'''
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <string>
#if LATEST
#include "helper.h"
#endif
int wmain() {
    namespace fs=std::filesystem;
    if(fs::exists("hold")) {
        std::ofstream("parent-ready") << GetCurrentProcessId();
        for(unsigned i=0;i<3000&&!fs::exists("exit");++i) Sleep(20);
        return 0;
    }
#if LATEST
    wchar_t file[1024]{}; if(!GetModuleFileNameW(nullptr,file,1024)) return 91;
    const fs::path exe=file, helper=exe.wstring()+L".updater.exe";
    std::ofstream out(helper,std::ios::binary|std::ios::trunc);
    out.write(reinterpret_cast<const char*>(fixtureHelper),sizeof(fixtureHelper));out.close();
    std::wstring cmd=L"\""+helper.wstring()+L"\" "+(fs::exists("bypass")?L"--prepare-assets":L"--prepare")+
                     L" \""+exe.wstring()+L"\" 127.0.0.1";
    STARTUPINFOW startup{sizeof(startup)};PROCESS_INFORMATION process{};
    if(!CreateProcessW(helper.c_str(),cmd.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&startup,&process)) return 92;
    CloseHandle(process.hThread);if(WaitForSingleObject(process.hProcess,90000)!=WAIT_OBJECT_0)return 93;
    DWORD code=0;GetExitCodeProcess(process.hProcess,&code);CloseHandle(process.hProcess);
    std::ofstream("new-launch-result")<<code;
#endif
    return 0;
}
''')
        (launcher / "CMakeLists.txt").write_text("""cmake_minimum_required(VERSION 3.24)
project(catchup_fixture LANGUAGES CXX)
add_executable(old main.cpp)
add_executable(latest main.cpp)
target_compile_features(old PRIVATE cxx_std_20)
target_compile_features(latest PRIVATE cxx_std_20)
target_compile_definitions(old PRIVATE LATEST=0)
target_compile_definitions(latest PRIVATE LATEST=1)
""")
        cmake(launcher, root / "launcher-build")
        latest = (root / "launcher-build/Release/latest.exe").read_bytes()
        original_latest = latest
        assert latest.count(owned_manifest) == 1, 'Signed harmless image lost its combined legacy/aggregate record'
        inspection_digests = {item['sha256'] for item in owned_groups[1]['entries']}
        requests, nonces = [], set()
        corrupt = False
        corrupt_inspection = False
        short_plan = False
        class Server(http.server.BaseHTTPRequestHandler):
            def log_message(self, *unused): pass
            def send(self, data):
                self.send_response(200);self.send_header("Content-Length", str(len(data)))
                self.end_headers();self.wfile.write(data)
            def do_POST(self):
                request=self.rfile.read(int(self.headers["Content-Length"]))
                magic,version,reserved,nonce,base=struct.unpack("<QII32s32s",request)
                assert self.path=="/updates/v2/check" and version==2 and not reserved and nonce not in nonces
                nonces.add(nonce);now=int(time.time());current=base==sha(latest)
                plan=struct.pack("<QIIQQ32s32s32s32sQQQQ",magic,2,0 if current else 1,now,
                    now+(1 if short_plan else 300),nonce,base,sha(latest),bytes(32) if current else sha(latest),
                    0,len(latest),0 if current else len(latest),30)
                signature=key.sign(plan,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=32),hashes.SHA256())
                requests.append(("check",current));self.send(plan+signature)
            def do_GET(self):
                if self.path=="/updates/v2/image/"+sha(latest).hex():
                    requests.append(("image",));self.send(latest);return
                prefix="/updates/v2/asset/"
                assert self.path.startswith(prefix)
                digest=self.path[len(prefix):]
                data=(map_payloads|owned_payloads)[digest]
                requests.append(("map" if digest in map_payloads else "inspect" if digest in inspection_digests else "bot",digest))
                bad = (corrupt and digest in map_payloads) or (corrupt_inspection and digest in inspection_digests)
                self.send(bytes([data[0]^1])+data[1:] if bad else data)
        server=http.server.ThreadingHTTPServer(("127.0.0.1",8085),Server)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        kernel=ctypes.WinDLL("kernel32",use_last_error=True)
        kernel.CreateEventW.argtypes=[ctypes.c_void_p,wintypes.BOOL,wintypes.BOOL,wintypes.LPCWSTR]
        kernel.CreateEventW.restype=wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes=[wintypes.HANDLE,wintypes.DWORD]
        kernel.CloseHandle.argtypes=[wintypes.HANDLE]

        def prepare(helper,game,expected,mode="--prepare"):
            result=subprocess.run([str(helper),mode,str(game),"127.0.0.1"],capture_output=True,
                                  creationflags=FLAGS,timeout=90)
            log=Path(str(game)+".update/result.log")
            assert result.returncode==expected,(mode,result.returncode,log.read_text() if log.exists() else "no log")

        def handoff(helper,game,mode="--apply",expected_apply=0):
            directory=game.parent
            (directory/"hold").touch()
            for name in ("exit","parent-ready","new-launch-result"):
                (directory/name).unlink(missing_ok=True)
            parent=subprocess.Popen([str(game)],cwd=directory,creationflags=FLAGS)
            event_name=f"Local\\CatchupFixture-{parent.pid}"
            event=kernel.CreateEventW(None,True,False,event_name);assert event
            apply=None
            try:
                apply=subprocess.Popen([str(helper),mode,str(game),str(parent.pid),event_name],creationflags=FLAGS)
                assert kernel.WaitForSingleObject(event,30000)==0
                assert parent.poll() is None and apply.poll() is None
                (directory/"hold").unlink();(directory/"exit").touch()
                assert parent.wait(timeout=10)==0 and apply.wait(timeout=45)==expected_apply
                if expected_apply:
                    return expected_apply # Failure must roll back without relaunch.
                for _ in range(600):
                    marker=directory/"new-launch-result"
                    if marker.exists():return int(marker.read_text())
                    time.sleep(0.05)
                raise AssertionError("Fixture relaunch did not run its embedded helper")
            finally:
                kernel.CloseHandle(event)
                for process in (parent,apply):
                    if process and process.poll() is None:
                        process.terminate();process.wait(timeout=10)

        try:
            for version,old_helper in historical.items():
                folder=root/("install-"+version);folder.mkdir();game=folder/"game.exe"
                shutil.copyfile(root/"launcher-build/Release/old.exe",game)
                old_hash=sha(game.read_bytes());before=len(requests)
                prepare(old_helper,game,20)
                assert not any(x[0]=="map" for x in requests[before:])
                assert not any(x[0]=="inspect" for x in requests[before:])
                first_launch = handoff(old_helper,game)
                assert first_launch == 20, (version, first_launch, Path(str(game)+".update/result.log").read_text(), requests[before:])
                assert game.read_bytes()==latest
                assert Path(str(game)+".updater.exe").read_bytes()==current_helper.read_bytes()
                assert not (folder/"mods").exists()
                assert any(x[0]=="map" for x in requests[before:])
                assert any(x[0]=="inspect" for x in requests[before:])
                assert (Path(str(game)+".update")/(old_hash.hex()+".backup.exe")).exists()
                assert handoff(current_helper,game)==10
                for relative,data in map_files.items():assert (folder/relative).read_bytes()==data
                for relative,data in owned_files.items():assert (folder/relative).read_bytes()==data
                before=len(requests);prepare(current_helper,game,10)
                assert requests[before:]==[("check",True)]
                checks.append(version+": real historical helper installs new EXE; first new launch stages maps using new embedded helper; asset-only apply then stays current")
                checks.append(version+": old helper ignores v2 inspection; new embedded helper downloads and installs both hash-bound owned groups")
            folder=root/"current-repair";folder.mkdir();game=folder/"game.exe";game.write_bytes(latest)
            for relative,data in map_files.items():
                p=folder/relative;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
            for relative,data in owned_files.items():
                p=folder/relative;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
            inspection_files = [name for name in owned_files if owned_owners[name] == 2]
            inspect_missing, inspect_corrupt = inspection_files[:2]
            (folder/inspect_missing).unlink()
            original_inspect = b'modified original inspection fixture\n'
            (folder/inspect_corrupt).write_bytes(original_inspect)
            first,second=list(map_files)[:2]
            (folder/first).unlink();data=map_files[second];(folder/second).write_bytes(bytes([data[0]^1])+data[1:])
            prepare(current_helper,game,20,"--prepare-assets")
            assert handoff(current_helper,game,"--apply-assets")==10 and game.read_bytes()==latest
            for relative,data in map_files.items():assert (folder/relative).read_bytes()==data
            for relative,data in owned_files.items():assert (folder/relative).read_bytes()==data
            backup_root=Path(str(game)+'.update')/'asset-backups'/sha(latest).hex()
            assert any(path.read_bytes()==original_inspect for path in backup_root.glob('*.bak'))
            journal=(backup_root/'recovery.tsv').read_text()
            assert inspect_corrupt in journal and sha(original_inspect).hex() in journal
            checks.append("Current EXE repairs missing and same-length corrupt map files without replacing its image")
            checks.append('New aggregate helper repairs missing/modified inspection FF/FP, preserves modified originals and a verified recovery journal')
            # Fail after replacing a bot file, while installing a later inspect
            # entry. The shared native transaction must restore that bot file.
            folder=root/'owned-rollback';folder.mkdir();game=folder/'game.exe';game.write_bytes(latest)
            for relative,data in (map_files|owned_files).items():
                p=folder/relative;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
            bot_file=next(name for name in owned_files if owned_owners[name]==1)
            original_bot=b'original bot fixture before failed aggregate install\n'
            (folder/bot_file).write_bytes(original_bot)
            blocked_inspect=inspection_files[-1]
            (folder/blocked_inspect).unlink();(folder/blocked_inspect).mkdir()
            prepare(current_helper,game,20,'--prepare-assets')
            assert handoff(current_helper,game,'--apply-assets',expected_apply=40)==40
            assert game.read_bytes()==latest and (folder/bot_file).read_bytes()==original_bot
            assert (folder/blocked_inspect).is_dir() and not (folder/'new-launch-result').exists()
            for relative,data in (map_files|owned_files).items():
                if relative not in (bot_file,blocked_inspect):assert (folder/relative).read_bytes()==data
            backup_root=Path(str(game)+'.update')/'asset-backups'/sha(latest).hex()
            assert any(path.read_bytes()==original_bot for path in backup_root.glob('*.bak'))
            assert bot_file in (backup_root/'recovery.tsv').read_text()
            checks.append('Inspection destination failure rolls back earlier bot replacement, retains original backup/journal and never relaunches')
            folder=root/"bypass";folder.mkdir();game=folder/"game.exe";game.write_bytes(latest+b"custom fixture edit")
            (folder/"bypass").touch();custom=game.read_bytes()
            prepare(current_helper,game,20,"--prepare-assets")
            assert handoff(current_helper,game,"--apply-assets")==10 and game.read_bytes()==custom
            checks.append("Bypassed custom EXE with matching authenticated own inventory repairs assets and never replaces EXE")
            # An official signed target with a different valid map declaration
            # must not update the bypassed client's own inventory.
            changed=bytearray(map_manifest);changed[-72:-40]=sha(b"different chunk")
            package=changed[72:104];changed[40:72]=sha(package+changed[104:])
            assert original_latest.count(map_manifest)==1
            latest=original_latest.replace(map_manifest,changed)
            before=game.read_bytes();prepare(current_helper,game,40,"--prepare-assets")
            assert game.read_bytes()==before
            latest=original_latest
            checks.append("Signed latest target with mismatching frozen inventory is rejected under bypass")
            folder=root/"corrupt";folder.mkdir();game=folder/"game.exe";game.write_bytes(latest)
            corrupt=True;prepare(current_helper,game,40);corrupt=False
            assert not (folder/"mods").exists() and game.read_bytes()==latest
            checks.append("Corrupt compressed payload is rejected before asset or EXE installation")
            folder=root/'corrupt-inspection';folder.mkdir();game=folder/'game.exe';game.write_bytes(latest)
            for relative,data in (map_files|owned_files).items():
                if owned_owners.get(relative)==2:continue
                p=folder/relative;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
            before=len(requests);corrupt_inspection=True
            try:prepare(current_helper,game,40,'--prepare-assets')
            finally:corrupt_inspection=False
            assert any(item[0]=='inspect' for item in requests[before:]) and game.read_bytes()==latest
            assert all(not (folder/relative).exists() for relative in inspection_files)
            assert not (Path(str(game)+'.update')/'asset-backups').exists()
            checks.append('Corrupt v2 inspection payload is rejected before replacement or backup of installed assets')
            folder=root/"expired";folder.mkdir();game=folder/"game.exe";game.write_bytes(latest)
            short_plan=True;prepare(current_helper,game,20,"--prepare-assets");short_plan=False
            time.sleep(2);before=len(requests)
            assert handoff(current_helper,game,"--apply-assets")==10
            assert any(x[0]=="check" for x in requests[before:])
            checks.append("Expired staged plan is refreshed with a fresh signed nonce before clean asset-only apply")
        finally:
            server.shutdown();server.server_close();thread.join(timeout=5)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps({"passed":True,"checks":checks,"historical_helpers":old_proofs,
        "build_proof":build_proof,
        "owned_fixture_versions":[1,2],"owned_fixture_groups":[1,2],
        "owned_fixture_manifest_sha256":sha(owned_manifest).hex(),
        "fixture_only":True,"fixture_key_only":True,"game_executed":False,"public_host_used":False,
        "installed_game_modified":False,"private_fixture_removed":True},indent=2)+"\n")
    print("PASS",len(checks),"historical helper/new-launch asset catch-up cases")


if __name__=="__main__":main()
