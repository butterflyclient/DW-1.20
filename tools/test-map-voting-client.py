"""Bind the map-voting native component and original Lua UI tests to a client build."""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = Path("E:/IW8/Builds/1.20-replay/game_dx12_ship_replay.exe")
IMAGE_SHA = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
NATIVE = {
    0x01191980: "Party_SetupVoteEntries",
    0x0118FDC0: "native local vote setter",
    0x0118CF60: "Party_GetXuid",
    0x010D23E0: "Playlist_RunRules",
    0x01B9D510: "native map vote display name",
    0x0118E960: "Party_IsPrivateParty",
    0x0118C2F0: "native party human vote tally",
    0x01198CF0: "native final vote selection",
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.snapshot.resolve(strict=True) / "src" if args.snapshot else ROOT / "integration/replay"
    header = source / "DW_MapVoting.h"
    controls = source / "DW_LobbyControls.cpp"
    linked = None
    if args.build:
        assert args.snapshot, "A linked gate requires the frozen source snapshot"
        report_path = args.build / "build-report.json" if args.build.is_dir() else args.build
        report = json.loads(report_path.read_bytes())
        image = Path(report["executable"])
        if not image.is_absolute(): image = report_path.parent / image
        assert sha(image) == report["sha256"] and report["unresolved_symbols"] == 0
        for symbol in ("DW_LobbyControls_Frame", "DW_LobbyControls_HostDocument", "DW_MapVoting_UIState"):
            assert report["symbols"][symbol] > 0
        rows = [row for row in report["cpp"] if Path(row["source"]).name == controls.name]
        assert len(rows) == 1
        row = rows[0]
        assert row["source_sha256"] == sha(controls)
        assert sha(Path(row["object"])) == row["object_sha256"]
        assert sha(Path(row["compiler"]["path"])) == row["compiler"]["sha256"]
        dependencies = {Path(item["path"]).name: item["sha256"] for item in row["dependencies"]}
        assert dependencies[header.name] == sha(header), "Client did not compile this exact ballot bridge"
        linked = dict(image_sha256=report["sha256"], object_sha256=row["object_sha256"],
                      source_sha256=sha(controls), dependency_sha256=sha(header))
    text = controls.read_text()
    assert text.count("dwMapVoting::Pending(") >= 3
    assert "dwMapVoting::Suspend();" in text
    assert text.index("dwMapVoting::Frame(party);") < text.index("DW_PlaylistUI_Frame();", text.index("dwMapVoting::Frame(party);"))
    assert sha(ORIGINAL) == IMAGE_SHA
    image = ORIGINAL.read_bytes()
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    sections, optional = struct.unpack_from("<H", image, pe + 6)[0], struct.unpack_from("<H", image, pe + 20)[0]
    table = pe + 24 + optional
    section_rows = [struct.unpack_from("<8sIIII", image, table + 40 * index) for index in range(sections)]
    proof = []
    with sqlite3.connect(ORIGINAL.with_suffix(".exe.sqlite").as_uri() + "?mode=ro", uri=True) as database:
        for rva, purpose in NATIVE.items():
            row = database.execute("select id,name,size,assembly,assembly_addrs,bytes_hash from functions where address=?",
                                   (str(0x140000000 + rva),)).fetchone()
            assert row, hex(rva)
            section = next(item for item in section_rows if item[2] <= rva < item[2] + max(item[1], item[3]))
            offset = section[4] + rva - section[2]
            body = image[offset:offset + row[2]]
            proof.append(dict(rva=hex(rva), purpose=purpose, database_id=row[0], name=row[1],
                              recovered_size=row[2], original_contiguous_bytes_sha256=hashlib.sha256(body).hexdigest(),
                              recovered_assembly_sha256=hashlib.sha256(row[3].encode()).hexdigest(),
                              recovered_instruction_rvas=json.loads(row[4]), export_bytes_md5=row[5]))
    compiler = Path("C:/Program Files/LLVM/bin/clang++.exe")
    with tempfile.TemporaryDirectory(prefix="map-voting-component-", dir=ROOT / "data") as temporary:
        directory = Path(temporary)
        dll = directory / "component.dll"
        command = [str(compiler), "--target=x86_64-pc-windows-msvc", str(ROOT / "tools/map_vote_harness.cpp"),
                   "-std=c++20", "-ffreestanding", "-fno-exceptions", "-fno-rtti", "-Wall", "-Wextra", "-Werror",
                   "-IE:/replay-compiler/src", '-DMAP_VOTE_HEADER="' + header.as_posix() + '"',
                   "-shared", "-fuse-ld=lld", "-Wl,/noentry,/nodefaultlib,/opt:ref", "-o", str(dll)]
        subprocess.run(command, check=True, capture_output=True, text=True)
        component = ctypes.WinDLL(str(dll))
        result = component.Test_Run()
        assert result == 0, f"Actual bridge failed native component assertion at harness line {result}"
        component.Test_Document.restype = ctypes.c_char_p
        document = json.loads(component.Test_Document())
        assert document["dw_map_vote"]["votes"] == {"1": 2, "2": 3}
        assert component.Test_LargeSnapshot() == 0, "A valid >8KB native host document lost the ballot handshake"
        component_hash = sha(dll)
        ctypes.windll.kernel32.FreeLibrary(ctypes.c_void_p(component._handle))
        ui_path = directory / "ui.json"
        ui_command = [sys.executable, str(ROOT / "tools/test-playlist-ui.py"), "--output", str(ui_path)]
        if args.snapshot: ui_command += ["--snapshot", str(args.snapshot)]
        if args.build: ui_command += ["--build", str(args.build)]
        subprocess.run(ui_command, check=True)
        ui = json.loads(ui_path.read_bytes())
    receipt = dict(passed=True, linked_build=linked, original_image_sha256=IMAGE_SHA,
                   native_function_provenance=proof, bridge_sha256=sha(header), controls_sha256=sha(controls),
                   harness_sha256=sha(ROOT / "tools/map_vote_harness.cpp"), compiler_sha256=sha(compiler),
                   component_sha256=component_hash, native_host_document=document, lua_ui=ui,
                   checks=["initial launch waits for exact lobby publication", "stale completed ballot cannot launch another lobby",
                           "stale button selection is retired on allocation change", "human primary native tally excludes bots and guest slots",
                           "host migration reapplies the frozen native winner", "frontend exit fences the same allocation until a newer round",
                           "private parties retain native behavior", "original UIButton focusability retires hidden/completed choices"],
                   modeled_boundaries="Native memory, dvar, engine calls and rendering; actual authored C++ bridge and Lua execute",
                   game_runs_performed=False, rendered_ui_verified=False)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + "\n")
    print("PASS: map voting native component, original UI focus contract and exact linked-source provenance")


if __name__ == "__main__":
    main()
