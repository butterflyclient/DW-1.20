"""Compile actual native bot roster growth policy against disposable engine boundaries."""

import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LLVM = Path(r"C:\Program Files\LLVM\bin")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--header-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = ROOT / "tools/bot_roster_growth_harness.cpp"
    with tempfile.TemporaryDirectory(prefix="bot-growth-", dir=ROOT / "build") as temporary:
        directory = Path(temporary)
        obj, image = directory / "growth.obj", directory / "growth.dll"
        subprocess.run([str(LLVM / "clang++.exe"), "--target=x86_64-pc-windows-msvc", "-c",
                        str(source), "-o", str(obj), "-std=c++20", "-O2", "-ffreestanding",
                        "-fno-exceptions", "-fno-rtti", "-ffunction-sections", "-fdata-sections",
                        "-fno-stack-protector", "-Wall", "-Wextra", "-Werror",
                        "-IE:/replay-compiler/src", "-I" + str(args.header_dir.resolve())], check=True)
        subprocess.run([str(LLVM / "lld-link.exe"), "/dll", "/noentry", "/nodefaultlib",
                        "/opt:ref", "/out:" + str(image), str(obj)], check=True)
        library = ctypes.CDLL(str(image))
        try:
            result = library.Test_Run()
            assert result == 0, f"Roster growth failed at harness line {result}"
        finally:
            ctypes.windll.kernel32.FreeLibrary.argtypes = [ctypes.c_void_p]
            ctypes.windll.kernel32.FreeLibrary(library._handle)
    inputs = [source, ROOT / "integration/replay/DW_BotRoster.cpp",
              ROOT / "integration/replay/DW_BotNames.h", args.header_dir / "DW_BotBindings.h"]
    args.output.write_text(json.dumps(dict(passed=True, game_launched=False,
        modeled_engine_boundaries=True, preserved_record_size=88,
        checks=["growth preserves earlier full records and slots", "reduction retains lower ordinals",
                "human collision moves only collided bot", "199 unique names preserve native200 capacity",
                "name collision retains appearance", "new lobby resets old roster cache"],
        inputs={str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}), indent=2) + "\n")
    print("PASS: native 88-byte roster growth, collision and 199-name component checks")

if __name__ == "__main__":
    main()
