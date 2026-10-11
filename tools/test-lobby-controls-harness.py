"""Compile and exercise native lobby controls at modeled engine boundaries."""

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
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = ROOT / "tools/lobby_controls_harness.cpp"
    integration = ROOT / "integration/replay/DW_LobbyControls.cpp"
    with tempfile.TemporaryDirectory(prefix="lobby-controls-", dir=ROOT / "build") as temporary:
        directory = Path(temporary).resolve()
        assert directory.is_relative_to((ROOT / "build").resolve())
        obj, image = directory / "controls.obj", directory / "controls.dll"
        subprocess.run(
            [
                str(LLVM / "clang++.exe"),
                "--target=x86_64-pc-windows-msvc",
                "-c",
                str(source),
                "-o",
                str(obj),
                "-std=c++20",
                "-O2",
                "-ffreestanding",
                "-fno-exceptions",
                "-fno-rtti",
                "-ffunction-sections",
                "-fdata-sections",
                "-fno-stack-protector",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I" + str(Path(r"E:\replay-compiler\src")),
            ],
            check=True,
        )
        subprocess.run(
            [
                str(LLVM / "lld-link.exe"),
                "/dll",
                "/noentry",
                "/nodefaultlib",
                "/opt:ref",
                "/out:" + str(image),
                str(obj),
            ],
            check=True,
        )
        library = ctypes.CDLL(str(image))
        try:
            result = library.Test_Run()
            assert result == 0, f"Lobby controls failed at harness line {result}"
        finally:
            ctypes.windll.kernel32.FreeLibrary.argtypes = [ctypes.c_void_p]
            ctypes.windll.kernel32.FreeLibrary(library._handle)
    proof = dict(
        passed=True,
        modeled_engine_boundaries=True,
        native_game_verified=False,
        checks=[
            "count parsing",
            "host/frontend/public/online gates",
            "queued additions",
            "existing pool additions",
            "capacity clamp",
            "MP team balance",
            "BR team restoration and No Fill preparation",
            "one-shot application",
            "new lobby reset",
            "invalid team counts before pool mutation",
            "BOOL global toggle and playlist frame callback",
            "30 second delay and 15 second gradual host-document fill",
            "exact request-token acknowledgement and timer-skew clamps",
            "native readiness side effects retained while final start body is gated",
            "no early start before actual native slot presence and completion acknowledgement",
            "human joins invalidate completion and native migration restarts the arm",
            "BR152 capacity with authoritative No Fill eligible target",
            "disable clears automatic native pool and restores normal launch",
        ],
        source_sha256={
            str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (source, integration)
        },
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(proof, indent=2) + "\n")
    print("PASS: fill_lobby policy harness; no game launched")


if __name__ == "__main__":
    main()
