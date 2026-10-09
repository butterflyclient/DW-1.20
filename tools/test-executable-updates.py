"""Actual Windows updater, signed backend and four compiled release fixtures.

These are small test executables, not native game validation. Includes an actual
wait/replace/relaunch cycle and full-image updates across missed releases.
"""

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import urllib.request
import http.server
import struct
import threading

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "publisher", ROOT / "tools/publish-full-executable.py"
)
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
FLAGS = subprocess.CREATE_NO_WINDOW


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    folder = ROOT / "data" / ("executable-update-fixture-" + str(time.time_ns()))
    data, source = folder / "data", folder / "source"
    data.mkdir(parents=True)
    source.mkdir()
    for name in (
        "platform-private.blob",
        "platform-public.blob",
        "replay-traffic-kdf.bin",
    ):
        shutil.copyfile(ROOT / "data" / name, data / name)
    source.joinpath("main.cpp").write_text(
        r"""
#include <windows.h>
#include <fstream>
int main() {
    std::ofstream("fixture-launched.txt") << VERSION;
    if (VERSION != 4) Sleep(180000);
    return 0;
}
"""
    )
    cmake = [
        "cmake_minimum_required(VERSION 3.24)",
        "project(update_fixture LANGUAGES CXX)",
    ]
    for version in range(1, 5):
        cmake += [
            f"add_executable(release{version} main.cpp)",
            f"target_compile_definitions(release{version} PRIVATE VERSION={version})",
        ]
    source.joinpath("CMakeLists.txt").write_text("\n".join(cmake) + "\n")
    for command in (
        [
            "cmake",
            "-S",
            str(source),
            "-B",
            str(folder / "build"),
            "-G",
            "Visual Studio 18 2026",
            "-A",
            "x64",
        ],
        [
            "cmake",
            "--build",
            str(folder / "build"),
            "--config",
            "Release",
            "--parallel",
            "2",
        ],
    ):
        subprocess.run(
            command, check=True, stdout=subprocess.DEVNULL, creationflags=FLAGS
        )
    images = []
    for version in range(1, 5):
        image = folder / "build/Release" / f"release{version}.exe"
        report = folder / f"fixture-report-{version}.json"
        report.write_text(
            json.dumps(
                {
                    "sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
                    "cpp": ["compiled fixture main.cpp"],
                }
            )
        )
        # Explicit synthetic gate records for the tiny fixtures, never game proof.
        (folder / "verification-report.json").write_text(
            json.dumps(
                {
                    "fixture_only": True,
                    "sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
                    "unresolved_symbols": 0,
                }
            )
        )
        (folder / "relocation-audit.json").write_text(
            json.dumps(
                {
                    "fixture_only": True,
                    "sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
                    "passed": True,
                }
            )
        )
        images.append(image)
    publication = data / "updates"
    catalog = publisher.publish(images[3], report, 4, publication)
    (publication / "images").mkdir()
    (publication / (catalog["latest"] + ".exe")).rename(
        publication / "images" / (catalog["latest"] + ".exe")
    )
    checks, server = [], None
    log = (folder / "server-output.log").open("wb")

    def check(name, condition):
        assert condition, name
        checks.append(name)
        print("PASS", name, flush=True)

    def prepare(image, wanted, name):
        result = subprocess.run(
            [str(args.helper), "--prepare", str(image), "127.0.0.1"],
            creationflags=FLAGS,
            timeout=90,
        )
        check(name, result.returncode == wanted)

    try:
        server = subprocess.Popen(
            [str(args.server), str(data)],
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=FLAGS,
        )
        for _ in range(100):
            assert (
                server.poll() is None
            ), "Fixture backend failed to start; port 8085 must be free"
            try:
                urllib.request.urlopen(
                    "http://127.0.0.1:8085/health", timeout=0.2
                ).close()
                break
            except OSError:
                time.sleep(0.1)
        # All three older clients jump directly to release 4.
        for version in range(1, 4):
            game = folder / f"old-{version}.exe"
            shutil.copyfile(images[version - 1], game)
            prepare(game, 20, f"release {version} stages latest release 4 directly")
            staged = Path(str(game) + ".update") / "next.exe"
            check(
                f"release {version} complete image exact",
                staged.read_bytes() == images[3].read_bytes(),
            )
            check(
                f"release {version} installed bytes untouched",
                game.read_bytes() == images[version - 1].read_bytes(),
            )
        prepare(images[3], 10, "current version requires no update")
        unknown = folder / "unknown.exe"
        unknown.write_bytes(b"MZunknown-modified-image")
        prepare(
            unknown,
            20,
            "unknown older image stages a complete release without a base archive",
        )
        check(
            "unknown base stages exact compiled image",
            (Path(str(unknown) + ".update") / "next.exe").read_bytes()
            == images[3].read_bytes(),
        )
        patch = data / "updates/images" / (catalog["latest"] + ".exe")
        original = patch.read_bytes()
        patch.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        prepare(folder / "old-1.exe", 40, "corrupt complete-image download rejected")
        patch.write_bytes(original)
        check(
            "corrupt download left installed EXE unchanged",
            (folder / "old-1.exe").read_bytes() == images[0].read_bytes(),
        )
        patch.rename(patch.with_suffix(".missing"))
        prepare(
            folder / "old-1.exe",
            40,
            "missing complete image never produces a usable plan",
        )
        patch.with_suffix(".missing").rename(patch)
        # Full process handoff, performed on the release-1 fixture EXE only.
        game = folder / "old-1.exe"
        parent = subprocess.Popen([str(game)], cwd=folder, creationflags=FLAGS)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateEventW.argtypes = [
            ctypes.c_void_p,
            wintypes.BOOL,
            wintypes.BOOL,
            wintypes.LPCWSTR,
        ]
        kernel.CreateEventW.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        event_name = f"Local\\ReplayUpdateFixture-{parent.pid}"
        event = kernel.CreateEventW(None, True, False, event_name)
        assert event
        updater = subprocess.Popen(
            [str(args.helper), "--apply", str(game), str(parent.pid), event_name],
            creationflags=FLAGS,
        )
        try:
            check(
                "helper acknowledges exact running parent",
                kernel.WaitForSingleObject(event, 15000) == 0,
            )
            check(
                "running executable is unchanged before exit",
                game.read_bytes() == images[0].read_bytes(),
            )
            check(
                "apply waits without killing the game",
                updater.poll() is None and parent.poll() is None,
            )
            parent.terminate()  # Controlled fixture shutdown, not a game process.
            parent.wait(timeout=10)
            check(
                "replacement helper exits successfully", updater.wait(timeout=20) == 0
            )
            for _ in range(100):
                marker = folder / "fixture-launched.txt"
                if marker.exists() and marker.read_text() == "4":
                    break
                time.sleep(0.05)
            check(
                "latest fixture relaunched from original directory",
                (folder / "fixture-launched.txt").read_text() == "4",
            )
            check(
                "installed target exactly matches compiled release 4",
                game.read_bytes() == images[3].read_bytes(),
            )
            backup = Path(str(game) + ".update") / (
                hashlib.sha256(images[0].read_bytes()).hexdigest() + ".backup.exe"
            )
            check(
                "previous executable preserved as exact recovery copy",
                backup.read_bytes() == images[0].read_bytes(),
            )
            prepare(game, 10, "relaunch cannot enter an update loop")
        finally:
            kernel.CloseHandle(event)
            if parent.poll() is None:
                parent.terminate()
                parent.wait(timeout=10)
            if updater.poll() is None:
                updater.terminate()
                updater.wait(timeout=10)
        request = struct.pack(
            "<QII32s32s",
            0x3155505744594C50,
            2,
            0,
            os.urandom(32),
            hashlib.sha256(images[0].read_bytes()).digest(),
        )
        signed = urllib.request.urlopen(
            urllib.request.Request(
                "http://127.0.0.1:8085/updates/v2/check", data=request
            ),
            timeout=5,
        ).read()
        server.terminate()
        server.wait(timeout=10)
        replay_target = folder / "replayed-manifest.exe"
        shutil.copyfile(images[0], replay_target)

        class ReplayResponse(http.server.BaseHTTPRequestHandler):
            response = signed

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(200)
                self.send_header("Content-Length", str(len(self.response)))
                self.end_headers()
                self.wfile.write(self.response)

            def log_message(self, *args):
                pass

        with http.server.HTTPServer(("127.0.0.1", 8085), ReplayResponse) as proxy:
            worker = threading.Thread(target=proxy.serve_forever, daemon=True)
            worker.start()
            try:
                prepare(
                    replay_target,
                    40,
                    "replayed signed manifest rejected by fresh request nonce",
                )
                ReplayResponse.response = signed[:-1] + bytes([signed[-1] ^ 1])
                prepare(replay_target, 40, "forged signature rejected")
                check(
                    "manifest rejection preserves installed bytes",
                    replay_target.read_bytes() == images[0].read_bytes(),
                )
            finally:
                proxy.shutdown()
                worker.join(timeout=5)
    finally:
        if server and server.poll() is None:
            server.terminate()
            server.wait(timeout=10)
        log.close()
    result = {
        "schema": 1,
        "passed": True,
        "native_game_verified": False,
        "server_sha256": hashlib.sha256(args.server.read_bytes()).hexdigest(),
        "helper_sha256": hashlib.sha256(args.helper.read_bytes()).hexdigest(),
        "fixture": str(folder),
        "checks": checks,
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
