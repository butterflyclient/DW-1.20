"""Hash-bound Replay slide input and per-bot command-state component gate."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

import pefile


ROOT = Path(__file__).resolve().parents[1]
TARGET = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
NATIVE = (
    ("Slide_CheckCanSlide", 0x112CE90, 1020, "1b0a391cd59d7685ac5decec99e9a6138c86d2938b9d6d3a8b67fe9aa528a978"),
    ("Slide_EndCheck", 0x112D5C0, 772, "9f777980a9af49c6d29cf4ec3c799e5c3b0daa6bdd9b8207f474af0145354f4e"),
    ("Slide_Update", 0x112EA70, 1273, "be9a36400d6bb0e3e553ced2d7ddb9a4b6a48b58d91309f7b7d0af805a763f66"),
    ("CL_Input_AddCurrentStanceToCmd", 0x15B4490, 272, "09b3b22773ca71718831f6a5dd38b3e80b554e86ce16a11b03b75a1629616891"),
)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", type=Path,
                        default=Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe"))
    parser.add_argument("--compiler", type=Path)
    args = parser.parse_args()
    header = ROOT / "integration/host-scale/sv_host_bot_slide.h"
    movement = ROOT / "integration/host-scale/Bot_UpdateMove_OffPathGrid.cpp"
    runner = ROOT / "tools/test-bot-slide-cancel.cpp"
    proof = None
    if args.snapshot:
        snapshot = args.snapshot.resolve()
        assert snapshot.is_relative_to((ROOT / "data").resolve())
        host = json.loads((snapshot / "generated/host-scale-integration.json").read_bytes())
        assert host["image_sha256"] == TARGET
        proof = host["slide_cancel"]
        header = snapshot / proof["header"]
        assert digest(header) == proof["header_sha256"]
        assert digest(runner) == proof["checker_cpp_sha256"]
        assert proof["slide_request"] == 0x400000 and proof["crouch_request"] == 0x80
        assert proof["slide_flag"] == 29 and proof["sprint_flag"] == 20
        assert proof["space_from_crouch_releases_stance"] and not proof["jump_or_prone_authored"]
        owner = next(row for row in host["replacements"] if row["symbol"] == "Bot_UpdateMove_OffPathGrid")
        movement = snapshot / owner["source"]
        assert digest(movement) == owner["source_sha256"]
    assert digest(args.image) == TARGET
    image = pefile.PE(str(args.image), fast_load=True)
    native = []
    for role, rva, size, expected in NATIVE:
        assert hashlib.sha256(image.get_data(rva, size)).hexdigest() == expected, role
        if proof:
            row = next(row for row in proof["native"] if row["role"] == role)
            assert (row["original_rva"], row["original_bytes"], row["original_sha256"]) == (rva, size, expected)
        native.append(dict(role=role, rva=rva, bytes=size, sha256=expected))
    image.close()
    # Guard integration ownership as well as the independently executed state
    # helper. It runs only after the exact native bot/client/profile gate.
    source = movement.read_text()
    gate = source.index("!CurrentMappedBot(bot, &profile)")
    mutation = source.index("command->buttons &= ~(stance", gate)
    assert gate < mutation
    assert "SV_HostBot_EquipmentActionActive(bot)" in source
    assert "SV_HostBot_GetLootGoal(bot, &lootGoal)" in source
    assert "SV_HostBot_InGulag(bot) || Locked(bot)" in source
    assert "player->weaponFlags & (1ull << 42)" in source
    assert "command->buttons & TravelInterruptButtons" in source
    compiler = args.compiler or shutil.which("clang++")
    if not compiler and os.name == "nt":
        compiler = Path(r"C:\Program Files\LLVM\bin\clang++.exe")
    if not compiler:
        raise SystemExit("A C++20 component compiler is required")
    with tempfile.TemporaryDirectory(prefix="bot-slide-component-", dir=ROOT / "data") as temporary:
        executable = Path(temporary) / ("slide-helper.exe" if os.name == "nt" else "slide-helper")
        command = [str(compiler), "-std=c++20", "-Wall", "-Wextra", "-Werror",
                   '-DDW_SLIDE_HEADER="' + header.as_posix() + '"', str(runner), "-o", str(executable)]
        subprocess.run(command, check=True, capture_output=True, text=True)
        result = subprocess.run([str(executable)], check=True, capture_output=True, text=True,
                                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        assert result.stdout.startswith("PASS:")
    linked = False
    if args.build:
        assert args.snapshot
        report = json.loads((args.build / "build-report.json").read_bytes())
        assert not report["unresolved_symbols"]
        assert digest(report["executable"]) == report["sha256"]
        assert digest(movement) in {row["source_sha256"] for row in report["cpp"]}
        linked = True
    receipt = dict(schema=1, passed=True, native_game_verified=False,
                   image_sha256=TARGET, native_consumers=native,
                   header_sha256=digest(header), movement_sha256=digest(movement),
                   helper_cpp_sha256=digest(runner), compiled_component_executed=True,
                   linked_source_verified=linked, checks=[
                       "Native C-slide request, fresh C-cancel edge and Space-from-crouch stance release",
                       "Actual sprint/slide/crouch/standing acknowledgments and native rejection timeout",
                       "Per-roster cooldown/jitter and interruption at every active phase",
                       "No authored jump/prone command and no playerstate/physics timer writes",
                       "Mapped bot command ownership and combat/equipment/loot/plate/Gulag gates",
                   ])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + "\n")
    print("PASS: Replay native slide consumers and per-bot C/C/Space component; no game run")


if __name__ == "__main__":
    main()
