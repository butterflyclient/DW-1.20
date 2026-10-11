"""Embed the editable Replay playlist UI source during private build preparation."""

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def prepare(snapshot, output, source=None):
    snapshot = snapshot.resolve(strict=True)
    if not snapshot.is_relative_to(ROOT / "data"):
        raise ValueError("Playlist UI compilation requires a private DW source snapshot")
    if (snapshot.parent / "client-readiness.json").exists():
        raise ValueError("Never regenerate a sealed completed client snapshot")
    destination = snapshot / "src/DW_PlaylistUI_Source.h"
    frozen_lua = snapshot / "src/DW_PlaylistUI.lua"
    # Check both destinations before writing either; a shared Lua source must
    # not cause rejection after the header has already been replaced.
    for path in (destination, frozen_lua):
        if path.exists() and path.stat().st_nlink != 1:
            raise ValueError("Playlist generated inputs must be independent private copies: " + str(path))
    source = Path(source or ROOT / "integration/replay/DW_PlaylistUI.lua").resolve(strict=True)
    data = source.read_bytes()
    text = data.decode("utf-8")
    delimiter = "REPLAYDW_UI"
    if ")" + delimiter + '"' in text:
        raise ValueError("Playlist source contains its C++ literal delimiter")
    header = ("#pragma once\n// Generated from DW_PlaylistUI.lua during compilation.\n"
              'inline constexpr char dwPlaylistUISource[] = R"' + delimiter + "(" +
              text + ")" + delimiter + '";\n').encode()
    destination.write_bytes(header)
    frozen_lua.write_bytes(data)
    receipt = dict(passed=True, source=str(source), source_sha256=hashlib.sha256(data).hexdigest(),
                   generated_header=str(destination), header_sha256=hashlib.sha256(header).hexdigest(),
                   main_preference="replay_dw_autoFillBots", localize_key="PLAYLIST/BRSOLOSTIM_NAME2",
                   localize_fallback="BR Stimulus Solos", game_runs_performed=False)
    receipt["frozen_lua"] = str(frozen_lua)
    receipt["generator_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source", type=Path, help="Explicit reviewed/frozen Lua source")
    args = parser.parse_args()
    print(json.dumps(prepare(args.snapshot, args.output, args.source), indent=2))
