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
    if any(path.exists() for path in (
        snapshot.parent / "client-readiness.json", snapshot.parent / "readiness.json",
        snapshot.parent / "local-readiness.json", snapshot.parent / "source-receipt.json",
        snapshot / "source-receipt.json",
    )):
        raise ValueError("Never regenerate a sealed completed client snapshot")
    destination = snapshot / "src/DW_PlaylistUI_Source.h"
    frozen_lua = snapshot / "src/DW_PlaylistUI.lua"
    inspect_destination = snapshot / "src/DW_WeaponInspectUI_Source.h"
    operators_destination = snapshot / "src/DW_CustomOperatorsUI_Source.h"
    # Preflight every input and private destination before writing any header.
    for path in (destination, frozen_lua, inspect_destination, operators_destination):
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
    inspect_lua = snapshot / "src/DW_WeaponInspectUI.lua"
    inspect_text = inspect_lua.read_text(encoding="utf-8")
    inspect_chunk = (
        "local state=MenuBuilder.m_types.replaydwplaylistfillstate(); "
        "if not state.InstallWeaponInspect then "
        "state.InstallWeaponInspect=(function()\n" + inspect_text +
        "\nend)() end; return state.InstallWeaponInspect() and 1 or 0\n"
    )
    if ")" + delimiter + '"' in inspect_chunk:
        raise ValueError("Inspect UI source contains its C++ literal delimiter")
    inspect_header = (
        '#pragma once\ninline constexpr char dwWeaponInspectUISource[] = R"' +
        delimiter + "(" + inspect_chunk + ")" + delimiter + '";\n'
    ).encode("utf-8")
    destination.write_bytes(header)
    frozen_lua.write_bytes(data)
    inspect_destination.write_bytes(inspect_header)
    operators_lua = snapshot / "src/DW_CustomOperatorsUI.lua"
    operators_text = operators_lua.read_text(encoding="utf-8")
    operators_chunk = (
        "local state=MenuBuilder.m_types.replaydwplaylistfillstate(); "
        "if not state.InstallCustomOperators then "
        "state.InstallCustomOperators=(function()\n" + operators_text +
        "\nend)() end; return state.InstallCustomOperators() and 1 or 0\n"
    )
    if ")" + delimiter + '"' in operators_chunk:
        raise ValueError("Operator UI source contains its C++ literal delimiter")
    operators_header = ('#pragma once\ninline constexpr char dwCustomOperatorsUISource[] = R"' +
        delimiter + "(" + operators_chunk + ")" + delimiter + '";\n').encode("utf-8")
    operators_destination.write_bytes(operators_header)
    receipt = dict(passed=True, source=str(source), source_sha256=hashlib.sha256(data).hexdigest(),
                   generated_header=str(destination), header_sha256=hashlib.sha256(header).hexdigest(),
                   main_preference="replay_dw_autoFillBots", localize_key="PLAYLIST/BRSOLOSTIM_NAME2",
                   localize_fallback="BR Stimulus Solos", game_runs_performed=False)
    receipt["cached_title_consumers"] = ["PlaylistPromotedButton", "PlaylistFeaturedButton",
                                          "BRPromotedButton", "BRFeatureButton"]
    receipt["cached_title_model"] = "name"
    receipt["warzone_featured_title_element"] = "GamemodeName"
    receipt["frozen_lua"] = str(frozen_lua)
    receipt["generator_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    receipt["weapon_inspect_ui"] = dict(
        source=str(inspect_lua), source_sha256=hashlib.sha256(inspect_lua.read_bytes()).hexdigest(),
        header_sha256=hashlib.sha256(inspect_header).hexdigest(),
    )
    receipt["custom_operators_ui"] = dict(source=str(operators_lua),
        source_sha256=hashlib.sha256(operators_lua.read_bytes()).hexdigest(),
        header_sha256=hashlib.sha256(operators_header).hexdigest())
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
