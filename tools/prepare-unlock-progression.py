"""Generate presentation caps and bind original Replay Lua registration targets."""

import csv
import hashlib
import json
from pathlib import Path
import struct

import pefile

ROOT = Path(__file__).resolve().parents[1]
ASSETS = Path(r"E:\replay-compiler\evidence\workstation-stringtable-actsexport-fixed"
              r"\mw19replay\code_post_gfx\mw19replay\code_post_gfx\assets\stringtable")
receipt = json.loads((ROOT / "validation/20261007-weapon-progression-assets.json").read_bytes())
assert hashlib.sha256((ROOT / "src/weapon_progression_data.h").read_bytes()).hexdigest() == receipt["header_sha256"]
inputs = {}

def rows(path):
    inputs[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return list(csv.reader(path.read_text(encoding="utf-8-sig").splitlines()))

rank_rows = rows(ASSETS / "mp/ranktable.csv.597.csv")
assert next(r for r in rank_rows if r[0] == "maxrank")[1] == "54"
assert next(r for r in rank_rows if r[0] == "maxelder")[1] == "100"
base = next(r for r in rank_rows if r[0] == "54")
assert int(base[2]) == 924100 and int(base[7]) == 960000
season_caps = []
for season in range(7):
    path = next((ASSETS / "mp/progression").glob(f"elder{season}_progression.csv.*.csv"))
    data = rows(path)
    assert next(r for r in data if r[0] == "maxrank")[1] == "100"
    season_caps.append(int(next(r for r in data if r[0] == "100")[2]))
caps = []
for definition in receipt["canonical_weapons"]:
    source = Path(definition["source"])
    assert hashlib.sha256(source.read_bytes()).hexdigest() == receipt["inputs"][str(source)]
    data = rows(source)
    maximum = max((int(r[0]) for r in data if r[0].isdigit()), default=0)
    assert maximum == definition["maximum_rank"]
    caps.append(dict(reference=definition["ref"], rank=maximum,
                     xp=receipt["minimum_xp"][maximum]))
assert len(caps) == 51
lines = ["#pragma once", "#include <stdint.h>", "",
         "// Same Replay native CSV tables; generated caps are presentation values only.",
         "struct DWReplayWeaponCap { const char *reference; uint64_t xp, rank; };",
         "inline constexpr DWReplayWeaponCap dwReplayWeaponCaps[] = {"]
lines += ['    {"%s", %d, %d},' % (c["reference"], c["xp"], c["rank"]) for c in caps]
lines += ["};", f"inline constexpr uint64_t dwReplayMaximumPlayerXp = {base[7]};",
          "inline constexpr uint64_t dwReplayMaximumSeasonXp[] = {" +
          ", ".join(map(str, season_caps)) + "};", ""]
header = ROOT / "integration/replay/dw_unlock_progression_caps.h"
header.write_text("\n".join(lines))
image = Path(r"E:\IW8\Builds\1.20-replay\game_dx12_ship_replay.exe")
raw = image.read_bytes()
image_hash = hashlib.sha256(raw).hexdigest()
assert image_hash == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
pe = pefile.PE(data=raw, fast_load=True)
image_base = pe.OPTIONAL_HEADER.ImageBase

def registrations(address):
    result = {}
    for index in range(64):
        name, callback = struct.unpack("<QQ", pe.get_data(address - image_base + 16 * index, 16))
        if not name:
            break
        result[pe.get_data(name - image_base, 128).split(b"\0")[0].decode()] = callback
    return result

player_targets = registrations(0x14241D8D0)
expected = {"CBJHJGIGDA": 0x1410592B0, "BDHJABHDDC": 0x141059360,
            "DFDGDCIAHI": 0x141059410, "CFEDCBACGI": 0x141059500,
            "DABCDDIHDG": 0x141059A80}
assert all(player_targets[name] == address for name, address in expected.items())
assert registrations(0x1423FA3F0)["BEDFIJHAB"] == 0x140F575F0
out = dict(passed=True, image_sha256=image_hash, inputs=inputs, player_max_xp=int(base[7]),
           maximum_internal_rank=154, maximum_display_level=155,
           season_maximum_xp=season_caps, weapon_caps=caps,
           original_player_callbacks={name: hex(address) for name, address in expected.items()},
           original_weapon_callback="0x140f575f0", replacement_weapon_helper="0x140f58c60",
           header_sha256=hashlib.sha256(header.read_bytes()).hexdigest(),
           game_launched=False, native_storage_modified=False)
(ROOT / "validation/20261011-unlock-progression-target.json").write_text(json.dumps(out, indent=2) + "\n")
print("PASS: native registration pointers, 51 original weapon caps and seven season tables")
