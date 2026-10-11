"""Run original Replay Lua progression consumers against compiled getter bodies."""

import ctypes
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "data/unlock-lua-runtime"))
from lupa import LuaRuntime

source = Path(r"E:\replay-compiler\evidence\workstation-luafile-decompiled-all"
              r"\ui\utils\progressionutils.lua.2223.lua")
assets = json.loads((ROOT / "validation/20261007-weapon-progression-assets.json").read_bytes())
assert hashlib.sha256(source.read_bytes()).hexdigest() == assets["inputs"][str(source)]
library = ctypes.CDLL(str(ROOT / "data/unlock-progression-fixture.dll"))
player = library.DWFixture_Player
player.argtypes = [ctypes.c_int, ctypes.c_bool, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int]
player.restype = ctypes.c_double
weapon = library.DWFixture_Weapon
weapon.argtypes = [ctypes.c_char_p, ctypes.c_bool, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_bool, ctypes.c_int]
weapon.restype = ctypes.c_uint64
lua = LuaRuntime(unpack_returned_tuples=True)
lua.execute("""
LUI = { clamp = function(v,a,b) return math.max(a,math.min(b,v)) end }
SEASON = { GetCurrentSeason = function() return 6 end }
CSV = {
 MPRank = {file='rank', cols={index=0,maxXP=7}},
 elderProgressionTable = {GetFile=function(s) return 'season'..s end,
   cols={rank=0,maxXP=2,minXP=1}},
 gunsmithProgressionTable = {GetFile=function(_,w) return w end,cols={level=0}}
}
OnlineProgression = {}
Gunsmith = {}
StringTable = {}
""")
enabled = True
base_xp, base_rank = 17500, 4
for name, kind in [("CBJHJGIGDA", 0), ("BDHJABHDDC", 1), ("DFDGDCIAHI", 2),
                   ("CFEDCBACGI", 3), ("DABCDDIHDG", 4)]:
    lua.globals().OnlineProgression[name] = lambda controller, season=0, kind=kind: player(
        kind, enabled, base_xp, base_rank, int(season))

def weapon_info(controller, reference):
    reference = reference.encode()
    return lua.table_from(dict(xp=weapon(reference, enabled, 1334 + controller * 100, 3 + controller, False, controller),
                               rank=weapon(reference, enabled, 1334 + controller * 100, 3 + controller, True, controller)))

lua.globals().Gunsmith.BEDFIJHAB = weapon_info
caps = {row["ref"]: row["maximum_rank"] for row in assets["canonical_weapons"]}
maxima = [2000500, 4028000, 6134100, 6134100, 6134100, 6134100, 6134100]

def lookup(file, column, key, output):
    if file == "rank":
        return {"maxrank": 54, "maxelder": 100}.get(str(key), 960000)
    if file.startswith("season"):
        return maxima[int(file[6:])]
    raise AssertionError(file)

lua.globals().StringTable.DIFCHIGDFB = lookup
lua.globals().StringTable.BFHCAIIDA = lambda file: 0
lua.globals().StringTable.CBGJCDIHCE = lambda file, row, column: str(caps[file])
lua.execute(source.read_text(encoding="utf-8-sig"))
p = lua.globals().PROGRESSION
assert p.IsElder(0) is True
assert p.GetPlayerRank(0) == 154
assert p.GetPlayerDisplayLevel(0) == 155
assert p.IsPlayerLifeTimeRankMax(0) is True
assert p.IsPlayerLifeTimeXPMax(0) is True
for controller in range(2):
    for reference, rank in caps.items():
        assert p.GetWeaponLevel(controller, reference) == rank + 1
        assert p.GetMaxWeaponLevel(reference) == rank + 1
        assert p.IsWeaponMaxLevel(controller, reference) is True
        assert p.GetWeaponXP(controller, reference) == assets["minimum_xp"][rank]
enabled = False
base_xp += 700
assert p.IsElder(0) is False
assert p.GetPlayerXP(0) == 18200
assert p.GetPlayerDisplayLevel(0) == 5
assert p.GetPlayerRank(0) == 4
for controller in range(2):
    for reference in caps:
        assert p.GetWeaponXP(controller, reference) == 1334 + controller * 100
        assert p.GetWeaponLevel(controller, reference) == 4 + controller
print("PASS: original Replay Lua computes elder eligibility, rank 155, 51 weapon maximums and reversible normal progression from compiled getters")
