"""Check the source-only inspection UI against Replay's actual options helpers."""

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "data/unlock-lua-runtime"))
from lupa.lua51 import LuaRuntime

ORIGINAL = Path(r"E:\replay-compiler\evidence\workstation-luafile-decompiled-all\ui")
SOURCE = ROOT / "integration/replay/DW_WeaponInspectUI.lua"


def helper(text, name, following):
    start = text.index("function OPTIONS." + name + "(")
    end = text.index("function OPTIONS." + following + "(", start)
    return text[start:end]


def main():
    target = ORIGINAL / "utils/optionsutils.lua.2217.lua"
    original = target.read_text(encoding="utf-8")
    vm = LuaRuntime(unpack_returned_tuples=True)
    install = vm.execute(SOURCE.read_text(encoding="utf-8"))
    assert install() is False, "Installation must wait for the stock options APIs"
    vm.execute(r"""
        OPTIONS = {}
        OPTIONS_DATA = { optionsDataList = {} }
        CSV = { keyBindingsOptions = { file = "keybindingsoptions.csv" },
                codCasterBindings = { file = "keybindingscodcaster.csv" } }
        local rows = {
            { identifier = "ReloadAction", stringID = "MENU/RELOAD_WEAPON",
              description = "MENU/RELOAD_WEAPON_DESC", action = "+reload",
              inputContext = "ONFOOT", showForMP = "Y" },
            { identifier = "AttackAction", stringID = "MENU/FIRE_WEAPON",
              description = "MENU/FIRE_WEAPON_DESC", action = "+attack",
              inputContext = "ONFOOT", showForMP = "Y" }
        }
        StringTable = { BFHCAIIDA = function(file)
            return file == "keybindingsoptions.csv" and #rows or 0
        end }
        CSV.ReadRow = function(csv, index) return rows[index + 1] end
        local yes = function() return true end
        local no = function() return false end
        ResetAllCalls = {}
        ResetKeyCalls = {}
        ResetOrder = {}
        Engine = { CBBHFCGDIC = function(key, ...) return "stock:" .. key, ... end,
            CGABICJHAI = yes, HDGDBCJFG = no, CAADCDEEIA = no,
            EAAHGICFBD = yes, ECHCFGDDDF = yes, EAIICIFIFA = no,
            EAHBBDJHID = function() end, DCCFJEGGGE = function() return "K" end,
            DEGABDJDH = function() return "" end,
            CGGHDFIDAF = function(controller, context, command, slot)
                ResetKeyCalls[#ResetKeyCalls + 1] = {
                    controller = controller, context = context, command = command, slot = slot
                }
                ResetOrder[#ResetOrder + 1] = "slot:" .. slot
            end,
            BFHCBIBDGH = function(controller, extra)
                ResetAllCalls[#ResetAllCalls + 1] = { controller = controller, extra = extra }
                ResetOrder[#ResetOrder + 1] = "native"
                return "native-reset-result"
            end,
            DABIGBHJDG = function() end }
        MP = { IsBRGameType = no }
        Lobby = { GetCurrentGameType = function() return "tdm" end, BFFCJFHJJB = no }
        CODCASTER = { CanCODCast = no }
        MLG = { DBIBHEAEGD = no }
        OPTIONS.CreateOption = function(menu, controller, data) return data end
        -- Only the private stock widget constructor is substituted. The two
        -- public helpers below are executed directly from the target dump.
        function BuildKeybind(controller, data)
            assert(data.type == "keyBinding")
            return { id = data.id, action = data.action,
                inputContext = data.inputContext,
                title = Engine.CBBHFCGDIC(data.stringID),
                description = Engine.CBBHFCGDIC(data.description),
                primary = Engine.DCCFJEGGGE(controller, data.inputContext, data.action, 0),
                secondary = Engine.DCCFJEGGGE(controller, data.inputContext, data.action, 1),
                default = Engine.DEGABDJDH(controller, data.inputContext, data.action, 0) }
        end
    """)
    vm.execute(helper(original, "InitKeybindOptionsList", "GetOptionsDataByIdentifier"))
    vm.execute(
        "local var_0_52 = BuildKeybind\n"
        + helper(original, "CreateOptionList", "CreateOptionCategory")
    )
    vm.globals().InstallInspect = install
    vm.execute(r"""
        local originalGlobals = {}
        for key in pairs(_G) do originalGlobals[key] = true end
        assert(InstallInspect())
        local init, create, localize, resetAll = OPTIONS.InitKeybindOptionsList,
            OPTIONS.CreateOptionList, Engine.CBBHFCGDIC, Engine.BFHCBIBDGH
        assert(InstallInspect())
        assert(OPTIONS.InitKeybindOptionsList == init)
        assert(OPTIONS.CreateOptionList == create)
        assert(Engine.CBBHFCGDIC == localize)
        assert(Engine.BFHCBIBDGH == resetAll)
        for key in pairs(_G) do assert(originalGlobals[key], key) end
        assert(Engine.CBBHFCGDIC("OTHER", 17) == "stock:OTHER")
        local _, extra = Engine.CBBHFCGDIC("OTHER", 17)
        assert(extra == 17)
        assert(Engine.BFHCBIBDGH(0, "forwarded") == "native-reset-result")
        assert(#ResetAllCalls == 1 and ResetAllCalls[1].controller == 0)
        assert(ResetAllCalls[1].extra == "forwarded")
        assert(#ResetKeyCalls == 2)
        for index, call in ipairs(ResetKeyCalls) do
            assert(call.controller == 0 and call.context == "ONFOOT")
            assert(call.command == "dw_inspect" and call.slot == index - 1)
        end
        assert(table.concat(ResetOrder, ",") == "native,slot:0,slot:1")
        assert(InstallInspect())
        Engine.BFHCBIBDGH(0, "again")
        assert(#ResetAllCalls == 2 and #ResetKeyCalls == 4)
        assert(ResetAllCalls[2].extra == "again")
        assert(table.concat(ResetOrder, ",") == "native,slot:0,slot:1,native,slot:0,slot:1")

        local menu, options = {}, {}
        OPTIONS.InitKeybindOptionsList(menu, 0, options, CSV.keyBindingsOptions)
        local inspect = assert(options.ReplayDWWeaponInspect)
        assert(inspect.type == "keyBinding" and inspect.controllerIndex == 0)
        assert(inspect.action == "dw_inspect" and inspect.inputContext == "ONFOOT")
        assert(inspect.disabled() == false)
        assert(menu._keybindActionList.dw_inspectONFOOT == inspect.stringID)
        OPTIONS.InitKeybindOptionsList(menu, 0, options, CSV.codCasterBindings)
        assert(options.ReplayDWWeaponInspect == inspect)
        local caster = {}
        OPTIONS.InitKeybindOptionsList({}, 0, caster, CSV.codCasterBindings)
        assert(caster.ReplayDWWeaponInspect == nil)

        local category = { "AttackAction", "ReloadAction", "Other" }
        local build = OPTIONS.CreateOptionList(menu, 0, category, false)
        assert(#category == 3 and category[3] == "Other")
        local widgets = build(menu, 0, options)
        assert(#widgets == 3 and widgets[3].id == "ReplayDWWeaponInspect")
        assert(widgets[3].title == "Inspect Weapon")
        assert(widgets[3].description == "Inspect the weapon you are holding.")
        assert(widgets[3].primary == "K" and widgets[3].secondary == "K")
        assert(widgets[3].default == "")
        local repeated = OPTIONS.CreateOptionList(menu, 0, category, false)(menu, 0, options)
        assert(#repeated == 3 and #category == 3)
        local duplicate = { "ReplayDWWeaponInspect", "ReloadAction",
                            "ReplayDWWeaponInspect", "AttackAction" }
        local deduped = OPTIONS.CreateOptionList(menu, 0, duplicate)(menu, 0, options)
        assert(#deduped == 3 and deduped[1].id == "ReloadAction")
        assert(deduped[2].id == "ReplayDWWeaponInspect")
        assert(#duplicate == 4 and duplicate[1] == "ReplayDWWeaponInspect")
        local unrelated = { "AttackAction" }
        assert(#OPTIONS.CreateOptionList(menu, 0, unrelated)(menu, 0, options) == 1)
    """)
    print(
        json.dumps(
            {
                "passed": True,
                "source": str(SOURCE),
                "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                "target_options_source": str(target),
                "target_options_sha256": hashlib.sha256(
                    target.read_bytes()
                ).hexdigest(),
                "scope": "Lua 5.1 execution using original Replay options-list helpers; private widget and native calls mocked",
                "game_runs_performed": False,
                "cpp_compiled": False,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
