"""Check custom operator selection, native walking and party isolation in Lua 5.1."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "data/unlock-lua-runtime"))
from lupa.lua51 import LuaRuntime


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    source = (args.snapshot / "src/DW_CustomOperatorsUI.lua" if args.snapshot else
              ROOT / "integration/replay/DW_CustomOperatorsUI.lua")
    vm = LuaRuntime(unpack_returned_tuples=True)
    vm.execute(r'''
        Selection, Ready, StockEquips = 0, true, 0
        _1080p = 1
        Dvar = {
            CFHDGABACF = function(name) assert(name == "dw_customOperator"); return Selection end,
            DFIJDJFIFD = function(name,value) assert(name == "dw_customOperator"); Selection=value end,
            IBEGCHEFE = function(name) assert(name == "replay_dw_customOperatorReady"); return Ready end
        }
        Engine = { CBBHFCGDIC = function(key) return key end }
        FONTS = { MainBold = {File="bold"}, GetFont=function(name) return name end }
        RegisterMaterial = function(name) return name end
        local methods = {}
        function methods:addElement(child) self.children[#self.children+1]=child end
        function methods:addEventHandler(event,fn) self.handlers[event]=fn end
        function methods:SetFont(value) self.font=value end
        function methods:SetAlignment(value) self.alignment=value end
        function methods:SetAnchorsAndPosition(...) self.bounds={...} end
        function methods:SetRGBFromInt(value) self.color=value end
        function methods:SetAlpha(value) self.alpha=value end
        function methods:setText(value) self.text=value end
        function methods:setImage(value) self.image=value end
        function methods:isInFocus() return false end
        function Node() return setmetatable({children={},handlers={}}, {__index=methods}) end
        LUI = { Alignment={Left=0}, UIButton={new=Node}, UIImage={new=Node}, UIText={new=Node} }
        StockCard = {headWest=10,bodyWest=11,headEast=12,bodyEast=13,execWest=20,weapons={"rifle"}}
        LocalMember = { isMyPlayer={GetValue=function() return true end} }
        RemoteMember = { isMyPlayer={GetValue=function() return false end} }
        Lobby = {
            GetPlayerCardDataForPartyMember=function() return StockCard end,
            UpdateLocalClientCharacter=function(c,i,b,h,...) LastLocal={c,i,b,h,...}; return "native-local" end,
            InferOperatorRefFromModel=function(b,h) if b=="stock_body" then return "stock" end return "" end,
            OperatorWalkAnimations={{"walk1","female1"},{"walk2","female2"},{"walk3","female3"},{"walk4","female4"}}
        }
        CSV={operators={file="operators",cols={ref=0,gender=1}}}
        StringTable={DIFCHIGDFB=function() return "0" end}
        LUI.Split=function(text) return {string.match(text,"^[^+]+") or text} end
        OPERATOR={
            GetEquippedOperatorSkin=function() return "stock_body","stock_head" end,
            GetEquippedOperatorData=function() return {ref="stock",name="Stock",gender="1",superfaction="0"} end,
            GetWeaponDataFromLoadout=function() return "rifle","pistol" end,
            UpdateClientCharacter=function(...) LastPreview={...} end
        }
        FrontEndScene={ClientCharacters={MainMenuWest=12,MainMenuEast=13},
            RequestBodyModels=function(models) LastBodies=models end,
            RequestHeadModels=function(models) LastHeads=models end}
        MenuBuilder={BuildRegisteredType=function(kind,options)
            local menu=Node()
            menu.OperatorNametagWest=Node();menu.OperatorNametagWest.Name=Node()
            menu.OperatorNametagEast=Node();menu.OperatorNametagEast.Name=Node()
            menu.EquipOperator=function() StockEquips=StockEquips+1; return "stock-equipped" end
            return menu
        end}
    ''')
    native_path = Path("E:/replay-compiler/evidence/workstation-luafile-decompiled-all/ui/utils/mplobbyutils.lua.2211.lua")
    native = native_path.read_text(encoding="utf-8")
    begin = native.index("function Lobby.GetWalkAnimationForIndex(")
    end = native.index("\nfunction Lobby.UpdateLocalClientCharacter", begin)
    vm.execute(native[begin:end])
    assert vm.eval('Lobby.GetWalkAnimationForIndex("dw_operator_bo2_body","dw_operator_bo2_head",1,"rifle")') == "chr_menu_male_idle_01_AR"
    install = vm.execute(source.read_text())
    assert install() is True
    assert install() is True
    checks = vm.execute(r'''
        local checks={}
        for selection=1,2 do
            Selection=selection
            local prefix=selection==1 and "dw_operator_nicky" or "dw_operator_bo2"
            local b,h=OPERATOR.GetEquippedOperatorSkin(0,0)
            assert(b==prefix.."_body" and h==prefix.."_head")
            for i=1,4 do assert(Lobby.GetWalkAnimationForIndex(b,h,i,"rifle")=="walk"..i) end
            assert(Lobby.GetWalkAnimationForIndex(b,h,1,"iw8_me_riotshield_mp+attachment")=="chr_menu_mp_squad_male_05")
            assert(Lobby.GetWalkAnimationForIndex("stock_body","stock_head",1,"rifle")=="walk1")
            local localCard=Lobby.GetPlayerCardDataForPartyMember(0,LocalMember)
            assert(localCard~=StockCard and localCard.headWest==59999+selection and localCard.bodyEast==59999+selection)
            assert(localCard.weapons==StockCard.weapons and localCard.execWest==20)
            assert(Lobby.GetPlayerCardDataForPartyMember(0,RemoteMember)==StockCard)
            assert(StockCard.headWest==10 and StockCard.bodyEast==13)
            assert(Lobby.UpdateLocalClientCharacter(0,7,"stock_body","stock_head",2,"menu")=="native-local")
            assert(LastLocal[3]==b and LastLocal[4]==h and LastLocal[5]==2 and LastLocal[6]=="menu")
            Ready=false
            assert(OPERATOR.GetEquippedOperatorSkin(0,0)=="stock_body")
            assert(Lobby.GetPlayerCardDataForPartyMember(0,LocalMember)==StockCard)
            Ready=true
            checks[#checks+1]="operator "..selection..": walk, shield, party identity, readiness and preserved card"
        end
        local build=MenuBuilder.BuildRegisteredType
        Selection=0
        assert(OPERATOR.GetEquippedOperatorSkin(0,0)=="stock_body")
        local menu=MenuBuilder.BuildRegisteredType("MPOperatorMenu",{controllerIndex=0})
        assert(menu.ReplayDWOperatorChoices==nil and #menu.children==0)
        assert(MenuBuilder.BuildRegisteredType==build)
        Selection=2
        local selectMenu=MenuBuilder.BuildRegisteredType("OperatorSelect",{controllerIndex=0})
        assert(selectMenu:EquipOperator()=="stock-equipped")
        assert(Selection==2 and StockEquips==1)
        checks[#checks+1]="selection remains dvar-only; native menus and stock equip handlers unchanged"
        return checks
    ''')
    linked = None
    if args.snapshot:
        header = args.snapshot / "src/DW_CustomOperatorsUI_Source.h"
        text = header.read_text()
        assert source.read_text() in text and "state.InstallCustomOperators()" in text
        if args.build:
            report = json.loads((args.build / "build-report.json").read_bytes())
            row = next(r for r in report["cpp"] if Path(r["source"]).name == "DW_PlaylistUI.cpp")
            dependencies = {Path(r["path"]).name:r["sha256"] for r in row["dependencies"]}
            assert dependencies[header.name] == sha(header)
            assert dependencies["DW_PlaylistUI.cpp"] == sha(args.snapshot / "src/DW_PlaylistUI.cpp")
            linked = dict(executable_sha256=report["sha256"], header_sha256=sha(header))
    result = dict(passed=True, source_sha256=sha(source), native_lobby_lua_sha256=sha(native_path),
        checks=list(checks.values()), original_idle_fallback_reproduced=True, linked=linked,
        native_ui_rendered=False, game_launched=False)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
