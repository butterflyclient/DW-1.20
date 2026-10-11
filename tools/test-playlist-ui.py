"""Exercise the compiled-in UI script with original Replay builders and Lua 5.1."""

import argparse
import hashlib
import json
import re
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "data/unlock-lua-runtime"))
from lupa.lua51 import LuaRuntime

ORIGINAL = Path(r"E:\replay-compiler\evidence\workstation-luafile-decompiled-all\ui")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    vm = LuaRuntime(unpack_returned_tuples=True)
    cpp = (ROOT / "integration/replay/DW_PlaylistUI.cpp").read_text()
    begin = cpp.index('constexpr char probe[] =')
    literal = cpp[begin:cpp.index('double installed =', begin)]
    vm.globals().PollSource = ''.join(json.loads(value) for value in re.findall(r'"(?:[^"\\]|\\.)*"', literal))
    vm.execute(r'''
        _1080p = 1
        local nodeMethods = {}
        function nodeMethods:addElement(child)
            child.parent = self
            table.insert(self.children, child)
        end
        function nodeMethods:addElementBefore(reference)
            local children = assert(self.parent).children
            for i, child in ipairs(children) do
                if child == self then table.remove(children, i); break end
            end
            for i, child in ipairs(children) do
                if child == reference then table.insert(children, i, self); return end
            end
            error("Missing native list reference")
        end
        function nodeMethods:SetAnchorsAndPosition(a,b,c,d,left,right,top,bottom)
            self.rect = {left=left, right=right, top=top, bottom=bottom}
        end
        function nodeMethods:GetCurrentAnchorsAndPositions() return self.rect end
        function nodeMethods:setText(value) self.text = value end
        function nodeMethods:getText() return self.text end
        function nodeMethods:registerEventHandler(name, callback) self.events[name] = callback end
        nodeMethods.addEventHandler = nodeMethods.registerEventHandler
        function nodeMethods:getRootController() return 0 end
        function nodeMethods:SetHandleMouse(value) self.mouse = value end
        function nodeMethods:AddTooltipData(controller, value) self.tooltip = value end
        function nodeMethods:getLocalRect() return 0,0,430,25 end
        function nodeMethods:getElementTextDims() return #self.text * 10,20 end
        local noOperation = function() end
        function MakeNode()
            return setmetatable({children={},events={},rect={left=0,right=430,top=0,bottom=50}}, {
                __index = function(_, key)
                    if nodeMethods[key] then return nodeMethods[key] end
                    for _, prefix in ipairs({"Set", "set", "Register", "Animate", "Subscribe",
                            "AddScrollbar", "Update", "Setup", "dispatch", "addAnimation"}) do
                        if string.sub(key,1,#prefix)==prefix then return noOperation end
                    end
                end
            })
        end
        LUI = {}
        for _, kind in ipairs({"UIElement","UIText","UIStyledText","UIImage","UIButton",
                "UITimer","UIVerticalList","UIHorizontalList","UICountdown","UILongCountdown",
                "UITechyDigits","UIBindButton","UIDataSourceGrid","UIScrollbar",
                "UIHorizontalStackedLayout","UIBorder"}) do
            LUI[kind] = {new=MakeNode,build=MakeNode}
        end
        LUI.Alignment = {Left=0,Top=0}
        LUI.DIRECTION = {horizontal=0,vertical=1}
        LUI.DataSourceInGlobalModel = {new=function() return {GetModel=noOperation} end}
        Engine = {
            DDJFBBJAIG=function() return false end,
            BHFFIBEFFH=noOperation,DCHDDCJCEG=noOperation,
            BHICADFIHA=function() return false end,
            CBBHFCGDIC=function(key,...) return NativeTranslations[key] or key end
        }
        NativeTranslations = {}
        Preference = false
        Dvar = {
            IBEGCHEFE=function(name) return name=="replay_dw_autoFillBots" and Preference end,
            DHEGHJJJHI=function(name,value)
                assert(name=="replay_dw_autoFillBots" and type(value)=="boolean")
                Preference=value
            end
        }
        CONDITIONS = setmetatable({}, {__index=function() return function() return false end end})
        Lobby = {GFFECBCCF=function() return false end,BGIADHIHAG=function() return false end}
        DataSources = {frontEnd={lobby={inSplitScreen={GetModel=noOperation},memberCount={GetModel=noOperation}}}}
        ACTIONS = {AnimateSequence=function(widget, sequence) widget.lastSequence=sequence end}
        TWEEN_PROPERTY = setmetatable({}, {__index=function(_, key) return key end})
        SWATCHES = {genericButton={textDefault={},textFocus={},background={},glow={}}}
        FONTS = {MainRegular={File="main"},GetFont=function(value) return value end}
        RegisterMaterial=function(value) return value end
        ToUpperCase=string.upper
        SOUND_SETS={mpMainMenu={move="move",moveUp="up",moveDown="down"}}
    ''')
    inputs = {}

    def original(relative, module_name):
        path = ORIGINAL / relative
        inputs[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        vm.execute(path.read_text(encoding="utf-8-sig"), module_name)

    utilities = ORIGINAL / "utils/lui.lua.2168.lua"
    raw = utilities.read_text(encoding="utf-8-sig")
    lock = raw[raw.index("function LockTable("):raw.index("\nif hpairs", raw.index("function LockTable("))]
    vm.execute(lock)
    inputs[str(utilities)] = hashlib.sha256(utilities.read_bytes()).hexdigest()
    original("menubuilder.lua.2077.lua", "MenuBuilder")
    vm.execute(r'''
        MenuBuilder.registerType("ButtonGlow", function()
            local widget=MakeNode();widget.Glow=MakeNode();return widget
        end)
        MenuBuilder.registerType("QuickPlayButtonContainer", function()
            local widget=MakeNode();widget.QuickPlayButton=MakeNode()
            widget.QuickPlayButton.Description=MakeNode();widget.QuickPlayFilterButton=MakeNode()
            return widget
        end)
        MenuBuilder.registerType("BRPlayButton", MakeNode)
        MenuBuilder.registerType("BRTrialsPlayButton", function()
            local widget=MakeNode();local button=MakeNode();button.Text=MakeNode()
            widget.PlayButtonWrapper={PlayButton=button};return widget
        end)
        MenuBuilder.registerType("VerticalMinimalScrollbar", MakeNode)
    ''')
    original("widgets/genericcheckbox.lua.2373.lua", "GenericCheckBoxModule")
    original("frontend/genericcheckboxbuttonwithlabel.lua.288.lua", "CheckBoxLabelModule")
    original("frontend/mp/mpplaymenubuttons.lua.561.lua", "MPPlayButtonsModule")
    original("frontend/mp/brplaymenubuttons.lua.395.lua", "BRPlayButtonsModule")
    original("frontend/playlistlist.lua.742.lua", "PlaylistListModule")
    vm.execute(r'''
        MenuBuilder.registerType("PlaylistMenu", function()
            local menu=MakeNode()
            menu.PlaylistList=MenuBuilder.BuildRegisteredType("PlaylistList",{controllerIndex=0})
            menu.PlaylistList:SetAnchorsAndPosition(0,1,0,1,130,550,217,807)
            menu:addElement(menu.PlaylistList);return menu
        end)
        MenuBuilder.registerType("BRPlaylistMenu",MenuBuilder.m_types.playlistmenu)
        LockTable(_G)
        LockTable(Engine)
        LockTable(Dvar)
    ''')
    source = ROOT / "integration/replay/DW_PlaylistUI.lua"
    assert vm.execute(source.read_text()) == 1
    checks = vm.execute(r'''
        local options={controllerIndex=0}
        local mp=MenuBuilder.BuildRegisteredType("MPPlayMenuButtons",options)
        local br=MenuBuilder.BuildRegisteredType("BRPlayMenuButtons",options)
        local grid=MenuBuilder.BuildRegisteredType("PlaylistMenu",options)
        local brGrid=MenuBuilder.BuildRegisteredType("BRPlaylistMenu",options)
        local results={}
        for _,panel in ipairs({mp,br}) do
            local checkbox=panel.ReplayDWFillLobbyBots
            assert(checkbox and panel.children[1]==checkbox)
            assert(checkbox.Text.text=="Fill lobby with bots" and checkbox.mouse==true)
            assert(checkbox.Checkbox:GetValue()==false)
            assert(checkbox.rect.bottom-checkbox.rect.top==25)
            assert(checkbox.navigation.down.navigation.up==checkbox)
        end
        results[#results+1]="Original MP/BR list builders contain one native checkbox before all playlists, with mouse and controller navigation"
        for _,menu in ipairs({grid,brGrid}) do
            local checkbox=menu.ReplayDWFillLobbyBots
            assert(checkbox and checkbox.rect.top==189 and checkbox.rect.bottom==214)
            assert(checkbox.navigation.down==menu.PlaylistList.PlaylistButtons)
            assert(menu.PlaylistList.PlaylistButtons.navigation.up==checkbox)
        end
        results[#results+1]="Playlist and BR playlist grids retain their native scrolling layout with one checkbox in the gap above the entries"
        mp.ReplayDWFillLobbyBots.events.button_action()
        assert(Preference==true)
        for _,checkbox in ipairs({mp.ReplayDWFillLobbyBots,br.ReplayDWFillLobbyBots,
                grid.ReplayDWFillLobbyBots,brGrid.ReplayDWFillLobbyBots}) do
            assert(checkbox.Checkbox:GetValue()==true)
        end
        br.ReplayDWFillLobbyBots.events.button_action()
        assert(Preference==false and mp.ReplayDWFillLobbyBots.Checkbox:GetValue()==false)
        results[#results+1]="One shared boolean preference updates every surviving checkbox in both directions"
        -- Execute the actual C++ poll payload: native policy may reject a
        -- setting or the console may change it without another focus event.
        Preference=true
        local poll=assert(loadstring(PollSource))
        assert(poll()==1)
        assert(mp.ReplayDWFillLobbyBots.Checkbox:GetValue()==true)
        Preference=false
        assert(poll()==1)
        for _,checkbox in ipairs({mp.ReplayDWFillLobbyBots,br.ReplayDWFillLobbyBots,
                grid.ReplayDWFillLobbyBots,brGrid.ReplayDWFillLobbyBots}) do
            assert(checkbox.Checkbox:GetValue()==false)
        end
        results[#results+1]="Native policy rejection and console changes refresh all checkboxes through the actual periodic C++ probe"
        local first=br.BRPlayButton
        local added=MakeNode();br:addElement(added);added:addElementBefore(first)
        assert(br.children[1]==br.ReplayDWFillLobbyBots)
        results[#results+1]="Later playlist insertion stays below the global toggle"
        local upper=MakeNode()
        upper.navigation={down=mp.QuickPlayButtonContainer}
        mp.QuickPlayButtonContainer.navigation.up=upper
        MenuBuilder.registerType("MPPlayMenu",function()
            local menu=MakeNode();menu.MPPlayMenuButtons=mp;return menu
        end)
        MenuBuilder.BuildRegisteredType("MPPlayMenu",options)
        assert(upper.navigation.down==mp.ReplayDWFillLobbyBots)
        assert(mp.ReplayDWFillLobbyBots.navigation.up==upper)
        assert(mp.ReplayDWFillLobbyBots.navigation.down==mp.QuickPlayButtonContainer)
        results[#results+1]="Parent post-load navigation includes the toggle in both directions"
        assert(Engine.CBBHFCGDIC("PLAYLIST/BRSOLOSTIM_NAME2")=="BR Stimulus Solos")
        NativeTranslations["PLAYLIST/BRSOLOSTIM_NAME2"]="Localized native title"
        assert(Engine.CBBHFCGDIC("PLAYLIST/BRSOLOSTIM_NAME2")=="Localized native title")
        assert(Engine.CBBHFCGDIC("UNRELATED_KEY")=="UNRELATED_KEY")
        results[#results+1]="Only the confirmed missing playlist title gets a fallback; native translations and unrelated keys remain authoritative"
        return results
    ''')
    old_builder = vm.globals().MenuBuilder.BuildRegisteredType
    assert vm.execute(source.read_text()) == 1
    # Compare through Lua equality, which retains exact closure identity.
    compare = vm.eval("function(previous) return previous==MenuBuilder.BuildRegisteredType end")
    assert compare(old_builder)
    items = [checks[i] for i in range(1, len(checks) + 1)]
    items.append("Repeated installation is idempotent and creates no sealed global/module fields")
    receipt = dict(passed=True,checks=items,source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                   original_lua_inputs=inputs,lua_version=vm.eval("_VERSION"),
                   modeled_boundaries="Native rendering/input/model APIs; original builder, checkbox and list Lua execute",
                   game_runs_performed=False,rendered_ui_verified=False)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(receipt,indent=2)+"\n")
    print("PASS: original Lua 5.1 playlist builders, shared toggle, navigation and title fallback")


if __name__ == "__main__":
    main()
