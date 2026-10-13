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
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--build", type=Path)
    args = parser.parse_args()
    snapshot = args.snapshot.resolve(strict=True) if args.snapshot else None
    if snapshot:
        assert snapshot.is_relative_to(ROOT / "data")
    source = (snapshot / "src/DW_PlaylistUI.lua" if snapshot else
              ROOT / "integration/replay/DW_PlaylistUI.lua")
    cpp_source = (snapshot / "src/DW_PlaylistUI.cpp" if snapshot else
                  ROOT / "integration/replay/DW_PlaylistUI.cpp")
    linked = None
    if args.build:
        assert snapshot is not None, "A linked consumer gate requires its frozen snapshot"
        build = args.build.resolve(strict=True)
        report_path = build / "build-report.json" if build.is_dir() else build
        report = json.loads(report_path.read_bytes())
        image = Path(report["executable"])
        if not image.is_absolute(): image = report_path.parent / image
        assert hashlib.sha256(image.read_bytes()).hexdigest() == report["sha256"]
        assert report["unresolved_symbols"] == 0 and report["symbols"]["DW_PlaylistUI_Frame"] > 0
        rows = [r for r in report["cpp"] if Path(r["source"]).name == "DW_PlaylistUI.cpp"]
        assert len(rows) == 1
        row = rows[0]
        cpp_hash = hashlib.sha256(cpp_source.read_bytes()).hexdigest()
        assert row["source_sha256"] == cpp_hash
        assert hashlib.sha256(Path(row["object"]).read_bytes()).hexdigest() == row["object_sha256"]
        assert hashlib.sha256(Path(row["compiler"]["path"]).read_bytes()).hexdigest() == row["compiler"]["sha256"]
        dependencies = {Path(d["path"]).name: d["sha256"] for d in row["dependencies"]}
        assert dependencies["DW_PlaylistUI.cpp"] == cpp_hash
        header_hash = hashlib.sha256((snapshot / "src/DW_PlaylistUI_Source.h").read_bytes()).hexdigest()
        assert dependencies["DW_PlaylistUI_Source.h"] == header_hash, "Build did not compile the supplied Lua header"
        linked = dict(image_sha256=report["sha256"], cpp_source_sha256=cpp_hash,
                      object_sha256=row["object_sha256"], header_sha256=header_hash,
                      lua_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest())
    vm = LuaRuntime(unpack_returned_tuples=True)
    cpp = cpp_source.read_text()
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
        function nodeMethods:SetAlpha(value) self.alpha = value end
        function nodeMethods:isInFocus() return self.focused == true end
        function nodeMethods:processEvent(event)
            if event.name == "gain_focus" then self.focused = true end
            if event.name == "lose_focus" then self.focused = false end
            if self.events[event.name] then return self.events[event.name](self,event) end
        end
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
        MapSelections = {}
        IntroPreferences = {}
        OnboardingNativeReads = 0
        OnboardingNativeWrites = 0
        Engine.ECCJEIDDC = function(controller,flag)
            assert(controller==0 and type(flag)=="number")
            OnboardingNativeReads=OnboardingNativeReads+1
            return false
        end
        Engine.CIHICIEBIA = function() OnboardingNativeWrites=OnboardingNativeWrites+1 end
        Dvar = {
            IBEGCHEFE=function(name)
                if name=="replay_dw_autoFillBots" then return Preference end
                return IntroPreferences[name]==true
            end,
            DHEGHJJJHI=function(name,value)
                assert(type(value)=="boolean")
                if string.find(name,"replay_dw_mapVoteSelect",1,true)==1 then
                    MapSelections[#MapSelections+1]=name;return
                end
                assert(name=="replay_dw_autoFillBots")
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
    button_source = ORIGINAL / "luibutton.lua.2037.lua"
    raw_button = button_source.read_text(encoding="utf-8-sig")
    focus_begin = raw_button.index("function LUI.UIButton.SetFocusable(")
    focus_end = raw_button.index("\nlocal function", focus_begin)
    vm.execute(raw_button[focus_begin:focus_end])
    vm.execute('''
        local create=LUI.UIButton.new
        LUI.UIButton.new=function()
            local button=create()
            button.SetFocusable=LUI.UIButton.SetFocusable
            button.AcceptsFocusType=LUI.UIButton.AcceptsFocusType
            button:SetFocusable(true)
            return button
        end
    ''')
    inputs[str(button_source)] = hashlib.sha256(button_source.read_bytes()).hexdigest()

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
    original("utils/onboarding.lua.2213.lua", "OnboardingModule")
    for relative, kind, field, scope, label_index, callback_index in (
        ("frontend/mp/playlistpromotedbutton.lua.578.lua", "PlaylistPromotedButton", "Name", "21", "8", "9"),
        ("frontend/mp/playlistfeaturedbutton.lua.572.lua", "PlaylistFeaturedButton", "Name", "21", "8", "9"),
        ("frontend/mp/brpromotedbutton.lua.401.lua", "BRPromotedButton", "GamemodeName", "15", "8", "9"),
        ("frontend/mp/brfeaturebutton.lua.390.lua", "BRFeatureButton", "GamemodeName", "14", "6", "7"),
    ):
        path = ORIGINAL / relative
        raw = path.read_text(encoding="utf-8-sig")
        inputs[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        begin = raw.index("\tlocal function var_" + scope + "_" + callback_index + "()")
        end = raw.index("\n\tvar_" + scope + "_" + label_index + ":SubscribeToModelThroughElement", begin)
        def variables(text):
            return (text.replace("var_21_8", "var_21_" + label_index)
                        .replace("var_21_9", "var_21_" + callback_index)
                        .replace("var_21", "var_" + scope)
                        .replace("widget.Name", "widget." + field))
        vm.execute(
            variables('''MenuBuilder.registerType(..., function()
                local widget=MakeNode()
                widget.modelName="PLAYLIST/BRSOLOSTIM_NAME2"
                local var_21_0=widget
                local var_21_1=0
                local var_21_8=MakeNode()
                widget.Name=var_21_8
                function widget:GetDataSource()
                    return {name={GetValue=function() return widget.modelName end}}
                end
            ''') + raw[begin:end] + variables('''
                widget.RefreshModel=var_21_9
                var_21_9()
                return widget
            end)'''), kind
        )
    playlist_utils = ORIGINAL / "utils/playlistutils.lua.2219.lua"
    raw = playlist_utils.read_text(encoding="utf-8-sig")
    featured = raw[raw.index("function PlaylistUtils.SetupFeaturedButtons("):
                   raw.index("function PlaylistUtils.SetupPromotedButtons(")]
    assert 'MenuBuilder.BuildRegisteredType("BRFeatureButton"' in featured
    inputs[str(playlist_utils)] = hashlib.sha256(playlist_utils.read_bytes()).hexdigest()
    vm.execute('''PlaylistUtils={MAX_FEATURED_GAMEMODE_BUTTONS=3,ButtonType={FEATURED=1}}
        PlaylistUtils.InitializePlaylistButton=function(widget,data,controller)
            widget.modelName=data.name:GetValue(controller)
            widget.RefreshModel()
        end
    ''' + featured)
    vm.execute(r'''
        MenuBuilder.registerType("PlaylistMenu", function()
            local menu=MakeNode()
            menu.PlaylistList=MenuBuilder.BuildRegisteredType("PlaylistList",{controllerIndex=0})
            menu.PlaylistList:SetAnchorsAndPosition(0,1,0,1,130,550,217,807)
            menu:addElement(menu.PlaylistList);return menu
        end)
        MenuBuilder.registerType("BRPlaylistMenu",MenuBuilder.m_types.playlistmenu)
        for _,pair in ipairs({{"MPPlayMenu","MPPlayMenuButtons"},{"BRPlayMenu","BRPlayMenuButtons"}}) do
            local menuName,panelName=pair[1],pair[2]
            MenuBuilder.registerType(menuName,function()
                local menu=MakeNode()
                local panel=MenuBuilder.BuildRegisteredType(panelName,{controllerIndex=0})
                panel:SetAnchorsAndPosition(0,1,0,1,130,560,217,807)
                menu[panelName]=panel;menu:addElement(panel)
                return menu
            end)
        end
        LockTable(_G)
        LockTable(Engine)
        LockTable(Dvar)
    ''')
    serialized = None
    if snapshot:
        frozen = snapshot / "src/DW_PlaylistUI.lua"
        header = snapshot / "src/DW_PlaylistUI_Source.h"
        data, embedded = frozen.read_bytes(), header.read_bytes()
        assert data == source.read_bytes()
        prefix, suffix = b'R"REPLAYDW_UI(', b')REPLAYDW_UI";\n'
        assert embedded.count(prefix) == 1 and embedded.endswith(suffix)
        assert embedded.split(prefix, 1)[1][:-len(suffix)] == data
        serialized = dict(frozen_lua_sha256=hashlib.sha256(data).hexdigest(),
                          generated_header_sha256=hashlib.sha256(embedded).hexdigest(),
                          exact_embedded_lua=True)
    assert vm.execute(source.read_text()) == 1
    checks = vm.execute(r'''
        local options={controllerIndex=0}
        local mpMenu=MenuBuilder.BuildRegisteredType("MPPlayMenu",options)
        local brMenu=MenuBuilder.BuildRegisteredType("BRPlayMenu",options)
        local mp,br=mpMenu.MPPlayMenuButtons,brMenu.BRPlayMenuButtons
        local grid=MenuBuilder.BuildRegisteredType("PlaylistMenu",options)
        local brGrid=MenuBuilder.BuildRegisteredType("BRPlaylistMenu",options)
        local results={}
        local ballot=MenuBuilder.m_types.replaydwplaylistfillstate()
        local panel=mpMenu.ReplayDWMapVote
        assert(panel and panel.alpha==0)
        for _,button in ipairs(panel.Choices) do assert(not button:AcceptsFocusType(0)) end
        ballot.RefreshMapVote({active=true,complete=false,remaining=12,choices={
            {name="Backlot",votes=1},{name="Crash",votes=2},{name="Office",votes=0}}})
        assert(panel.alpha==1 and panel.Choices[1].Label.text=="Backlot   (1 votes)")
        assert(panel.Choices[3].navigation.down==panel.Choices[1])
        assert(panel.Choices[1].navigation.up==panel.Choices[3])
        panel.Choices[3].events.button_action()
        assert(MapSelections[1]=="replay_dw_mapVoteSelectC")
        panel.Choices[3]:processEvent({name="gain_focus"})
        ballot.RefreshMapVote({active=true,complete=false,choices={{name="Backlot",votes=1}}})
        assert(not panel.Choices[3]:AcceptsFocusType(0) and not panel.Choices[3]:isInFocus())
        assert(panel.Anchor:isInFocus() and panel.Choices[1].navigation.up==panel.Choices[1])
        panel.Choices[1]:processEvent({name="gain_focus"})
        ballot.RefreshMapVote({active=true,complete=true,choices={{name="Backlot",votes=1,winner=true}}})
        assert(not panel.Choices[1]:isInFocus() and not panel.Choices[1]:AcceptsFocusType(0))
        panel.Choices[1].events.button_action(); assert(#MapSelections==1)
        ballot.RefreshMapVote({active=false})
        for _,button in ipairs(panel.Choices) do assert(not button:AcceptsFocusType(0) and not button.mouse) end
        results[#results+1]="Native map-choice actions select A/B/C; reduced, completed and inactive ballots retire controller focus through original UIButton focusability methods"
        for _,panel in ipairs({mp,br}) do
            local checkbox=panel.ReplayDWFillLobbyBots
            assert(checkbox and checkbox.parent==panel.parent)
            for _,child in ipairs(panel.children) do assert(child~=checkbox) end
            assert(checkbox.rect.top==189 and checkbox.rect.bottom==214)
            assert(panel.rect.top==217 and panel.rect.bottom==807)
            assert(checkbox.Text.text=="Fill lobby with bots" and checkbox.mouse==true)
            assert(checkbox.Checkbox:GetValue()==false)
            assert(checkbox.rect.bottom-checkbox.rect.top==25)
            assert(checkbox.navigation.down.navigation.up==checkbox)
        end
        results[#results+1]="Original MP/BR lists retain their rectangle and rows; one sibling checkbox sits above with mouse and controller navigation"
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
        assert(br.children[1]==added and br.ReplayDWFillLobbyBots.parent==brMenu)
        results[#results+1]="Later playlist insertion remains in the unchanged list; toggle never consumes a row"
        local upper=MakeNode()
        upper.navigation={down=mp.QuickPlayButtonContainer}
        mp.QuickPlayButtonContainer.navigation.up=upper
        -- Construct a new parent whose stock post-load connects an upper item.
        MenuBuilder.m_types.mpplaymenu=function()
            local menu=MakeNode()
            local panel=MenuBuilder.BuildRegisteredType("MPPlayMenuButtons",options)
            panel.QuickPlayButtonContainer.navigation={up=upper}
            upper.navigation.down=panel.QuickPlayButtonContainer
            menu.MPPlayMenuButtons=panel;menu:addElement(panel);return menu
        end
        mp=MenuBuilder.BuildRegisteredType("MPPlayMenu",options).MPPlayMenuButtons
        assert(upper.navigation.down==mp.ReplayDWFillLobbyBots)
        assert(mp.ReplayDWFillLobbyBots.navigation.up==upper)
        assert(mp.ReplayDWFillLobbyBots.navigation.down==mp.QuickPlayButtonContainer)
        results[#results+1]="Parent post-load navigation includes the toggle in both directions"
        assert(Engine.CBBHFCGDIC("PLAYLIST/BRSOLOSTIM_NAME2")=="BR Stimulus Solos")
        NativeTranslations["PLAYLIST/BRSOLOSTIM_NAME2"]="Localized native title"
        assert(Engine.CBBHFCGDIC("PLAYLIST/BRSOLOSTIM_NAME2")=="Localized native title")
        assert(Engine.CBBHFCGDIC("UNRELATED_KEY")=="UNRELATED_KEY")
        results[#results+1]="Only the confirmed missing playlist title gets a fallback; native translations and unrelated keys remain authoritative"
        for _,kind in ipairs({"PlaylistPromotedButton","PlaylistFeaturedButton","BRPromotedButton","BRFeatureButton"}) do
            local widget=MenuBuilder.BuildRegisteredType(kind,options)
            local label=widget.Name or widget.GamemodeName
            assert(label:getText()=="BR STIMULUS SOLOS")
            widget.modelName="@PLAYLIST/BRSOLOSTIM_NAME2"
            widget.RefreshModel()
            assert(label:getText()=="BR STIMULUS SOLOS")
            widget.modelName="Localized native title"
            widget.RefreshModel()
            assert(label:getText()=="LOCALIZED NATIVE TITLE")
            widget.modelName="PLAYLIST/UNRELATED_KEY"
            widget.RefreshModel()
            assert(label:getText()=="PLAYLIST/UNRELATED_KEY")
            widget.modelName=nil
            widget.RefreshModel()
            assert(label:getText()=="PLAYLIST/UNRELATED_KEY")
        end
        results[#results+1]="Original MP and BR promoted/featured callbacks repair cached initial names and later model updates without Localize; BRFeatureButton uses its actual GamemodeName callback"
        local panel=MakeNode()
        panel.featuredButtonWidgets={}
        function panel:InsertIntoButtonList(widget,list,kind)
            assert(kind==PlaylistUtils.ButtonType.FEATURED)
            table.insert(list,widget);self:addElement(widget)
        end
        function panel:AddButtonTooltipData() end
        local names={"BR QUADS","BR SOLOS","PLAYLIST/BRSOLOSTIM_NAME2"}
        local category={index={GetValue=function() return nil end},playlists={}}
        function category.playlists:GetCountValue() return #names end
        function category.playlists:GetDataSourceAtIndex(index)
            return {name={GetValue=function() return names[index+1] end},
                    playlistIndex={GetValue=function() return index end}}
        end
        CONDITIONS.IsMagmaGameMode=function() return true end
        PlaylistUtils.SetupFeaturedButtons(panel,0,category)
        assert(#panel.featuredButtonWidgets==3)
        assert(panel.featuredButtonWidgets[3].GamemodeName:getText()=="BR STIMULUS SOLOS")
        assert(panel.featuredButtonWidgets[1].GamemodeName:getText()=="BR QUADS")
        assert(panel.featuredButtonWidgets[2].GamemodeName:getText()=="BR SOLOS")
        panel.featuredButtonWidgets[3].modelName="@PLAYLIST/BRSOLOSTIM_NAME2"
        panel.featuredButtonWidgets[3].RefreshModel()
        assert(panel.featuredButtonWidgets[3].GamemodeName:getText()=="BR STIMULUS SOLOS")
        results[#results+1]="Original Warzone SetupFeaturedButtons selects BRFeatureButton and the third tile repairs cached and subsequent names while neighboring titles stay unchanged"
        assert(Onboarding.SeasonVideo.WasCompleted(nil,0,3)==true)
        assert(Onboarding.MagmaVideo.WasCompleted(nil,0)==true)
        assert(Onboarding.WARZONE_INTRODUCTION.WasCompleted(nil,0)==true)
        assert(Onboarding.WARZONE_TUTORIAL_GAMEPLAY_INITIATED.WasCompleted(nil,0)==true)
        assert(Onboarding.Plunder.WasCompleted(nil,0)==true)
        assert(OnboardingNativeReads==0 and OnboardingNativeWrites==0)
        IntroPreferences.lui_dwIntroVideos=true
        IntroPreferences.lui_dwTutorialPrompts=true
        assert(Onboarding.SeasonVideo.WasCompleted(nil,0,3)==false)
        assert(Onboarding.MagmaVideo.WasCompleted(nil,0)==false)
        assert(Onboarding.WARZONE_INTRODUCTION.WasCompleted(nil,0)==false)
        assert(Onboarding.WARZONE_TUTORIAL_GAMEPLAY_INITIATED.WasCompleted(nil,0)==false)
        assert(Onboarding.Plunder.WasCompleted(nil,0)==false)
        assert(OnboardingNativeReads==5 and OnboardingNativeWrites==0)
        IntroPreferences.lui_dwIntroVideos=false
        IntroPreferences.lui_dwTutorialPrompts=false
        local stage=Onboarding.MagmaVideo
        local current=stage.WasCompleted
        MenuBuilder.m_types.replaydwplaylistfillstate().Refresh()
        assert(stage.WasCompleted==current)
        stage.WasCompleted=function() return false end
        MenuBuilder.m_types.replaydwplaylistfillstate().Refresh()
        assert(stage.WasCompleted(nil,0)==true)
        results[#results+1]="Automatic season/mode videos and BR tutorial prompts default off; enabling their dvars delegates to original onboarding checks without changing saved flags, and reloaded stages are repaired idempotently"
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
                   serialized_source=serialized,
                   linked_build=linked,
                   modeled_boundaries="Native rendering/input/model APIs; original builder, checkbox and list Lua execute",
                   game_runs_performed=False,rendered_ui_verified=False)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(receipt,indent=2)+"\n")
    print("PASS: original Lua 5.1 playlist builders, shared toggle, navigation and title fallback")


if __name__ == "__main__":
    main()
