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


def check_map_vote_native_apis(lua):
    # Stock builders retain their broad model/animation mocks below. Keep this
    # custom panel's much smaller API surface explicit so a misspelled or
    # unavailable Set*/set* call cannot silently succeed in that fallback.
    panel = lua[:lua.index("local function readPreference()")]
    supported = {
        "AcceptsFocusType", "SetAlpha", "SetAnchorsAndPosition", "SetFocusable",
        "SetFont", "SetAlignment", "SetHandleMouse", "SetRGBFromInt",
        "addElement", "addEventHandler", "getFirstChild", "getNextSibling",
        "isInFocus", "processEvent", "setImage", "setText", "gsub",
    }
    used = set(re.findall(r":([A-Za-z_][A-Za-z_0-9]*)\s*\(", panel))
    assert used <= supported, "Unverified map-vote API: " + repr(sorted(used - supported))
    constructors = set(re.findall(r"LUI\.([A-Za-z_][A-Za-z_0-9]*)\.new\s*\(", panel))
    assert constructors <= {"UIElement", "UIButton", "UIText", "UIImage"}
    assert not re.search(r"AddTooltipData|tooltipDescription|SetButtonDescription", panel), "Voting UI must not register tooltips"
    return sorted(used)


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
            self.anchors = {a,b,c,d}
        end
        function nodeMethods:GetCurrentAnchorsAndPositions() return self.rect end
        function nodeMethods:SetLeft(value) self.rect.left=value end
        function nodeMethods:SetRight(value) self.rect.right=value end
        function nodeMethods:SetTop(value)
            self.rect.top=value;self.layoutWrites=(self.layoutWrites or 0)+1
        end
        function nodeMethods:SetBottom(value)
            self.rect.bottom=value;self.layoutWrites=(self.layoutWrites or 0)+1
        end
        function nodeMethods:GetMaxVisibleRows() return assert(self.maxVisibleRows) end
        function nodeMethods:SetMaxVisibleRows(value)
            assert(type(value)=="number" and value>=1)
            self.maxVisibleRows=value
            self.rowWrites=(self.rowWrites or 0)+1
        end
        function nodeMethods:AddArrow(value)
            self.arrows=self.arrows or {};self.arrows[#self.arrows+1]=value
        end
        function nodeMethods:AddItemNumbers(value) self.itemNumbers=value end
        function nodeMethods:SetGridDataSource(value) self.gridDataSource=value end
        function nodeMethods:RefreshContent() self.refreshes=(self.refreshes or 0)+1 end
        function nodeMethods:setText(value) self.text = value end
        function nodeMethods:getText() return self.text end
        function nodeMethods:registerEventHandler(name, callback) self.events[name] = callback end
        nodeMethods.addEventHandler = nodeMethods.registerEventHandler
        function nodeMethods:getRootController() return 0 end
        function nodeMethods:getParent() return self.parent end
        function nodeMethods:getFirstChild() return self.children[1] end
        function nodeMethods:getNextSibling()
            if not self.parent then return nil end
            for index,child in ipairs(self.parent.children) do
                if child==self then return self.parent.children[index+1] end
            end
        end
        function nodeMethods:UnsubscribeFromAllModels() end
        function nodeMethods:RemoveDataLinks() end
        function nodeMethods:ClearLastFocus() self.closed=true end
        function nodeMethods:GetCurrentMenu() return nil end
        function nodeMethods:GetPromptContainer() return MakeNode() end
        function nodeMethods:Wait() return {} end
        function nodeMethods:RemoveElement(child)
            for index, value in ipairs(self.children) do
                if value == child then table.remove(self.children,index);break end
            end
            child.parent = nil
        end
        function nodeMethods:SetHandleMouse(value) self.mouse = value end
        function nodeMethods:SetAlpha(value) self.alpha = value end
        function nodeMethods:SetFont(value)
            assert(value == "main" or value == "bold" or value == "body", "Unverified Replay font")
            self.font = value
        end
        function nodeMethods:SetAlignment(value)
            assert(value ~= nil, "Missing native alignment constant")
            self.alignment = value
        end
        function nodeMethods:SetRGBFromInt(value) self.color = value end
        function nodeMethods:SetRGBFromTable(value) self.colorTable = value end
        function nodeMethods:setImage(value)
            assert(type(value)=="string" and #value>0, "Missing material")
            self.image = value
        end
        function nodeMethods:SetButtonDisabled(value) self.buttonDisabled = value end
        function nodeMethods:SetDataSource(source) self.dataSource = source end
        function nodeMethods:isInFocus() return self.focused == true end
        function nodeMethods:processEvent(event)
            if event.name == "gain_focus" then self.focused = true end
            if event.name == "lose_focus" then self.focused = false end
            if self.events[event.name] then return self.events[event.name](self,event) end
        end
        function nodeMethods:AddTooltipData(controller, value)
            self.tooltip=value;self.tooltipRegistrations=(self.tooltipRegistrations or 0)+1
        end
        function nodeMethods:getLocalRect() return 0,0,430,25 end
        function nodeMethods:getElementTextDims() return #self.text * 10,20 end
        local noOperation = function() end
        function MakeNode()
            local events={}
            return setmetatable({children={},events=events,m_eventHandlers=events,rect={left=0,right=430,top=0,bottom=50}}, {
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
        LUI.Alignment = {Left=0,Top=0,Center=1,Right=2}
        LUI.DIRECTION = {horizontal=0,vertical=1}
        LUI.BEARING = {up=0,down=1}
        LUI.DataSourceFromList = {new=function() return {} end}
        LUI.DataSourceInGlobalModel = {new=function() return {GetModel=noOperation,GetValue=function() return 2 end} end}
        LUI.EASING = {outQuadratic=0}
        Engine = {
            DDJFBBJAIG=function() return false end,
            BHFFIBEFFH=noOperation,DCHDDCJCEG=noOperation,
            BHICADFIHA=function() return false end,
            CBBHFCGDIC=function(key,...) return NativeTranslations[key] or key end
        }
        NativeTranslations = {}
        Preference = false
        TournamentAllowed = true
        CustomMaps = " "
        MapSelections = {}
        MapVoteRawMaps = {"mp_backlot","mp_crash","mp_nuketown"}
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
                if name=="NLPONNQNRS" then TournamentAllowed=value;return end
                assert(name=="replay_dw_autoFillBots")
                Preference=value
            end,
            CFHDGABACF=function(name) return name=="MTTRPNMPRP" and 24 or 1 end,
            DHEEJCCJBH=function(name)
                if name=="replay_dw_customMaps" then return CustomMaps end
                for index,key in ipairs({"NSMOLKMMPM","MSQROKTRSN","ROLQKTOMM"}) do
                    if name==key then return MapVoteRawMaps[index] end
                end
                error("Unexpected native string dvar: "..tostring(name))
            end
        }
        CONDITIONS = setmetatable({}, {__index=function() return function() return false end end})
        Lobby = {GFFECBCCF=function() return false end,BGIADHIHAG=function() return false end}
        DataSources = {frontEnd={lobby={inSplitScreen={GetModel=noOperation},memberCount={GetModel=noOperation}}}}
        DataSources.frontEnd.lobby.memberMaxCount={GetModel=noOperation,GetValue=function() return 12 end}
        DataSources.frontEnd.lobby.mapName={GetModel=noOperation}
        ACTIONS = {AnimateSequence=function(widget, sequence) widget.lastSequence=sequence end}
        TWEEN_PROPERTY = setmetatable({}, {__index=function(_, key) return key end})
        SWATCHES = {genericButton={textDefault={},textFocus={},background={},glow={},description={}},
            text={primaryText={}}}
        FONTS = {MainRegular={File="main"},MainBold={File="bold"},BodyRegular={File="body"},
            GetFont=function(value) return value end}
        RegisterMaterial=function(value) return value end
        ToUpperCase=string.upper
        SOUND_SETS={mpMainMenu={move="move",moveUp="up",moveDown="down"}}
        FrontEndScene={ClientCharacters={LocalSquadMember=0},HideAllLobbyCharactersPastIndex=noOperation,
            HideAllCharacters=noOperation,RequestWeaponWorldModels=noOperation}
        OPERATOR={GetSelectedOperatorIndex=function() return 0 end,GetEquippedOperatorSkin=function() return 0,0 end,
            GetWeaponDataFromLoadout=function() return 0,0 end,GetPetForEquippedOperator=function() return 0 end,
            ShowGhostTeaser=noOperation}
        Teams={allies=1,axis=2}
        CoD={SFX={LobbyTextCoalition=0,LobbyTextAllegiance=1,MouseClick=2}}
        FocusType={MouseOver=0}
        LAYOUT={GetElementWidth=function() return 100 end,GetTextWidth=function() return 100 end}
        MP={GetFactionReference=tostring,GetTeamLogo=function() return "logo" end,GetTeamName=tostring,
            LOBBY_PLAYER_COUNT={medium=12}}
        CSV={mpMapTable={file="maps-fixture.csv",cols={ref=0,name=1,loadingImage=2}}}
        MapLookupFixtures={
            mp_backlot={"Backlot","native_backlot_material_fixture"},
            mp_crash={"Crash","native_crash_material_fixture"}
        }
        MapLookupCalls={}
        StringTable={DIFCHIGDFB=function(file,column,ref,resultColumn)
            assert(file==CSV.mpMapTable.file and column==CSV.mpMapTable.cols.ref)
            assert(type(ref)=="string" and (resultColumn==1 or resultColumn==2))
            MapLookupCalls[#MapLookupCalls+1]={ref=ref,column=resultColumn}
            local row=MapLookupFixtures[ref]
            return row and row[resultColumn] or ""
        end}
        Engine.DHFCHIIJCA=noOperation;Engine.BJDBIAGIDA=noOperation;Engine.CBEAHDFCFC=tostring
        Lobby.GetLocalClientTeam=function() return Teams.allies end
        Lobby.UpdateClientCharacters=function() return {} end
        Lobby.BuildFocusArrowWidget=MakeNode;Lobby.UpdateFocusArrow=noOperation
        Lobby.UpdateLocalClientCharacter=noOperation;Lobby.PreloadViewHandsForLocalPlayer=noOperation
        Lobby.PartyState={STARTING=4}
        Lobby.EBDDFIIHID=function() return true end
        Lobby.BGIBDIBHH=function() return NativePartyState,{timeRemaining=30000} end
        Lobby.AllMembersPath="members";Lobby.SquadMembersPath="squad"
        Lobby.GetLobbyMemberDataSourceAtIndex=function() return noOperation end
        Lobby.IsCurrentGameTypeteamBased=function() return true end
        NativePartyState=1
    ''')
    inputs = {}
    for relative, tokens in (
        ("frontend/mp/mapvotebutton.lua.529.lua",
         (":setImage(RegisterMaterial(", ":SetFont(FONTS.GetFont(", ":SetAlignment(LUI.Alignment.Left)")),
        ("frontend/mp/mapvotebuttonbackground.lua.530.lua",
         (":SetRGBFromInt(", 'RegisterMaterial("widg_gradient_top_to_bottom")')),
        ("uieditor/fonts.lua.2103.lua", ("FONTS.MainRegular", "FONTS.BodyRegular")),
        ("ingame/codcasterlayer.lua.976.lua", (":SetMaxVisibleRows(",)),
        ("luigrid.lua.2049.lua", (":GetMaxVisibleRows()",)),
    ):
        native = ORIGINAL / relative
        native_text = native.read_text(encoding="utf-8-sig")
        assert all(token in native_text for token in tokens), "Native widget API evidence changed: " + relative
        inputs[str(native)] = hashlib.sha256(native.read_bytes()).hexdigest()
    map_utils = ORIGINAL / "utils/mp/mputils.lua.2204.lua"
    raw_map_utils = map_utils.read_text(encoding="utf-8-sig")
    vm.execute(raw_map_utils[raw_map_utils.index("function MP.GetMapName("):
                             raw_map_utils.index("function MP.GetGameTypeImage(")])
    inputs[str(map_utils)] = hashlib.sha256(map_utils.read_bytes()).hexdigest()
    element_source = ORIGINAL / "luielement.lua.2044.lua"
    raw_element = element_source.read_text(encoding="utf-8-sig")
    vm.execute(raw_element[raw_element.index("function LUI.UIElement.RemoveFromParent("):
                           raw_element.index("function LUI.UIElement.getFullID(")])
    vm.execute(raw_element[raw_element.index("local function var_0_1(arg_52_0"):
                           raw_element.index("function LUI.UIElement.addAndCallEventHandler(")])
    vm.execute('''
        local create=MakeNode
        MakeNode=function()
            local node=create()
            node.addEventHandler=LUI.UIElement.addEventHandler
            node.closeTree=LUI.UIElement.closeTree
            node.closeChildren=LUI.UIElement.closeChildren
            node.RemoveFromParent=LUI.UIElement.RemoveFromParent
            return node
        end
        for _,kind in pairs(LUI) do
            if type(kind)=="table" and kind.new==create then kind.new=MakeNode;kind.build=MakeNode end
        end
    ''')
    inputs[str(element_source)] = hashlib.sha256(element_source.read_bytes()).hexdigest()
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
        MenuBuilder.registerType("NavigationArrow", function()
            local widget=MakeNode();widget.Arrow=MakeNode();return widget
        end)
        local gridCreate=LUI.UIDataSourceGrid.new
        LUI.UIDataSourceGrid.new=function(options)
            local grid=gridCreate()
            grid.maxVisibleRows=options.maxVisibleRows
            grid.gridOptions=options
            return grid
        end
    ''')
    original("widgets/genericcheckbox.lua.2373.lua", "GenericCheckBoxModule")
    original("frontend/genericcheckboxbuttonwithlabel.lua.288.lua", "CheckBoxLabelModule")
    original("frontend/mp/mpplaymenubuttons.lua.561.lua", "MPPlayButtonsModule")
    original("frontend/mp/brplaymenubuttons.lua.395.lua", "BRPlayButtonsModule")
    original("frontend/playlistlist.lua.742.lua", "PlaylistListModule")
    original("utils/onboarding.lua.2213.lua", "OnboardingModule")
    vm.execute('''
        MenuBuilder.registerType("LobbyMap",MakeNode)
        MenuBuilder.registerType("ChallengesSummary",MakeNode)
        MenuBuilder.registerType("LobbyTeamDetails",function()
            local detail=MakeNode()
            for _,name in ipairs({"LobbyTeamSwitcher","FactionIcon","SuperfactionName","TeamSwitchName","TeamViewName"}) do
                detail[name]=MakeNode()
            end
            detail.LobbyTeamSwitcher.StyledLabel=MakeNode()
            return detail
        end)
    ''')
    original("frontend/lobbymembergrid.lua.336.lua", "NativeLobbyMemberGrid")
    original("frontend/mp/matchmakinglobby.lua.538.lua", "NativeMatchmakingLobby")
    original("frontend/mp/lobbysmallteammatchmade.lua.514.lua", "NativeSmallTeamLobby")
    flow_path = ORIGINAL / "frontend/mp/lobbyflowwidget.lua.503.lua"
    flow_source = flow_path.read_text(encoding="utf-8-sig")
    vm.globals().NativeLobbyFlow = vm.execute(
        flow_source[:flow_source.index("local function var_0_12(")] +
        "return { UpdateLobbyBasedOnMatchmakerState=var_0_9, UpdateLobbyStatus=var_0_10, "
        "GetMatchMadeWidgetToBuild=var_0_3, AddMatchMadeWidget=var_0_4, UpdateLobbyState=var_0_5, "
        "ReplaceLobbyWidget=var_0_8, UpdateParentLobbyStatus=var_0_7, InMatchMadeState=var_0_2}",
        "NativeLobbyFlowSpec")
    inputs[str(flow_path)] = hashlib.sha256(flow_path.read_bytes()).hexdigest()
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
    map_vote_apis = check_map_vote_native_apis(source.read_text())
    fonts = vm.globals().FONTS
    title_font = fonts.MainBold
    fonts.MainBold = None
    assert vm.execute(source.read_text()) == 0
    assert not vm.eval('MenuBuilder.IsTypeRegistered("ReplayDWPlaylistFillState")')
    fonts.MainBold = title_font
    assert vm.execute(source.read_text()) == 1
    checks = vm.execute(r'''
        local options={controllerIndex=0}
        assert(TournamentAllowed==true)
        local brProbe=MenuBuilder.BuildRegisteredType("BRPlayMenu",options)
        assert(TournamentAllowed==true)
        local mpMenu=MenuBuilder.BuildRegisteredType("MPPlayMenu",options)
        assert(TournamentAllowed==false)
        local brMenu=MenuBuilder.BuildRegisteredType("BRPlayMenu",options)
        local mp,br=mpMenu.MPPlayMenuButtons,brMenu.BRPlayMenuButtons
        local grid=MenuBuilder.BuildRegisteredType("PlaylistMenu",options)
        local brGrid=MenuBuilder.BuildRegisteredType("BRPlaylistMenu",options)
        local results={}
        local ballot=MenuBuilder.m_types.replaydwplaylistfillstate()
        assert(not mpMenu.ReplayDWMapVote and not brMenu.ReplayDWMapVote)
        local nativeRoster=MenuBuilder.BuildRegisteredType("LobbyMemberGrid",{controllerIndex=0,modelPath="members"})
        local rosterFields={"PlayerList","PlayerCount","Line","VerticalMinimalScrollbar","ArrowUp","ArrowDown","ListCount"}
        local function assertRosterUntouched(roster)
            assert(roster.PlayerList:GetMaxVisibleRows()==11 and not roster.PlayerList.rowWrites)
            for _,field in ipairs(rosterFields) do
                local original,current=nativeRoster[field],roster[field]
                for _,edge in ipairs({"left","right","top","bottom"}) do
                    assert(original.rect[edge]==current.rect[edge], "Vote UI moved native roster "..field.." "..edge)
                end
                assert(original.layoutWrites==current.layoutWrites, "Vote UI resized native roster "..field)
            end
        end
        local ballotMenu=MenuBuilder.BuildRegisteredType("MatchmakingLobby",options)
        local panel=ballotMenu.ReplayDWMapVote
        assert(panel and panel.alpha==0)
        assertRosterUntouched(ballotMenu.lobbyMemberGrid)
        for _,button in ipairs(panel.Choices) do assert(not button:AcceptsFocusType(0)) end
        local function localRect(node,width,height)
            local r,a=node.rect,assert(node.anchors)
            return {left=a[1]*width+r.left,right=(1-a[2])*width+r.right,
                    top=a[3]*height+r.top,bottom=(1-a[4])*height+r.bottom}
        end
        local function inside(node,width,height)
            local r=localRect(node,width,height)
            assert(r.left>=0 and r.right<=width and r.top>=0 and r.bottom<=height)
            assert(r.right>r.left and r.bottom>r.top)
            return r
        end
        assert(panel.rect.left==96 and panel.rect.right==768 and panel.rect.top==849 and panel.rect.bottom==979)
        for _,field in ipairs(rosterFields) do
            assert(panel.rect.top>=nativeRoster[field].rect.bottom, "Map ballot overlaps native roster "..field)
        end
        assert(panel.rect.left<=96 and panel.rect.right>=526 and panel.rect.top<=849 and panel.rect.bottom>=979,
            "Map ballot must fully cover the native map tile")
        assert(panel.Background.alpha==1 and panel.Background.image=="white", "Map tile cover must be opaque")
        assert(panel.Title.font=="bold" and panel.Title.alignment==LUI.Alignment.Left)
        assert(panel.Countdown.font and panel.Countdown.alignment~=nil)
        assert(not panel.Status, "Compact voting panel must have no footer")
        inside(panel.Title,672,130);inside(panel.Countdown,672,130)
        assert(panel.Title.rect.top==8 and panel.Title.rect.bottom==24)
        local function assertNoTooltips(node)
            assert(not node.tooltip and not node.tooltipDescription and not node.buttonDescription
                and not node.tooltipRegistrations, "Voting subtree registered a tooltip")
            for _,child in ipairs(node.children) do assertNoTooltips(child) end
        end
        assertNoTooltips(panel)
        local previous
        for _,card in ipairs(panel.Choices) do
            local r=inside(card,672,130)
            assert(r.top==35 and r.bottom==121 and r.right-r.left==208)
            if previous then assert(previous.right<r.left and previous.top==r.top) end
            previous=r
            for _,text in ipairs({card.Label,card.Votes,card.Selection}) do
                assert(text.font and text.alignment~=nil, "Ballot text lacks an explicit native font/alignment")
                inside(text,208,86)
            end
            assert(card.Label.font=="bold" and card.Votes.font=="main")
            assert(card.Image and card.Scrim and card.Background and card.Accent and #card.Border==4)
            local image=inside(card.Image,208,86)
            assert(image.left==1 and image.right==207 and image.top==1 and image.bottom==85)
            assert(card.Label.rect.top==48 and card.Label.rect.bottom==64)
            assert(card.Votes.rect.top==66 and card.Votes.rect.bottom==82)
            assert(card.Selection.rect.top==27 and card.Selection.rect.bottom==41)
            assert(card.Background.image=="white" and card.Accent.image=="white")
            for _,border in ipairs(card.Border) do assert(border.image=="white") end
        end
        local choices={{name="Backlot",votes=1},{name="Crash",votes=2},{name="Office",votes=0}}
        ballot.RefreshMapVote({active=true,complete=false,round=10,selected=0,remaining=12,choices=choices})
        assert(panel.alpha==1 and string.upper(panel.Choices[1].Label.text)=="BACKLOT")
        for _,kind in ipairs({"MPPlayMenu","BRPlayMenu"}) do
            local home=MenuBuilder.BuildRegisteredType(kind,options)
            assert(not home.ReplayDWMapVote, "Cached active ballot leaked onto rebuilt home Play menu")
        end
        assert(panel.Choices[1].Image.image=="native_backlot_material_fixture")
        assert(panel.Choices[2].Image.image=="native_crash_material_fixture")
        assert(panel.Choices[3].Image.image=="loading_mp_generic_bg")
        assert(panel.Choices[1].Votes.text=="1 VOTE" and panel.Choices[2].Votes.text=="2 VOTES")
        assert(panel.Choices[3].Votes.text=="0 VOTES")
        assert(panel.Title.text=="VOTE FOR THE NEXT MAP" and panel.Countdown.text=="12s")
        assertRosterUntouched(ballotMenu.lobbyMemberGrid)
        assert(panel.Choices[1].navigation.right==panel.Choices[2])
        assert(panel.Choices[2].navigation.left==panel.Choices[1])
        assert(panel.Choices[2].navigation.right==panel.Choices[3])
        assert(panel.Choices[3].navigation.left==panel.Choices[2])
        assert(panel.Choices[1].navigation.left==panel.Anchor and panel.Choices[3].navigation.right==panel.Anchor)
        local function style(card)
            local values={tostring(card.Background.color),tostring(card.Background.alpha),
                tostring(card.Accent.color),tostring(card.Accent.alpha)}
            for _,border in ipairs(card.Border) do
                values[#values+1]=tostring(border.color);values[#values+1]=tostring(border.alpha)
            end
            return table.concat(values,",")
        end
        local card=panel.Choices[2]
        local normal=style(card)
        card:processEvent({name="button_over",controller=0})
        assert(style(card)~=normal, "Mouse hover has no visible styling")
        card:processEvent({name="button_up",controller=0})
        assert(style(card)==normal)
        card:processEvent({name="gain_focus",controller=0})
        assert(style(card)~=normal, "Controller focus has no visible styling")
        card:processEvent({name="lose_focus",controller=0})
        assert(style(card)==normal)
        results[#results+1]="Three bounded horizontal image cards cover the native map tile with an opaque background, explicit Replay fonts/alignment, native image lookup/fallback, countdown and visible focus styles; no footer or tooltips are registered"
        ballot.RefreshMapVote({active=true,complete=false,round=10,selected=0,remaining=12,choices={
            {name="Backlot",votes=1},{name="Crash",votes=2},{name="Office",votes=0}}})
        assert(panel.Choices[3].navigation.down==panel.Choices[1])
        assert(panel.Choices[1].navigation.up==panel.Choices[3])
        panel.Choices[3].events.button_action()
        assert(MapSelections[1]=="replay_dw_mapVoteSelectC")
        assert(panel.Choices[3].Selection.text=="VOTING...")
        ballot.RefreshMapVote({active=true,complete=false,round=10,selected=0,remaining=11,choices=choices})
        assert(panel.Choices[3].Selection.text=="VOTING...", "Polling erased an unacknowledged vote")
        ballot.RefreshMapVote({active=true,complete=false,round=10,selected=3,remaining=10,choices=choices})
        assert(panel.Choices[3].Selection.text=="YOUR VOTE")
        panel.Choices[1].events.button_action()
        assert(MapSelections[2]=="replay_dw_mapVoteSelectA" and panel.Choices[1].Selection.text=="VOTING...")
        ballot.RefreshMapVote({active=true,complete=false,round=10,selected=3,remaining=9,choices=choices})
        assert(panel.Choices[1].Selection.text=="VOTING...")
        ballot.RefreshMapVote({active=true,complete=false,round=10,selected=1,remaining=8,choices=choices})
        assert(panel.Choices[1].Selection.text=="YOUR VOTE")
        panel.Choices[2].events.button_action()
        assert(MapSelections[3]=="replay_dw_mapVoteSelectB" and panel.Choices[2].Selection.text=="VOTING...")
        ballot.RefreshMapVote({active=true,complete=false,round=11,selected=0,remaining=20,choices=choices})
        for _,button in ipairs(panel.Choices) do
            assert(button.Selection.text~="VOTING..." and button.Selection.text~="YOUR VOTE")
        end
        panel.Choices[3].events.button_action()
        ballot.RefreshMapVote({active=false})
        ballot.RefreshMapVote({active=true,complete=false,round=11,selected=0,remaining=19,choices=choices})
        for _,button in ipairs(panel.Choices) do assert(button.Selection.text~="VOTING...") end
        panel.Choices[1].events.button_action()
        MapVoteRawMaps[1]="mp_vacant"
        ballot.RefreshMapVote({active=true,complete=false,round=11,selected=0,remaining=18,choices={
            {name="Vacant",votes=0},{name="Crash",votes=0},{name="Office",votes=0}}})
        for _,button in ipairs(panel.Choices) do assert(button.Selection.text~="VOTING...") end
        MapVoteRawMaps[1]="mp_backlot"
        results[#results+1]="A/B/C native vote actions show pending submission until native selected acknowledges, permit changed votes, and clear stale selection across rounds and inactive ballots"
        panel.Choices[3]:processEvent({name="gain_focus"})
        ballot.RefreshMapVote({active=true,complete=false,choices={{name="Backlot",votes=1}}})
        assert(not panel.Choices[3]:AcceptsFocusType(0) and not panel.Choices[3]:isInFocus())
        assert(panel.Anchor:isInFocus() and panel.Choices[1].navigation.up==panel.Choices[1])
        panel.Choices[1]:processEvent({name="gain_focus"})
        ballot.RefreshMapVote({active=true,complete=true,choices={{name="Backlot",votes=1,winner=true}}})
        assert(not panel.Choices[1]:isInFocus() and not panel.Choices[1]:AcceptsFocusType(0))
        assert(panel.alpha==0, "Completed ballot still covers native map tile")
        assertRosterUntouched(ballotMenu.lobbyMemberGrid)
        local submitted=#MapSelections
        panel.Choices[1].events.button_action(); assert(#MapSelections==submitted)
        ballot.RefreshMapVote({active=false})
        assert(panel.alpha==0)
        for _,button in ipairs(panel.Choices) do assert(not button:AcceptsFocusType(0) and not button.mouse) end
        results[#results+1]="Native map-choice actions select A/B/C; reduced, completed and inactive ballots retire controller focus through original UIButton focusability methods"
        local flow=MakeNode()
        flow._state=1
        for name,callback in pairs(NativeLobbyFlow) do flow[name]=callback end
        flow.CRMMain=MakeNode()
        function flow.CRMMain:ShouldHideCRM() return false end
        function flow.CRMMain:HideCRM() end
        flow.Nat=MakeNode();flow.JoinableStatus=MakeNode()
        flow:UpdateLobbyBasedOnMatchmakerState(0)
        assert(flow._state==2 and flow.matchMakingLobby.id=="MatchmakingLobby")
        local waiting=flow.matchMakingLobby
        assert(waiting.ReplayDWMapVote and waiting.ReplayDWMapVote.Anchor==waiting.lobbyMemberGrid)
        local roster=waiting.lobbyMemberGrid
        assertRosterUntouched(roster)
        local rosterData=roster.PlayerList.gridDataSource
        ballot.RefreshMapVote({active=true,complete=false,remaining=20,choices={{name="Backlot",votes=1},{name="Crash",votes=0}}})
        assert(waiting.ReplayDWMapVote.alpha==1 and waiting.lobbyMemberGrid.navigation.right==waiting.ReplayDWMapVote.Choices[1])
        assertRosterUntouched(roster)
        ballot.RefreshMapVote({active=true,complete=false,remaining=19,choices={{name="Backlot",votes=1},{name="Crash",votes=0}}})
        assert(roster.PlayerList.gridDataSource==rosterData)
        assertRosterUntouched(roster)
        ballot.RefreshMapVote({active=true,complete=true,remaining=0,choices={{name="Backlot",votes=1,winner=true},{name="Crash",votes=0}}})
        assert(waiting.ReplayDWMapVote.alpha==0)
        assertRosterUntouched(roster)
        ballot.RefreshMapVote({active=false})
        assert(waiting.ReplayDWMapVote.alpha==0)
        assertRosterUntouched(roster)
        ballot.RefreshMapVote({active=true,complete=false,remaining=20,choices={{name="Backlot",votes=1},{name="Crash",votes=0}}})
        assertRosterUntouched(roster)
        flow:UpdateLobbyStatus(0)
        assert(flow._state==2 and flow.matchMakingLobby==waiting)
        NativePartyState=Lobby.PartyState.STARTING
        flow:UpdateLobbyStatus(0)
        assert(flow._state==3 and flow.matchMadeLobby.id=="LobbySmallTeamMatchmade")
        local matched=flow.matchMadeLobby
        assert(matched.ReplayDWMapVote and not matched.ReplayDWMapVote.Anchor)
        matched:processEvent({name="update_lobby",controller=0})
        ballot.RefreshMapVote({active=true,complete=false,remaining=19,choices={{name="Backlot",votes=1},{name="Crash",votes=0}}})
        assert(matched.ReplayDWMapVote.Anchor==matched.lobbyMemberGrid)
        assertRosterUntouched(matched.lobbyMemberGrid)
        assert(matched.lobbyMemberGrid.navigation.right==matched.ReplayDWMapVote.Choices[1])
        assert(matched.ReplayDWMapVote.Choices[1].navigation.left==matched.lobbyMemberGrid)
        results[#results+1]="Original LobbyFlowWidget shows votes in MatchmakingLobby before STARTING, keeps the native transition, and binds the timer-created small-team roster controller route"
        results[#results+1]="Original LobbyMemberGrid retains all eleven visible rows, every native position and its data source with zero extra row/layout writes across active, refreshed, completed and inactive ballots"
        results[#results+1]="Home MP/BR Play menus never build map ballots even with cached active voting, preventing the exit-to-home overlay from waiting for a backend poll"
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
        results[#results+1]="Building the MP play menu clears online_tournament_enabled (tournament entry hidden); BR builds leave it untouched"
        assert(Engine.CBBHFCGDIC("PLAYLIST/NUKETOWN_TDM")=="Nuketown TDM")
        assert(Engine.CBBHFCGDIC("LUA_MENU_MP/NUKETOWN_TDM_DESC")=="Team Deathmatch on Nuketown.")
        NativeTranslations["PLAYLIST/NUKETOWN_TDM"]="Native Nuketown"
        assert(Engine.CBBHFCGDIC("PLAYLIST/NUKETOWN_TDM")=="Native Nuketown")
        NativeTranslations["PLAYLIST/NUKETOWN_TDM"]=nil
        local nuke=MenuBuilder.BuildRegisteredType("PlaylistFeaturedButton",options)
        nuke.modelName="PLAYLIST/NUKETOWN_TDM";nuke.RefreshModel()
        assert(string.sub(nuke.Name:getText(),1,12)=="NUKETOWN TDM")
        nuke.DisabledText=MakeNode()
        local function source(id) return {ID={GetValue=function(_,controller) assert(controller==0);return id end}} end
        CustomMaps=" mp_crash "
        nuke:SetDataSource(source(65),0)
        assert(nuke.dataSource.ID:GetValue(0)==65 and nuke.buttonDisabled==true)
        assert(nuke.DisabledText.text=="Requires the Nuketown map files")
        nuke:SetButtonDisabled(false)
        assert(nuke.buttonDisabled==true)
        CustomMaps=" mp_crash mp_nuketown "
        nuke:SetButtonDisabled(false)
        assert(nuke.buttonDisabled==false)
        nuke:SetButtonDisabled(true)
        assert(nuke.buttonDisabled==true)
        CustomMaps=" "
        local other=MenuBuilder.BuildRegisteredType("PlaylistFeaturedButton",options)
        other:SetDataSource(source(16),0)
        other:SetButtonDisabled(false)
        assert(other.buttonDisabled==false)
        CustomMaps=" mp_nuketown_c "
        nuke:SetDataSource(source(65),0)
        assert(nuke.buttonDisabled==true)
        MenuBuilder.registerType("LobbyStatusPanel", function()
            local widget=MakeNode();widget.Title=MakeNode()
            widget.Title:setText(string.upper("PLAYLIST/NUKETOWN_TDM"))
            return widget
        end)
        local status=MenuBuilder.BuildRegisteredType("LobbyStatusPanel",options)
        assert(string.sub(status.Title:getText(),1,12)=="NUKETOWN TDM")
        status.Title:setText("@PLAYLIST/NUKETOWN_TDM");assert(string.sub(status.Title:getText(),1,12)=="NUKETOWN TDM")
        status.Title:setText("TEAM DEATHMATCH");assert(status.Title:getText()=="TEAM DEATHMATCH")
        results[#results+1]="Nuketown TDM title/description fall back only when untranslated; the public lobby status title is repaired; its featured button stays disabled unless replay_dw_customMaps lists exactly mp_nuketown, other playlists are unaffected"
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
        local retained={}
        local retiredCalls=0
        local function guardTree(node)
            retained[#retained+1]=node
            for _,name in ipairs({"SetAlpha","setText","setImage","SetRGBFromInt","SetFont",
                    "SetTop","SetBottom","SetMaxVisibleRows",
                    "SetAlignment","SetHandleMouse","SetFocusable","isInFocus","processEvent","SetValue"}) do
                local original=node[name]
                if original then
                    node[name]=function(self,...)
                        if self.closed then retiredCalls=retiredCalls+1;error("Native call on closed "..tostring(self.id)..":"..name) end
                        return original(self,...)
                    end
                end
            end
            for _,child in ipairs(node.children) do guardTree(child) end
        end
        local function liveBallot()
            ballot.RefreshMapVote({active=true,complete=false,remaining=10,
                choices={{name="Backlot",votes=1},{name="Crash",votes=0}}})
        end
        local function refreshRetained()
            liveBallot()
            ballot.RefreshMapVote({active=false})
            ballot.Refresh()
            assert(retiredCalls==0)
        end
        local oldToggle=MenuBuilder.m_types.genericcheckboxbuttonwithlabel
        local legacyClosed=0
        MenuBuilder.m_types.genericcheckboxbuttonwithlabel=function(...)
            local toggle=oldToggle(...)
            toggle:addEventHandler("on_close",function() legacyClosed=legacyClosed+1 end)
            return toggle
        end
        local closedMenu=MenuBuilder.BuildRegisteredType("MPPlayMenu",options)
        local closedLobby=MenuBuilder.BuildRegisteredType("MatchmakingLobby",options)
        local closedPanel=closedLobby.ReplayDWMapVote
        local closedToggle=closedMenu.MPPlayMenuButtons.ReplayDWFillLobbyBots
        liveBallot()
        assert(closedPanel.alpha==1)
        guardTree(closedMenu)
        guardTree(closedLobby)
        closedLobby:closeTree()
        assert(closedPanel.ReplayDWRetired and closedPanel.closed and not closedPanel.parent)
        assert(ballot.mapVotes[closedPanel]==nil, "Lobby close waited for a ballot refresh")
        local exitHome=MenuBuilder.BuildRegisteredType("MPPlayMenu",options)
        assert(not exitHome.ReplayDWMapVote and ballot.ballot.active)
        closedMenu:closeTree()
        assert(legacyClosed==1 and closedPanel.ReplayDWRetired and closedToggle.ReplayDWRetired)
        assert(ballot.mapVotes[closedPanel]==nil and ballot.widgets[closedToggle]==nil)
        refreshRetained()
        local childMenu=MenuBuilder.BuildRegisteredType("MPPlayMenu",options)
        local childLobby=MenuBuilder.BuildRegisteredType("MatchmakingLobby",options)
        local childPanel=childLobby.ReplayDWMapVote
        local childToggle=childMenu.MPPlayMenuButtons.ReplayDWFillLobbyBots
        guardTree(childMenu)
        guardTree(childLobby)
        childPanel.Choices[2]:closeTree()
        assert(childPanel.ReplayDWRetired and ballot.mapVotes[childPanel]==nil)
        childToggle.Checkbox:closeTree()
        refreshRetained()
        assert(childPanel.ReplayDWRetired and childToggle.ReplayDWRetired)
        refreshRetained()
        for _,event in ipairs({"lose_focus","gain_focus"}) do
            local reentrant=MenuBuilder.BuildRegisteredType("MatchmakingLobby",options)
            local reentrantPanel=reentrant.ReplayDWMapVote
            liveBallot()
            reentrantPanel.Choices[1]:processEvent({name="gain_focus"})
            local target=event=="lose_focus" and reentrantPanel.Choices[1] or reentrantPanel.Anchor
            target:addEventHandler(event,function() reentrant:closeTree() end)
            guardTree(reentrant)
            ballot.RefreshMapVote({active=false})
            assert(reentrantPanel.ReplayDWRetired)
            refreshRetained()
        end
        local replacing=MenuBuilder.BuildRegisteredType("MatchmakingLobby",options)
        local replacingPanel=replacing.ReplayDWMapVote
        local oldAnchor=replacing.lobbyMemberGrid
        liveBallot()
        assert(replacingPanel.Choices[2].navigation.right==oldAnchor)
        guardTree(oldAnchor)
        oldAnchor:closeTree()
        for _,button in ipairs(replacingPanel.Choices) do
            assert(button.navigation.left~=oldAnchor and button.navigation.right~=oldAnchor,
                "Horizontal vote navigation retains a closed roster anchor")
        end
        refreshRetained()
        assert(not replacingPanel.ReplayDWRetired and not replacingPanel.Anchor)
        local newAnchor=MenuBuilder.BuildRegisteredType("LobbyMemberGrid",{controllerIndex=0,modelPath="members"})
        replacing.lobbyMemberGrid=newAnchor
        replacing:addElement(newAnchor)
        liveBallot()
        assert(replacingPanel.Anchor==newAnchor and newAnchor.navigation.right==replacingPanel.Choices[1])
        assert(replacingPanel.Choices[1].navigation.left==newAnchor)
        assertRosterUntouched(newAnchor)
        ballot.RefreshMapVote({active=false})
        local closingMenu=MenuBuilder.BuildRegisteredType("MatchmakingLobby",options)
        local closingPanel,closingAnchor=closingMenu.ReplayDWMapVote,closingMenu.lobbyMemberGrid
        liveBallot()
        assertRosterUntouched(closingAnchor)
        guardTree(closingMenu)
        closingPanel:closeTree()
        assert(closingPanel.ReplayDWRetired and closingPanel.closed and not closingPanel.parent)
        assertRosterUntouched(closingAnchor)
        assert(not closingAnchor.navigation.right)
        refreshRetained()
        assert(#retained>0 and retiredCalls==0)
        results[#results+1]="Original closeTree/addEventHandler retire panels and toggle subtrees synchronously while preserving prior handlers; strongly retained closed nodes receive zero later refresh/focus calls, including reentrant lose/gain focus and replaced roster anchors"
        return results
    ''')
    old_builder = vm.globals().MenuBuilder.BuildRegisteredType
    assert vm.execute(source.read_text()) == 1
    # Compare through Lua equality, which retains exact closure identity.
    compare = vm.eval("function(previous) return previous==MenuBuilder.BuildRegisteredType end")
    assert compare(old_builder)
    items = [checks[i] for i in range(1, len(checks) + 1)]
    items.append("Absent native title fonts defer installation without registering the marker; installation retries successfully after fonts become available")
    items.append("Repeated installation is idempotent and creates no sealed global/module fields")
    receipt = dict(passed=True,checks=items,source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                   original_lua_inputs=inputs,lua_version=vm.eval("_VERSION"),
                   map_vote_verified_api_surface=map_vote_apis,
                   serialized_source=serialized,
                   linked_build=linked,
                   modeled_boundaries="Native rendering/input/model APIs; original builder, checkbox and list Lua execute",
                   game_runs_performed=False,rendered_ui_verified=False)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(receipt,indent=2)+"\n")
    print("PASS: original Lua 5.1 playlist builders, shared toggle, navigation and title fallback")


if __name__ == "__main__":
    main()
