-- Native Replay widgets and one preference shared by MP and Warzone playlists.
-- The marker lives in the stock builder registry; sealed _G stays unchanged.
local marker = "ReplayDWPlaylistFillState"
if not MenuBuilder or not MenuBuilder.IsTypeRegistered or not
    MenuBuilder.BuildRegisteredType or not Engine or not Engine.CBBHFCGDIC or
    not Dvar or not Dvar.IBEGCHEFE or not Dvar.DHEGHJJJHI then
    return 0
end
if MenuBuilder.IsTypeRegistered(marker) then
    return 1
end

local originalBuild = MenuBuilder.BuildRegisteredType
local originalLocalize = Engine.CBBHFCGDIC
local state = { widgets = setmetatable({}, { __mode = "k" }) }
local preference = "replay_dw_autoFillBots"
local scale = _1080p or 1

local function readPreference()
    return Dvar.IBEGCHEFE(preference) == true
end

local function refreshCheckboxes()
    local enabled = readPreference()
    for widget in pairs(state.widgets) do
        widget.Checkbox:SetValue(enabled, true)
    end
end
state.Refresh = refreshCheckboxes

local function buildToggle(options)
    if not MenuBuilder.IsTypeRegistered("GenericCheckBoxButtonWithLabel") then
        return nil
    end
    local toggle = originalBuild("GenericCheckBoxButtonWithLabel", options)
    toggle.id = "ReplayDWFillLobbyBots"
    toggle.Text:setText("Fill lobby with bots", 0)
    toggle.Checkbox:SetValue(readPreference(), true)
    state.widgets[toggle] = true
    toggle:addEventHandler("button_action", function()
        Dvar.DHEGHJJJHI(preference, not readPreference())
        refreshCheckboxes()
    end)
    toggle:addEventHandler("gain_focus", refreshCheckboxes)
    if toggle.AddTooltipData then
        toggle:AddTooltipData(options and options.controllerIndex or 0, {
            tooltipDescription = "Wait 30 seconds, then fill available lobby slots " ..
                "with bots over 15 seconds. The match waits until every bot has joined."
        })
    end
    return toggle
end

local function firstPlaylistButton(panel)
    if panel.ReplayDWOriginalFirst then
        return panel:ReplayDWOriginalFirst()
    end
    return panel.QuickPlayButtonContainer or panel.BRPlayButton or panel.TutorialButton
end

local function connectNavigation(panel)
    local toggle = panel.ReplayDWFillLobbyBots
    local first = firstPlaylistButton(panel)
    if not toggle or not first then
        return
    end
    toggle.navigation = toggle.navigation or {}
    first.navigation = first.navigation or {}
    if first.navigation.up and first.navigation.up ~= toggle then
        toggle.navigation.up = first.navigation.up
        local previous = first.navigation.up
        if previous.navigation and previous.navigation.down == first then
            previous.navigation.down = toggle
        end
    end
    toggle.navigation.down = first
    first.navigation.up = toggle
end

local function addAboveVerticalList(menu, panel, options)
    if not panel or panel.ReplayDWFillLobbyBots then
        return
    end
    local first = firstPlaylistButton(panel)
    local toggle = first and buildToggle(options)
    if not toggle then
        return
    end
    -- Keep this outside the vertical layout: inserting a row in the list
    -- pushes the last Warzone entries behind the stock footer.
    local rect = panel:GetCurrentAnchorsAndPositions()
    toggle:SetAnchorsAndPosition(0, 1, 0, 1,
        rect.left, rect.left + 430 * scale,
        rect.top - 28 * scale, rect.top - 3 * scale)
    menu:addElement(toggle)
    panel.ReplayDWFillLobbyBots = toggle
    if panel.GetFirstButtonWidget then
        panel.ReplayDWOriginalFirst = panel.GetFirstButtonWidget
        panel.GetFirstButtonWidget = function()
            return toggle
        end
    end
    connectNavigation(panel)
end

local function addAboveGrid(menu, options)
    local list = menu.PlaylistList
    if not list or menu.ReplayDWFillLobbyBots then
        return
    end
    local toggle = buildToggle(options)
    if not toggle then
        return
    end
    local rect = list:GetCurrentAnchorsAndPositions()
    toggle:SetAnchorsAndPosition(0, 1, 0, 1,
        rect.left + 34 * scale, rect.left + 430 * scale,
        rect.top - 28 * scale, rect.top - 3 * scale)
    menu:addElement(toggle)
    menu.ReplayDWFillLobbyBots = toggle
    toggle.navigation = { down = list.PlaylistButtons }
    list.PlaylistButtons.navigation = list.PlaylistButtons.navigation or {}
    list.PlaylistButtons.navigation.up = toggle
end

Engine.CBBHFCGDIC = function(key, ...)
    local text = originalLocalize(key, ...)
    if key == "PLAYLIST/BRSOLOSTIM_NAME2" and
        (not text or text == "" or text == key or text == "@" .. key) then
        return "BR Stimulus Solos"
    end
    return text
end

MenuBuilder.BuildRegisteredType = function(kind, options)
    local widget = originalBuild(kind, options)
    local name = string.lower(kind)
    if name == "mpplaymenu" then
        addAboveVerticalList(widget, widget.MPPlayMenuButtons, options)
    elseif name == "brplaymenu" then
        addAboveVerticalList(widget, widget.BRPlayMenuButtons, options)
    elseif name == "playlistmenu" or name == "brplaylistmenu" then
        addAboveGrid(widget, options)
    end
    return widget
end
MenuBuilder.registerType(marker, function()
    return state
end)
return 1
