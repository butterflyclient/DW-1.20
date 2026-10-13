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
state.mapVotes = setmetatable({}, { __mode = "k" })
state.ballot = { active = false, choices = {} }
state.presentation = setmetatable({}, { __mode = "k" })
local preference = "replay_dw_autoFillBots"
local scale = _1080p or 1
local closedAnchors = setmetatable({}, { __mode = "k" })

local function watchCloseTree(widget, retire)
    widget:addEventHandler("on_close", retire)
    local child = widget:getFirstChild()
    while child do
        watchCloseTree(child, retire)
        child = child:getNextSibling()
    end
end

local function detachAnchor(panel)
    local anchor = panel.Anchor
    if anchor then
        if anchor.navigation and anchor.navigation.right == panel.Choices[1] then
            anchor.navigation.right = panel.PreviousRight
        end
        for _, button in ipairs(panel.Choices) do
            if button.navigation.left == anchor then button.navigation.left = nil end
        end
    end
    panel.Anchor, panel.PreviousRight = nil, nil
end

local function bindAnchor(panel, anchor)
    if not anchor or closedAnchors[anchor] or panel.ReplayDWRetired then return end
    panel.Anchor = anchor
    panel.PreviousRight = anchor.navigation and anchor.navigation.right
    for _, button in ipairs(panel.Choices) do button.navigation.left = anchor end
    anchor:addEventHandler("on_close", function()
        closedAnchors[anchor] = true
        if panel.Anchor == anchor then detachAnchor(panel) end
    end)
end

local function retireMapVote(panel)
    if panel.ReplayDWRetired then return end
    panel.ReplayDWRetired = true
    state.mapVotes[panel] = nil
    detachAnchor(panel)
end

local function refreshMapVote(panel, ballot)
    if panel.ReplayDWRetired then return end
    -- Small-team lobbies create their roster on the first update_lobby timer.
    -- Bind its existing controller route once that native child is available.
    if not panel.Anchor and panel.Menu.lobbyMemberGrid then
        bindAnchor(panel, panel.Menu.lobbyMemberGrid)
    end
    panel:SetAlpha(ballot.active and 1 or 0, 0)
    panel.Title:setText(ballot.complete and "Map selected" or
        ("Vote for the next map  •  " .. tostring(ballot.remaining or 0) .. "s"), 0)
    for index, button in ipairs(panel.Choices) do
        if panel.ReplayDWRetired then return end
        local choice = ballot.choices and ballot.choices[index]
        local enabled = ballot.active and choice ~= nil and not ballot.complete
        local retiringFocus = not enabled and button:isInFocus()
        button:SetAlpha(choice and 1 or 0, 0)
        button:SetHandleMouse(enabled)
        button:SetFocusable(enabled)
        if retiringFocus then
            button:processEvent({ name = "lose_focus", controller = panel.Controller })
            if panel.ReplayDWRetired then return end
            if panel.Anchor then panel.Anchor:processEvent({ name = "gain_focus", controller = panel.Controller }) end
            if panel.ReplayDWRetired then return end
        end
        if choice then
            local name = choice.name:gsub("^mp_", ""):gsub("_", " ")
            button.Label:setText((choice.winner and "✓  " or "") .. name ..
                "   (" .. tostring(choice.votes or 0) .. " votes)", 0)
            local count = #ballot.choices
            button.navigation.up = panel.Choices[index == 1 and count or index - 1]
            button.navigation.down = panel.Choices[index == count and 1 or index + 1]
        end
    end
    if panel.Anchor then
        panel.Anchor.navigation = panel.Anchor.navigation or {}
        if ballot.active and not ballot.complete then
            panel.Anchor.navigation.right = panel.Choices[1]
        elseif panel.Anchor.navigation.right == panel.Choices[1] then
            panel.Anchor.navigation.right = panel.PreviousRight
        end
    end
end

state.RefreshMapVote = function(ballot)
    state.ballot = ballot
    for panel in pairs(state.mapVotes) do refreshMapVote(panel, ballot) end
end

local function addMapVote(menu, options, anchor)
    if menu.ReplayDWMapVote or not LUI or not LUI.UIElement or not LUI.UIButton or not LUI.UIText then return end
    local panel = LUI.UIElement.new()
    panel.id = "ReplayDWMapVote"
    panel:SetAnchorsAndPosition(0, 1, 0, 1, 660 * scale, 1050 * scale, 430 * scale, 680 * scale)
    panel.Title = LUI.UIText.new()
    panel.Title:SetAnchorsAndPosition(0, 0, 0, 1, 0, 0, 0, 30 * scale)
    panel:addElement(panel.Title)
    panel.Choices = {}
    panel.Menu = menu
    panel.Controller = options and options.controllerIndex or 0
    local selectors = { "replay_dw_mapVoteSelectA", "replay_dw_mapVoteSelectB", "replay_dw_mapVoteSelectC" }
    for index = 1, 3 do
        local button = LUI.UIButton.new()
        button.id = "ReplayDWMapChoice" .. tostring(index)
        button:SetAnchorsAndPosition(0, 0, 0, 1, 0, 0, (36 + (index - 1) * 52) * scale, (82 + (index - 1) * 52) * scale)
        button.Label = LUI.UIText.new()
        button.Label:SetAnchorsAndPosition(0, 0, 0, 0, 8 * scale, -8 * scale, 8 * scale, -8 * scale)
        button:addElement(button.Label)
        button:addEventHandler("button_action", function()
            local ballot = state.ballot
            if not panel.ReplayDWRetired and ballot.active and not ballot.complete and ballot.choices[index] then
                Dvar.DHEGHJJJHI(selectors[index], true)
            end
        end)
        button.navigation = {}
        button.navigation.left = anchor
        panel.Choices[index] = button
        panel:addElement(button)
    end
    for index, button in ipairs(panel.Choices) do
        button.navigation.up = panel.Choices[index == 1 and 3 or index - 1]
        button.navigation.down = panel.Choices[index == 3 and 1 or index + 1]
    end
    menu:addElement(panel)
    menu.ReplayDWMapVote = panel
    watchCloseTree(panel, function() retireMapVote(panel) end)
    menu:addEventHandler("on_close", function() retireMapVote(panel) end)
    bindAnchor(panel, anchor)
    state.mapVotes[panel] = true
    refreshMapVote(panel, state.ballot)
end

local function readPreference()
    return Dvar.IBEGCHEFE(preference) == true
end

local function refreshCheckboxes()
    local enabled = readPreference()
    for widget in pairs(state.widgets) do
        if not widget.ReplayDWRetired then widget.Checkbox:SetValue(enabled, true) end
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
    watchCloseTree(toggle, function()
        toggle.ReplayDWRetired = true
        state.widgets[toggle] = nil
    end)
    toggle:addEventHandler("button_action", function()
        if toggle.ReplayDWRetired then return end
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

local function playlistTitle(text)
    if text == "PLAYLIST/BRSOLOSTIM_NAME2" or
        text == "@PLAYLIST/BRSOLOSTIM_NAME2" then
        return "BR STIMULUS SOLOS"
    end
    return text
end

local function repairPlaylistTitle(widget)
    local name = widget and (widget.Name or widget.GamemodeName)
    if not name or name.ReplayDWTitleFixed then
        return
    end
    -- These stock buttons read their already localized data model directly;
    -- their subscription callbacks do not call Engine.Localize again.
    local originalSetText = name.setText
    name.setText = function(element, text, ...)
        return originalSetText(element, playlistTitle(text), ...)
    end
    name.ReplayDWTitleFixed = true
    local current = name:getText()
    if playlistTitle(current) ~= current then
        name:setText(current, 0)
    end
end

local function installPresentationGates()
    local onboarding = rawget(_G, "Onboarding")
    if not onboarding then
        return
    end
    local function gate(name, preference)
        local stage = onboarding[name]
        local original = stage and stage.WasCompleted
        if type(original) ~= "function" or state.presentation[stage] == original then
            return
        end
        local wrapped = function(...)
            if Dvar.IBEGCHEFE(preference) ~= true then
                return true
            end
            return original(...)
        end
        stage.WasCompleted = wrapped
        state.presentation[stage] = wrapped
    end
    -- Gate automatic presentation only. Keep the original saved flags and
    -- MarkCompleted methods intact, including explicit training/trailer actions.
    gate("SeasonVideo", "lui_dwIntroVideos")
    gate("MagmaVideo", "lui_dwIntroVideos")
    gate("WARZONE_INTRODUCTION", "lui_dwTutorialPrompts")
    gate("WARZONE_TUTORIAL_GAMEPLAY_INITIATED", "lui_dwTutorialPrompts")
    gate("Plunder", "lui_dwTutorialPrompts")
end

state.Refresh = function()
    refreshCheckboxes()
    installPresentationGates()
end
installPresentationGates()

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
        addMapVote(widget, options, firstPlaylistButton(widget.MPPlayMenuButtons))
    elseif name == "brplaymenu" then
        addAboveVerticalList(widget, widget.BRPlayMenuButtons, options)
        addMapVote(widget, options, firstPlaylistButton(widget.BRPlayMenuButtons))
    elseif name == "matchmakinglobby" or name == "lobbysmallteammatchmade" or
        name == "lobbyindividualmatchmade" or name == "lobbylpcmatchmade" or name == "lobbybattleroyale" then
        -- LobbyFlowWidget holds MatchmakingLobby until native STARTING, then
        -- chooses the small-team, individual or LPC match-made presentation.
        addMapVote(widget, options, widget.lobbyMemberGrid)
    elseif name == "playlistmenu" or name == "brplaylistmenu" then
        addAboveGrid(widget, options)
    elseif name == "playlistpromotedbutton" or name == "playlistfeaturedbutton" or
        name == "brpromotedbutton" or name == "brfeaturebutton" then
        -- Warzone featured tiles use BRFeatureButton, not BRPromotedButton.
        -- Its cached-name subscription writes GamemodeName without Localize.
        repairPlaylistTitle(widget)
    end
    return widget
end
MenuBuilder.registerType(marker, function()
    return state
end)
return 1
