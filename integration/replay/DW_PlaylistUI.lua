-- Native Replay widgets and one preference shared by MP and Warzone playlists.
-- The marker lives in the stock builder registry; sealed _G stays unchanged.
local marker = "ReplayDWPlaylistFillState"
if not MenuBuilder or not MenuBuilder.IsTypeRegistered or not
    MenuBuilder.BuildRegisteredType or not Engine or not Engine.CBBHFCGDIC or
    not Dvar or not Dvar.IBEGCHEFE or not Dvar.DHEGHJJJHI or
    not LUI or not LUI.UIImage or not FONTS or not FONTS.MainBold or
    not FONTS.MainRegular or not RegisterMaterial then
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
local preference = "replay_dw_autoFillBots"
local scale = _1080p or 1
local closedAnchors = setmetatable({}, { __mode = "k" })
local voteMapDvars = { "NSMOLKMMPM", "MSQROKTRSN", "ROLQKTOMM" }
local voteColors = {
    background = 0x0D171C, card = 0x17252D, focus = 0x2A3F49,
    text = 0xEFF3F4, muted = 0xA4B3BA, accent = 0x83BCC7, gold = 0xDEC374
}

local function voteImage(parent, id, left, right, top, bottom, color, alpha)
    local image = LUI.UIImage.new()
    image.id = id
    image:setImage(RegisterMaterial("white"), 0)
    image:SetRGBFromInt(color, 0)
    image:SetAlpha(alpha or 1, 0)
    image:SetAnchorsAndPosition(0, 1, 0, 1,
        left * scale, right * scale, top * scale, bottom * scale)
    parent:addElement(image)
    return image
end

local function voteText(parent, id, left, right, top, bottom, font, alignment, color)
    local text = LUI.UIText.new()
    text.id = id
    text:SetFont(FONTS.GetFont(font.File))
    text:SetAlignment(alignment)
    text:SetRGBFromInt(color or voteColors.text, 0)
    text:SetAnchorsAndPosition(0, 1, 0, 1,
        left * scale, right * scale, top * scale, bottom * scale)
    parent:addElement(text)
    return text
end

local function styleMapChoice(button)
    local focus = button.ReplayDWOver or button:isInFocus()
    local marked = button.ReplayDWWinner or button.ReplayDWSelected or button.ReplayDWPending
    local accent = button.ReplayDWWinner and voteColors.gold or voteColors.accent
    button.Background:SetRGBFromInt(focus and voteColors.focus or voteColors.card, 0)
    button.Image:SetAlpha(button.ReplayDWWinner and 1 or (focus and 0.95 or 0.7), 0)
    button.Accent:SetRGBFromInt(accent, 0)
    button.Accent:SetAlpha(marked and 1 or 0.25, 0)
    button.Selection:SetRGBFromInt(accent, 0)
    for _, edge in ipairs(button.Border) do
        edge:SetRGBFromInt(button.ReplayDWWinner and voteColors.gold or voteColors.accent, 0)
        edge:SetAlpha((focus or marked) and 1 or 0.15, 0)
    end
end

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
            if button.navigation.right == anchor then button.navigation.right = nil end
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
    panel:SetAlpha(ballot.active and not ballot.complete and 1 or 0, 0)
    panel.Title:setText(ballot.complete and "MAP SELECTED" or "VOTE FOR THE NEXT MAP", 0)
    panel.Countdown:setText(ballot.complete and "LOCKED" or tostring(ballot.remaining or 0) .. "s", 0)
    panel.Countdown:SetRGBFromInt(ballot.complete and voteColors.gold or voteColors.accent, 0)
    for index, button in ipairs(panel.Choices) do
        if panel.ReplayDWRetired then return end
        local choice = ballot.choices and ballot.choices[index]
        local enabled = ballot.active and choice ~= nil and not ballot.complete
        local retiringFocus = not enabled and button:isInFocus()
        button:SetAlpha(choice and 1 or 0, 0)
        button:SetHandleMouse(enabled)
        button:SetFocusable(enabled)
        if not enabled then button.ReplayDWOver = false end
        if retiringFocus then
            button:processEvent({ name = "lose_focus", controller = panel.Controller })
            if panel.ReplayDWRetired then return end
            if panel.Anchor then panel.Anchor:processEvent({ name = "gain_focus", controller = panel.Controller }) end
            if panel.ReplayDWRetired then return end
        end
        if choice then
            local name = choice.name:gsub("^mp_", ""):gsub("_", " ")
            button.Label:setText(string.upper(name), 0)
            local votes = choice.votes or 0
            button.Votes:setText(tostring(votes) .. (votes == 1 and " VOTE" or " VOTES"), 0)
            button.ReplayDWWinner = choice.winner == true
            button.ReplayDWPending = state.pendingVote == index
            button.ReplayDWSelected = not state.pendingVote and ballot.selected == index
            button.Selection:setText(choice.winner and "SELECTED MAP" or
                (button.ReplayDWPending and "VOTING..." or
                (button.ReplayDWSelected and "YOUR VOTE" or "")), 0)
            -- These are the same three native dvars read by Replay's vote-map
            -- display-name getter. Use the stock material lookup/fallback.
            local map = Dvar.DHEEJCCJBH and Dvar.DHEEJCCJBH(voteMapDvars[index])
            if map ~= button.ReplayDWMap then
                button.ReplayDWMap = map
                local image = MP and MP.GetMapImage and MP.GetMapImage(map or "") or "loading_mp_generic_bg"
                button.Image:setImage(RegisterMaterial(image), 0)
            end
            local count = #ballot.choices
            button.navigation.up = panel.Choices[index == 1 and count or index - 1]
            button.navigation.down = panel.Choices[index == count and 1 or index + 1]
            button.navigation.left = index == 1 and panel.Anchor or panel.Choices[index - 1]
            button.navigation.right = index == count and panel.Anchor or panel.Choices[index + 1]
            styleMapChoice(button)
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
    local key = tostring(ballot.round or 0)
    for index, choice in ipairs(ballot.choices or {}) do
        key = key .. "|" .. choice.name .. ":" ..
            (Dvar.DHEEJCCJBH and Dvar.DHEEJCCJBH(voteMapDvars[index]) or "")
    end
    if not ballot.active or ballot.complete or key ~= state.voteRoundKey or
        ballot.selected == state.pendingVote then
        state.pendingVote = nil
    end
    state.voteRoundKey = key
    state.ballot = ballot
    for panel in pairs(state.mapVotes) do refreshMapVote(panel, ballot) end
end

local function addMapVote(menu, options, anchor)
    if menu.ReplayDWMapVote or not LUI or not LUI.UIElement or not LUI.UIButton or not LUI.UIText then return end
    local panel = LUI.UIElement.new()
    panel.id = "ReplayDWMapVote"
    -- Cover the native map tile (96..526, 849..979) while voting, leaving
    -- every roster row and footer control untouched. Completion reveals it.
    panel:SetAnchorsAndPosition(0, 1, 0, 1, 96 * scale, 768 * scale, 849 * scale, 979 * scale)
    panel.Background = voteImage(panel, "Background", 0, 672, 0, 130, voteColors.background)
    voteImage(panel, "HeaderAccent", 0, 3, 0, 30, voteColors.accent)
    voteImage(panel, "Divider", 18, 654, 29, 30, voteColors.accent, 0.3)
    panel.Title = voteText(panel, "Title", 18, 500, 8, 24, FONTS.MainBold, LUI.Alignment.Left)
    panel.Countdown = voteText(panel, "Countdown", 518, 654, 7, 26,
        FONTS.MainRegular, LUI.Alignment.Right, voteColors.accent)
    panel.Choices = {}
    panel.Menu = menu
    panel.Controller = options and options.controllerIndex or 0
    local selectors = { "replay_dw_mapVoteSelectA", "replay_dw_mapVoteSelectB", "replay_dw_mapVoteSelectC" }
    for index = 1, 3 do
        local button = LUI.UIButton.new()
        button.id = "ReplayDWMapChoice" .. tostring(index)
        local left = 18 + (index - 1) * 214
        button:SetAnchorsAndPosition(0, 1, 0, 1,
            left * scale, (left + 208) * scale, 35 * scale, 121 * scale)
        button.Background = voteImage(button, "Background", 0, 208, 0, 86, voteColors.card)
        button.Image = voteImage(button, "MapImage", 1, 207, 1, 85, 0xFFFFFF)
        button.Image:setImage(RegisterMaterial("loading_mp_generic_bg"), 0)
        button.Scrim = voteImage(button, "ImageShade", 1, 207, 44, 85, voteColors.background, 0.86)
        button.Label = voteText(button, "MapName", 10, 198, 48, 64,
            FONTS.MainBold, LUI.Alignment.Left)
        button.Votes = voteText(button, "Votes", 10, 198, 66, 82,
            FONTS.MainRegular, LUI.Alignment.Left, voteColors.muted)
        button.Selection = voteText(button, "Selection", 10, 198, 27, 41,
            FONTS.MainRegular, LUI.Alignment.Right, voteColors.accent)
        button.Accent = voteImage(button, "Accent", 0, 208, 83, 86, voteColors.accent, 0.25)
        button.Border = {
            voteImage(button, "Top", 0, 208, 0, 1, voteColors.accent, 0.15),
            voteImage(button, "Bottom", 0, 208, 85, 86, voteColors.accent, 0.15),
            voteImage(button, "Left", 0, 1, 0, 86, voteColors.accent, 0.15),
            voteImage(button, "Right", 207, 208, 0, 86, voteColors.accent, 0.15)
        }
        button:addEventHandler("button_over", function()
            if panel.ReplayDWRetired then return end
            button.ReplayDWOver = true
            styleMapChoice(button)
        end)
        button:addEventHandler("button_up", function()
            if panel.ReplayDWRetired then return end
            button.ReplayDWOver = false
            styleMapChoice(button)
        end)
        button:addEventHandler("gain_focus", function()
            if not panel.ReplayDWRetired then styleMapChoice(button) end
        end)
        button:addEventHandler("lose_focus", function()
            if not panel.ReplayDWRetired then styleMapChoice(button) end
        end)
        button:addEventHandler("button_action", function()
            local ballot = state.ballot
            if not panel.ReplayDWRetired and ballot.active and not ballot.complete and ballot.choices[index] then
                Dvar.DHEGHJJJHI(selectors[index], true)
                state.pendingVote = index
                for activePanel in pairs(state.mapVotes) do refreshMapVote(activePanel, ballot) end
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
    if text == "PLAYLIST/NUKETOWN_TDM" or text == "@PLAYLIST/NUKETOWN_TDM" then
        -- A guarded (locked) Nuketown says so in its title, with what the guard
        -- read; a padlock without this suffix is a native lock, not the guard.
        local status = state.mapGuardStatus and state.mapGuardStatus("mp_nuketown")
        return status and "NUKETOWN TDM (NEEDS MAP)" or "NUKETOWN TDM"
    end
    return text
end

-- Playlists of a custom map package (DW publication) stay disabled for a
-- player without that package: replay_dw_customMaps lists the installed ids.
local requiredMaps = { [65] = { map = "mp_nuketown", label = "Nuketown" } }

local function customMapInstalled(map)
    -- replay_dw_map_<id> (bool) follows every package scan; the list string is
    -- fixed when first registered.
    local ok, flag = pcall(Dvar.IBEGCHEFE, "replay_dw_map_" .. map)
    if ok and flag == true then
        return true
    end
    local installed = Dvar.DHEEJCCJBH and Dvar.DHEEJCCJBH("replay_dw_customMaps")
    return type(installed) == "string" and string.find(installed, " " .. map .. " ", 1, true) ~= nil
end

-- nil when installed, else a short diagnostic of the two dvar reads.
state.mapGuardStatus = function(map)
    if customMapInstalled(map) then
        return nil
    end
    local ok, flag = pcall(Dvar.IBEGCHEFE, "replay_dw_map_" .. map)
    local installed = Dvar.DHEEJCCJBH and Dvar.DHEEJCCJBH("replay_dw_customMaps")
    return "b=" .. tostring(ok) .. "/" .. tostring(flag) .. " s=" ..
        (type(installed) == "string" and tostring(#installed) or type(installed))
end

local function guardRequiredMap(widget, options)
    if not widget or widget.ReplayDWMapGuard or type(widget.SetDataSource) ~= "function" or
        type(widget.SetButtonDisabled) ~= "function" then
        return
    end
    widget.ReplayDWMapGuard = true
    local controller = options and options.controllerIndex or 0
    local originalSetDataSource = widget.SetDataSource
    local originalDisabled = widget.SetButtonDisabled
    local function missing()
        local source = widget.ReplayDWDataSource
        local id = source and source.ID and source.ID.GetValue and source.ID:GetValue(controller)
        local required = id and requiredMaps[id]
        return required and not customMapInstalled(required.map) and required or nil
    end
    widget.SetDataSource = function(element, source, ...)
        element.ReplayDWDataSource = source
        local result = originalSetDataSource(element, source, ...)
        local required = missing()
        if required then
            originalDisabled(element, true)
            if element.DisabledText then
                element.DisabledText:setText("Requires the " .. required.label .. " map files", 0)
            end
        end
        return result
    end
    -- Lobby updates re-enable featured buttons; a missing package keeps it off.
    widget.SetButtonDisabled = function(element, disabled, ...)
        return originalDisabled(element, disabled or missing() ~= nil, ...)
    end
end

local function repairPlaylistTitle(widget, label)
    local name = label or widget and (widget.Name or widget.GamemodeName)
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

local customStrings = {
    ["PLAYLIST/NUKETOWN_TDM"] = "Nuketown TDM",
    ["LUA_MENU_MP/NUKETOWN_TDM_DESC"] = "Team Deathmatch on Nuketown.",
}

Engine.CBBHFCGDIC = function(key, ...)
    local text = originalLocalize(key, ...)
    if key == "PLAYLIST/BRSOLOSTIM_NAME2" and
        (not text or text == "" or text == key or text == "@" .. key) then
        return "BR Stimulus Solos"
    end
    if customStrings[key] and (not text or text == "" or text == key or text == "@" .. key) then
        return customStrings[key]
    end
    return text
end

MenuBuilder.BuildRegisteredType = function(kind, options)
    local name = string.lower(kind)
    if name == "mpplaymenu" or name == "mpplaymenubuttons" then
        -- No tournament entry in the MP play menu (owner 2026-10-16): stock
        -- CONDITIONS.IsTournamentModeAllowed reads online_tournament_enabled.
        -- The executable enforces the same value each frame; never let a
        -- refused write abort the native menu build.
        pcall(Dvar.DHEGHJJJHI, "NLPONNQNRS", false)
    end
    local widget = originalBuild(kind, options)
    if name == "mpplaymenu" then
        addAboveVerticalList(widget, widget.MPPlayMenuButtons, options)
    elseif name == "brplaymenu" then
        addAboveVerticalList(widget, widget.BRPlayMenuButtons, options)
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
        guardRequiredMap(widget, options)
    elseif name == "lobbystatuspanel" then
        -- The public lobby's single-playlist title is the same localized model
        -- value (ToUpperCase only).
        repairPlaylistTitle(widget, widget and widget.Title)
    end
    return widget
end
MenuBuilder.registerType(marker, function()
    return state
end)
return 1
