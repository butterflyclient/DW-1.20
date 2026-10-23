-- Frontend model and animation adapters for the archived custom-operator dvar.
local installed = false
local preference = "dw_customOperator"
local entries = {
    { id = 0, ref = "equipped", name = "EQUIPPED OPERATORS" },
    { id = 1, ref = "dw_nicky", name = "NICKY", body = "dw_operator_nicky_body", head = "dw_operator_nicky_head" },
    { id = 2, ref = "dw_bo2_seal", name = "BO2 SEAL", body = "dw_operator_bo2_body", head = "dw_operator_bo2_head" }
}
local function selected()
    return entries[(Dvar.CFHDGABACF(preference) or 0) + 1] or entries[1]
end
local function appearance()
    local entry = selected()
    if entry.id > 0 and Dvar.IBEGCHEFE("replay_dw_customOperatorReady") then return entry end
end
local function modelEntry(body, head)
    for i = 2, #entries do
        local entry = entries[i]
        if body == entry.body or head == entry.head then return entry end
    end
end
local function copy(source)
    local result = {}
    for key, value in pairs(source) do result[key] = value end
    return result
end

return function()
    if installed then return true end
    if not Lobby or not OPERATOR or not Dvar or not FrontEndScene or
        type(Lobby.GetPlayerCardDataForPartyMember) ~= "function" or
        type(Lobby.UpdateLocalClientCharacter) ~= "function" or
        type(Lobby.GetWalkAnimationForIndex) ~= "function" or
        not Lobby.OperatorWalkAnimations or
        type(OPERATOR.GetEquippedOperatorSkin) ~= "function" or
        type(OPERATOR.GetEquippedOperatorData) ~= "function" or
        type(Dvar.CFHDGABACF) ~= "function" then return false end

    local originalCard = Lobby.GetPlayerCardDataForPartyMember
    local originalLocal = Lobby.UpdateLocalClientCharacter
    local originalWalk = Lobby.GetWalkAnimationForIndex
    local originalSkin = OPERATOR.GetEquippedOperatorSkin
    local originalData = OPERATOR.GetEquippedOperatorData
    local originalLocalize = Engine.CBBHFCGDIC

    Engine.CBBHFCGDIC = function(key, ...)
        if key == "REPLAY_DW/OPERATOR_NICKY" then return "Nicky" end
        if key == "REPLAY_DW/OPERATOR_BO2_SEAL" then return "BO2 SEAL" end
        return originalLocalize(key, ...)
    end
    Lobby.GetPlayerCardDataForPartyMember = function(controller, member, ...)
        local card = originalCard(controller, member, ...)
        local entry = appearance()
        if card and entry and member and member.isMyPlayer and member.isMyPlayer:GetValue(controller) then
            card = copy(card)
            card.headWest = 59999 + entry.id
            card.bodyWest = card.headWest
            card.headEast = card.headWest
            card.bodyEast = card.headWest
        end
        return card
    end
    Lobby.UpdateLocalClientCharacter = function(controller, character, body, head, ...)
        local entry = appearance()
        if entry then body, head = entry.body, entry.head end
        return originalLocal(controller, character, body, head, ...)
    end
    Lobby.GetWalkAnimationForIndex = function(body, head, index, weapon)
        if modelEntry(body, head) then
            local base = weapon and string.match(weapon, "^[^+]+")
            if base == "iw8_me_riotshield_mp" or base == "iw8_me_riotshield_mp_frontend_sorting" then
                return "chr_menu_mp_squad_male_05"
            end
            local animations = Lobby.OperatorWalkAnimations[index]
            if animations and animations[1] then return animations[1] end
        end
        return originalWalk(body, head, index, weapon)
    end
    OPERATOR.GetEquippedOperatorSkin = function(controller, faction, ...)
        local entry = appearance()
        if entry then return entry.body, entry.head end
        return originalSkin(controller, faction, ...)
    end
    OPERATOR.GetEquippedOperatorData = function(controller, faction, ...)
        local data = originalData(controller, faction, ...)
        local entry = appearance()
        if data and entry then
            data = copy(data)
            data.name = entry.id == 1 and "REPLAY_DW/OPERATOR_NICKY" or "REPLAY_DW/OPERATOR_BO2_SEAL"
            data.gender = "0"
            data.defaultPose = "chr_menu_male_idle_01_AR"
        end
        return data
    end

    installed = true
    return true
end
