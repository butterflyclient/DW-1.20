-- Execute this chunk once per frontend VM and retain its returned installer in
-- the existing UI injection closure. Call the installer from that UI's Refresh
-- function until OPTIONS and CSV have been loaded. No global names are added.
--
-- The native binding adapters must recognize dw_inspect for capture, bound-key
-- lookup, default-key lookup, reset and unbind. Its two saved keys are separate
-- from Replay's byte-sized native command table.
local installed = false
local identifier = "ReplayDWWeaponInspect"
local command = "dw_inspect"
local context = "ONFOOT"
local titleKey = "REPLAY_DW/WEAPON_INSPECT"
local descriptionKey = "REPLAY_DW/WEAPON_INSPECT_DESC"

return function()
    if installed then
        return true
    end
    if not OPTIONS or type(OPTIONS.InitKeybindOptionsList) ~= "function" or
        type(OPTIONS.CreateOptionList) ~= "function" or not CSV or
        not CSV.keyBindingsOptions or not Engine or
        type(Engine.CBBHFCGDIC) ~= "function" or
        type(Engine.EAHBBDJHID) ~= "function" or
        type(Engine.DCCFJEGGGE) ~= "function" or
        type(Engine.DEGABDJDH) ~= "function" or
        type(Engine.CGGHDFIDAF) ~= "function" or
        type(Engine.DABIGBHJDG) ~= "function" then
        return false
    end

    local originalInit = OPTIONS.InitKeybindOptionsList
    local originalCreate = OPTIONS.CreateOptionList
    local originalLocalize = Engine.CBBHFCGDIC
    local originalResetAll = Engine.BFHCBIBDGH

    if type(originalResetAll) == "function" then
        Engine.BFHCBIBDGH = function(controller, ...)
            local result = originalResetAll(controller, ...)
            Engine.CGGHDFIDAF(controller, context, command, 0)
            Engine.CGGHDFIDAF(controller, context, command, 1)
            return result
        end
    end

    Engine.CBBHFCGDIC = function(key, ...)
        if key == titleKey then
            return "Inspect Weapon"
        elseif key == descriptionKey then
            return "Inspect the weapon you are holding."
        end
        return originalLocalize(key, ...)
    end

    OPTIONS.InitKeybindOptionsList = function(menu, controller, options, csv, ...)
        originalInit(menu, controller, options, csv, ...)
        -- This is the same schema produced by Replay's stock initializer.
        -- The caster list is initialized separately and keeps its own entries.
        if csv == CSV.keyBindingsOptions and options.ReloadAction then
            options[identifier] = {
                type = "keyBinding",
                controllerIndex = controller,
                id = identifier,
                stringID = titleKey,
                description = descriptionKey,
                action = command,
                inputContext = context,
                disabled = function() return false end
            }
            menu._keybindActionList = menu._keybindActionList or {}
            menu._keybindActionList[command .. context] = titleKey
        end
    end

    OPTIONS.CreateOptionList = function(menu, controller, identifiers, applyable, ...)
        -- The category belongs to the stock options layout. Never modify it:
        -- repeated tab changes and menu openings reuse that identifier array.
        local containsReload = false
        for _, id in ipairs(identifiers) do
            if id == "ReloadAction" then
                containsReload = true
                break
            end
        end
        if not containsReload then
            return originalCreate(menu, controller, identifiers, applyable, ...)
        end
        local expanded = {}
        local inserted = false
        for _, id in ipairs(identifiers) do
            if id ~= identifier then
                expanded[#expanded + 1] = id
                if id == "ReloadAction" and not inserted then
                    expanded[#expanded + 1] = identifier
                    inserted = true
                end
            end
        end
        return originalCreate(menu, controller, expanded, applyable, ...)
    end

    installed = true
    return true
end
