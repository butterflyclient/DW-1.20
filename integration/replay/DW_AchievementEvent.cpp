#include "DW_AchievementEventBindings.h"

extern "C" bool DW_LocalBackend_IsEnabled();

namespace
{
    bool SameName(const char *left, const char *right)
    {
        while (*left && *left == *right)
        {
            ++left;
            ++right;
        }
        return *left == *right;
    }

    bool HasKey(const DWReplayAchievementEvent *event, const char *key)
    {
        for (unsigned index = 0; index < event->pairCount; ++index)
            if (SameName(event->pairs[index].key, key))
                return true;
        return false;
    }
}

extern "C" void bdAchievementEvent_SetTimeStamp(DWReplayAchievementEvent *event, uint64_t value)
{
    // Preserve the original timestamp store even for ordinary Replay and for
    // unrelated/numeric SDK events. Native append owns its virtual references.
    event->timestamp = value;
    if (!DW_LocalBackend_IsEnabled() || event->numericName ||
        event->pairCount >= DWReplayAchievementPairCapacity)
        return;
    if (SameName(event->name, "start_match"))
    {
        // Param0 already carries the native match ID. Only the allocation ID
        // is additional, keeping the two independent identities separate.
        if (!HasKey(event, "dw_lobby_id"))
        {
            const auto lobby = DW_Achievement_GetLobbyId(DW_Achievement_Matchmaker);
            if (lobby)
                DW_Achievement_AddKeyValue(event, "dw_lobby_id", lobby);
        }
        return;
    }
    for (const auto *name : DWReplayMatchEventNames)
        if (SameName(event->name, name))
        {
            // Repeated stamping of one event must retain its first owner.
            // The original reset clears the active pair count for reuse.
            if (!HasKey(event, "dw_match_id"))
            {
                const auto match = DW_Achievement_GetMatchId();
                if (match)
                    DW_Achievement_AddKeyValue(event, "dw_match_id", match);
            }
            return;
        }
}
