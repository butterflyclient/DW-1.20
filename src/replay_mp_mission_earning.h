#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include "replay_kill_event.h"

namespace replay_mp_mission_earning
{
    inline constexpr std::array<uint32_t, 29> StageIds = {
        1502, 1516, 1545, 1546, 1547, 1548, 1549, 1550, 1551, 1552, 1566,
        1575, 1601, 1602, 10005, 10009, 10010, 10011, 10014, 10015, 10016,
        10017, 10018, 10019, 10020, 10021, 10022, 10023, 10024};

    // Original ProcessParams 0x140F35980 packs attachment-table row ordinals
    // plus one into five complete 12-bit slots in Param3. The upper four bits
    // cannot hold another complete attachment ID. Param5 low byte is the
    // recognized count; 255 is the explicit no_attachments sentinel.
    inline bool hasAttachment(const ReplayKillEvent &event, uint16_t first, uint16_t last)
    {
        const unsigned count = event.attachmentCount();
        if (count == 0 || count == 255)
            return false;
        for (unsigned slot = 0; slot < std::min(count, 5u); ++slot)
        {
            const auto attachment = static_cast<uint16_t>((event.parameters[3] >> (slot * 12)) & 0xFFF);
            if (attachment >= first && attachment <= last)
                return true;
        }
        return false;
    }

    inline uint64_t killProgress(uint32_t id, const ReplayKillEvent &event)
    {
        if (!event.targets(ReplayKillTarget::Player) || (event.classification() & 1) == 0)
            return 0;
        switch (id)
        {
        case 1516:
            // Slots are loot/iw8_pi_golf21_attachment_ids.csv id % 1000 + 1:
            // silencer..silencer3 (35..37), silencer4 (184) and the integrally
            // suppressed barrels barsil/barsil2 (185, 186).
            return hasAttachment(event, 35, 37) || hasAttachment(event, 184, 186);
        case 1601:
            return event.cause() == 8 && hasAttachment(event, 120, 120);
        case 1602:
        case 10005:
            return event.hasModifier(ReplayKillModifier::Hipfire) &&
                   (id != 10005 || event.classification() == 5) &&
                   hasAttachment(event, 54, 58);
        default:
            return 0;
        }
    }

    // Caller admits field_end only after its existing public-MP authorization,
    // version/gamemode and unsigned parameter validation. This three-field
    // packet is [super ID, per-upgrade result, operators]. No guessed generic
    // use counter belongs here: cover reports damage; ammo reports use count.
    inline uint64_t fieldProgress(uint32_t id, std::span<const uint64_t> parameters)
    {
        if (parameters.size() != 3 || parameters[0] > UINT32_MAX || parameters[1] > UINT32_MAX)
            return 0;
        const auto super = parameters[0];
        const auto result = parameters[1];
        switch (id)
        {
        case 1566:
            // All nine have retained native end producers. A tactical
            // insertion ends with zero when destroyed before a respawn; its
            // deployment was still a field-upgrade use.
            return super == 280009 || super == 280010 || super == 280011 ||
                   super == 280012 || super == 280015 || super == 280017 ||
                   super == 280018 || super == 280019 || super == 280021;
        case 10014:
        case 10017:
            return super == 280010 ? result : 0; // reconDroneMarks
        case 10015:
        case 10016:
            return super == 280019 ? result : 0; // munitionsBoxUsed
        case 10018:
            return super == 280017 ? result : 0; // deadSilenceKills
        case 10019:
            return super == 280012 ? result : 0; // stoppingPowerKills
        case 10020:
            return super == 280015 ? result : 0; // trophySystemHits
        case 10021:
            return super == 280009;
        case 10022:
            return super == 280018 && result == 1; // successful insertion spawn
        case 10023:
            return super == 280011 ? result : 0; // empDroneHits
        case 10024:
            return super == 280021 ? result : 0; // weapons successfully given
        default:
            return 0;
        }
    }

    // Native recordkillstreakendstats sends duration, endtime, kills, then
    // three zero placeholders. ProcessParams reorders this to the seven-field
    // packet below. A terminal report proves one activation; Param1 is kills,
    // not duration. Specialist perk grants are outside these called streaks.
    inline uint64_t killstreakProgress(uint32_t id, std::span<const uint64_t> parameters)
    {
        if (parameters.size() != 7 ||
            std::any_of(parameters.begin(), parameters.end(),
                        [](uint64_t value) { return value > UINT32_MAX; }))
            return 0;
        const auto streak = parameters[0];
        const auto kills = parameters[1];
        if (streak < 70000 || streak > 70032)
            return 0;
        switch (id)
        {
        case 1502:
            return 1;
        case 1545:
            return streak == 70009; // Personal Radar / radar_drone_overwatch
        case 1547:
        case 10009:
            return streak == 70000;
        case 1548:
        case 10010:
            return streak == 70001;
        case 10011:
            return streak == 70002;
        case 1546:
            return streak == 70012 ? kills : 0; // Shield Turret
        case 1549:
            return streak == 70013 ? kills : 0; // Cluster Strike
        case 1550:
            return streak == 70003 ? kills : 0; // Precision Airstrike
        case 1551:
            return streak == 70017 ? kills : 0; // Wheelson / pac_sentry
        case 1552:
            return streak == 70018 ? kills : 0;
        case 1575:
            return kills;
        default:
            return 0;
        }
    }
} // namespace replay_mp_mission_earning
