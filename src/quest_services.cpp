#include "quest_services.h"
#include "replay_quest_data.h"
#include "replay_kill_data.h"
#include "replay_kill_event.h"
#include "replay_objective_event.h"
#include "replay_buy_item_event.h"
#include "replay_mp_mission_earning.h"
#include "replay_br_cp_mission_earning.h"
#include "replay_match_completion.h"
#include "replay_groundwar_mission_earning.h"
#include <algorithm>
#include <optional>
#include <string_view>

namespace services
{
    namespace
    {
        using Json = nlohmann::json;

        uint64_t number(const Json &row, const char *key)
        {
            const auto value = row.value(key, Json(uint64_t{0}));
            wire::require(value.is_number_unsigned());
            return value.get<uint64_t>();
        }

        const ReplayQuest *quest(uint64_t id)
        {
            const auto row = std::find_if(replayQuests.begin(), replayQuests.end(),
                                           [id](const auto &value) { return value.id == id; });
            return row == replayQuests.end() ? nullptr : &*row;
        }

        Json *find(Json &states, uint32_t id)
        {
            const auto row = std::find_if(states.begin(), states.end(),
                                           [id](const Json &value) { return number(value, "id") == id; });
            return row == states.end() ? nullptr : &*row;
        }

        // Same-image ProcessParams 0x140F35980: Param0 low 16 = weapon/equipment
        // ID; Param5 high 16 = class mask, low byte = attachment count; Param6
        // bits 16..31 = means-of-death ordinal. Kill events bypass the <=4-param
        // aggregate caches. Do not interpret packed values as raw kill counts.
        bool killMatches(uint32_t id, const Json &values)
        {
            ReplayKillEvent event{};
            for (unsigned index = 0; index < event.parameters.size(); ++index)
                event.parameters[index] = number(values, ("Param" + std::to_string(index)).c_str());
            const auto weapon = event.weapon();
            const auto classification = event.classification();
            const auto attachments = event.attachmentCount();
            const auto cause = event.cause();
            const auto mode = event.gameType();
            const auto marksman = std::find(replay_kill_data::Marksman.begin(),
                                            replay_kill_data::Marksman.end(), weapon) !=
                                  replay_kill_data::Marksman.end();
            const auto sniper = std::find(replay_kill_data::Sniper.begin(),
                                          replay_kill_data::Sniper.end(), weapon) !=
                                replay_kill_data::Sniper.end();
            // Destruction is reported through the same native kill packet.
            // Its flags overlap: a killstreak vehicle satisfies both criteria.
            // Special weapon IDs from loot/special_weapon_ids.csv: 10000 IAV
            // turret, 10001 Little Bird, 10002 APC turret, 10003 vehicle crush.
            if (id == 10036 || id == 10037)
                return event.targets(ReplayKillTarget::Vehicle) &&
                       weapon == (id == 10036 ? 10002 : 10000);
            if (id == 10012)
                return event.targets(ReplayKillTarget::Vehicle);
            if (id == 10013)
                return event.targets(ReplayKillTarget::Killstreak);
            if (!event.targets(ReplayKillTarget::Player))
                return false;
            switch (id)
            {
            case 1501:
            case 1569:
                return true;
            case 1503:
                return (classification & 0xC00) == 0xC00;
            case 1505:
                return classification == 3;
            case 1506:
                return classification == 5;
            case 1507:
                return classification == 9;
            case 1508:
                return classification == 17;
            case 1509:
                // Replay packs DMRs into the same class mask. The shipped
                // statstable distinguishes weapon_dmr from weapon_sniper.
                return classification == 65 && sniper;
            case 1510:
                return classification == 129;
            case 1513:
                return cause == 21;
            case 1514:
            case 1563:
                return event.hasPerk(replay_kill_data::Ghost);
            case 1562:
                return (classification & 0xC00) == 0xC00 &&
                       event.hasPerk(replay_kill_data::Shrapnel);
            case 1565:
            case 10001:
                return event.hasModifier(ReplayKillModifier::SecondaryWeapon) &&
                       (id != 10001 || classification == 5) &&
                       std::any_of(replay_kill_context::OverkillPerks.begin(),
                                   replay_kill_context::OverkillPerks.end(),
                                   [&event](uint16_t perk) { return event.hasPerk(perk); });
            case 1553:
                return weapon == 50000;
            case 1555:
                return weapon == 50002;
            case 1556:
                return weapon == 50007;
            case 1557:
                return weapon == 50001;
            case 1559:
            case 10007:
                return weapon == 50004 || weapon == 50017;
            case 1560:
                return weapon == 50006;
            case 1571:
                return (classification & 0x400) != 0;
            case 1570:
                return mode == ReplayChallengeGameType::war && cause == 9;
            case 1573:
                return event.hasModifier(ReplayKillModifier::Pointblank);
            case 1576:
                return event.hasModifier(ReplayKillModifier::SecondaryWeapon);
            case 1577:
                return event.hasModifier(ReplayKillModifier::Longshot);
            case 1586:
                return event.hasModifier(ReplayKillModifier::Quadfeed);
            case 1589:
                return mode == ReplayChallengeGameType::war;
            case 1592:
                return mode == ReplayChallengeGameType::hq;
            case 1594:
                return attachments == 1 && (classification & 1) != 0;
            case 1595:
                return cause == 9 && event.optic() == replay_kill_data::Reflex &&
                       (classification & 1) != 0;
            case 1596:
                return classification == 17 && attachments == 5;
            case 1597:
                return weapon == 18;
            case 1598:
                return classification == 65 && marksman && attachments == 5;
            case 1600:
                return classification == 65 && sniper &&
                       attachments == 5 && cause == 9;
            case 1624:
                return classification == 129 && event.optic() == replay_kill_data::Reflex;
            case 10000:
                return classification == 5 && cause == 9;
            case 10003:
                return classification == 5 && event.hasPerk(replay_kill_data::Tracker);
            case 10006:
                return classification == 5 && event.hasPerk(replay_kill_data::DoubleTime);
            case 10004:
                return classification == 5 && mode == ReplayChallengeGameType::arena;
            case 10047:
                return weapon == replay_challenge_mode_data::M19Weapon &&
                       mode == ReplayChallengeGameType::dom;
            case 10040:
                return cause == 9 && event.optic() == replay_kill_data::VariableZoom &&
                       (classification & 1) != 0;
            case 10038:
                return event.hasModifier(ReplayKillModifier::Ads) &&
                       event.optic() == replay_kill_data::Reflex;
            case 10039:
                return event.hasModifier(ReplayKillModifier::Longshot) &&
                       (event.optic() == replay_kill_context::Thermal ||
                        event.optic() == replay_kill_context::ThermalHybrid);
            case 10044:
                return weapon == 1;
            case 10046:
                return weapon == 5 && attachments == 3;
            case 10131:
                return weapon == replay_kill_data::Ak47 && cause == 9;
            case 10130:
                return weapon == replay_kill_context::Oden &&
                       event.hasModifier(ReplayKillModifier::Longshot);
            case 10134:
                return weapon == replay_kill_context::Fal &&
                       event.hasModifier(ReplayKillModifier::Ads);
            case 10135:
                return weapon == replay_kill_context::M13 &&
                       event.hasModifier(ReplayKillModifier::Kingslayer);
            case 1561:
                // Scavenger (perktable 11 loadout row, 37 base ability): no native
                // resupply event exists; each enemy killed drops its resupply bag.
                return event.hasPerk(11) || event.hasPerk(37);
            case 10002:
                // Param2 low word packs both selected operators (field_end uses
                // the same word): high 16 = Coalition, low 16 = Allegiance.
                // loot/operator_ids.csv: 20013 golem_western.
                return classification == 5 &&
                       static_cast<uint16_t>(event.parameters[2] >> 16) == 20013;
            case 10008:
                return classification == 5 && event.hasModifier(ReplayKillModifier::Insmoke);
            // Attachment slots: loot/iw8_pi_golf21_attachment_ids.csv id % 1000 + 1
            // (ProcessParams 0x140F35980); names from the exported English strings.
            case 10042:
                // reflexmini3 (1001014): "Cronen LP945 Mini Reflex".
                return event.hasModifier(ReplayKillModifier::Pointblank) &&
                       replay_mp_mission_earning::hasAttachment(event, 15, 15);
            case 10043:
                // acog (1001000): "Scout Combat Optic".
                return event.hasModifier(ReplayKillModifier::Ads) &&
                       replay_mp_mission_earning::hasAttachment(event, 1, 1);
            case 1599:
                // Unsuppressed barrels: barlong, barmid, barshort, barshortnoguard,
                // barcust, barcust2 (72..77), barcustnoguard (174), barextra (199).
                return classification == 3 && event.hasModifier(ReplayKillModifier::Longshot) &&
                       (replay_mp_mission_earning::hasAttachment(event, 72, 77) ||
                        replay_mp_mission_earning::hasAttachment(event, 174, 174) ||
                        replay_mp_mission_earning::hasAttachment(event, 199, 199));
            case 10032:
                return weapon == 10000;
            case 10033:
                return weapon == 10001;
            case 10034:
                return weapon == 10002;
            case 10035:
                return weapon >= 10000 && weapon <= 10003;
            default:
                return replay_mp_mission_earning::killProgress(id, event) != 0 ||
                       replay_groundwar_mission_earning::killProgress(id, event) != 0;
            }
        }

        bool completeParameters(const Json &values, unsigned count)
        {
            for (unsigned index = 0; index < count; ++index)
                if (!values.contains("Param" + std::to_string(index)))
                    return false;
            return true;
        }

        uint64_t counter(const Json &values, const char *name)
        {
            const auto value = number(values, name);
            wire::require(value <= UINT32_MAX);
            return value;
        }

        // Co-op enemies are AI agents (findenemytype masks); players count too.
        bool coopEnemy(const ReplayKillEvent &kill)
        {
            return kill.targets(ReplayKillTarget::Player) || kill.targets(ReplayKillTarget::AgentSoldier) ||
                   kill.targets(ReplayKillTarget::AgentJuggernaut) ||
                   kill.targets(ReplayKillTarget::AgentSuicideBomber) ||
                   kill.targets(ReplayKillTarget::AgentShield);
        }

        // Co-op operations (gamemode 4, public cp_* allocation). Operators are the
        // packed Param2 word: high 16 Coalition, low 16 Allegiance
        // (loot/operator_ids.csv: 20009 otter, 20024 kreuger, 20029 minotavr).
        uint64_t cpProgress(uint32_t id, const Json &event)
        {
            const auto &values = event.at("values");
            const auto &name = event.at("name");
            if (name == "cp_complete")
                return id == 10062;
            if (name == "assist")
                return id == 10063 && completeParameters(values, 2);
            if (name == "killstreak_end" && completeParameters(values, 7))
            {
                const auto streakId = number(values, "Param0"), kills = number(values, "Param1");
                if (streakId < 70000 || streakId > 70032 || kills > UINT32_MAX)
                    return 0;
                // loot/killstreak_ids.csv: 70003 precision_airstrike, 70027 sentry_gun.
                if (id == 10061)
                    return streakId == 70003 ? kills : 0;
                if (id == 10065)
                    return streakId == 70027 ? kills : 0;
                return id == 10069;
            }
            if (name != "kill" || !completeParameters(values, 7))
                return 0;
            ReplayKillEvent kill{};
            for (unsigned index = 0; index < kill.parameters.size(); ++index)
                kill.parameters[index] = number(values, ("Param" + std::to_string(index)).c_str());
            const auto weapon = kill.weapon();
            const auto classification = kill.classification();
            const auto coalition = static_cast<uint16_t>(kill.parameters[2] >> 16);
            const auto allegiance = static_cast<uint16_t>(kill.parameters[2]);
            if (id == 10060)
                return kill.targets(ReplayKillTarget::Vehicle);
            if (!coopEnemy(kill))
                return 0;
            const auto inList = [weapon](const auto &list)
            { return std::find(list.begin(), list.end(), weapon) != list.end(); };
            switch (id)
            {
            case 10057:
                return classification == 65 || inList(replay_kill_data::Sniper) ||
                       inList(replay_kill_data::Marksman);
            case 10058:
                return kill.targets(ReplayKillTarget::AgentJuggernaut) && coalition == 20009;
            case 10059:
                return kill.cause() == 21 || kill.hasModifier(ReplayKillModifier::Execution);
            case 10064:
                return weapon == 50006 && allegiance == 20029;
            case 10066:
                return classification == 129;
            case 10067:
                return (weapon == 50004 || weapon == 50017) && allegiance == 20024;
            case 10068:
                return kill.hasModifier(ReplayKillModifier::InVehicle) ||
                       (weapon >= 10000 && weapon <= 10003);
            default:
                return 0;
            }
        }

        // Stages that count streaks rather than single reports. The journal is
        // ordered and timestamped server-side; "death" ends a life and
        // "start_match" ends every streak. Native script rearms its rapid-kill
        // wait 4 seconds after each kill; minute windows consume their kills.
        struct Streak
        {
            unsigned kind; // 1 rapid chain, 2 kills per life, 3 minute window
            unsigned count;
        };

        std::optional<Streak> streak(uint32_t id)
        {
            switch (id)
            {
            case 1580: case 10041: case 10132: return Streak{1, 2};
            case 1582: return Streak{1, 3};
            case 1584: return Streak{1, 4};
            case 1581: return Streak{2, 5};
            case 1583: return Streak{2, 10};
            case 1585: return Streak{2, 15};
            case 10045: case 10049: return Streak{2, 2};
            case 10133: return Streak{2, 3};
            case 10136: return Streak{3, 7};
            case 10137: case 10140: case 10141: return Streak{3, 3};
            case 10138: return Streak{3, 4};
            case 10139: return Streak{3, 2};
            default: return std::nullopt;
            }
        }

        bool streakKill(uint32_t id, const ReplayKillEvent &kill)
        {
            if (!kill.targets(ReplayKillTarget::Player) || (kill.classification() & 1) == 0)
                return false;
            switch (id)
            {
            case 10041:
                // hybrid, hybrid2, hybrid3, hybrid4 attachment refs (24, 26, 28, 30).
                return replay_mp_mission_earning::hasAttachment(kill, 24, 24) ||
                       replay_mp_mission_earning::hasAttachment(kill, 26, 26) ||
                       replay_mp_mission_earning::hasAttachment(kill, 28, 28) ||
                       replay_mp_mission_earning::hasAttachment(kill, 30, 30);
            case 10132: return kill.weapon() == 18; // iw8_ar_falpha, the FR 5.56
            case 10045: return kill.weapon() == 4; // iw8_pi_mike1911
            case 10133: return kill.weapon() == 22; // iw8_ar_scharlie, FN Scar 17
            case 10049:
                return kill.classification() == 129 && kill.hasModifier(ReplayKillModifier::Headshot);
            case 10137: return kill.hasModifier(ReplayKillModifier::Headshot);
            case 10138: return kill.hasModifier(ReplayKillModifier::Longshot);
            case 10139:
                return kill.cause() == 21 || kill.hasModifier(ReplayKillModifier::Execution);
            case 10140: return kill.hasModifier(ReplayKillModifier::Quickscope);
            case 10141: return kill.hasModifier(ReplayKillModifier::Pointblank);
            default: return true;
            }
        }

        uint64_t trackedProgress(uint32_t id, const Json &event, Json &state)
        {
            const auto rule = streak(id);
            if (!rule)
                return 0;
            const auto &name = event.at("name");
            auto tracker = state.value("tracker", Json::object());
            wire::require(tracker.is_object());
            const auto timestamp = number(event, "timestamp");
            uint64_t increment = 0;
            if (name == "start_match" || name == "death")
            {
                tracker["life"] = uint64_t{0};
                tracker["chain"] = uint64_t{0};
                if (name == "start_match")
                    tracker["window"] = Json::array();
            }
            else if (name == "kill" && completeParameters(event.at("values"), 7))
            {
                ReplayKillEvent kill{};
                for (unsigned index = 0; index < kill.parameters.size(); ++index)
                    kill.parameters[index] =
                        number(event.at("values"), ("Param" + std::to_string(index)).c_str());
                if (!streakKill(id, kill))
                    return 0;
                if (rule->kind == 1)
                {
                    const auto chain = number(tracker, "chain");
                    const auto last = number(tracker, "chainAt");
                    const auto next =
                        chain && timestamp >= last && timestamp - last <= 4 ? chain + 1 : uint64_t{1};
                    tracker["chain"] = next;
                    tracker["chainAt"] = timestamp;
                    increment = next == rule->count;
                }
                else if (rule->kind == 2)
                {
                    const auto life = number(tracker, "life") + 1;
                    tracker["life"] = life;
                    increment = life == rule->count;
                }
                else
                {
                    Json window = Json::array();
                    for (const auto &value : tracker.value("window", Json::array()))
                        if (value.is_number_unsigned() && value.get<uint64_t>() + 60 > timestamp &&
                            value.get<uint64_t>() <= timestamp)
                            window.push_back(value);
                    window.push_back(timestamp);
                    if (window.size() >= rule->count)
                    {
                        increment = 1;
                        window = Json::array();
                    }
                    wire::require(window.size() <= 16);
                    tracker["window"] = std::move(window);
                }
            }
            else
                return 0;
            state["tracker"] = std::move(tracker);
            return increment;
        }

        uint64_t mpProgress(uint32_t id, const Json &event, Json &state)
        {
            if (streak(id))
                return trackedProgress(id, event, state);
            if (id == 1567)
            {
                // Kill Chain (mp/perktable.csv row 10, icon_perk_kill_chain): the
                // terminal killstreak report carries kills but no loadout, so the
                // perk set comes from this player's latest kill packet (Param4).
                const auto &values = event.at("values");
                if (event.at("name") == "kill" && completeParameters(values, 7))
                {
                    ReplayKillEvent kill{};
                    for (unsigned index = 0; index < kill.parameters.size(); ++index)
                        kill.parameters[index] = number(values, ("Param" + std::to_string(index)).c_str());
                    auto tracker = state.value("tracker", Json::object());
                    tracker["killChain"] = kill.hasPerk(10);
                    state["tracker"] = std::move(tracker);
                    return 0;
                }
                if (event.at("name") == "killstreak_end" && completeParameters(values, 7) &&
                    state.value("tracker", Json::object()).value("killChain", false))
                {
                    const auto streakId = number(values, "Param0"), kills = number(values, "Param1");
                    return streakId >= 70000 && streakId <= 70032 && kills <= UINT32_MAX ? kills : 0;
                }
                return 0;
            }
            const auto &values = event.at("values");
            const auto &name = event.at("name");
            if ((name == "capture" || name == "plant" || name == "defuse") &&
                completeParameters(values, 2))
            {
                const ReplayObjectiveEvent objective{{number(values, "Param0"), number(values, "Param1")}};
                const auto mode = objective.gameType();
                if (name == "capture")
                {
                    if (id == 1512 || id == 1588)
                        return mode == ReplayChallengeGameType::dom;
                    if (id == 1517)
                        return mode == ReplayChallengeGameType::hq;
                    return replay_groundwar_mission_earning::captureProgress(id, objective);
                }
                // Shipped onplant calls the defuse event too. Both native names
                // describe one completed bomb action for this combined criterion.
                if (id == 1590 && (name == "plant" || name == "defuse"))
                    return mode == ReplayChallengeGameType::sd || mode == ReplayChallengeGameType::cyber;
                return 0;
            }
            if (id == 1558 && event.at("name") == "stim" && completeParameters(values, 1))
            {
                // Original ProcessParams converts the reported health amount
                // to an integer before it is submitted as Param0.
                // Count that amount, rather than treating each use as one heal.
                return counter(values, "Param0");
            }
            // Dedicated native "stun" and "hack" achievement events (upload dvars
            // NLRLNKNTTN / LRRLSLKRLM default on): one report per affected target.
            if (id == 1554 && name == "stun")
                return 1;
            if (id == 1564 && name == "hack")
                return 1;
            if (event.at("name") == "kill" && completeParameters(values, 7))
                return killMatches(id, values) ? uint64_t{1} : uint64_t{0};
            if (name == "field_end" && completeParameters(values, 3))
                return replay_mp_mission_earning::fieldProgress(id,
                    std::array<uint64_t, 3>{number(values, "Param0"), number(values, "Param1"),
                                             number(values, "Param2")});
            if (name == "killstreak_end" && completeParameters(values, 7))
            {
                std::array<uint64_t, 7> packet{};
                for (unsigned index = 0; index < packet.size(); ++index)
                    packet[index] = number(values, ("Param" + std::to_string(index)).c_str());
                return replay_mp_mission_earning::killstreakProgress(id, packet);
            }
            return 0;
        }

        uint64_t brProgress(uint32_t id, const Json &event, Json &state)
        {
            const auto &values = event.at("values");
            const auto &name = event.at("name").get_ref<const std::string &>();
            if (name == "kill" && completeParameters(values, 7))
            {
                ReplayKillEvent kill{};
                for (unsigned index = 0; index < kill.parameters.size(); ++index)
                    kill.parameters[index] = number(values, ("Param" + std::to_string(index)).c_str());
                if (kill.gameType() != ReplayChallengeGameType::br)
                    return 0;
                // A destroyed vehicle with an enemy aboard (one report per vehicle).
                if (id == 50020 || id == 50056 || id == 50087)
                    return kill.targets(ReplayKillTarget::Vehicle) &&
                           kill.hasModifier(ReplayKillModifier::VictimInVehicle);
                if (!kill.targets(ReplayKillTarget::Player))
                    return 0;
                switch (id)
                {
                case 50027: return kill.rarity() == ReplayLootRarity::Epic;
                case 50028: return kill.rarity() == ReplayLootRarity::Legendary;
                case 50038:
                case 50083: return kill.rarity() == ReplayLootRarity::Common;
                // circletimer(0) owns the first delay/closing cycle. The
                // producer's 65535 default (including pre-circle -1) does not
                // establish an active first circle and earns no early kill.
                case 50041: return kill.circleIndex() == 0;
                case 50073: return kill.hasModifier(ReplayKillModifier::VictimLastStand);
                case 50013:
                case 50045:
                case 50080: return kill.hasModifier(ReplayKillModifier::InVehicle);
                default: return replay_br_cp_mission_earning::killMatches(id, kill);
                }
            }
            if (name == "buy_item" && completeParameters(values, 3))
            {
                const ReplayBuyItemEvent purchase{{number(values, "Param0"),
                                                    number(values, "Param1"),
                                                    number(values, "Param2")}};
                const auto *item = purchase.purchase();
                if (!item)
                    return 0;
                // Every report is one completed purchase. Native scripts also
                // report free/token redeploys; no currency threshold belongs
                // here. Pair validation excludes cross-category item IDs.
                switch (id)
                {
                case 50035: return item->category == ReplayKioskCategory::Killstreak;
                case 50052: return item->id == ReplayKioskItem::Teamrevive;
                case 50055: return item->id == ReplayKioskItem::SupplyDrop;
                case 50062: return item->id == ReplayKioskItem::SuperAmmoDrop;
                default: return 0;
                }
            }
            uint64_t contractLocale = 0;
            // Shipped setupchallengelocales assigns IDs to location_volume
            // script_noteworthy labels. Param1 is the contract card's locale;
            // Param0 is the player's locale and can differ near a boundary.
            switch (id)
            {
            case 50012: contractLocale = 4; break; // dam
            case 50015:
            case 50082: contractLocale = 33; break; // tvstation
            case 50019:
            case 50068: contractLocale = 15; break; // port
            case 50022:
            case 50075: contractLocale = 32; break; // transit / train station
            case 50026:
            case 50078: contractLocale = 6; break; // farms
            case 50029: contractLocale = 31; break; // super
            case 50033: contractLocale = 11; break; // lumber
            case 50036: contractLocale = 2; break; // boneyard
            case 50040: contractLocale = 10; break; // layover / airport
            case 50043: contractLocale = 5; break; // downtown
            case 50047:
            case 50085: contractLocale = 7; break; // gulag / prison complex
            case 50050: contractLocale = 8; break; // hospital
            case 50054:
            case 50071: contractLocale = 1; break; // airfield / military base
            case 50057: contractLocale = 20; break; // stadium
            case 50061: contractLocale = 21; break; // storagetown
            case 50064: contractLocale = 16; break; // quarry
            default: break;
            }
            if (contractLocale)
                return name == "contract_start" && completeParameters(values, 3) &&
                       number(values, "Param1") == contractLocale ? 1 : 0;
            switch (id)
            {
            case 50006:
            case 50034:
                // Successful crate selection reports both preset (0) and custom
                // (1) classes. The generic collection stages accept either.
                return name == "loadout" && completeParameters(values, 2) &&
                       number(values, "Param0") <= 1 ? 1 : 0;
            case 50011:
            case 50024:
            case 50070:
                // Replay's shared UI/BR reference table maps armor_plate to 7.
                // Collecting a plate is distinct from consuming it.
                return name == "use_item" && completeParameters(values, 2) &&
                       number(values, "Param0") == 7 ? 1 : 0;
            case 50016:
            case 50023:
            case 50030:
            case 50037:
            case 50044:
            case 50051:
            case 50058:
            case 50065:
            case 50072:
            case 50079:
            case 50086:
                // brmissions.csv defines IDs 1..11. releaseteamonquest reports
                // success=1 to contract owners (role=1), including dead team
                // members; hunted targets (role=2) receive a separate outcome.
                return name == "contract_end" && completeParameters(values, 5) &&
                       number(values, "Param0") >= 1 && number(values, "Param0") <= 11 &&
                       number(values, "Param1") == 1 && number(values, "Param2") <= 1 &&
                       number(values, "Param3") == 1 ? 1 : 0;
            case 50000:
            case 50001:
            case 50003:
                if (name != "ping" || !completeParameters(values, 2))
                    return 0;
                // Native UI StringTable mp/achievementenginerefs.csv. Other
                // builds differ: Replay's object is 13, not map_enemy (11).
                return number(values, "Param0") ==
                       (id == 50000 ? 9u : id == 50001 ? 13u : 10u) ? 1 : 0;
            case 50014:
            case 50077:
                return name == "revive" && completeParameters(values, 3) &&
                       number(values, "Param0") == 1 && number(values, "Param1") == 1 ? 1 : 0;
            case 50049:
                return name == "revive" && completeParameters(values, 3) &&
                       number(values, "Param0") == 0 && number(values, "Param1") == 1 ? 1 : 0;
            case 50048:
            case 50076:
                return name == "gulag_end_match" && completeParameters(values, 2) &&
                       number(values, "Param0") == 1 ? 1 : 0;
            case 50005:
                return name == "pickup" && completeParameters(values, 4)
                           ? counter(values, "Param0") : 0;
            case 50007:
            case 50042:
            case 50066:
            case 50069:
                return name == "pickup" && completeParameters(values, 4)
                           ? counter(values, "Param1") : 0;
            case 50010:
            case 50031:
            case 50084:
                return name == "pickup" && completeParameters(values, 4)
                           ? counter(values, "Param2") : 0;
            default:
                break;
            }
            uint64_t divisor = 0;
            if ((id == 50008 || id == 50063) && name == "alive_in_gas")
                divisor = 1000;
            else if ((id == 50009 || id == 50021) && name == "driving")
                divisor = 60000;
            else if (id == 50059 && name == "alive_not_downed")
                divisor = 60000;
            if (!divisor || !completeParameters(values, 2))
                return 0;
            // The original script reports gettime() differences in ms. Timers
            // and pickup counts are summed by native event caches. Preserve
            // sub-unit time across batches and restarts, never round up.
            const auto remainder = number(state, "timerRemainderMs");
            wire::require(remainder < divisor);
            const auto total = remainder + counter(values, "Param0");
            state["timerRemainderMs"] = total % divisor;
            return total / divisor;
        }

        std::string snapshotHash(const Json &states, const Json &state)
        {
            auto selected = Json::array();
            const auto *owner = quest(number(state, "id"));
            if (!owner)
            {
                wire::require(replayDailyChallenge(number(state, "id")));
                const auto bytes = state.dump();
                return wire::base64Encode(crypto::sha256(
                    {reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size()}));
            }
            for (const auto &candidate : states)
                if (number(candidate, "kind") == 15 && number(candidate, "status") == 1)
                    if (const auto *definition = quest(number(candidate, "id"));
                        definition && definition->category == owner->category)
                        selected.push_back(number(candidate, "id"));
            const auto bytes = Json{{"state", state}, {"selected", selected}}.dump();
            return wire::base64Encode(crypto::sha256(
                {reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size()}));
        }
    } // namespace

    const ReplayDailyChallenge *replayDailyChallenge(uint64_t identity)
    {
        const auto row = std::find_if(replayDailyChallenges.begin(), replayDailyChallenges.end(),
            [identity](const auto &value) { return value.id == identity; });
        return row == replayDailyChallenges.end() ? nullptr : &*row;
    }

    bool synchronizeReplayDailies(Json &states, uint64_t now)
    {
        wire::require(states.is_array() && states.size() <= 15000 && now <= UINT64_MAX - 86400);
        const auto cycle = now / 86400;
        bool changed = false;
        for (const auto &definition : replayDailyChallenges)
        {
            auto *existing = find(states, definition.id);
            if (existing && number(*existing, "dailyCycle") == cycle && existing->contains("dailyCycle"))
            {
                wire::require(existing->at("name") == definition.name() &&
                              number(*existing, "kind") == definition.kind &&
                              number(*existing, "target") == definition.target &&
                              number(*existing, "progress") <= definition.target &&
                              number(*existing, "activationTimestamp") >= cycle * 86400 &&
                              number(*existing, "activationTimestamp") <= now &&
                              number(*existing, "expirationTimestamp") == (cycle + 1) * 86400 &&
                              number(*existing, "status") == (number(*existing, "progress") == definition.target ? 3u : 1u));
                continue;
            }
            Json initial{{"id", uint64_t{definition.id}}, {"name", definition.name()},
                         {"kind", uint64_t{definition.kind}}, {"status", uint64_t{1}},
                         {"progress", uint64_t{0}}, {"target", uint64_t{definition.target}},
                         {"completionCount", uint64_t{0}}, {"completionTimestamp", uint64_t{0}},
                         {"dailyCycle", cycle}, {"activationTimestamp", now},
                         {"expirationTimestamp", (cycle + 1) * 86400}};
            if (existing)
            {
                wire::require(number(*existing, "kind") == definition.kind);
                *existing = std::move(initial);
            }
            else
                states.push_back(std::move(initial));
            changed = true;
        }
        // Never overfill the original three-entry caches with another unmanaged
        // daily publication. Preserve it and report storage failure for review.
        for (const auto kind : {12u, 27u, 30u})
            wire::require(std::count_if(states.begin(), states.end(), [kind](const Json &state)
                { return number(state, "kind") == kind; }) == 3);
        return changed;
    }

    QuestProgress advanceReplayDailies(const Json &stored, const Json &events,
                                     std::span<const ReplayQuestEventContext> contexts, uint64_t now)
    {
        wire::require(stored.is_array() && events.is_array() && contexts.size() == events.size());
        QuestProgress result;
        result.states = stored;
        for (size_t index = 0; index < events.size(); ++index)
        {
            const auto &event = events[index];
            const auto &values = event.at("values");
            const auto timestamp = number(event, "timestamp");
            // Daily kinds: 12 MP (gamemode 2), 27 BR (8/24), 30 co-op (4). The
            // owner's public allocation category must match the event family.
            const auto mode = number(values, "gamemode");
            const unsigned category = mode == 2 ? 0u : mode == 4 ? 4u : (mode == 8 || mode == 24) ? 1u : 9u;
            if (!contexts[index].category || *contexts[index].category != category ||
                number(values, "version") != 1 || timestamp > now)
                continue;
            const auto &name = event.at("name");
            std::optional<ReplayKillEvent> kill;
            if (name == "kill" && completeParameters(values, 7))
            {
                kill.emplace();
                for (unsigned slot = 0; slot < kill->parameters.size(); ++slot)
                    kill->parameters[slot] = number(values, ("Param" + std::to_string(slot)).c_str());
            }
            const ReplayKioskPurchase *purchase = nullptr;
            if (name == "buy_item" && completeParameters(values, 3))
                purchase = ReplayBuyItemEvent{{number(values, "Param0"), number(values, "Param1"),
                                               number(values, "Param2")}}.purchase();
            if (!kill && !purchase)
                continue;
            for (const auto &definition : replayDailyChallenges)
            {
                const unsigned kindCategory = definition.kind == 12 ? 0u : definition.kind == 27 ? 1u : 4u;
                if (kindCategory != category)
                    continue;
                auto *state = find(result.states, definition.id);
                if (!state || definition.criterion == ReplayDailyCriterion::Pending ||
                    number(*state, "status") != 1 || number(*state, "dailyCycle") != now / 86400 ||
                    timestamp < number(*state, "activationTimestamp") ||
                    timestamp >= number(*state, "expirationTimestamp") ||
                    contexts[index].activationCutoff < number(*state, "activationTimestamp"))
                    continue;
                const bool playerKill = kill && kill->targets(ReplayKillTarget::Player);
                const bool coopKill = kill && coopEnemy(*kill);
                bool matches = false;
                switch (definition.criterion)
                {
                case ReplayDailyCriterion::PlayerKill: matches = playerKill; break;
                case ReplayDailyCriterion::Headshot: matches = playerKill && kill->cause() == 9; break;
                case ReplayDailyCriterion::Melee: matches = playerKill && kill->cause() == 8; break;
                case ReplayDailyCriterion::BuyMunitionsBox:
                    matches = purchase && purchase->id == ReplayKioskItem::SuperAmmoDrop;
                    break;
                case ReplayDailyCriterion::BuyKillstreak:
                    matches = purchase && purchase->category == ReplayKioskCategory::Killstreak;
                    break;
                case ReplayDailyCriterion::BuyLoadoutDrop:
                    matches = purchase && purchase->id == ReplayKioskItem::SupplyDrop;
                    break;
                case ReplayDailyCriterion::CoopAssaultRifleKill:
                    matches = coopKill && kill->classification() == 3;
                    break;
                case ReplayDailyCriterion::CoopAssaultRifleHeadshot:
                    matches = coopKill && kill->classification() == 3 && kill->cause() == 9;
                    break;
                case ReplayDailyCriterion::CoopSmgKill:
                    matches = coopKill && kill->classification() == 5;
                    break;
                case ReplayDailyCriterion::Pending: break;
                }
                if (!matches)
                    continue;
                const auto before = number(*state, "progress");
                wire::require(before < definition.target && state->at("name") == definition.name() &&
                              number(*state, "target") == definition.target &&
                              number(*state, "kind") == definition.kind);
                (*state)["progress"] = before + 1;
                const bool completed = before + 1 == definition.target;
                if (completed)
                {
                    (*state)["status"] = uint64_t{3};
                    (*state)["completionCount"] = uint64_t{1};
                    (*state)["completionTimestamp"] = timestamp;
                    wire::require(result.xp <= UINT64_MAX - definition.xpReward);
                    result.xp += definition.xpReward;
                    if (definition.itemReward)
                        result.items.insert(definition.itemReward);
                }
                result.updates[definition.id] = completed || result.updates[definition.id];
            }
        }
        return result;
    }

    std::vector<Delivery> replayDailyUpdates(const platform::LobbyIdentity &id,
                                           const std::string &context,
                                           const QuestProgress &progress, bool refresh)
    {
        std::vector<Delivery> result;
        for (const auto &[identity, completed] : progress.updates)
        {
            const auto *definition = replayDailyChallenge(identity);
            wire::require(definition);
            const auto state = std::find_if(progress.states.begin(), progress.states.end(),
                [identity](const Json &value) { return number(value, "id") == identity; });
            wire::require(state != progress.states.end());
            Json event{{"type", "ACHIEVEMENT"}, {"kind", uint64_t{definition->kind}},
                       {"id_", uint64_t{identity}}, {"name", definition->name()},
                       {"progress", number(*state, "progress")},
                       {"completionTimestamp", number(*state, "completionTimestamp")},
                       {"reason", completed && !refresh ? "completed" : "inProgress"}};
            wire::Writer push;
            push.u32(67);
            push.u8(1);
            push.u64(id.userId);
            push.text("uno");
            push.text(context);
            push.data.push_back(7);
            wire::raw(push.data, int32_t{1});
            push.u32(1);
            push.data.push_back(7);
            wire::raw(push.data, int32_t{1});
            push.text(event.dump());
            Delivery delivery{id.userId, std::move(push.data)};
            delivery.questContext = context;
            delivery.questId = identity;
            delivery.questStateHash = snapshotHash(progress.states, *state);
            result.push_back(std::move(delivery));
        }
        return result;
    }

    bool replayQuestEventMayEarn(const std::string &name)
    {
        // Keep admission beside the earning rules. The achievement transport
        // must not maintain a separate list that silently drops a new family.
        static constexpr std::array<std::string_view, 27> supported = {
            "kill", "stim", "pickup", "driving", "alive_in_gas", "alive_not_downed",
            "revive", "gulag_end_match", "ping", "contract_start", "contract_end",
            "use_item", "loadout", "capture", "plant", "defuse", "buy_item",
            "field_end", "killstreak_end", "end_match", "match_placement",
            "death", "start_match", "stun", "hack", "assist", "cp_complete"};
        return std::find(supported.begin(), supported.end(), std::string_view(name)) != supported.end();
    }

    QuestProgress advanceReplayQuests(const Json &stored, const Json &events,
                                       std::optional<unsigned> publicCategory)
    {
        const std::vector<ReplayQuestEventContext> contexts(events.size(), {publicCategory, UINT64_MAX});
        return advanceReplayQuests(stored, events, std::span(contexts));
    }

    QuestProgress advanceReplayQuests(const Json &stored, const Json &events,
                                       std::span<const ReplayQuestEventContext> publicContexts)
    {
        wire::require(stored.is_array() && stored.size() <= 15000);
        wire::require(events.is_array() && publicContexts.size() == events.size());
        QuestProgress result;
        result.states = stored;
        for (size_t index = 0; index < events.size(); ++index)
        {
            const auto &context = publicContexts[index];
            const auto publicCategory = context.category;
            if (!publicCategory)
                continue;
            const auto &event = events[index];
            const auto &values = event.at("values");
            // The original AddGamemode emits 2 for MP, 8/24 for BR. Neither
            // client gamemode nor a public-looking name proves lobby membership.
            const auto mode = number(values, "gamemode");
            if (number(values, "version") != 1 || (mode != 2 && mode != 4 && mode != 8 && mode != 24))
                continue;
            const auto category = mode == 2 ? 0u : mode == 4 ? 4u : 1u;
            if (category != *publicCategory)
                continue;
            std::vector<uint32_t> active;
            for (const auto &state : result.states)
                if (number(state, "kind") == 15 && number(state, "status") == 1)
                    if (const auto *row = quest(number(state, "id")); row && row->category == category)
                        active.push_back(row->id);
            wire::require(active.size() <= 1);
            // Snapshot active selections before processing this event: one report
            // cannot also satisfy the successor activated by that same kill.
            for (const auto identity : active)
            {
                const auto &row = *quest(identity);
                auto &state = *find(result.states, identity);
                if (state.at("name") != row.name || number(state, "target") != row.target ||
                    number(event, "timestamp") < number(state, "activationTimestamp") ||
                    context.activationCutoff < number(state, "activationTimestamp"))
                    continue;
                const auto before = number(state, "progress");
                if (before >= row.target)
                    continue;
                const auto oldRemainder = number(state, "timerRemainderMs");
                uint64_t increment = 0;
                if (event.at("name") == "end_match")
                {
                    if (category == 0 && context.firstEnd && context.nativeMatch &&
                        completeParameters(values, 5))
                        increment = ReplayMatchCompletion{{number(values, "Param0"),
                            number(values, "Param1"), number(values, "Param2"),
                            number(values, "Param3"), number(values, "Param4")}}.matches(identity);
                }
                else if (event.at("name") == "match_placement")
                {
                    if (category == 1 && context.firstPlacement && context.nativeMatch &&
                        completeParameters(values, 3))
                        increment = replay_br_cp_mission_earning::placementMatches(identity,
                            {number(values, "Param0"), number(values, "Param1"), number(values, "Param2")});
                }
                else
                {
                    const auto trackerBefore = state.value("tracker", Json());
                    increment = category == 1 ? brProgress(identity, event, state)
                        : category == 4           ? cpProgress(identity, event)
                                                  : mpProgress(identity, event, state);
                    if (state.value("tracker", Json()) != trackerBefore)
                        result.stateChanged = true;
                }
                if (!increment && oldRemainder == number(state, "timerRemainderMs"))
                    continue;
                const auto total = before + std::min(increment, uint64_t{row.target} - before);
                state["progress"] = total;
                const bool finished = total == row.target;
                result.updates[identity] = finished;
                if (!finished)
                    continue;
                state["status"] = uint64_t{3};
                state["completionCount"] = uint64_t{1};
                state["completionTimestamp"] = number(event, "timestamp");
                wire::require(result.xp <= UINT64_MAX - row.xpReward);
                result.xp += row.xpReward;
                if (row.itemReward)
                    result.items.insert(row.itemReward);
                if (const auto *next = quest(row.nextId))
                {
                    auto *successor = find(result.states, next->id);
                    if (!successor)
                    {
                        wire::require(result.states.size() < 15000);
                        result.states.push_back(Json{{"id", uint64_t{next->id}},
                                                      {"name", next->name},
                                                      {"kind", uint64_t{15}},
                                                      {"status", uint64_t{2}},
                                                      {"progress", uint64_t{0}},
                                                      {"target", uint64_t{next->target}}});
                        successor = &result.states.back();
                    }
                    if (number(*successor, "status") == 2)
                    {
                        wire::require(successor->at("name") == next->name &&
                                      number(*successor, "kind") == 15 &&
                                      number(*successor, "target") == next->target);
                        (*successor)["status"] = uint64_t{1};
                        (*successor)["activationTimestamp"] = number(event, "timestamp");
                        result.successors[identity] = next->id;
                    }
                }
            }
        }
        return result;
    }

    std::vector<Delivery> replayQuestUpdates(const platform::LobbyIdentity &id,
                                              const std::string &context,
                                              const QuestProgress &progress,
                                              const RankInventory *inventory,
                                              bool refresh)
    {
        std::vector<Delivery> result;
        for (const auto &[identity, completed] : progress.updates)
        {
            const auto &row = *quest(identity);
            const auto state = std::find_if(progress.states.begin(), progress.states.end(),
                                             [identity](const Json &value)
                                             { return number(value, "id") == identity; });
            wire::require(state != progress.states.end());
            Json event{{"type", "ACHIEVEMENT"}, {"kind", uint64_t{15}},
                       {"id_", uint64_t{identity}}, {"name", row.name},
                       {"progress", number(*state, "progress")},
                       {"reason", completed && !refresh ? "completed" : "inProgress"}};
            auto triggers = Json::array();
            if (completed && row.itemReward && inventory)
                for (const auto &[item, quantity] : inventory->quantities)
                    if (item == row.itemReward && quantity)
                        triggers.push_back(Json{{"type", "GRANT_PRODUCT"},
                                                {"inventory", {{"granted_items", Json::array(
                                                    {{{"id", item}, {"quantity", quantity}}})}}}});
            // HandleCompletion 0x1410635F0 consumes this named activation trigger.
            // Retries refresh absolute progress without replaying completion UI
            // or appending another successor to the native 640-stage cache.
            if (completed && !refresh && progress.successors.contains(identity))
                if (const auto *next = quest(progress.successors.at(identity)))
                    triggers.push_back(Json{{"type", "ACTIVATE_ACHIEVEMENT"}, {"name", next->name}});
            if (!triggers.empty())
                event["triggers"] = std::move(triggers);
            wire::Writer push;
            push.u32(67);
            push.u8(1);
            push.u64(id.userId);
            push.text("uno");
            push.text(context);
            push.data.push_back(7);
            wire::raw(push.data, int32_t{1});
            push.u32(1);
            push.data.push_back(7);
            wire::raw(push.data, int32_t{1});
            push.text(event.dump());
            Delivery delivery{id.userId, std::move(push.data)};
            delivery.questContext = context;
            delivery.questId = identity;
            delivery.questStateHash = snapshotHash(progress.states, *state);
            result.push_back(std::move(delivery));
        }
        return result;
    }

    bool replayQuestDeliveryValid(const Json &states, const Delivery &delivery)
    {
        wire::require(states.is_array() && states.size() <= 15000 &&
                      (quest(delivery.questId) || replayDailyChallenge(delivery.questId)));
        const auto row = std::find_if(states.begin(), states.end(), [&](const Json &value)
                                     { return number(value, "id") == delivery.questId; });
        return row != states.end() && snapshotHash(states, *row) == delivery.questStateHash;
    }
} // namespace services
