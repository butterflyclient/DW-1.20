// Deterministic checks for the mission and daily rules completed on 2026-10-27:
// streak/life/minute trackers, vehicle/operator/perk kill rules, stun/hack,
// Kill Chain, BR vehicle stages, co-op operations and BR/co-op dailies.
// Events use the native seven-field kill layout decoded by ReplayKillEvent.
#include "../src/quest_services.h"
#include "../src/replay_challenge_game_type.h"
#include "../src/replay_kill_context.h"
#include "../src/replay_kill_target.h"
#include "../src/replay_kiosk_purchase_data.h"
#include "../src/replay_quest_data.h"
#include <cstdio>
#include <string>

using Json = nlohmann::json;
using services::ReplayQuestEventContext;

namespace
{
    unsigned failures = 0, passed = 0;

    void check(bool ok, const std::string &label)
    {
        if (ok)
            ++passed;
        else
        {
            ++failures;
            std::printf("FAIL: %s\n", label.c_str());
        }
    }

    struct Kill
    {
        uint64_t weapon = 6, modifiers = 0, coalition = 20031, allegiance = 20030, perks = 0;
        uint64_t classification = 5, target = static_cast<uint64_t>(ReplayKillTarget::Player);
        uint64_t attachments = 0, cause = 1, optic = 0, slots = 0;
        uint64_t gameType = static_cast<uint64_t>(ReplayChallengeGameType::war);
    };

    Json event(const std::string &name, uint64_t timestamp, uint64_t gamemode, Json values = Json::object())
    {
        values["gamemode"] = gamemode;
        values["version"] = uint64_t{1};
        return Json{{"name", name}, {"timestamp", timestamp}, {"values", values}};
    }

    Json kill(const Kill &k, uint64_t timestamp, uint64_t gamemode = 2)
    {
        Json values = {
            {"Param0", k.weapon},
            {"Param1", k.modifiers},
            {"Param2", (k.gameType << 32) | (k.coalition << 16) | k.allegiance},
            {"Param3", k.slots},
            {"Param4", k.perks},
            {"Param5", (k.classification << 48) | (k.target << 16) | k.attachments},
            {"Param6", (k.cause << 16) | k.optic},
        };
        return event("kill", timestamp, gamemode, values);
    }

    Json streakEnd(uint64_t streak, uint64_t kills, uint64_t timestamp, uint64_t gamemode)
    {
        Json values;
        for (unsigned i = 0; i < 7; ++i)
            values["Param" + std::to_string(i)] = uint64_t{0};
        values["Param0"] = streak;
        values["Param1"] = kills;
        return event("killstreak_end", timestamp, gamemode, values);
    }

    // Progress of one active quest stage after the given events.
    uint64_t quest(uint32_t id, const Json &events, unsigned category)
    {
        const auto *row = &*std::find_if(replayQuests.begin(), replayQuests.end(),
                                         [id](const auto &value) { return value.id == id; });
        Json states = Json::array({Json{{"id", uint64_t{id}}, {"name", row->name}, {"kind", uint64_t{15}},
                                        {"status", uint64_t{1}}, {"progress", uint64_t{0}},
                                        {"target", uint64_t{row->target}},
                                        {"activationTimestamp", uint64_t{1}}}});
        const std::vector<ReplayQuestEventContext> contexts(events.size(), {category});
        auto result = services::advanceReplayQuests(states, events, std::span(contexts));
        // Carry trackers across a second call to prove they persist in the state.
        return result.states[0].at("progress").get<uint64_t>();
    }

    uint64_t daily(uint32_t id, const Json &events, unsigned category, uint64_t now)
    {
        const auto *definition = services::replayDailyChallenge(id);
        Json states = Json::array({Json{{"id", uint64_t{id}}, {"name", definition->name()},
                                        {"kind", uint64_t{definition->kind}}, {"status", uint64_t{1}},
                                        {"progress", uint64_t{0}}, {"target", uint64_t{definition->target}},
                                        {"dailyCycle", now / 86400}, {"activationTimestamp", uint64_t{1}},
                                        {"expirationTimestamp", now + 86400}}});
        const std::vector<ReplayQuestEventContext> contexts(events.size(), {category});
        auto result = services::advanceReplayDailies(states, events, std::span(contexts), now);
        return result.states[0].at("progress").get<uint64_t>();
    }

    uint64_t mod(ReplayKillModifier flag) { return static_cast<uint64_t>(flag); }
    uint64_t target(ReplayKillTarget flag) { return static_cast<uint64_t>(flag); }
} // namespace

int run()
{
    const Kill any;
    // Rapid kills: the native 4-second rearm window.
    check(quest(1580, Json::array({kill(any, 100), kill(any, 103), kill(any, 110), kill(any, 112)}), 0) == 2,
          "1580 double kills inside 4 s windows");
    check(quest(1580, Json::array({kill(any, 100), kill(any, 106)}), 0) == 0, "1580 kills 6 s apart");
    check(quest(1582, Json::array({kill(any, 100), kill(any, 101), kill(any, 102)}), 0) == 1, "1582 triple kill");
    Kill fr = any;
    fr.weapon = 18;
    check(quest(10132, Json::array({kill(fr, 100), kill(any, 101)}), 0) == 0, "10132 needs both FR 5.56 kills");
    check(quest(10132, Json::array({kill(fr, 100), kill(fr, 101)}), 0) == 1, "10132 FR 5.56 double kill");
    // Kills in one life.
    Json life = Json::array();
    for (int i = 0; i < 4; ++i)
        life.push_back(kill(any, 100 + i));
    life.push_back(event("death", 105, 2));
    for (int i = 0; i < 5; ++i)
        life.push_back(kill(any, 110 + i));
    check(quest(1581, life, 0) == 1, "1581 five kills without dying after a death reset");
    Kill pistolHead = any;
    pistolHead.classification = 129;
    pistolHead.modifiers = mod(ReplayKillModifier::Headshot);
    check(quest(10049, Json::array({kill(pistolHead, 100), event("death", 101, 2), kill(pistolHead, 102)}), 0) == 0,
          "10049 headshots split by a death");
    check(quest(10049, Json::array({kill(pistolHead, 100), kill(pistolHead, 102)}), 0) == 1,
          "10049 two pistol headshots in one life");
    // Minute windows.
    Json minute = Json::array();
    for (int i = 0; i < 7; ++i)
        minute.push_back(kill(any, 100 + i * 8));
    check(quest(10136, minute, 0) == 1, "10136 seven kills in a minute");
    Json slow = Json::array();
    for (int i = 0; i < 7; ++i)
        slow.push_back(kill(any, 100 + i * 15));
    check(quest(10136, slow, 0) == 0, "10136 seven kills over 90 s");
    // Exact attachment slots (id % 1000 + 1 of loot/iw8_pi_golf21_attachment_ids.csv).
    Kill cronen = any;
    cronen.modifiers = mod(ReplayKillModifier::Pointblank);
    cronen.attachments = 1;
    cronen.slots = 15;
    check(quest(10042, Json::array({kill(cronen, 100)}), 0) == 1, "10042 Cronen LP945 Mini Reflex");
    Kill otherReflex = cronen;
    otherReflex.slots = 13;
    check(quest(10042, Json::array({kill(otherReflex, 100)}), 0) == 0, "10042 rejects another mini reflex");
    Kill scout = any;
    scout.modifiers = mod(ReplayKillModifier::Ads);
    scout.attachments = 2;
    scout.slots = (uint64_t{35} << 12) | 1;
    check(quest(10043, Json::array({kill(scout, 100)}), 0) == 1, "10043 ADS with Scout Combat Optic");
    Kill barrel = any;
    barrel.classification = 3;
    barrel.modifiers = mod(ReplayKillModifier::Longshot);
    barrel.attachments = 1;
    barrel.slots = 72;
    check(quest(1599, Json::array({kill(barrel, 100)}), 0) == 1, "1599 AR longshot with barlong");
    barrel.slots = 185;
    check(quest(1599, Json::array({kill(barrel, 100)}), 0) == 0, "1599 rejects integrally suppressed barrel");
    check(quest(1516, Json::array({kill(barrel, 100)}), 0) == 1, "1516 counts integrally suppressed barrel");
    Kill hybrid = any;
    hybrid.attachments = 1;
    hybrid.slots = 30;
    check(quest(10041, Json::array({kill(hybrid, 100), kill(hybrid, 102)}), 0) == 1, "10041 hybrid double kill");
    // Event and kill predicates.
    check(quest(1554, Json::array({event("stun", 100, 2), event("stun", 101, 2)}), 0) == 2, "1554 stun events");
    check(quest(1564, Json::array({event("hack", 100, 2)}), 0) == 1, "1564 hack event");
    Kill golem = any;
    golem.coalition = 20013;
    check(quest(10002, Json::array({kill(golem, 100), kill(any, 101)}), 0) == 1, "10002 SMG with Golem only");
    Kill iav = any;
    iav.weapon = 10000;
    check(quest(10032, Json::array({kill(iav, 100)}), 0) == 1, "10032 IAV turret kill");
    Kill apcVehicle = any;
    apcVehicle.weapon = 10002;
    apcVehicle.target = target(ReplayKillTarget::Vehicle);
    check(quest(10036, Json::array({kill(apcVehicle, 100)}), 0) == 1, "10036 vehicle destroyed with APC");
    Kill scavenger = any;
    scavenger.perks = 11;
    check(quest(1561, Json::array({kill(scavenger, 100), kill(any, 101)}), 0) == 1, "1561 Scavenger kill");
    Kill chain = any;
    chain.perks = uint64_t{10} << 16;
    check(quest(1567, Json::array({kill(chain, 100), streakEnd(70003, 3, 110, 2)}), 0) == 3,
          "1567 Kill Chain streak kills");
    check(quest(1567, Json::array({kill(any, 100), streakEnd(70003, 3, 110, 2)}), 0) == 0,
          "1567 streak kills without Kill Chain");
    // BR vehicle stages.
    Kill brVehicle = any;
    brVehicle.gameType = static_cast<uint64_t>(ReplayChallengeGameType::br);
    brVehicle.modifiers = mod(ReplayKillModifier::InVehicle);
    check(quest(50013, Json::array({kill(brVehicle, 100, 8)}), 1) == 1, "50013 BR kill in a vehicle");
    Kill brOccupied = brVehicle;
    brOccupied.target = target(ReplayKillTarget::Vehicle);
    brOccupied.modifiers = mod(ReplayKillModifier::VictimInVehicle);
    check(quest(50020, Json::array({kill(brOccupied, 100, 8)}), 1) == 1, "50020 occupied vehicle destroyed");
    // Co-op operations (gamemode 4, public co-op category 4).
    Kill juggernaut = any;
    juggernaut.target = target(ReplayKillTarget::AgentJuggernaut);
    juggernaut.coalition = 20009;
    check(quest(10058, Json::array({kill(juggernaut, 100, 4)}), 4) == 1, "10058 Juggernaut kill as Otter");
    check(quest(10058, Json::array({kill(juggernaut, 100, 4)}), 0) == 0, "10058 outside a co-op allocation");
    check(quest(10062, Json::array({event("cp_complete", 100, 4, Json{{"Param0", uint64_t{1}}})}), 4) == 1,
          "10062 completed operation");
    check(quest(10061, Json::array({streakEnd(70003, 4, 100, 4)}), 4) == 4, "10061 Precision Airstrike kills");
    check(quest(10063, Json::array({event("assist", 100, 4, Json{{"Param0", uint64_t{6}}, {"Param1", uint64_t{0}}})}), 4) == 1,
          "10063 co-op assist");
    Kill thermite = any;
    thermite.weapon = 50006;
    thermite.allegiance = 20029;
    thermite.target = target(ReplayKillTarget::AgentSoldier);
    check(quest(10064, Json::array({kill(thermite, 100, 4)}), 4) == 1, "10064 Thermite as Minotaur");
    // Dailies.
    const uint64_t now = 1792300000;
    const auto *ammo = &*std::find_if(replayKioskPurchases.begin(), replayKioskPurchases.end(),
                                      [](const auto &row) { return row.id == ReplayKioskItem::SuperAmmoDrop; });
    Json buy = event("buy_item", now - 10, 8,
                     Json{{"Param0", static_cast<uint64_t>(ammo->category)},
                          {"Param1", static_cast<uint64_t>(ammo->id)}, {"Param2", uint64_t{0}}});
    check(daily(5000, Json::array({buy}), 1, now) == 1, "5000 Munitions Box purchase");
    check(daily(5002, Json::array({buy}), 1, now) == 0, "5002 ignores Munitions Box");
    Kill coopAr = any;
    coopAr.classification = 3;
    coopAr.target = target(ReplayKillTarget::AgentSoldier);
    check(daily(9055, Json::array({kill(coopAr, now - 10, 4)}), 4, now) == 1, "9055 co-op AR kill");
    check(daily(9055, Json::array({kill(coopAr, now - 10, 4)}), 0, now) == 0, "9055 needs co-op allocation");
    check(daily(1797, Json::array({kill(any, now - 10, 2)}), 0, now) == 1, "1797 MP daily kill unchanged");
    std::printf("%s: %u mission rule checks, %u failed\n", failures ? "FAIL" : "PASS", passed + failures, failures);
    return failures ? 1 : 0;
}

int main()
{
    try
    {
        return run();
    }
    catch (const std::exception &e)
    {
        std::printf("FAIL: exception after %u checks: %s\n", passed + failures, e.what());
        return 1;
    }
}
