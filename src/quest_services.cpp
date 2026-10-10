#include "quest_services.h"
#include "replay_quest_data.h"
#include <algorithm>

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
            const auto weapon = number(values, "Param0") & 0xFFFF;
            const auto classification = number(values, "Param5") >> 48;
            const auto attachments = number(values, "Param5") & 0xFF;
            const auto cause = (number(values, "Param6") >> 16) & 0xFFFF;
            const auto target = (number(values, "Param5") >> 16) & 0xFFFF;
            // Shipped cp_mp/challenges.gsc also emits kill for equipment,
            // vehicles and streaks. findenemytype sets bit 0 only for players.
            if (!(target & 1))
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
                return classification == 65 && weapon >= 30 && weapon <= 32;
            case 1510:
                return classification == 129;
            case 1513:
                return cause == 21;
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
            case 1594:
                return attachments == 1 && (classification & 1) != 0;
            case 1596:
                return classification == 17 && attachments == 5;
            case 1597:
                return weapon == 18;
            case 1600:
                return classification == 65 && weapon >= 30 && weapon <= 32 &&
                       attachments == 5 && cause == 9;
            case 10044:
                return weapon == 1;
            case 10046:
                return weapon == 5 && attachments == 3;
            default:
                return false;
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

        uint64_t brProgress(uint32_t id, const Json &event, Json &state)
        {
            const auto &values = event.at("values");
            const auto &name = event.at("name").get_ref<const std::string &>();
            switch (id)
            {
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
            wire::require(owner);
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

    QuestProgress advanceReplayQuests(const Json &stored, const Json &events,
                                       std::optional<unsigned> publicCategory)
    {
        wire::require(stored.is_array() && stored.size() <= 15000);
        QuestProgress result;
        result.states = stored;
        if (!publicCategory)
            return result;
        for (const auto &event : events)
        {
            const auto &values = event.at("values");
            // The original AddGamemode emits 2 for MP, 8/24 for BR. Neither
            // client gamemode nor a public-looking name proves lobby membership.
            const auto mode = number(values, "gamemode");
            if (number(values, "version") != 1 || (mode != 2 && mode != 8 && mode != 24))
                continue;
            const auto category = mode == 2 ? 0u : 1u;
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
                    number(event, "timestamp") < number(state, "activationTimestamp"))
                    continue;
                const auto before = number(state, "progress");
                if (before >= row.target)
                    continue;
                const auto oldRemainder = number(state, "timerRemainderMs");
                const auto increment = category == 1 ? brProgress(identity, event, state)
                    : (event.at("name") == "kill" && completeParameters(values, 7) &&
                       killMatches(identity, values) ? uint64_t{1} : uint64_t{0});
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
        wire::require(states.is_array() && states.size() <= 15000 && quest(delivery.questId));
        const auto row = std::find_if(states.begin(), states.end(), [&](const Json &value)
                                     { return number(value, "id") == delivery.questId; });
        return row != states.end() && snapshotHash(states, *row) == delivery.questStateHash;
    }
} // namespace services
