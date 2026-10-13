// Replay bot records are serialized with GameStateInfo, not Demonware users.
// Bind those records to the stock lobby models and to native ClientBegin.
#include "com_debugstates.h"
#include "replay_dvar.h"
#include "DW_BotBindings.h"
#include "DW_BotNames.h"
#include "DW_BotStyleSelection.h"
#include "DW_BotStyleProfile.h"
#include <initializer_list>

extern "C"
{
    bool DW_LocalBackend_IsEnabled();
    void DW_MatchmakingAssignments_PrepareLaunch(const void *);
    void BG_GameStateInfo_ExpandBotData(const void *, void *);
    bool func_141187FA0();                       // Lobby_IsInLobby
    void *func_141187EE0();                      // Lobby_GetPartyData
    bool func_14118E1F0(const void *, unsigned); // Party_IsMemberPresent
    bool func_14118E020(const void *, unsigned); // Party_IsMemberIndexDataAvailable
    bool func_14118E2C0(const void *, unsigned); // Party_IsMemberUIVisible
    bool func_14118EE80(const void *, unsigned); // Party_IsWaitingForPartyMember
    bool func_14118E0E0(const void *, unsigned); // Party_IsMemberLocal
    bool func_140CA2250();                       // BG_GameStateInfo_IsBotMatchMakingDataInitialized
    bool func_140CA1C80();                       // BG_Bots_IsBotMatchMakingAllowedForPlaylist
    bool func_140CA2270(unsigned);               // BG_GameStateInfo_IsBotMemberPresent
    const void *func_140CA2230(unsigned);        // BG_GameStateInfo_GetBotMemberReadOnly
    void *func_140CA2210(unsigned);              // BG_GameStateInfo_GetBotMember
    bool func_141359F90(unsigned);               // SV_BotIsBot
    bool func_141371450(unsigned);               // SV_ClientMP_HasAssignedTeam
    void *func_14137D670();                      // SV_MainMP_GetServerLobby
    void *func_14118CF60(uint64_t *, const void *, unsigned); // Party_GetXuid
    int func_14118C070(const void *, uint64_t);               // Party_GetAssignedSquad
    int func_14118C110(const void *, uint64_t);               // Party_GetAssignedTeam
    const char *func_14107EA60(const uint64_t *);             // XUID::ToDevString
    void func_1412B0570(int, const char *, ...);              // Com_PrintError
    extern unsigned char gl_14E183D00[];                      // g_svMPBotData, 200 native records
    extern unsigned char gl_14EEF12A4[];                      // frontend client state
    extern int gl_14EEF1288[];                                // clientUIActives.connectionState
    extern unsigned char g_partyData[];
    extern dvar_t *gl_14D386988, *gl_14D386990, *gl_14C796328;
    void func_141B23610(const void *, int *);                   // SortPartyMembers
    void func_141B22140(const void *, unsigned, uint16_t, int); // stock human binding
    bool func_141528240();                                      // GameBattles active feature
    bool func_140F22880();                                      // GameBattles active session
    void func_140F23A00(const void *, uint16_t, int *, int *);
    bool func_14118DDB0(const void *);               // Party_IsHostDedicated
    unsigned func_14118C7D0(const void *);           // Party_GetNumGameSlots
    uint16_t func_141B0D390(uint16_t, const char *); // CreateModelFromPath
    void func_141B0E150(uint16_t, int);              // SetInt
    void func_141B0E0B0(uint16_t, bool);             // SetBool
    void func_141B0E280(uint16_t, const char *);     // SetString
    uint16_t func_141B0D520();                           // GetGlobalModel
    uint16_t func_141B0D710(uint16_t, const char *);     // GetModelFromPath
    int func_141B0D530(uint16_t);                        // GetInt
    bool func_141192AC0(const void *);                   // Party_UsingTeams (verified below)
    bool func_141192AA0(const void *);                   // Party_UsingSquads
    extern uint8_t replay_rva_0c27e4b0[];                // Native matchmaker lobby identity
}

namespace
{
    // All 88 bytes, including the complete opaque portion of the native 36-byte
    // wire data. Offsets are verified against Replay ReadBotData and its users.
    struct BotRecord
    {
        char name[36];
        char clan[11];
        uint8_t displayPad;
        uint16_t nameIndex;
        uint8_t unknown50[2];
        uint32_t modelIndex[3];
        uint8_t unknown64[12];
        uint8_t unknown76, team;
        uint16_t skill;
        uint8_t opaque80[2];
        uint16_t unknown82;
        uint8_t valid, inUse, client, pad;
    };

    static_assert(sizeof(BotRecord) == 88 && offsetof(BotRecord, team) == 77);
    static_assert(offsetof(BotRecord, opaque80) == 80);
    static_assert(offsetof(BotRecord, valid) == 84 && offsetof(BotRecord, client) == 86);
    // ReadBotData synchronizes these exact 36 bytes independently of the
    // expanded display record. Guests derive names from the same index/skill,
    // without depending on host-only roster state or widening UInt16 indices.
    struct BotWireRecord
    {
        uint16_t nameIndex;
        uint8_t unknown50[2];
        uint32_t modelIndex[3];
        uint8_t unknown64[12];
        uint8_t unknown76, team;
        uint16_t skill;
        uint8_t opaque80[2];
        uint16_t unknown82;
    };
    static_assert(sizeof(BotWireRecord) == 36);
    static_assert(offsetof(BotWireRecord, skill) == 30);
    static_assert(offsetof(BotRecord, skill) - offsetof(BotRecord, nameIndex) ==
                  offsetof(BotWireRecord, skill));
    // Five visible characters, including the brackets. The engine's two-byte
    // color controls do not occupy visible tag characters; the complete text
    // and terminator still fit the native eleven-byte bot clan field.
    constexpr char BotClanTag[] = "[^3Bot^7]";
    static_assert(sizeof(BotClanTag) <= sizeof(BotRecord::clan));

    struct MemberRecord
    {
        uint8_t unknown0[52];
        char name[36];
        uint8_t unknown88[52];
        int follower;
        uint8_t unknown144[244];
        int subparty, team, squad;
        uint8_t unknown400[2], status, unknown403[5];
        uint64_t xuid;
        uint8_t unknown416[72];
    };

    static_assert(sizeof(MemberRecord) == 488 && offsetof(MemberRecord, team) == 392);
    static_assert(offsetof(MemberRecord, xuid) == 408);
    dvar_t *s_reserved{}, *s_squadSize{};
    BotRecord s_rosterRecords[200]{};
    unsigned s_rosterSlots[200]{};
    bool s_rosterCreated[200]{};
    const void *s_rosterParty = nullptr;
    uint64_t s_rosterLobby = 0;
    unsigned s_rosterStart = 0, s_rosterCandidate = 0;
    bool s_rosterValid = false;

    bool SelectAppearance(BotRecord &bot)
    {
        if (!DW_Bot_CustomizationEnabled)
            return false;
        const auto *groups = reinterpret_cast<const DWBotCustomizationGroup *>(DW_Bot_CustomizationGroups);
        const auto *packages = reinterpret_cast<const DWBotCustomizationPackage *>(DW_Bot_CustomizationPackages);
        // Use registered random-eligible male/female packages, exactly like the
        // native random customization consumer. Never seed the engine RNG or
        // borrow a human's equipped skin. Stable bot name/skill select the pair.
        const unsigned seed = unsigned(bot.nameIndex) * 2654435761u + bot.skill;
        constexpr unsigned skinCount = sizeof(DWBotOperatorSkins) / sizeof(*DWBotOperatorSkins);
        for (unsigned attempt = 0; attempt < skinCount; ++attempt)
        {
            const auto &skin = DWBotOperatorSkins[(seed + attempt) % skinCount];
            const uint16_t wanted[] = {skin.head, skin.body};
            const DWBotCustomizationPackage *pair[2]{};
            for (unsigned kind = 0; kind < 2; ++kind)
            {
                const auto &group = groups[kind];
                if (!group.count || group.count > DWBotCustomizationPackageLimit ||
                    unsigned(group.first) + group.count > DWBotCustomizationPackageLimit)
                    return false;
                for (unsigned i = 0; i < group.count; ++i)
                {
                    const auto &package = packages[group.first + i];
                    if (package.primary == wanted[kind] && !package.invalid)
                    {
                        pair[kind] = &package;
                        break;
                    }
                }
            }
            if (pair[0] && pair[1] && pair[0]->category == pair[1]->category)
            {
                bot.modelIndex[0] = skin.head;
                bot.modelIndex[1] = skin.body;
                return true;
            }
        }
        for (unsigned attempt = 0; attempt < 2; ++attempt)
        {
            const unsigned category = (seed + attempt) & 1;
            uint16_t selected[2]{};
            bool complete = true;
            for (unsigned kind = 0; kind < 2; ++kind)
            {
                const auto &group = groups[kind];
                if (!group.count || group.count > DWBotCustomizationPackageLimit ||
                    unsigned(group.first) + group.count > DWBotCustomizationPackageLimit)
                    return false;
                unsigned eligible = 0;
                for (unsigned i = 0; i < group.count; ++i)
                {
                    const auto &package = packages[group.first + i];
                    if (package.randomEligible && !package.invalid && package.category == category &&
                        package.primary && package.primary != UINT16_MAX)
                        ++eligible;
                }
                if (!eligible)
                {
                    complete = false;
                    break;
                }
                unsigned ordinal = (seed / (kind ? 17u : 7u)) % eligible;
                for (unsigned i = 0; i < group.count; ++i)
                {
                    const auto &package = packages[group.first + i];
                    if (package.randomEligible && !package.invalid && package.category == category &&
                        package.primary && package.primary != UINT16_MAX && !ordinal--)
                    {
                        selected[kind] = package.primary;
                        break;
                    }
                }
            }
            if (complete)
            {
                bot.modelIndex[0] = selected[0];
                bot.modelIndex[1] = selected[1];
                return true;
            }
        }
        return false;
    }

    const MemberRecord &Member(const void *party, unsigned index)
    {
        return reinterpret_cast<const MemberRecord *>(static_cast<const uint8_t *>(party) +
                                                      2192)[index];
    }

    bool SameName(const char *first, const char *second)
    {
        unsigned a = 0, b = 0;
        while (a < 36 && b < 36)
        {
            if (first[a] == '^' && a + 1 < 36 && first[a + 1] >= '0' && first[a + 1] <= '9')
            {
                a += 2;
                continue;
            }
            if (second[b] == '^' && b + 1 < 36 && second[b + 1] >= '0' && second[b + 1] <= '9')
            {
                b += 2;
                continue;
            }
            char left = first[a++], right = second[b++];
            if (left >= 'A' && left <= 'Z')
                left += 'a' - 'A';
            if (right >= 'A' && right <= 'Z')
                right += 'a' - 'A';
            if (left != right)
                return false;
            if (!left)
                return true;
        }
        return false;
    }

    bool Ready(const void *party)
    {
        return party && DW_LocalBackend_IsEnabled() && func_141187FA0() &&
               party == func_141187EE0() && func_140CA2250();
    }

    struct Assignments
    {
        const BotRecord *bots[200]{};
        int groups[200]{};
    };

    void Calculate(const void *party, Assignments &result, const BotRecord *serverPool = nullptr)
    {
        if (!party || (!serverPool && !Ready(party)))
            return;
        const unsigned size = s_squadSize ? unsigned(s_squadSize->current.integer) : 0;
        const unsigned limit = size == 1 ? 152 : 63;
        unsigned count[152]{};
        bool reserved[152]{};
        const char *value = s_reserved ? s_reserved->current.string : nullptr;
        bool validMask = value != nullptr;
        if (validMask)
        {
            for (unsigned i = 0; i < 50; ++i)
                if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f')))
                {
                    validMask = false;
                    break;
                }
            if (validMask && value[50])
                validMask = false;
        }
        if (validMask)
            for (unsigned i = 0; i < limit; ++i)
            {
                const char digit = value[49 - i / 4];
                const unsigned bits = unsigned(digit <= '9' ? digit - '0' : digit - 'a' + 10);
                reserved[i] = (bits & (1u << (i % 4))) != 0;
            }
        for (unsigned i = 0; i < 200; ++i)
        {
            result.groups[i] = -1;
            const bool human = func_14118E1F0(party, i);
            if (human)
            {
                const auto &member = Member(party, i);
                const int group = size == 1 ? member.team - 1 : member.squad;
                if (group >= 0 && unsigned(group) < limit)
                {
                    ++count[group];
                    if (!validMask)
                        reserved[group] = true;
                }
            }
            else if (serverPool)
            {
                if (serverPool[i].valid)
                    result.bots[i] = &serverPool[i];
            }
            else if (!func_14118E020(party, i) && func_140CA2270(i))
                result.bots[i] = static_cast<const BotRecord *>(func_140CA2230(i));
        }
        if (!size)
            return;
        unsigned group = 0;
        for (unsigned i = 0; i < 200; ++i)
            if (result.bots[i])
            {
                while (group < limit && (reserved[group] || count[group] >= size))
                    ++group;
                if (group == limit)
                    break;
                ++count[group];
                result.groups[i] = int(group);
            }
    }

    int Group(const void *party, unsigned index, const BotRecord *pool)
    {
        Assignments assignments{};
        Calculate(party, assignments, pool);
        return index < 200 ? assignments.groups[index] : -1;
    }

    int Team(const Assignments &assignments, unsigned index)
    {
        return assignments.groups[index] >= 0 ? assignments.groups[index] + 1
                                              : assignments.bots[index]->team;
    }

    int Squad(const Assignments &assignments, unsigned index)
    {
        return s_squadSize && s_squadSize->current.integer > 1 ? assignments.groups[index] : -1;
    }

    const BotRecord *ServerBot(unsigned client, unsigned &index)
    {
        const auto *nativeClient = DW_LocalBackend_IsEnabled()
            ? DWBot_CurrentNativeClient(client) : nullptr;
        if (!nativeClient || !DWBot_IsCurrentEntity(client, nativeClient->entity) ||
            !func_141359F90(client))
            return nullptr;
        const auto *pool = reinterpret_cast<const BotRecord *>(gl_14E183D00);
        for (index = 0; index < 200; ++index)
            if (pool[index].valid && pool[index].inUse && pool[index].client == client)
                return &pool[index];
        return nullptr;
    }

    void Int(uint16_t parent, const char *key, int value)
    {
        func_141B0E150(func_141B0D390(parent, key), value);
    }

    void Bool(uint16_t parent, const char *key, bool value)
    {
        func_141B0E0B0(func_141B0D390(parent, key), value);
    }

    void Text(uint16_t parent, const char *key, const char *value)
    {
        func_141B0E280(func_141B0D390(parent, key), value);
    }

    uint16_t Row(uint16_t model, unsigned number)
    {
        char text[4]{};
        if (number >= 100)
        {
            text[0] = char('0' + number / 100);
            text[1] = char('0' + number / 10 % 10);
            text[2] = char('0' + number % 10);
        }
        else if (number >= 10)
        {
            text[0] = char('0' + number / 10);
            text[1] = char('0' + number % 10);
        }
        else
            text[0] = char('0' + number);
        return func_141B0D390(model, text);
    }

    void PushBot(const void *,
                 unsigned index,
                 const BotRecord &bot,
                 uint16_t model,
                 const Assignments &assignments)
    {
        char name[37]{};
        for (unsigned i = 0; i < 36; ++i)
            name[i] = bot.name[i];
        Int(model, "memberIndex", int(index));
        // Unique UI key only. It never enters a native party member, backend
        // identity or playercard cache. Zero for every bot collapses the stock
        // scene's XUID-keyed character list to one character on remote clients.
        char displayKey[24]{};
        Com_sprintf(displayKey, sizeof(displayKey), "%llu", 0xB070000000000000ULL | bot.nameIndex);
        Text(model, "xuid", displayKey);
        Text(model, "platformId", "0");
        Text(model, "gamertag", name);
        Text(model, "gamertagWithHash", name);
        Text(model, "clanTag", BotClanTag);
        Bool(model, "isBot", true);
        for (const auto *key : {"isLobbyHost",
                                "isPrivatePartyHost",
                                "missingGamertag",
                                "isMyPlayer",
                                "isCrossplayPlayer",
                                "customEmblemEquipped",
                                "isPlaceHolderPlayer"})
            Bool(model, key, false);
        Bool(model, "commitReady", true);
        Bool(model, "usingGamepad", false);
        Int(model, "controllerIndex", -1);
        Int(model, "subparty", -1);
        Int(model, "team", Team(assignments, index));
        Int(model, "squad", Squad(assignments, index));
        Int(model, "desiredTeam", Team(assignments, index));
        const uint64_t profile = DWBotStyle::ProfileSeed(bot.nameIndex, bot.skill, bot.modelIndex);
        const auto rank = DWBotStyle::SelectRank(profile);
        Int(model, "rank", rank.index);
        Int(model, "baseRank", rank.index);
        for (const auto *key : {"prestige",
                                "microphoneState",
                                "presencePlatform",
                                "emblemIndex",
                                "backgroundIndex",
                                "followersCount"})
            Int(model, key, 0);
        Int(model, "followerIndex", -1);
        // These are the same primary head/body IDs read by native AddMPBot
        // into ctzHead/ctzBody, and transported in the stock 36-byte wire data.
        Int(model, "selectedOperatorIndex", 0);
        for (const auto *key : {"headWest", "headEast"})
            Int(model, key, int(bot.modelIndex[0]));
        for (const auto *key : {"bodyWest", "bodyEast"})
            Int(model, key, int(bot.modelIndex[1]));
        Int(model, "execWest", 0);
        Int(model, "execEast", 0);
        // Real Replay base loot IDs. Every bot has an independent stock weapon
        // presentation; clear every old customization child when rows are reused
        // so the UI never falls back to a human's favorite weapon or attachments.
        const auto style = DWBotStyle::SelectStyle(profile);
        Text(model, "botLoadoutStyle", DWBotStyle::StyleNames[unsigned(style)]);
        const auto setup = func_141B0D390(model, "weaponSetup");
        for (unsigned slot = 0; slot < 2; ++slot)
        {
            const auto weapon = Row(setup, slot);
            const auto *selected = DWBotStyle::WeaponForSlot(profile, slot);
            const auto attachmentsSelected = DWBotStyle::Select(selected, profile, style);
            Int(weapon, "weaponLootID", selected ? int(selected->baseLoot) : 0);
            Text(weapon, "cosmeticAttachment", "");
            Text(weapon, "weaponCamo", "");
            const auto stickers = func_141B0D390(weapon, "sticker");
            for (unsigned i = 0; i < 4; ++i)
                func_141B0E280(Row(stickers, i), "");
            Int(weapon, "stickerCount", 4);
            const auto attachments = func_141B0D390(weapon, "attachment");
            for (unsigned i = 0; i < 5; ++i)
            {
                const auto attachment = Row(attachments, i);
                Int(attachment, "variant", int(attachmentsSelected.variants[i]));
                Text(attachment, "attachment", attachmentsSelected.references[i]);
            }
            Int(weapon, "attachmentCount", int(attachmentsSelected.count));
        }
        Int(model, "weaponCount", 2);
    }
} // namespace

extern "C" void DW_BotPolicy_Register()
{
    if (s_reserved)
        return;
    DvarValue value{};
    DvarLimits limits{};
    value.string = "";
    s_reserved = Dvar_RegisterVariant("replay_dw_reservedSquads",
                                      Dvar_GenerateChecksum("replay_dw_reservedSquads"),
                                      9,
                                      0,
                                      &value,
                                      &limits,
                                      "DW No Fill squad reservations (200-bit hexadecimal)");
    s_squadSize =
        Dvar_RegisterInt("replay_dw_squadSize", 0, 0, 200, 0, "DW native battle royale squad size");
}

extern "C" void DW_BotPolicy_BuildRoster(const void *party, unsigned capacity, unsigned count)
{
    if (!party || !count || count > 199 || capacity > 200 || count > capacity || !func_140CA2250())
        return;
    const uint64_t lobby = *reinterpret_cast<const uint64_t *>(replay_rva_0c27e4b0 + 79656);
    if (!s_rosterValid || s_rosterLobby != lobby || s_rosterParty != party)
    {
        s_rosterLobby = lobby;
        s_rosterParty = party;
        s_rosterStart = (static_cast<const BotRecord *>(func_140CA2230(0))->nameIndex +
                         static_cast<const BotRecord *>(func_140CA2230(0))->skill) % DWBotWireNameCount;
        s_rosterCandidate = 0;
        for (unsigned i = 0; i < 200; ++i)
        {
            s_rosterCreated[i] = false;
            s_rosterSlots[i] = 200;
        }
        s_rosterValid = true;
    }
    unsigned available = 0;
    for (unsigned slot = 0; slot < capacity; ++slot)
        if (!func_14118E020(party, slot))
            ++available;
    if (count > available)
        return;
    // Keep complete native records and their prior slots across gradual fills.
    // The native selector may have regenerated its prefix, so reuse the cache
    // before copying any newly selected record. Only a human collision moves
    // an existing bot; a reduction retires the highest logical ordinals.
    for (unsigned i = 0; i < count; ++i)
    {
        const bool created = s_rosterCreated[i];
        if (!created)
            s_rosterRecords[i] = *static_cast<const BotRecord *>(func_140CA2230(i));
        auto &selected = s_rosterRecords[i];
        bool collision = false;
        for (unsigned human = 0; human < capacity; ++human)
            if (func_14118E020(party, human) && SameName(Member(party, human).name, selected.name))
                collision = true;
        if (created && !collision)
            continue;
        // 73 is coprime to 32768: every custom UInt16 choice is visited once.
        // Each preserved native skill selects its bank in the 100k-name pool.
        // Only actual humans and the at-most-199 cached bots are compared.
        bool unique = false;
        unsigned attempts = 0;
        while (!unique && attempts++ < DWBotWireNameCount)
        {
            const unsigned candidate = s_rosterCandidate++ % DWBotWireNameCount;
            const unsigned name = (s_rosterStart + candidate * 73) % DWBotWireNameCount;
            selected.nameIndex = uint16_t(0x8000 | name);
            BG_GameStateInfo_ExpandBotData(&selected.nameIndex, &selected);
            unique = true;
            for (unsigned human = 0; human < capacity; ++human)
                if (func_14118E020(party, human) && SameName(Member(party, human).name, selected.name))
                    unique = false;
            for (unsigned previous = 0; previous < 200; ++previous)
                if (previous != i && s_rosterCreated[previous] &&
                    SameName(s_rosterRecords[previous].name, selected.name))
                    unique = false;
        }
        if (!unique)
            return;
        if (!created)
            SelectAppearance(selected);
        s_rosterCreated[i] = true;
    }
    bool claimed[200]{};
    for (unsigned i = count; i < 200; ++i)
        s_rosterSlots[i] = 200;
    for (unsigned i = 0; i < count; ++i)
    {
        const unsigned slot = s_rosterSlots[i];
        if (slot < capacity && !func_14118E020(party, slot) && !claimed[slot])
            claimed[slot] = true;
        else
            s_rosterSlots[i] = 200;
    }
    for (unsigned i = 0; i < count; ++i)
        if (s_rosterSlots[i] == 200)
            for (unsigned slot = 0; slot < capacity; ++slot)
                if (!claimed[slot] && !func_14118E020(party, slot))
                {
                    s_rosterSlots[i] = slot;
                    claimed[slot] = true;
                    break;
                }
    for (unsigned i = 0; i < 200; ++i)
        *static_cast<BotRecord *>(func_140CA2210(i)) = {};
    for (unsigned i = 0; i < count; ++i)
        *static_cast<BotRecord *>(func_140CA2210(s_rosterSlots[i])) = s_rosterRecords[i];
}

extern "C" void DW_BotPolicy_ResetRoster()
{
    s_rosterValid = false;
}

extern "C" void DW_BotPolicy_CaptureRoster()
{
    if (!s_rosterValid || !func_140CA2250())
        return;
    for (unsigned i = 0; i < 200; ++i)
        if (s_rosterCreated[i] && s_rosterSlots[i] < 200)
        {
            const auto &record = *static_cast<const BotRecord *>(func_140CA2230(s_rosterSlots[i]));
            if (record.valid)
                s_rosterRecords[i] = record;
        }
}

extern "C" void BG_GameStateInfo_ExpandBotData(const void *wireData, void *displayData)
{
    if (!wireData || !displayData)
        return;
    const auto &wire = *static_cast<const BotWireRecord *>(wireData);
    const unsigned index = wire.nameIndex;
    auto *bot = static_cast<BotRecord *>(displayData);
    const char *name = nullptr;
    if (DW_LocalBackend_IsEnabled() && index >= 0x8000)
        name = DWBotNameForWire(wire.nameIndex, wire.skill);
    else
    {
        const void *table = nullptr;
        DW_Bot_StringTableAsset(DW_Bot_NameTable, &table);
        if (!table)
        {
            func_1412B0570(1, "ERROR: bot name file %s not found!\n", DW_Bot_NameTable);
            name = "filemissing";
        }
        else if (index >= unsigned(DW_Bot_StringTableRows(table)))
        {
            func_1412B0570(1, "ERROR: bot index %d out of range for %d in file %s!\n", index,
                          DW_Bot_StringTableRows(table), DW_Bot_NameTable);
            name = "outofrange";
        }
        else
            name = DW_Bot_StringTableColumn(table, index, 1);
    }
    unsigned character = 0;
    if (name && name != bot->name)
    {
        while (character + 1 < sizeof(bot->name) && name[character])
        {
            bot->name[character] = name[character];
            ++character;
        }
        bot->name[character] = 0;
    }
    else if (!name)
        bot->name[0] = 0;
    const char *clan = DW_LocalBackend_IsEnabled() ? BotClanTag : "[^3Bot]";
    for (character = 0; character + 1 < sizeof(bot->clan) && clan[character]; ++character)
        bot->clan[character] = clan[character];
    bot->clan[character] = 0;
}

// Received bot records are authoritative even on a guest whose playlist bot
// eligibility/controller flag differs from the host. Stock behavior is retained
// outside DW. Do not fabricate private-party members or bot platform identities.
extern "C" bool BG_GameStateInfo_IsBotMemberPresent(unsigned index)
{
    if (index >= 200)
        return false;
    if (DW_LocalBackend_IsEnabled())
        return func_140CA2250() &&
               static_cast<const BotRecord *>(func_140CA2230(index))->valid == 1;
    return func_140CA1C80() &&
           static_cast<const BotRecord *>(func_140CA2230(index))->valid == 1;
}

extern "C" bool func_14118E2C0(const void *party, unsigned index)
{
    if (!party || index >= 200)
        return false;
    if (Member(party, index).status >= 5 || func_14118EE80(party, index))
        return true;
    return Ready(party) && !func_14118E020(party, index) && func_140CA2270(index);
}

extern "C" unsigned func_14118ADD0(const void *party)
{
    if (!party)
        return 0;
    const auto *bytes = static_cast<const uint8_t *>(party);
    if (!*reinterpret_cast<const int *>(bytes + 311116) ||
        (*reinterpret_cast<const int *>(bytes + 311112) &&
         !*reinterpret_cast<const int *>(bytes + 311020)))
        return 0;
    unsigned count = 0;
    for (unsigned i = 0; i < 200; ++i)
        if (func_14118E2C0(party, i))
            ++count;
    return count;
}

extern "C" bool DW_BotPolicy_IsBattleRoyale()
{
    return DW_LocalBackend_IsEnabled() && s_squadSize && s_squadSize->current.integer > 0;
}

extern "C" bool DW_BotPolicy_ProfileSeed(unsigned client, uint64_t *seed)
{
    unsigned index = 0;
    const auto *bot = ServerBot(client, index);
    if (!bot || !seed)
        return false;
    *seed = DWBotStyle::ProfileSeed(bot->nameIndex, bot->skill, bot->modelIndex);
    return true;
}

extern "C" void DW_BotPolicy_Prepare(const void *party)
{
    Assignments assignments{};
    Calculate(party, assignments);
    unsigned axis = 0, allies = 0;
    for (unsigned i = 0; i < 200; ++i)
        if (func_14118E1F0(party, i))
        {
            if (Member(party, i).team == 1)
                ++axis;
            if (Member(party, i).team == 2)
                ++allies;
        }
    for (unsigned i = 0; i < 200; ++i)
        if (assignments.bots[i])
        {
            auto *bot = static_cast<BotRecord *>(func_140CA2210(i));
            for (unsigned character = 0; character < sizeof(bot->clan); ++character)
                bot->clan[character] = character < sizeof(BotClanTag) ? BotClanTag[character] : 0;
            if (s_squadSize && s_squadSize->current.integer > 0)
                bot->team = uint8_t(Team(assignments, i));
            else if (gl_14C796328->current.integer == 2)
            {
                bot->team = allies <= axis ? 2 : 1;
                if (bot->team == 2)
                    ++allies;
                else
                    ++axis;
            }
        }
}

// BR scripts request bots through the stock spawn quotas. Select from the
// native pool, then ClientBegin applies the explicit BR group instead of
// restricting available bot records to axis/allies.
extern "C" int func_14132ED80(unsigned requestedTeam)
{
    auto *pool = reinterpret_cast<BotRecord *>(gl_14E183D00);
    const bool br = DW_LocalBackend_IsEnabled() && s_squadSize && s_squadSize->current.integer > 0;
    int selected = -1;
    for (unsigned i = 0; i < 200; ++i)
        if ((br || pool[i].team == requestedTeam) && !pool[i].inUse && pool[i].valid &&
            !func_14118E1F0(func_141187EE0(), i))
        {
            pool[i].inUse = 1;
            selected = int(i);
            break;
        }
    Com_Printf(131087,
               "SV_AssignBotDataToTeam: Assigning bot data for index %d for team %d\n",
               selected,
               requestedTeam);
    return selected;
}

// Complete native ClientBegin getters. Bots receive their pool assignment
// before GSC begins; human, non-DW and non-BR behavior remains native.
extern "C" int func_1413707D0(unsigned client)
{
    unsigned index = 0;
    if (ServerBot(client, index) && s_squadSize && s_squadSize->current.integer > 0)
        return s_squadSize->current.integer == 1
                   ? -1
                   : Group(func_14137D670(),
                           index,
                           reinterpret_cast<const BotRecord *>(gl_14E183D00));
    const bool br = DW_BotPolicy_IsBattleRoyale();
    auto *party = br ? func_14137D670() : nullptr;
    if (br)
        DW_MatchmakingAssignments_PrepareLaunch(party);
    if (!func_141371450(client))
        return 0;
    if (!party)
        party = func_14137D670();
    uint64_t xuid{};
    func_14118CF60(&xuid, party, client);
    if (xuid)
        return func_14118C070(party, xuid);
    func_1412B0570(15,
                   "SV_GetAssignedSquad Error: unknown xuid (%s) for client (%i).\n",
                   func_14107EA60(&xuid),
                   client);
    return -1;
}

extern "C" int func_141370860(unsigned client)
{
    // Native ClientBegin calls this before CalculateRanks and its GSC thread.
    // Bind the transported profile here; later native setrank calls retain it.
    DW_BotRank_Apply(client);
    unsigned index = 0;
    if (const auto *bot = ServerBot(client, index);
        bot && s_squadSize && s_squadSize->current.integer > 0)
    {
        const int group =
            Group(func_14137D670(), index, reinterpret_cast<const BotRecord *>(gl_14E183D00));
        return group >= 0 ? group + 1 : bot->team;
    }
    const bool br = DW_BotPolicy_IsBattleRoyale();
    auto *party = br ? func_14137D670() : nullptr;
    if (br)
        DW_MatchmakingAssignments_PrepareLaunch(party);
    if (!func_141371450(client))
        return 0;
    if (!party)
        party = func_14137D670();
    uint64_t xuid{};
    func_14118CF60(&xuid, party, client);
    if (xuid)
        return func_14118C110(party, xuid);
    func_1412B0570(15,
                   "SV_GetAssignedTeam Error: unknown xuid (%s) for client (%i).\n",
                   func_14107EA60(&xuid),
                   client);
    return 0;
}

// Complete stock party-to-model sequence, adding the native pool at the same
// model root and leaving the human binding untouched. No party records, XUIDs,
// session identities or backend members are fabricated for display.
extern "C" void func_141B21D50(const void *party, uint16_t model)
{
    if (!party || !*reinterpret_cast<const int *>(static_cast<const uint8_t *>(party) + 311116) ||
        (!gl_14EEF12A4[0] && gl_14EEF1288[0] >= 3))
        return;
    int sorted[200]{}, teamCounts[156]{}, subparty = 0, friendlyTeam = 0, friendlySquad = 0;
    func_141B23610(party, sorted);
    const int limit = gl_14D386988->current.enabled ? gl_14D386990->current.integer : 28;
    for (int slot : sorted)
        if (slot >= 0 && slot < 200 && func_14118E0E0(party, unsigned(slot)))
        {
            const auto &member = Member(party, unsigned(slot));
            subparty = member.subparty;
            friendlyTeam = member.team;
            friendlySquad = member.squad;
            break;
        }
    Int(model, "friendlySubPartyIndex", subparty);
    Assignments assignments{};
    Calculate(party, assignments);
    unsigned shown = 0, count = 0, all = 0;
    const bool gameBattlesFeature = func_141528240(), gameBattlesActive = func_140F22880();
    if (gameBattlesFeature && gameBattlesActive)
        func_140F23A00(party, model, sorted, teamCounts);
    else
    {
        for (int ordinal = 0; ordinal < limit && ordinal < 200; ++ordinal)
        {
            const int slot = sorted[ordinal];
            if (slot < 0 || slot >= 200 || assignments.bots[slot] ||
                !func_14118E2C0(party, unsigned(slot)))
                continue;
            const auto &member = Member(party, unsigned(slot));
            func_141B22140(party, unsigned(slot), Row(model, shown++), ordinal);
            if (member.team >= 0 && member.team < 156)
                ++teamCounts[member.team];
            if (!member.follower)
                ++count;
        }
        for (unsigned i = 0; i < 200; ++i)
            if (const auto *bot = assignments.bots[i])
            {
                ++all;
                if (int(shown) < limit && shown < 200)
                {
                    PushBot(party, i, *bot, Row(model, shown++), assignments);
                    const int team = Team(assignments, i);
                    if (team >= 0 && team < 156)
                        ++teamCounts[team];
                    ++count;
                }
            }
    }
    for (int slot : sorted)
        if (slot >= 0 && slot < 200 && !assignments.bots[slot] &&
            func_14118E2C0(party, unsigned(slot)))
            ++all;
    Int(model,
        "friendlyTeamCount",
        friendlyTeam >= 0 && friendlyTeam < 156 ? teamCounts[friendlyTeam] : 0);
    Int(model, "teamAlliesCount", teamCounts[2]);
    Int(model, "teamAxisCount", teamCounts[1]);
    Int(model, "teamSpectatorCount", teamCounts[153]);
    Int(model, "teamFollowerCount", teamCounts[154]);
    Bool(model, "isDedi", func_14118DDB0(g_partyData));
    Int(model, "count", int(count));
    Int(model, "memberCount", int(all));
    Int(model, "maxCount", int(func_14118C7D0(party)));
    Int(model, "friendlyTeamIndex", friendlyTeam);
    Int(model, "friendlySquadIndex", friendlySquad);
}

extern "C" void func_141B22B40(const void *party, uint16_t model)
{
    if (!party || !*reinterpret_cast<const int *>(static_cast<const uint8_t *>(party) + 311116) ||
        (!gl_14EEF12A4[0] && gl_14EEF1288[0] >= 3))
        return;
    const auto global = func_141B0D520();
    const int squad = func_141B0D530(
        func_141B0D710(global, "alwaysLoaded.activeParty.members.friendlySquadIndex"));
    const int team = func_141B0D530(
        func_141B0D710(global, "alwaysLoaded.activeParty.members.friendlyTeamIndex"));
    const bool teams = func_141192AC0(party), squads = func_141192AA0(party);
    int sorted[200]{};
    func_141B23610(party, sorted);
    const int limit = gl_14D386988->current.enabled ? gl_14D386990->current.integer : 28;
    Assignments assignments{};
    Calculate(party, assignments);
    unsigned shown = 0, count = 0, all = 0;
    for (int ordinal = 0; ordinal < limit && ordinal < 200; ++ordinal)
    {
        const int slot = sorted[ordinal];
        if (slot < 0 || slot >= 200 || assignments.bots[slot] ||
            !func_14118E2C0(party, unsigned(slot)))
            continue;
        const auto &member = Member(party, unsigned(slot));
        if (func_14118E0E0(party, unsigned(slot)) ||
            ((!teams || (team != 0 && member.team == team)) &&
             (!squads || (squad != -1 && member.squad == squad))))
        {
            func_141B22140(party, unsigned(slot), Row(model, shown++), ordinal);
            if (!member.follower)
                ++count;
        }
    }
    for (unsigned i = 0; i < 200; ++i)
        if (const auto *bot = assignments.bots[i])
        {
            ++all;
            if (int(shown) < limit && shown < 200 &&
                (!teams || (team != 0 && Team(assignments, i) == team)) &&
                (!squads || (squad != -1 && Squad(assignments, i) == squad)))
            {
                PushBot(party, i, *bot, Row(model, shown++), assignments);
                ++count;
            }
        }
    for (int slot : sorted)
        if (slot >= 0 && slot < 200 && !assignments.bots[slot] &&
            func_14118E2C0(party, unsigned(slot)))
            ++all;
    Int(model, "count", int(count));
    Int(model, "memberCount", int(all));
}
