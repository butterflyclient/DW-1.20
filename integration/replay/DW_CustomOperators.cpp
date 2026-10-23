// Custom operators use native client customization; network appearance stays stock.
#include "DW_CustomOperators.h"
#include "DW_CustomOperatorsBindings.h"
#include "DW_CustomOperatorsData.h"
#include "DW_BotBindings.h"
#include "replay_dvar.h"
#include <intrin.h>
#include <stddef.h>

extern "C" unsigned DWBSZ_PollFastfileState(const char *);
extern "C" void DW_LocalBackend_LogLine(const char *);

// Replay StringTable is a dictionary of unique strings and hashes, indexed by
// row-major unsigned-short cells. This is the complete native 48-byte header.
struct CO_StringTable
{
    const char *name;
    int columns, rows, uniqueStrings, padding;
    const uint16_t *cells;
    const uint32_t *hashes;
    const char *const *strings;
};
static_assert(sizeof(CO_StringTable) == 48);
static_assert(offsetof(CO_StringTable, columns) == 8);
static_assert(offsetof(CO_StringTable, rows) == 12);
static_assert(offsetof(CO_StringTable, uniqueStrings) == 16);
static_assert(offsetof(CO_StringTable, padding) == 20);
static_assert(offsetof(CO_StringTable, cells) == 24);
static_assert(offsetof(CO_StringTable, hashes) == 32);
static_assert(offsetof(CO_StringTable, strings) == 40);

namespace
{
    dvar_t *s_selection{};
    dvar_t *s_ready{};
    int s_lastSelection = -1;
    bool s_registered[2]{};
    bool s_zoneInstalled{}, s_zoneStaged{};
    bool s_bindingsReady{};
    bool s_refreshPending{};
    bool s_registeringTables{};
    unsigned s_localCardReadCount{};
    uint16_t s_packageSlots[2][DWCustomOperators::Count]{};

    // Native package ordinals occupy the existing head/body/hand groups. The
    // primary IDs belong to the profile tables; wire data contains ordinals.
    void RegisterPackages(unsigned kind)
    {
        auto *groups = reinterpret_cast<DWBotCustomizationGroup *>(DW_Bot_CustomizationGroups);
        auto *packages = reinterpret_cast<DWBotCustomizationPackage *>(DW_Bot_CustomizationPackages);
        auto &group = groups[kind];
        s_registered[kind] = false;
        s_bindingsReady = false;
        const unsigned limit = kind ? 1024 : 6143;
        if (!group.count || group.count + DWCustomOperators::Count > limit ||
            unsigned(group.first) + group.count + DWCustomOperators::Count > DWBotCustomizationPackageLimit)
        {
            CO_Print(16, "DW: custom operator package group is unavailable.\n");
            return;
        }
        const uint16_t hands = kind ? packages[group.first].viewhands : UINT16_MAX;
        if (kind && (hands == UINT16_MAX || hands >= DWBotCustomizationPackageLimit))
            return;
        for (unsigned i = 0; i < DWCustomOperators::Count; ++i)
        {
            const auto &entry = DWCustomOperators::Operators[i];
            const char *model = kind ? entry.body : entry.head;
            const char *fallback = packages[group.first].fallback;
            const uint16_t slot = CO_RegisterPackage(model, fallback, kind);
            if (slot >= DWBotCustomizationPackageLimit)
                return;
            s_packageSlots[kind][i] = slot;
            auto &package = packages[slot];
            package.primary = entry.primary;
            package.secondary = kind ? UINT16_MAX : 0;
            package.viewhands = hands;
            // A custom operator is an explicit choice; native bot/random
            // pools retain their stock male/female counts and eligibility.
            if (package.randomEligible)
            {
                package.randomEligible = 0;
                --group.maleCount;
            }
        }
        s_registered[kind] = true;
    }

    bool AssetsReady()
    {
        if (!s_zoneStaged || !s_registered[0] || !s_registered[1] ||
            DWBSZ_PollFastfileState(DWCustomOperators::ZoneName) != 2 ||
            DWBSZ_PollFastfileState("global_stream_mp") != 2 ||
            DWBSZ_PollFastfileState("common_mp") != 2)
            return false;
        return true;
    }

    bool ModelsReady()
    {
        if (!s_bindingsReady || !AssetsReady())
            return false;
        const auto *packages = reinterpret_cast<const DWBotCustomizationPackage *>(DW_Bot_CustomizationPackages);
        for (unsigned kind = 0; kind < 2; ++kind)
            for (unsigned i = 0; i < DWCustomOperators::Count; ++i)
                if (packages[s_packageSlots[kind][i]].invalid)
                    return false;
        return true;
    }

    unsigned Selection()
    {
        const int value = s_selection ? s_selection->current.integer : 0;
        return value > 0 && unsigned(value) <= DWCustomOperators::Count && ModelsReady() ? unsigned(value) : 0;
    }

    void SetPair(uint32_t *west, uint32_t *east, unsigned selection)
    {
        const unsigned primary = DWCustomOperators::Operators[selection - 1].primary;
        west[0] = west[1] = east[0] = east[1] = primary;
        // Execution selection is independent of the operator body and head.
    }

    bool Equal(const char *a, const char *b)
    {
        if (!a || !b) return false;
        while (*a && *a == *b) { ++a; ++b; }
        return *a == *b;
    }
}

extern "C" void DW_CustomOperators_RegisterDvars()
{
    if (s_selection)
        return;
    Dvar_BeginPermanentRegistration();
    s_selection = Dvar_RegisterInt("dw_customOperator", 0, 0, DWCustomOperators::Count, 1,
        "Custom operator: 0 equipped stock operator, 1 Nicky, 2 BO2 soldier. Select in the lobby.");
    s_ready = Dvar_RegisterBool("replay_dw_customOperatorReady", false, 0,
        "Custom operator models are loaded and validated.");
    Dvar_EndPermanentRegistration();
}

extern "C" uint64_t DW_CustomOperators_RegisterHeads(const char *table)
{
    s_registeringTables = true;
    const auto result = CO_RegisterHeadsNative(table);
    s_registeringTables = false;
    RegisterPackages(0);
    DW_CustomOperators_RegisterDvars();
    return result;
}

extern "C" uint64_t DW_CustomOperators_RegisterBodies(const char *table)
{
    s_registeringTables = true;
    const auto result = CO_RegisterBodiesNative(table);
    s_registeringTables = false;
    RegisterPackages(1);
    return result;
}

extern "C" uint64_t DW_CustomOperators_BuildCustomization(void *out, unsigned head,
                                                           unsigned variant, unsigned body,
                                                           bool firstPerson)
{
    // The local viewhands cache and all replicated customization remain stock.
    return CO_BuildCustomizationNative(out, head, variant, body, firstPerson);
}

extern "C" uint64_t DW_CustomOperators_CardModels(unsigned controller, uint8_t *selectedFaction,
    uint32_t *west, uint32_t *east, void *context, void *state)
{
    // Playercards uploaded to the backend must remain readable by older clients.
    return CO_CardModelsNative(controller, selectedFaction, west, east, context, state);
}

extern "C" uint64_t DW_CustomOperators_GetPlayercard(uint64_t xuid, const char *name, void *out)
{
    const auto result = CO_GetPlayercardNative(xuid, name, out);
    if (!result || !out || !xuid || !s_selection || s_selection->current.integer <= 0)
        return result;
    uint64_t localXuid{};
    CO_GetLocalXuid(&localXuid, 0);
    const unsigned selection = xuid == localXuid ? Selection() : 0;
    if (selection)
    {
        auto *bytes = static_cast<uint8_t *>(out);
        // ReadPlayerProfileFromDDL stores two 24-byte faction records: public
        // head/body/execution at +0 and private head/body/execution at +12.
        SetPair(reinterpret_cast<uint32_t *>(bytes + 80), reinterpret_cast<uint32_t *>(bytes + 104), selection);
        SetPair(reinterpret_cast<uint32_t *>(bytes + 92), reinterpret_cast<uint32_t *>(bytes + 116), selection);
        ++s_localCardReadCount;
    }
    return result;
}

extern "C" uint64_t DW_CustomOperators_SetCustomization(void *context, uint64_t entityRef)
{
    // The server builds the equipped stock body and its normal collision model.
    return CO_SetCustomizationNative(context, entityRef);
}

// ClientInfo's complete customization field and the character's leading
// client number, as consumed by Replay's native active-model selector.
struct CO_ClientModelSelection
{
    uint8_t identity[100];
    uint32_t models[3];
};
static_assert(sizeof(CO_ClientModelSelection) == 112);
static_assert(offsetof(CO_ClientModelSelection, models) == 100);

struct CO_LocalPlayerView
{
    uint8_t beforeMovement[20];
    int32_t movementType;
    uint8_t beforeFlags[12];
    uint32_t otherFlags;
    uint8_t beforeClient[416];
    uint32_t predictedClient;
    uint8_t beforeLocalClient[25172];
    uint32_t localClient;
    uint8_t beforeKillcam[508084];
    int32_t inKillcam;
};
static_assert(offsetof(CO_LocalPlayerView, otherFlags) == 36);
static_assert(offsetof(CO_LocalPlayerView, predictedClient) == 456);
static_assert(offsetof(CO_LocalPlayerView, localClient) == 25632);
static_assert(offsetof(CO_LocalPlayerView, inKillcam) == 533720);

extern "C" const void *CO_GetLegsSourceModel(const void *object, unsigned index)
{
    const void *stock = CO_DObjGetModel(object, index);
    const auto *globals = reinterpret_cast<const CO_LocalPlayerView *>(CO_LocalClientGlobals[0]);
    if (index || !globals || globals->localClient || globals->inKillcam ||
        globals->movementType == 5 || (globals->otherFlags & 0x80000000u))
        return stock;
    const unsigned selection = Selection();
    if (!selection)
        return stock;
    const void *custom = CO_FindAsset(9, DWCustomOperators::Operators[selection - 1].body, 0);
    return custom ? custom : stock;
}

extern "C" bool DW_CustomOperators_ShouldRecreateLegs(unsigned localClient, unsigned entity)
{
    return CO_ShouldRecreateLegsNative(localClient, entity);
}

extern "C" void DW_CustomOperators_UpdateLegs(unsigned localClient, const void *entity)
{
    CO_UpdateLegsNative(localClient, entity);
}

extern "C" const char *DW_CustomOperators_GetActiveModel(unsigned localClient,
    const void *clientInfo, const void *characterInfo, unsigned kind, bool *loaded)
{
    const char *stock = CO_GetActiveModelNative(localClient, clientInfo, characterInfo, kind, loaded);
    if (localClient != 0 || kind >= 2 || !characterInfo || !loaded)
        return stock;
    const auto *globals = reinterpret_cast<const CO_LocalPlayerView *>(CO_LocalClientGlobals[localClient]);
    if (!globals || globals->localClient != localClient || globals->inKillcam ||
        globals->movementType == 5 || (globals->otherFlags & 0x80000000u) ||
        *static_cast<const unsigned *>(characterInfo) != globals->predictedClient)
        return stock;
    const unsigned selection = Selection();
    if (!selection)
        return stock;
    const auto *groups = reinterpret_cast<const DWBotCustomizationGroup *>(DW_Bot_CustomizationGroups);
    CO_ClientModelSelection appearance{};
    for (unsigned type = 0; type < 2; ++type)
        appearance.models[type] = s_packageSlots[type][selection - 1] - groups[type].first;
    const char *custom = nullptr;
    // Keep native residency validation and the ordinary model/DObj update path.
    // Only this client's own visual selection changes; ClientInfo is not written.
    // Replay reads the sixth argument as a full 32-bit integer on the stack.
    const bool fallback = CO_GenerateActiveModel(localClient, &custom, &appearance,
                                                characterInfo, kind, 0) != 0;
    if (!fallback && custom && *custom)
    {
        *loaded = true;
        return custom;
    }
    return stock;
}

namespace
{
    struct TableView
    {
        volatile long lock{};
        CO_StringTable table{};
        const CO_StringTable *source{};
        const uint16_t *sourceCells{};
        const char *const *sourceStrings{};
        uint16_t cells[8192 * 32]{};
        uint32_t hashes[65536]{};
        const char *strings[65536]{};
        char primary[DWCustomOperators::Count][8]{};
    };
    TableView s_tables[4]{};

    const CO_StringTable *Table(const void *asset)
    {
        const auto *original = static_cast<const CO_StringTable *>(asset);
        if (s_registeringTables || !original || !original->name) return original;
        for (const auto &view : s_tables)
            if (original == &view.table) return original;
        const char *names[]{"mp/cac/heads.csv", "mp/cac/bodies.csv", "mp/cac/alt_heads.csv", "mp/cac/alt_bodies.csv"};
        unsigned kind = 0;
        while (kind < 4 && !Equal(original->name, names[kind])) ++kind;
        if (kind == 4 || original->rows <= 0 || original->rows + int(DWCustomOperators::Count) > 8192 ||
            original->columns <= 10 || original->columns > 32 || original->uniqueStrings < 0 ||
            original->uniqueStrings + int(DWCustomOperators::Count) * original->columns > 65536 ||
            !original->cells || !original->hashes || !original->strings) return original;
        auto &view = s_tables[kind];
        struct Guard
        {
            volatile long *lock;
            explicit Guard(volatile long *value) : lock(value)
            {
                while (_InterlockedCompareExchange(lock, 1, 0)) _mm_pause();
            }
            ~Guard() { _InterlockedExchange(lock, 0); }
        } guard(&view.lock);
        if (view.source == original && view.sourceCells == original->cells && view.sourceStrings == original->strings &&
            view.table.rows == original->rows + int(DWCustomOperators::Count) &&
            view.table.columns == original->columns &&
            view.table.uniqueStrings == original->uniqueStrings + int(DWCustomOperators::Count) * original->columns)
            return &view.table;
        for (int i = 0; i < original->rows * original->columns; ++i) view.cells[i] = original->cells[i];
        for (int i = 0; i < original->uniqueStrings; ++i)
        {
            view.hashes[i] = original->hashes[i];
            view.strings[i] = original->strings[i];
        }
        for (unsigned i = 0; i < DWCustomOperators::Count; ++i)
        {
            CO_Format(view.primary[i], sizeof(view.primary[i]), "%u", unsigned(DWCustomOperators::Operators[i].primary));
            const char *model = kind % 2 ? DWCustomOperators::Operators[i].body : DWCustomOperators::Operators[i].head;
            for (int column = 0; column < original->columns; ++column)
            {
                const unsigned cell = original->cells[column];
                if (cell >= unsigned(original->uniqueStrings)) return original;
                const char *text = original->strings[cell];
                if (column == 0) text = view.primary[i];
                if (column == 1 || column == (kind % 2 ? 10 : 9)) text = model;
                const unsigned unique = original->uniqueStrings + i * original->columns + column;
                view.cells[(original->rows + i) * original->columns + column] = uint16_t(unique);
                view.strings[unique] = text ? text : "";
                view.hashes[unique] = CO_TableHash(view.strings[unique]);
            }
        }
        view.table = {original->name, original->columns, original->rows + int(DWCustomOperators::Count),
            original->uniqueStrings + int(DWCustomOperators::Count) * original->columns, original->padding,
            view.cells, view.hashes, view.strings};
        view.source = original;
        view.sourceCells = original->cells;
        view.sourceStrings = original->strings;
        return &view.table;
    }
}

// The existing map-availability owner composes this view with its native
// table lookup so map presentation overrides keep the same single owner.
extern "C" const void *DW_CustomOperators_TableView(const void *asset)
{
    return Table(asset);
}

extern "C" const void *DW_CustomOperators_GetTable(const char *name, const void **out)
{
    CO_GetTableNative(name, out);
    *out = Table(*out);
    return *out;
}

extern "C" int DW_CustomOperators_TableMultiRow(const void *asset, const int *columns,
    const char *const *values, int count)
{
    return CO_TableMultiRowNative(Table(asset), columns, values, count);
}

extern "C" int DW_CustomOperators_TableRow(const void *asset, int column, const char *value)
{
    return CO_TableRowNative(Table(asset), column, value);
}

extern "C" const char *DW_CustomOperators_TableColumn(const void *asset, int row, int column)
{
    const auto *table = Table(asset);
    // The native leaf returns an empty string for every invalid row, column,
    // or dictionary index. Keep those bounds before dereferencing any cell.
    if (column < 0 || row < 0 || column >= table->columns || row >= table->rows) return "";
    const unsigned cell = table->cells[row * table->columns + column];
    return int(cell) < table->uniqueStrings ? table->strings[cell] : "";
}

extern "C" unsigned DW_CustomOperators_TableRows(const void *asset)
{
    return unsigned(Table(asset)->rows);
}

extern "C" void DW_CustomOperators_Frame()
{
    // The same native completion state is used by ComFastFile's loading
    // module. Staging files or queueing a request does not make models ready.
    const bool assetsReady = AssetsReady();
    if (!assetsReady)
        s_bindingsReady = false;
    else if (!s_bindingsReady)
    {
        // Registration can precede this zone's load. Re-enter the native
        // binding validation after completion rather than clearing errors.
        CO_UpdatePackageBindings("custom operator zone loaded");
        s_bindingsReady = true;
    }
    const bool ready = ModelsReady();
    if (s_ready && s_ready->current.enabled != ready)
    {
        DvarValue value{};
        value.enabled = ready;
        Dvar_SetVariant(s_ready, &value, 0);
    }
    if (ready != s_zoneInstalled)
    {
        s_zoneInstalled = ready;
        s_refreshPending = true;
    }
    if (!s_selection || (!s_refreshPending && s_selection->current.integer == s_lastSelection))
        return;
    const int previousSelection = s_lastSelection;
    s_lastSelection = s_selection->current.integer;
    s_refreshPending = false;
    if (s_lastSelection == 0 && previousSelection <= 0)
        return;
    // The local customization cache supplies viewhands only. Appearance uses
    // the native playercard producer and its compressed public/private sets.
    CO_UpdateLocalCustomization(0);
    CO_RequestCardUpload(0);
    // Upload checks signed-in state, mode support, and the native card state
    // before touching its profile. The request flag retries through its normal
    // update loop if those prerequisites have not completed yet.
    const auto uploaded = CO_UploadCard(0);
    char message[160]{};
    CO_Format(message, sizeof(message), "DW: local custom operator selection=%d modelsReady=%u nativeCardRefresh=%u localReads=%u; server appearance unchanged.",
        s_lastSelection, unsigned(ready), unsigned(uploaded), s_localCardReadCount);
    DW_LocalBackend_LogLine(message);
}

extern "C" void DW_CustomOperators_ZoneInstalled(bool installed)
{
    s_zoneStaged = installed;
    if (!installed) s_bindingsReady = false;
    if (!installed && s_zoneInstalled)
    {
        s_zoneInstalled = false;
        s_refreshPending = true;
    }
}
