#include "com_debugstates.h"
#include "com_optimized.h"
#include "replay_dvar.h"

extern "C" float SV_HostScale_GetSimulationFPS();

extern "C" {
#ifdef REPLAY_COMPILER_OPTIMIZED
// The distributable performance build registers the command but does not
// poll getters or submit developer text until explicitly requested.
comDebugStates_t s_comDebugStates = {0, 1, 0, 0, 0, 0, 0, 0, {0, 0}, {}};
#else
comDebugStates_t s_comDebugStates = {1, 1, 0, 0, 0, 0, 0, 0, {0, 0}, {}};
#endif
}

namespace {
cmd_function_s s_debugStatesCommand{};
bool s_debugStatesRegistered = false;
bool s_debugStatesDump = false;
unsigned s_debugStatesFramesUntilUpdate = 0;

// Getters run on the engine main thread, with fixed Replay client/controller
// bounds. Validate dynamic pointers before entering native code; SEH cannot
// prevent the game's VEH from seeing an invalid read first.
bool Com_DebugStates_IsReadable(const void* address, size_t length) {
    uintptr_t cursor = reinterpret_cast<uintptr_t>(address);
    if (!cursor || length > UINTPTR_MAX - cursor)
        return false;
    const uintptr_t end = cursor + length;
    while (cursor < end) {
        ComDebugMemoryInfo memory{};
        if (VirtualQuery(reinterpret_cast<const void*>(cursor), &memory, sizeof(memory)) !=
                sizeof(memory) || memory.state != 0x1000 || (memory.protect & 0x100))
            return false;
        const unsigned protection = memory.protect & 0xff;
        if (protection != 2 && protection != 4 && protection != 8 && protection != 0x20 &&
            protection != 0x40 && protection != 0x80)
            return false;
        const uintptr_t first = reinterpret_cast<uintptr_t>(memory.base);
        if (memory.regionSize > UINTPTR_MAX - first || first + memory.regionSize <= cursor)
            return false;
        cursor = first + memory.regionSize;
    }
    return true;
}

bool Com_DebugStates_Equal(const char* a, const char* b) {
    while (*a && *a == *b) {
        ++a;
        ++b;
    }
    return *a == *b;
}

bool Com_DebugStates_SetupPlacement(float (&placement)[27]) {
    // Replay's ScrPlace_ApplyRect reads a 108-byte ScreenPlacement, including
    // subScreenLeft at +0x68. Keep its scale/aspect transform, but restore the
    // game-test 0.9 safe-area defaults for this developer overlay alone.
    const auto* native = reinterpret_cast<const float*>(scrPlaceFull);
    for (unsigned i = 0; i < 27; ++i) placement[i] = native[i];
    const float width = placement[8], height = placement[9]; // realViewportSize
    if (!(width > 0 && width <= 32768 && height > 0 && height <= 32768 &&
          placement[0] > 0 && placement[1] > 0)) return false;
    const float left = placement[6] + width * 0.05f;
    const float top = placement[7] + height * 0.05f;
    const float right = placement[6] + width * 0.95f;
    const float bottom = placement[7] + height * 0.95f;
    // Retain any narrower safe area already supplied by Replay.
    if (placement[14] < left) placement[14] = left;
    if (placement[15] < top) placement[15] = top;
    if (placement[16] > right) placement[16] = right;
    if (placement[17] > bottom) placement[17] = bottom;
    return placement[14] < placement[16] && placement[15] < placement[17];
}

void Com_DebugStates_AddValue(const char* name, int value) {
    auto& row = s_comDebugStates.rowCount[0];
    if (row < 32)
        Com_sprintf(s_comDebugStates.rows[0][row++], 96, "%s: %d", name, value);
}

template<typename... Args>
void Com_DebugStates_AddRow(const char* format, Args... args) {
    auto& row = s_comDebugStates.rowCount[0];
    if (row < 32)
        Com_sprintf(s_comDebugStates.rows[0][row++], 96, format, args...);
}

void Com_DebugStates_AddUnavailable(const char* name) {
    auto& row = s_comDebugStates.rowCount[0];
    if (row < 32)
        Com_sprintf(s_comDebugStates.rows[0][row++], 96, "%s: unavailable", name);
    ++s_comDebugStates.unavailable;
}

// New read-only getters use the same data and CRITSECT_DOBJ_ALLOC (9) as
// Com_GetFreeDObjIndex / Com_SafeServerDObjFree. Slot zero is reserved.
void Com_DebugStates_GetDObjCounts() {
    Sys_EnterCriticalSection(9);
    const int capacity = s_comDObjCount;
    const int freeCount = s_comDObjFreeCount;
    const bool ready = s_comDObjBuffer && capacity > 0 && capacity <= 2048 &&
                       freeCount >= 0 && freeCount < capacity;
    Sys_LeaveCriticalSection(9);
    if (ready) {
        Com_DebugStates_AddRow("DObj used: %d  free: %d  usable: %d",
                               capacity - 1 - freeCount, freeCount, capacity - 1);
    } else
        Com_DebugStates_AddUnavailable("DObj pool");
}

void Com_DebugStates_GetLoadingStates() {
    Com_DebugStates_AddRow("FASTFILES: progress / load state / DB request");
    static const char* const states[] = {"idle", "loading", "loaded", "paused", "failed"};
    for (unsigned index = 0; index < 11; ++index) {
        // Verified Replay: initializer 0x341ac0 gives eleven 0x1e8 modules;
        // UpdateSelf 0x10b58xx uses state +0x24, progress +0x28, request +0x2c,
        // paused +0x35; zone lists are three 0x48 records at +0x38/+0x110.
        const auto* module = s_fastfileLoadModules[index];
        const unsigned state = module[0x24];
        const auto* zones = module + (state ? 0x38 : 0x110);
        char names[64]{};
        unsigned used = 0;
        for (unsigned zone = 0; zone < 3 && zones[zone * 0x48]; ++zone) {
            if (used && used < sizeof(names) - 1) names[used++] = ',';
            for (unsigned at = 0; at < 64 && zones[zone * 0x48 + at] && used < sizeof(names) - 1; ++at) {
                const unsigned char c = zones[zone * 0x48 + at];
                names[used++] = c >= 32 && c < 127 && c != '^' ? static_cast<char>(c) : '?';
            }
        }
        if (!names[0]) Com_sprintf(names, sizeof(names), "fastfile[%u]", index);
        const float progress = *reinterpret_cast<const float*>(module + 0x28);
        if (state < 5 && progress >= 0.0f && progress <= 1.0f)
            Com_DebugStates_AddRow("%s: %.2f %s%s", names, double(progress),
                                   states[state], module[0x35] ? " [p]" : "");
        else
            Com_DebugStates_AddUnavailable(names);
        ++s_comDebugStates.getterCalls;
    }
    // Shipping Replay retains the database-ready event, but strips the
    // developer DB work-period string. Display the event's actual meaning.
    Com_DebugStates_AddRow("DB: %s (database-ready event)", Sys_IsDatabaseReady() ? "Ready" : "Busy");
    ++s_comDebugStates.getterCalls;

    unsigned models = 0, images = 0;
    bool queuesReady = true;
    // Native GetClientRequestQueue maps view-model types 3..5 to this client's
    // private queues; types 0..2 are shared world queues and counted once.
    for (unsigned queue = 0; queue < 6; ++queue) {
        const auto* data = static_cast<const uint8_t*>(queue < 3 ? s_worldRequestQueue[queue] :
                                                                      s_clientRequestQueue[queue]);
        if (!Com_DebugStates_IsReadable(data, 0x28)) {
            queuesReady = false;
            continue;
        }
        models += *reinterpret_cast<const uint32_t*>(data + 0x20);
        images += *reinterpret_cast<const uint32_t*>(data + 0x24);
    }
    if (queuesReady)
        Com_DebugStates_AddRow("ClStreaming: %um %ui", models, images);
    else Com_DebugStates_AddUnavailable("ClStreaming queues");
    const auto* frontend = static_cast<const uint8_t*>(streamFrontendGlob);
    if (frontend && Com_DebugStates_IsReadable(frontend + 0x98b0c0, 4))
        Com_DebugStates_AddRow("Streamer level init: %s", Stream_LevelInit_IsDone() ? "Done" : "Pending");
    else Com_DebugStates_AddUnavailable("Streamer level init");
    s_comDebugStates.getterCalls += 2;
}

void Com_DebugStates_GetFenceState(unsigned index) {
    const auto* object = static_cast<const uint8_t*>(s_fenceObjects[index]);
    char name[40]{};
    const char* source = s_fenceNames[index];
    for (unsigned i = 0; source && i < sizeof(name) - 1; ++i) {
        if (!Com_DebugStates_IsReadable(source + i, 1))
            break;
        const unsigned char c = static_cast<unsigned char>(source[i]);
        if (!c)
            break;
        // Keep native formatting escapes out of the text renderer.
        name[i] = c >= 32 && c < 127 && c != '^' ? static_cast<char>(c) : '?';
    }
    if (!name[0])
        Com_sprintf(name, sizeof(name), "fence %u", index);
    auto& row = s_comDebugStates.rowCount[1];
    if (row >= 32)
        return;
    if (Com_DebugStates_IsReadable(object, 80)) {
        // The developer engine uses these same Pending/Active/Failed labels.
        const char* status = object[14] ? "Failed" : object[13] ? "Passing" :
                             object[12] ? "Active" : "Pending";
        // Replay FenceManager_GetStatusString (0xf195a0) invokes vtable slot
        // zero for GetErrorCode, just like game-test's FenceManager_DrawDebug.
        // This is polymorphic: the controller field at +8 is not that value.
        const auto* table = *reinterpret_cast<const uintptr_t* const*>(object);
        const uintptr_t getter = Com_DebugStates_IsReadable(table, sizeof(*table)) ? table[0] : 0;
        if (Com_DebugStates_IsReadable(reinterpret_cast<const void*>(getter), 1)) {
            const unsigned error = reinterpret_cast<unsigned (*)(const void*)>(getter)(object);
            Com_sprintf(s_comDebugStates.rows[1][row++], 96, "%s %u  %s [d%u/p%u/f%u]", status,
                        error, name, unsigned(object[12]), unsigned(object[13]), unsigned(object[14]));
            ++s_comDebugStates.getterCalls;
        } else {
            Com_sprintf(s_comDebugStates.rows[1][row++], 96, "Unavailable 0  %s", name);
            ++s_comDebugStates.unavailable;
        }
    }
    else {
        Com_sprintf(s_comDebugStates.rows[1][row++], 96, "Unavailable 0  %s", name);
        ++s_comDebugStates.unavailable;
    }
    ++s_comDebugStates.getterCalls;
}
}

extern "C" void Com_DebugStates_Capture(int localClientNum) {
    if (localClientNum != 0 || !Sys_IsMainThread())
        return;
    s_comDebugStates.captureFrame = s_comDebugStates.frame;
    ++s_comDebugStates.captures;
    s_comDebugStates.getterCalls = 0;
    s_comDebugStates.unavailable = 0;
    s_comDebugStates.rowCount[0] = s_comDebugStates.rowCount[1] = 0;
    // Keep the game-test fastfile/DB/streaming group at the top-right, before
    // the extra state rows. The first fifteen rows always belong to it.
    Com_DebugStates_GetLoadingStates();

    // These Replay getters only inspect fixed globals or checked native dvars.
    const float simulationFPS = SV_HostScale_GetSimulationFPS();
    if (simulationFPS >= 0)
        Com_DebugStates_AddRow("Simulation FPS: %.1f (local server)", double(simulationFPS));
    else
        Com_DebugStates_AddRow("Simulation FPS: N/A (no local server)");
    Com_DebugStates_AddRow("Game mode: %d  frontend: %d  server: %d/%d", Com_GameMode_GetActiveGameMode(),
                           int(Com_FrontEndScene_IsActive()), int(Com_IsAnyLocalServerRunning()), int(SV_Loaded()));
    Com_DebugStates_AddRow("Clients: %d  allInactive: %d  active: %d/%d", CL_GetLocalClientActiveCount(),
                           int(CL_AllLocalClientsInactive()), int(CL_IsLocalClientActive(localClientNum)),
                           int(CL_Mgr_IsClientActive(localClientNum)));
    const int controllerIndex = CL_Mgr_GetControllerFromClient(localClientNum);
    s_comDebugStates.getterCalls += 9;
    if (controllerIndex == 0) {
        const bool controllerActive = CL_Mgr_IsControllerActive(controllerIndex);
        const bool profileReady = GamerProfile_IsProfileLoggedIn(controllerIndex);
        Com_DebugStates_AddRow("Controller: %d  active: %d  isProfileLoggedIn: %d", controllerIndex,
                               int(controllerActive), int(profileReady));
        s_comDebugStates.getterCalls += 2;
        if (profileReady) {
            Com_DebugStates_AddRow("curDifficulty: %d  specialistMode: %d  yoloMode: %d",
                GamerProfile_GetDifficulty(controllerIndex), int(GamerProfile_GetSpecialistMode(controllerIndex)),
                int(GamerProfile_GetYoloMode(controllerIndex)));
            Com_DebugStates_AddRow("Profile mount: gamepad %d  keyboard %d", GamerProfile_GetMountButton(controllerIndex),
                GamerProfile_GetMountButtonKBM(controllerIndex));
            Com_DebugStates_AddRow("Profile pullAway: gamepad %d  keyboard %d", int(GamerProfile_GetMountPullAwayEnabled(controllerIndex)),
                int(GamerProfile_GetMountPullAwayEnabledKBM(controllerIndex)));
            Com_DebugStates_AddRow("Profile toggleADS: gamepad %d  keyboard %d", int(GamerProfile_GetToggleADSEnabledGamepad(controllerIndex)),
                int(GamerProfile_GetToggleADSEnabledKeyboard(controllerIndex)));
            Com_DebugStates_AddRow("Profile scoreboard: %d  voiceMuteStrategy: %d", int(GamerProfile_GetToggleScoreboardMapEnabled(controllerIndex)),
                GamerProfile_GetVoiceMuteStrategy(controllerIndex));
            s_comDebugStates.getterCalls += 11;
        } else
            Com_DebugStates_AddUnavailable("profile settings");
        Com_DebugStates_AddRow("OnlineData [none/SP/MP/CP]: %d/%d/%d/%d", Live_OnlineData_GetState(controllerIndex, 0),
            Live_OnlineData_GetState(controllerIndex, 1), Live_OnlineData_GetState(controllerIndex, 2),
            Live_OnlineData_GetState(controllerIndex, 3));
        s_comDebugStates.getterCalls += 4;
    } else
        Com_DebugStates_AddUnavailable("controller/profile/online data");

    Com_DebugStates_AddValue("registered dvars", s_dvarCount);
    // Replay Dvar_GetInt64Safe reads the type at +0x1d and current at +0x28.
    const auto* uiDvar = reinterpret_cast<const uint8_t*>(ui_serverFrameDuration);
    if (Com_DebugStates_IsReadable(uiDvar, 0x2c) && uiDvar[0x1d] == 5)
        Com_DebugStates_AddValue("ui_serverFrameDuration", *reinterpret_cast<const int32_t*>(uiDvar + 0x28));
    else
        Com_DebugStates_AddUnavailable("ui_serverFrameDuration");
    Com_DebugStates_GetDObjCounts();
    const unsigned patchType = 0;
    auto& right = s_comDebugStates.rowCount[1];
    Com_sprintf(s_comDebugStates.rows[1][right++], 96, "FENCES: dependencies / passing / failed");
    for (unsigned fence = 0; fence < 27; ++fence)
        Com_DebugStates_GetFenceState(fence);
    Com_sprintf(s_comDebugStates.rows[1][right++], 96, "Patch state: %d   error: %d",
                Live_PatchFence_GetState(&patchType), Live_PatchFence_GetErrorCode(&patchType));
    s_comDebugStates.getterCalls += 6; // dvar, UI dvar, DObj counts, patch getters
}

extern "C" void Com_DebugStates_f() {
    if (!Sys_IsMainThread())
        return;
    const int argc = Cmd_Argc();
    const char* argument = argc == 2 ? Cmd_Argv(1) : "";
    if (argc > 2) {
        Com_Printf(16, "usage: com_debugStates [0|1|toggle|dump]\n");
        return;
    }
    if (!*argument || Com_DebugStates_Equal(argument, "toggle"))
        s_comDebugStates.enabled = !s_comDebugStates.enabled;
    else if (Com_DebugStates_Equal(argument, "1") || Com_DebugStates_Equal(argument, "on"))
        s_comDebugStates.enabled = 1;
    else if (Com_DebugStates_Equal(argument, "0") || Com_DebugStates_Equal(argument, "off"))
        s_comDebugStates.enabled = 0;
    else if (Com_DebugStates_Equal(argument, "dump")) {
        s_debugStatesDump = true;
        s_comDebugStates.enabled = 1;
    } else {
        Com_Printf(16, "usage: com_debugStates [0|1|toggle|dump]\n");
        return;
    }
    s_debugStatesFramesUntilUpdate = 0;
    Com_Printf(16, "com_debugStates %s; snapshot interval 20 frames\n",
               s_comDebugStates.enabled ? "on" : "off");
}

extern "C" void Com_DebugStates_Frame(int localClientNum) {
    if (localClientNum != 0 || !Sys_IsMainThread())
        return;
    ++s_comDebugStates.frame;
    if (!s_debugStatesRegistered) {
        Cmd_AddCommandInternal("com_debugStates", Com_DebugStates_f, &s_debugStatesCommand);
        s_debugStatesRegistered = true;
        Com_Printf(16, "Com_DebugStates: command registered; enabled=%u; refresh every 20 frames\n", s_comDebugStates.enabled);
    }
    if (!s_comDebugStates.enabled)
        return;
    if (Com_Optimized_IsEnabled())
        return;
    if (!s_debugStatesFramesUntilUpdate) {
        Com_DebugStates_Capture(localClientNum);
        s_debugStatesFramesUntilUpdate = 20;
        if (s_debugStatesDump) {
            for (unsigned column = 0; column < 2; ++column)
                for (unsigned row = 0; row < s_comDebugStates.rowCount[column]; ++row)
                    Com_Printf(16, "%s\n", s_comDebugStates.rows[column][row]);
            s_debugStatesDump = false;
        }
    }
    --s_debugStatesFramesUntilUpdate;
    const void* font = cls_smallDevFont;
    if (!Com_DebugStates_IsReadable(font, 16))
        return;
    const int fontHeight = *reinterpret_cast<const int*>(static_cast<const uint8_t*>(font) + 8);
    if (fontHeight <= 0 || fontHeight > 128)
        return;
    float placement[27]{};
    if (!Com_DebugStates_SetupPlacement(placement)) return;
    const float white[] = {0.95f, 0.95f, 0.95f, 1.0f};
    const float cyan[] = {0.3f, 0.9f, 1.0f, 1.0f};
    const float green[] = {0.2f, 1.0f, 0.3f, 1.0f};
    const float red[] = {1.0f, 0.25f, 0.25f, 1.0f};
    // Game-test CG_DrawDevString: 0.75 scale, top-to-baseline height, shadow
    // style 7; CornerPrint advances height * 0.8. Replay uses the same font
    // initializer and ScreenPlacement transform. Horizontal alignment 3
    // anchors to realViewableMax, so the right edge survives aspect changes.
    constexpr float scale = 0.75f;
    const float height = float(fontHeight) * scale;
    const float line = height * 0.8f;
    auto draw = [&](const char* text, float x, float y, bool right, int horizontal,
                    int vertical, const float* color) {
        if (right) x -= float(R_TextWidth(text, 95, font)) * scale;
        CL_DrawText(placement, text, 95, font, x, y + height, horizontal, vertical,
                    scale, scale, color, 7);
    };
    float y = 10.0f; // cg_debugInfoCornerOffsetMP.y in game-test
    for (unsigned row = 1; row < 15; ++row) {
        const char* text = s_comDebugStates.rows[0][row];
        // The developer iterator omits modules with no requested/active zones.
        if (text[0] == 'f' && text[8] == '[') continue;
        draw(text, 15.0f, y, true, 3, 1, white); // corner X offset 20 minus 5
        y += line;
    }
    y = 20.0f; // FenceManager_DrawDebug starts at 20, status X 75 - width 50
    for (unsigned row = 1; row <= 27; ++row) {
        const char* text = s_comDebugStates.rows[1][row];
        if (text[0] == 'P' && text[1] == 'a') continue; // passing fences are hidden
        const float* color = text[0] == 'F' ? red : text[0] == 'A' ? green : white;
        char status[24]{}, name[64]{};
        unsigned at = 0;
        while (text[at] && at < sizeof(status) - 1) {
            status[at] = text[at];
            if (text[at] == ' ' && text[at + 1] == ' ') { ++at; break; }
            ++at;
        }
        if (text[at] == ' ') ++at;
        for (unsigned n = 0; text[at] && n < sizeof(name) - 1; ++n, ++at) {
            if (text[at] == ' ' && text[at + 1] == '[') break;
            name[n] = text[at];
        }
        draw(status, 25.0f, y, true, 1, 1, color);
        draw(name, 25.0f, y, false, 1, 1, color);
        y += line;
    }
    // Additional requested profile/game/object states use a bottom-left block
    // like the developer entitlement panel, leaving both reference anchors free.
    const unsigned extra = s_comDebugStates.rowCount[0] - 15;
    y = -10.0f - height - line * float(extra + 1);
    for (unsigned row = 15; row < s_comDebugStates.rowCount[0]; ++row) {
        draw(s_comDebugStates.rows[0][row], 0.0f, y, false, 1, 3, white);
        y += line;
    }
    draw(s_comDebugStates.rows[1][28], 0.0f, y, false, 1, 3, white);
    y += line;
    char title[96]{};
    Com_sprintf(title, sizeof(title), "com_debugStates frame %u sample %u (20 frames) unavailable %u",
                s_comDebugStates.frame, s_comDebugStates.captureFrame, s_comDebugStates.unavailable);
    draw(title, 0.0f, y, false, 1, 3, cyan);
    ++s_comDebugStates.draws;
}

