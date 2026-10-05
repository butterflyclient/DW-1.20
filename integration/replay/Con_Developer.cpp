// Private DW executable integration; compiled and linked by the frozen-source
// workflow. Native bindings are link-time identities, never runtime patches.
#include "com_debugstates.h"
#include "replay_dvar.h"
#include "con_dvar_names.h"

extern "C" {
bool DW_LocalBackend_IsEnabled();
void replay_rva_015ae0b0(int); // Con_DrawConsole, exact Replay implementation
void replay_rva_015b18c0(); // Con_ToggleConsole
void replay_rva_015b1930(); // Con_ToggleConsoleOutput
bool replay_rva_015b0ef0(int); // Con_IsActive
extern void* replay_rva_12d36330; // native game HWND
__declspec(dllimport) short __stdcall GetAsyncKeyState(int);
__declspec(dllimport) void* __stdcall GetForegroundWindow();
}

// CL_Keys_ConsoleKey proves the native 16-byte buffer layout and client-zero
// base. GScr_AddDebugCommand originally selects the NEXT buffer instead.
struct conCommandBuffer_t {
    char* data;
    int capacity;
    int size;
};
static_assert(sizeof(conCommandBuffer_t) == 16);
static_assert(offsetof(conCommandBuffer_t, size) == 12);
extern "C" conCommandBuffer_t replay_rva_0d216d70[];

namespace {
cmd_function_s s_toggleCommand{};
bool s_registered = false;
bool s_visibilitySet = false;
bool s_f7Held = false;
// Translation and immediate Cbuf submission are main-thread-only. Keep this
// scratch space off the event stack; no allocation or large stack probe needed.
char s_translation[4096];

bool Equal(const char* text, unsigned length, const char* other) {
    unsigned i = 0;
    for (; i < length && other[i]; ++i)
        if (text[i] != other[i]) return false;
    return i == length && other[i] == 0;
}

bool Space(char c) { return c == ' ' || c == '\t' || c == '\v' || c == '\f'; }

// Match the proxy's translation rules without introducing STL allocation or
// new CRT dependencies. Values, quoted strings, comments and command boundaries
// remain intact. Reject the whole command on overflow; never execute a prefix.
bool Translate(const char* input, char (&output)[4096]) {
    unsigned position = 0, used = 0, tokenIndex = 0;
    bool dvarCommand = false;
    while (input[position]) {
        if (position >= sizeof(output) - 1) return false;
        const unsigned start = position;
        const char c = input[position];
        const char* replacement = nullptr;
        if (c == ';' || c == '\n' || c == '\r') {
            tokenIndex = 0;
            dvarCommand = false;
            ++position;
        } else if (Space(c)) {
            ++position;
        } else if (c == '/' && input[position + 1] == '/') {
            while (input[position] && input[position] != '\n' && input[position] != '\r') {
                if (++position >= sizeof(output) - 1) return false;
            }
        } else {
            if (c == '"') {
                ++position;
                while (input[position]) {
                    if (position >= sizeof(output) - 1) return false;
                    if (input[position] == '\\' && input[position + 1]) {
                        position += 2;
                        continue;
                    }
                    if (input[position++] == '"') break;
                }
            } else {
                while (input[position] && !Space(input[position]) &&
                       input[position] != ';' && input[position] != '\n' && input[position] != '\r') {
                    if (++position >= sizeof(output) - 1) return false;
                }
                const unsigned length = position - start;
                if (tokenIndex == 0) {
                    dvarCommand = Equal(input + start, length, "set") ||
                        Equal(input + start, length, "seta") || Equal(input + start, length, "setu") ||
                        Equal(input + start, length, "sets") || Equal(input + start, length, "toggle") ||
                        Equal(input + start, length, "reset");
                    if (Equal(input + start, length, "noclip") ||
                        Equal(input + start, length, "mw_noclip")) replacement = "cmd noclip";
                    else if (Equal(input + start, length, "mw_setpos")) replacement = "cmd mw_setpos";
                }
                if ((tokenIndex == 0 && !dvarCommand) || (tokenIndex == 1 && dvarCommand)) {
                    for (const auto& entry : dvardb::kEntries) {
                        if (Equal(input + start, length, entry.name)) {
                            replacement = entry.token;
                            break;
                        }
                    }
                }
            }
            ++tokenIndex;
        }
        if (replacement) {
            for (unsigned i = 0; replacement[i]; ++i) {
                if (used >= sizeof(output) - 1) return false;
                output[used++] = replacement[i];
            }
        } else {
            for (unsigned i = start; i < position; ++i) {
                if (used >= sizeof(output) - 1) return false;
                output[used++] = input[i];
            }
        }
    }
    output[used] = 0;
    return true;
}

void Con_ToggleDeveloper_f() {
    replay_rva_015b18c0();
}

void Con_DeveloperFrame(int client) {
    if (client != 0 || !Sys_IsMainThread()) return;
    if (!s_registered) {
        Cmd_AddCommandInternal("dw_console", Con_ToggleDeveloper_f, &s_toggleCommand);
        s_registered = true;
        Com_Printf(16, "Developer console: F7; Shift+F7 toggles full output.\n");
    }
    if (!s_visibilitySet) {
        if (auto* hidden = Dvar_FindVarByName("NRNSMTPL")) {
            DvarValue value{};
            value.enabled = false;
            Dvar_SetVariant(hidden, &value, 0);
            s_visibilitySet = true;
        }
    }
    // Poll on the main render thread. Replay's stock key path can return
    // through LUI before reaching its console-toggle branch. F7 has no stock
    // console branch, so polling it cannot double-toggle the native console.
    // Native grave-key handling, character input, editing, history and
    // autocomplete remain owned by CL_Keys_Event / CL_Keys_ConsoleKey.
    const bool held = (GetAsyncKeyState(0x76) & 0x8000) != 0;
    const bool focused = GetForegroundWindow() == replay_rva_12d36330;
    if (focused && held && !s_f7Held) {
        if (GetAsyncKeyState(0x10) & 0x8000) {
            if (!replay_rva_015b0ef0(client)) replay_rva_015b18c0();
            replay_rva_015b1930();
        } else {
            replay_rva_015b18c0();
        }
    }
    s_f7Held = held;
}
}

// The exact target overlay is mov ecx,edx; jmp nullsub_2144 (a bare ret).
// Restore the native console draw at the same overlay boundary as the proxy.
extern "C" uintptr_t func_1415E1340(uintptr_t, int localClientNum) {
    if (DW_LocalBackend_IsEnabled()) {
        Con_DeveloperFrame(localClientNum);
        replay_rva_015ae0b0(localClientNum);
    }
    return 0;
}

// Source replacement of GScr_AddDebugCommand; no detour or injected DLL.
// Preserve the native debugger buffer for other callers. The developer console
// submits client zero on the main thread and must append to client zero's Cbuf.
extern "C" uintptr_t func_1415C1C20(int client, const char* text) {
    if (!text || client < 0 || client > 1) return 0;
    const bool console = client == 0 && DW_LocalBackend_IsEnabled() && Sys_IsMainThread();
    if (console) {
        if (!Translate(text, s_translation)) {
            Com_Printf(16, "Developer console: command exceeds translation buffer.\n");
            return 0;
        }
        text = s_translation;
    }
    unsigned length = 0;
    while (text[length]) ++length;
    Sys_EnterCriticalSection(35);
    auto& buffer = replay_rva_0d216d70[console ? 0 : client + 1];
    if (buffer.data && buffer.capacity > 0 && buffer.size >= 0 &&
        buffer.size < buffer.capacity && length < unsigned(buffer.capacity - buffer.size)) {
        for (unsigned i = 0; i <= length; ++i) buffer.data[buffer.size + i] = text[i];
        buffer.size += int(length);
    } else {
        Com_Printf(16, "Cbuf_AddText: overflow (adding '%s')\n", text);
    }
    Sys_LeaveCriticalSection(35);
    return 0;
}
