#include "com_debugstates.h"
#include "replay_dvar.h"
#include <stdarg.h>
extern "C"
{
    bool DW_LocalBackend_IsEnabled();
    bool replay_rva_0118dd00(const void *);
    bool replay_rva_01528420();
    bool replay_rva_01189120(const void *);
    void *replay_rva_01187ee0();
    bool replay_rva_0118e020(const void *, unsigned);
    unsigned replay_rva_0148fce0();
    void replay_rva_0119a5a0(void *);
    extern uint8_t replay_rva_0c27e4b0[];
    extern dvar_t *gl_14D386820;
    extern dvar_t *DVARBOOL_onlinegame;
}
#ifndef MAP_VOTE_HEADER
#define MAP_VOTE_HEADER "../integration/replay/DW_MapVoting.h"
#endif
#include MAP_VOTE_HEADER

namespace
{
    dvar_t variables[32]{}, privateMatch{}, online{};
    unsigned registered = 0, milliseconds = 1000, applied = 0, selectedEntry = 0, setups = 0;
    bool owner = true, privateParty = false;
    uint8_t party[352000]{}, nodes[2][208]{};
    char packed[16384]{};
    uint64_t users[4] = {1, 2, 0, 999};
    void Bind(uint64_t id)
    {
        for (unsigned part = 0; part < 4; ++part)
            dwMapVoting::allocation[part]->current.integer = int((id >> (part * 16)) & 65535);
    }
}
extern "C"
{
    void *memset(void *target, int value, size_t size)
    {
        auto *bytes = static_cast<volatile uint8_t *>(target);
        for (size_t i = 0; i < size; ++i) bytes[i] = uint8_t(value);
        return target;
    }
    void *memcpy(void *target, const void *source, size_t size)
    {
        auto *bytes = static_cast<volatile uint8_t *>(target);
        auto *input = static_cast<const volatile uint8_t *>(source);
        for (size_t i = 0; i < size; ++i) bytes[i] = input[i];
        return target;
    }
    uint8_t replay_rva_0c27e4b0[132000]{};
    dvar_t *gl_14D386820 = &privateMatch, *DVARBOOL_onlinegame = &online;
    bool DW_LocalBackend_IsEnabled() { return true; }
    bool Com_FrontEndScene_IsActive() { return true; }
    int Com_GameMode_GetActiveGameMode() { return 2; }
    bool replay_rva_0118dd00(const void *) { return true; }
    bool replay_rva_01528420() { return false; }
    bool replay_rva_01189120(const void *) { return owner; }
    bool replay_rva_0118e960(const void *) { return privateParty; }
    void *replay_rva_01187ee0() { return party; }
    bool replay_rva_0118e020(const void *, unsigned slot) { return slot < 4 && users[slot]; }
    unsigned replay_rva_0148fce0() { return milliseconds; }
    void replay_rva_0119a5a0(void *) {}
    void replay_rva_01191980(unsigned a, unsigned b, unsigned c)
    {
        if (a == 1 && b == 5 && c == 9) ++setups;
    }
    void replay_rva_0118fdc0(void *data, unsigned value)
    {
        *reinterpret_cast<unsigned *>(static_cast<uint8_t *>(data) + 311148) = value;
    }
    uint64_t *replay_rva_0118cf60(uint64_t *out, const void *, int slot)
    {
        *out = users[slot]; return out;
    }
    void replay_rva_010d23e0(int, unsigned entry) { ++applied; selectedEntry = entry; }
    const char *replay_rva_01b9d510(int choice)
    {
        const char *names[] = {"Backlot", "Crash's map", "Office"}; return names[choice];
    }
    dvar_t *Dvar_RegisterInt(const char *name, int32_t value, int32_t minimum, int32_t maximum, uint32_t, const char *)
    {
        auto &v = variables[registered++]; v.name = name; v.type = 5;
        v.current.integer = value; v.domain.integer = {minimum, maximum}; return &v;
    }
    dvar_t *Dvar_RegisterBool(const char *name, bool value, uint32_t, const char *)
    {
        auto &v = variables[registered++]; v.name = name; v.type = 0; v.current.enabled = value; return &v;
    }
    void Dvar_SetVariant(dvar_t *v, const DvarValue *value, int) { v->current = *value; }
    int Com_sprintf(char *out, size_t capacity, const char *format, ...)
    {
        va_list arguments; va_start(arguments, format);
        size_t used = 0;
        for (const char *cursor = format; *cursor; ++cursor)
        {
            if (*cursor != '%')
            {
                if (used + 1 >= capacity) { va_end(arguments); return -1; }
                out[used++] = *cursor; continue;
            }
            ++cursor;
            if (*cursor == 's')
            {
                const char *value = va_arg(arguments, const char *);
                for (; value && *value; ++value)
                {
                    if (used + 1 >= capacity) { va_end(arguments); return -1; }
                    out[used++] = *value;
                }
                continue;
            }
            uint64_t value = 0;
            if (*cursor == 'l' && cursor[1] == 'l' && cursor[2] == 'u')
            {
                cursor += 2; value = va_arg(arguments, uint64_t);
            }
            else if (*cursor == 'u') value = va_arg(arguments, unsigned);
            else if (*cursor == 'd') value = uint64_t(va_arg(arguments, int));
            else { va_end(arguments); return -1; }
            uint64_t place = 1;
            while (place <= value / 10) place *= 10;
            do
            {
                if (used + 1 >= capacity) { va_end(arguments); return -1; }
                out[used++] = char('0' + value / place); value %= place; place /= 10;
            } while (place);
        }
        va_end(arguments); out[used] = 0; return int(used);
    }
}
#define VERIFY(value) if (!(value)) return __LINE__
extern "C" __declspec(dllexport) int Test_Run()
{
    online.current.enabled = true;
    dwMapVoting::Register();
    const uint64_t first = 0x1234567812340001ull, next = 0x1234567812340002ull;
    *reinterpret_cast<uint64_t *>(replay_rva_0c27e4b0 + 79656) = first;
    VERIFY(dwMapVoting::Pending(party));
    dwMapVoting::Frame(party);
    VERIFY(applied == 0 && *reinterpret_cast<bool *>(replay_rva_0c27e4b0 + 79636));
    dwMapVoting::active->current.enabled = true;
    dwMapVoting::complete->current.enabled = true;
    dwMapVoting::choiceCount->current.integer = 3;
    dwMapVoting::entries[0]->current.integer = 1;
    dwMapVoting::entries[1]->current.integer = 5;
    dwMapVoting::entries[2]->current.integer = 9;
    dwMapVoting::winner->current.integer = 1;
    Bind(first); dwMapVoting::Frame(party);
    VERIFY(applied == 1 && selectedEntry == 5 && !dwMapVoting::Pending(party));
    *reinterpret_cast<uint64_t *>(replay_rva_0c27e4b0 + 79656) = next;
    dwMapVoting::select[0]->current.enabled = true;
    milliseconds += 1000; dwMapVoting::Frame(party);
    VERIFY(applied == 1 && dwMapVoting::Pending(party));
    VERIFY(!dwMapVoting::select[0]->current.enabled);
    Bind(next); dwMapVoting::complete->current.enabled = false;
    dwMapVoting::cycle->current.integer = 1; dwMapVoting::Frame(party);
    VERIFY(setups == 2 && dwMapVoting::Pending(party));
    dwMapVoting::select[2]->current.enabled = true; dwMapVoting::Frame(party);
    VERIFY(*reinterpret_cast<unsigned *>(party + 311148) == 3 && !dwMapVoting::select[2]->current.enabled);
    const auto head = reinterpret_cast<uintptr_t>(replay_rva_0c27e4b0 + 46424);
    *reinterpret_cast<uintptr_t *>(replay_rva_0c27e4b0 + 46432) = reinterpret_cast<uintptr_t>(nodes[0]);
    for (unsigned i = 0; i < 2; ++i)
    {
        *reinterpret_cast<uintptr_t *>(nodes[i] + 8) = i == 0 ? reinterpret_cast<uintptr_t>(nodes[1]) : head;
        *reinterpret_cast<uint64_t *>(nodes[i] + 104) = users[i]; nodes[i][121] = 1;
        *reinterpret_cast<unsigned *>(nodes[i] + 184) = 2;
    }
    for (unsigned i = 0; i < 4; ++i)
    {
        *reinterpret_cast<unsigned *>(party + 2292 + i * 488) = i == 0 ? 2 : 3;
        party[2292 + i * 488 + 302] = 5;
    }
    const char original[] = "{\"game_state\":{\"state\":\"intermission\"}}";
    const char *source = original; unsigned length = sizeof(original);
    dwMapVoting::HostDocument(next, &source, &length);
    for (unsigned i = 0; i < length; ++i) packed[i] = source[i];
    dwMapVoting::complete->current.enabled = true; dwMapVoting::Frame(party);
    VERIFY(applied == 2 && !dwMapVoting::Pending(party));
    owner = false; dwMapVoting::Frame(party);
    owner = true; dwMapVoting::Frame(party);
    VERIFY(applied == 3 && selectedEntry == 5);
    dwMapVoting::Suspend(); dwMapVoting::Frame(party);
    VERIFY(applied == 3 && dwMapVoting::Pending(party));
    dwMapVoting::cycle->current.integer = 2; dwMapVoting::complete->current.enabled = false;
    dwMapVoting::Frame(party); VERIFY(dwMapVoting::Pending(party) && setups == 3);
    *reinterpret_cast<uint64_t *>(replay_rva_0c27e4b0 + 79656) = next + 1;
    VERIFY(dwMapVoting::Pending(party));
    privateParty = true; VERIFY(!dwMapVoting::Pending(party));
    privateParty = false;
    return 0;
}
extern "C" __declspec(dllexport) const char *Test_Document() { return packed; }
extern "C" __declspec(dllexport) int Test_LargeSnapshot()
{
    static char large[10000]{};
    const char prefix[] = "{\"padding\":\"";
    unsigned used = 0;
    for (; used < sizeof(prefix) - 1; ++used) large[used] = prefix[used];
    for (; used < 9000; ++used) large[used] = 'x';
    const char tail[] = "\",\"game_state\":{\"state\":\"intermission\"}}";
    for (unsigned i = 0; i < sizeof(tail); ++i) large[used++] = tail[i];
    const auto id = *reinterpret_cast<uint64_t *>(replay_rva_0c27e4b0 + 79656);
    Bind(id);
    const char *source = large;
    unsigned length = used;
    dwMapVoting::HostDocument(id, &source, &length);
    VERIFY(source != large && length > used && length < 16384);
    return 0;
}
