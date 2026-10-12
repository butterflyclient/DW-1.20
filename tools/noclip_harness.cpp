#include "DW_Noclip.h"
#include "DW_NoclipBindings.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <string>

extern "C" bool DW_Noclip_StringCommand(DWNoclip::ServerClient *, void *, int, bool);
extern "C" {
    DWNoclip::ServerClient *NC_Clients[200]{};
    uint32_t NC_ClientCount = 3;
    HostScale::Entity *NC_Entities;
}
namespace {
    HostScale::Entity entities[3]{};
    DWNoclip::ServerClient clients[3]{};
    DWNoclip::PlayerClient players[3]{};
    dvar_t cheats{};
    bool loaded, local[3], dvarPresent;
    unsigned delegates, nativeCalls, replies;
    std::string args[3], message;
    const uintptr_t *table;
    void Reply(DWNoclip::ServerClient *client, int reliability, const char *text) {
        assert(client >= clients && client < clients + 3 && reliability == 0);
        message = text; ++replies;
    }
    void Reset() {
        memset(entities, 0, sizeof(entities)); memset(clients, 0, sizeof(clients));
        memset(players, 0, sizeof(players)); memset(&cheats, 0, sizeof(cheats));
        static const uintptr_t vtable[]{0, reinterpret_cast<uintptr_t>(&Reply)};
        table = vtable; NC_Entities = entities; NC_ClientCount = 3;
        loaded = dvarPresent = true; delegates = nativeCalls = replies = 0;
        message.clear(); args[0] = "noclip"; args[1].clear(); args[2].clear();
        for (unsigned i = 0; i < 3; ++i) {
            entities[i].number = int16_t(i); entities[i].health = 100;
            entities[i].client = reinterpret_cast<uint8_t *>(&players[i]);
            clients[i].vtable = table; clients[i].state = 5; clients[i].entity = &entities[i];
            NC_Clients[i] = &clients[i]; players[i].clientNumber = int(i);
            players[i].connectionState = 2; players[i].sessionState = 0;
            players[i].flags = 0x4a0; local[i] = i == 2;
        }
    }
}
extern "C" const char *NC_Argv(int index) { assert(index >= 0 && index < 3); return args[index].c_str(); }
extern "C" bool NC_ServerLoaded() { return loaded; }
extern "C" bool NC_IsLocalClient(int index) { assert(index >= 0 && index < 3); return local[index]; }
extern "C" const dvar_t *NC_FindDvar(const char *name) { assert(!strcmp(name, "NTPNRQTKNP")); return dvarPresent ? &cheats : nullptr; }
extern "C" void NC_ClientCommandNative(int) { ++delegates; }
extern "C" bool NC_StringCommandNative(DWNoclip::ServerClient *client, void *messagePointer, int sequence, bool old) {
    assert(client == &clients[2] && messagePointer == &cheats && sequence == 37 && old);
    ++nativeCalls; return true;
}
int main() {
    unsigned cases = 0;
    for (unsigned slot = 0; slot < 3; ++slot)
        for (bool enabled : {false, true}) {
            Reset(); cheats.current.enabled = enabled;
            DW_Noclip_ClientCommand(int(slot));
            assert(players[slot].flags == (slot == 2 || enabled ? 0x4a1u : 0x4a0u));
            for (unsigned other = 0; other < 3; ++other)
                if (other != slot) assert(players[other].flags == 0x4a0);
            assert(replies == 1 && !delegates); ++cases;
        }
    for (const char *value : {"1", "on", "ON", "0", "off", "OFF", ""}) {
        Reset(); args[1] = value; players[2].flags |= 1;
        DW_Noclip_ClientCommand(2);
        const bool wanted = !strcmp(value, "1") || !strcmp(value, "on") || !strcmp(value, "ON");
        assert(players[2].flags == (wanted ? 0x4a1u : 0x4a0u)); ++cases;
    }
    for (unsigned invalid = 0; invalid < 16; ++invalid) {
        Reset();
        switch (invalid) {
        case 0: loaded = false; break;
        case 1: NC_ClientCount = 0; break;
        case 2: NC_ClientCount = 201; break;
        case 3: NC_Entities = nullptr; break;
        case 4: NC_Clients[2] = nullptr; break;
        case 5: clients[2].state = 4; break;
        case 6: clients[2].entity = &entities[0]; break;
        case 7: entities[2].number = 1; break;
        case 8: entities[2].client = nullptr; break;
        case 9: players[2].clientNumber = 0; break;
        case 10: players[2].connectionState = 0; break;
        case 11: players[2].sessionState = 1; break;
        case 12: entities[2].health = 0; break;
        case 13: args[1] = "2"; break;
        case 14: args[2] = "0"; break;
        case 15: args[1] = "-1"; break;
        }
        DW_Noclip_ClientCommand(2);
        assert(players[2].flags == 0x4a0 && !delegates); ++cases;
    }
    for (int index : {-1, 3, 200, 0x7fffffff}) {
        Reset(); DW_Noclip_ClientCommand(index); assert(!replies && !delegates); ++cases;
    }
    // Dvar missing/wrong type fails closed for a network guest. A host works
    // without a dvar; the server's value is checked afresh on every request.
    for (unsigned scenario = 0; scenario < 3; ++scenario) {
        Reset(); if (!scenario) dvarPresent = false; else cheats.type = 1;
        cheats.current.enabled = true;
        DW_Noclip_ClientCommand(0); assert(players[0].flags == 0x4a0);
        DW_Noclip_ClientCommand(2); assert(players[2].flags == 0x4a1); ++cases;
    }
    Reset(); cheats.current.enabled = true; args[1] = "on";
    DW_Noclip_ClientCommand(0); assert(players[0].flags == 0x4a1);
    cheats.current.enabled = false; args[1] = "off";
    DW_Noclip_ClientCommand(0); assert(players[0].flags == 0x4a1); // Denied command, no mutation.
    cheats.current.enabled = true; DW_Noclip_ClientCommand(0); assert(players[0].flags == 0x4a0); ++cases;
    for (const char *name : {"noclipx", "say", "lui", "", "cmd"}) {
        Reset(); args[0] = name; DW_Noclip_ClientCommand(2);
        assert(delegates == 1 && !replies && players[2].flags == 0x4a0); ++cases;
    }
    for (const char *name : {"NOCLIP", "mw_noclip"}) {
        Reset(); args[0] = name; DW_Noclip_ClientCommand(2);
        assert(players[2].flags == 0x4a1 && !delegates); ++cases;
    }
    Reset(); assert(DW_Noclip_StringCommand(&clients[2], &cheats, 37, true));
    assert(nativeCalls == 1 && !replies && !delegates); ++cases;
    printf("PASS %u server noclip permission/slot/command cases; native authentication delegation preserved.\n", cases);
}
