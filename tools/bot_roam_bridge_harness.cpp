#define main ExistingWeaponMain
#define SV_HostBot_RequestRoamGoal Existing_SV_HostBot_RequestRoamGoal
#define SV_HostBot_CancelRoamGoal Existing_SV_HostBot_CancelRoamGoal
#define SM_AddInt Existing_SM_AddInt
#define SVHS_ScriptAddVector Existing_SVHS_ScriptAddVector
#define SVHS_LevelTime Existing_SVHS_LevelTime
#define SM_GetNumParam Existing_SM_GetNumParam
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wreturn-type"
#include "bot_style_weapon_harness.cpp"
#pragma clang diagnostic pop
#undef SM_GetNumParam
#undef main
#undef SV_HostBot_RequestRoamGoal
#undef SV_HostBot_CancelRoamGoal
#undef SM_AddInt
#undef SVHS_ScriptAddVector
#undef SVHS_LevelTime
extern "C" void DW_BotRoamRequestMethod(void *, uint64_t);
extern "C" void DW_BotRoamGoalMethod(void *, uint64_t);
extern "C" void DW_BotRoamCancelMethod(void *, uint64_t);
namespace
{
unsigned requestCalls, cancelCalls, intAdds, vectorAdds;
unsigned nextState = 2;
int32_t returnedState = -1;
HostScale::Vec3 nextDestination{2000, 3000, 40}, returnedVector{};
void *lastRequestContext, *lastRequestBot;
void *const alternateContext = reinterpret_cast<void *>(0x43210);
void ResetCounters()
{
    requestCalls = cancelCalls = intAdds = vectorAdds = 0;
    returnedState = -1;
    returnedVector = {};
}
void Setup(Fixture &f)
{
    current = &f;
    f.br = true;
    f.params = 2;
    SVHS_ClientCount = 200;
    SVHS_Clients[33] = f.nativeClient;
    ResetCounters();
}
void Request(Fixture &f)
{
    f.params = 2;
    DW_BotRoamRequestMethod(context, f.self);
}
void Goal(Fixture &f, void *ctx = context)
{
    f.params = 0;
    DW_BotRoamGoalMethod(ctx, f.self);
}
} // namespace
extern "C" int32_t SVHS_LevelTime = 1000;
extern "C" uint32_t SM_GetNumParam(void *)
{
    return current->params;
}
extern "C" void SM_AddInt(void *, int32_t value)
{
    ++intAdds;
    returnedState = value;
}
extern "C" void SVHS_ScriptAddVector(void *, const void *value)
{
    ++vectorAdds;
    returnedVector = *static_cast<const HostScale::Vec3 *>(value);
}
extern "C" unsigned SV_HostBot_RequestRoamGoal(void *bot, const HostScale::Vec3 *center,
                                               float radius, HostScale::Vec3 *out, void *ctx)
{
    ++requestCalls;
    assert(bot == current->nativeClient + 1368);
    assert(center->x == 0 && radius == 1000);
    lastRequestContext = ctx;
    lastRequestBot = bot;
    *out = nextDestination;
    return nextState;
}
extern "C" void SV_HostBot_CancelRoamGoal(void *bot)
{
    ++cancelCalls;
    assert(bot == current->nativeClient + 1368);
}
int main()
{
    unsigned cases = 0;
    {
        Fixture f;
        Setup(f);
        nextState = 2;
        Request(f);
        assert(requestCalls == 1 && returnedState == 2 && intAdds == 1);
        Goal(f);
        assert(vectorAdds == 1 && returnedVector.x == 2000 && requestCalls == 1 &&
               lastRequestContext == context);
        Goal(f);
        assert(vectorAdds == 1 && requestCalls == 1);
        ++cases;
    }
    for (unsigned status : {0u, 1u})
    {
        Fixture f;
        Setup(f);
        nextState = status;
        Request(f);
        Goal(f);
        assert(requestCalls == 1 && returnedState == int(status) && vectorAdds == 0);
        ++cases;
    }
    for (unsigned scenario = 0; scenario < 10; ++scenario)
    {
        Fixture f;
        Setup(f);
        nextState = 2;
        if (scenario == 0)
            f.bot = false;
        if (scenario == 1)
            f.br = false;
        if (scenario == 2)
            f.self |= uint64_t(1) << 32;
        if (scenario == 3)
            f.self = 200;
        if (scenario == 4)
            SVHS_ClientCount = 33;
        if (scenario == 5)
            f.entityPresent = false;
        if (scenario == 6)
            DW_Bot_Clients[33]->entity = nullptr;
        if (scenario == 7)
            DW_Bot_Clients[33]->clientType = 1;
        if (scenario == 8)
            HostScale::Field<int32_t>(f.player, 448) = 34;
        if (scenario == 9)
            f.params = 1;
        DW_BotRoamRequestMethod(context, f.self);
        assert(!requestCalls && returnedState == 0);
        Goal(f);
        assert(!vectorAdds);
        ++cases;
    }
    for (unsigned scenario = 0; scenario < 11; ++scenario)
    {
        Fixture f;
        Setup(f);
        nextState = 2;
        Request(f);
        if (scenario == 0)
            ++f.profile;
        if (scenario == 1)
            ++SVHS_LevelTime;
        if (scenario == 2)
        {
            Goal(f, alternateContext);
            assert(!vectorAdds);
            Goal(f);
            assert(!vectorAdds);
            ++cases;
            continue;
        }
        if (scenario == 3)
        {
            f.entityPresent = false;
            Goal(f);
            f.entityPresent = true;
        }
        if (scenario == 4)
        {
            f.bot = false;
            Goal(f);
            f.bot = true;
        }
        if (scenario == 5)
        {
            f.params = 1;
            DW_BotRoamGoalMethod(context, f.self);
            f.params = 0;
        }
        if (scenario == 6)
        {
            f.params = 1;
            DW_BotRoamRequestMethod(context, f.self);
            f.params = 0;
        }
        if (scenario == 7)
        {
            f.profile += 1;
            Goal(f);
            f.profile -= 1;
        }
        if (scenario == 8)
        {
            f.self |= uint64_t(1) << 32;
            Goal(f);
            assert(!vectorAdds);
            f.self = 33;
            Goal(f);
            assert(vectorAdds == 1);
            Goal(f);
            assert(vectorAdds == 1);
            ++cases;
            continue;
        }
        if (scenario == 9)
        {
            f.params = 1;
            DW_BotRoamCancelMethod(context, f.self);
            f.params = 0;
            assert(!cancelCalls);
        }
        if (scenario == 10)
        {
            static unsigned char player[22340]{};
            HostScale::Field<int32_t>(player, 448) = 33;
            f.entity.client = player;
            Goal(f);
            f.entity.client = f.player;
        }
        Goal(f);
        assert(!vectorAdds);
        ++cases;
    }
    {
        Fixture f;
        Setup(f);
        nextState = 2;
        Request(f);
        static unsigned char alternateClient[321192]{};
        auto *owner = reinterpret_cast<DWBotNativeClient *>(alternateClient);
        owner->entity = &f.entity;
        owner->clientType = 2;
        DW_Bot_Clients[33] = owner;
        SVHS_Clients[33] = alternateClient;
        Goal(f);
        assert(!vectorAdds);
        DW_Bot_Clients[33] = reinterpret_cast<DWBotNativeClient *>(f.nativeClient);
        SVHS_Clients[33] = f.nativeClient;
        Goal(f);
        assert(!vectorAdds);
        ++cases;
    }
    {
        Fixture f;
        Setup(f);
        nextState = 2;
        Request(f);
        DW_Bot_Clients[33]->entity = nullptr;
        Goal(f);
        assert(!vectorAdds);
        DW_Bot_Clients[33]->entity = &f.entity;
        Goal(f);
        assert(!vectorAdds);
        ++cases;
    }
    {
        Fixture f;
        Setup(f);
        nextState = 2;
        Request(f);
        f.params = 0;
        DW_BotRoamCancelMethod(context, f.self);
        Goal(f);
        assert(cancelCalls == 1 && vectorAdds == 0);
        ++cases;
    }
    {
        Fixture f;
        Setup(f);
        nextState = 2;
        Request(f);
        nextDestination = {4000, 5000, 60};
        Request(f);
        Goal(f);
        assert(requestCalls == 2 && vectorAdds == 1 && returnedVector.x == 4000);
        ++cases;
    }
    {
        Fixture f;
        Setup(f);
        nextState = 2;
        Request(f);
        nextState = 1;
        Request(f);
        Goal(f);
        assert(requestCalls == 2 && !vectorAdds);
        ++cases;
    }
    printf("PASS BR roam bridge:%u "
           "ownership/cache/once-request/vector-replay/context/profile/time/arity/cancel/overwrite "
           "cases\n",
           cases);
    return 0;
}
