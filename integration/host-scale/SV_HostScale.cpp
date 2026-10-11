#include "sv_host_scale.h"
#include "com_optimized.h"
#include "com_debugstates.h"
#include "sv_host_navigation.h"

extern "C"
{
    __declspec(dllimport) int __stdcall QueryPerformanceCounter(int64_t *);
    __declspec(dllimport) int __stdcall QueryPerformanceFrequency(int64_t *);
}

namespace
{
    cmd_function_s s_statusCommand{};
    bool s_registered;
    uint32_t s_population, s_sightCalls, s_candidates, s_evaluations, s_deferred;
    uint32_t s_queued, s_serial, s_backpressure;
    uint32_t s_botFrames, s_thought, s_reused;
    uint64_t s_brainTicks, s_moveTicks, s_peakTicks, s_frequency;
    int32_t s_populationTime = -1;
    void *s_populationBase;
    uint32_t s_simulationFrames;
    uint64_t s_simulationTick;
    float s_simulationFPS;

    uint32_t Read(const uint32_t &value)
    {
        return __atomic_load_n(&value, __ATOMIC_RELAXED);
    }

    void Status()
    {
        Com_Printf(15,
            "Host scaling %s: population %u; native capacity %u; "
            "bot moves queued %u / serial %u; full-queue worker assists %u\n",
            HostScale::Enabled() ? "enabled" : "disabled", Read(s_population),
            SVHS_ClientCount, Read(s_queued), Read(s_serial), Read(s_backpressure));
        Com_Printf(15,
            "Host sight totals: %u updates, %u candidates, %u visibility evaluations, "
            "%u deferred candidates. Counters are cumulative; compare their deltas.\n",
            Read(s_sightCalls), Read(s_candidates), Read(s_evaluations), Read(s_deferred));
        const auto frames = Read(s_botFrames);
        const auto frequency = __atomic_load_n(&s_frequency, __ATOMIC_RELAXED);
        if (frames && frequency)
        {
            const double milliseconds = 1000.0 / double(frequency);
            Com_Printf(15, "Bot CPU: %u frames; %u full decisions / %u reused commands; "
                "average decisions %.3f ms, movement %.3f ms, peak combined %.3f ms\n",
                frames, Read(s_thought), Read(s_reused),
                double(__atomic_load_n(&s_brainTicks, __ATOMIC_RELAXED)) * milliseconds / frames,
                double(__atomic_load_n(&s_moveTicks, __ATOMIC_RELAXED)) * milliseconds / frames,
                double(__atomic_load_n(&s_peakTicks, __ATOMIC_RELAXED)) * milliseconds);
        }
        SV_HostNav_PrintStatus();
    }
}

bool HostScale::Enabled()
{
    return Com_Optimized_IsEnabled();
}

unsigned HostScale::Population()
{
    // Called on the server thread. Capacity is not population: a 150-slot lobby
    // containing two players must not trigger the experimental AI policy.
    const int32_t now = SVHS_LevelTime;
    void *base = SVHS_Clients[0];
    if (now != s_populationTime || base != s_populationBase)
    {
        uint32_t count = 0;
        const unsigned limit = SVHS_ClientCount < 200 ? SVHS_ClientCount : 200;
        for (unsigned i = 0; i < limit; ++i)
            if (SVHS_Clients[i] && Field<uint8_t>(SVHS_Clients[i], 8) >= 3)
                ++count;
        __atomic_store_n(&s_population, count, __ATOMIC_RELAXED);
        s_populationTime = now;
        s_populationBase = base;
    }
    return Read(s_population);
}

void HostScale::RecordSight(unsigned candidates, unsigned evaluations, unsigned deferred)
{
    __atomic_fetch_add(&s_sightCalls, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&s_candidates, candidates, __ATOMIC_RELAXED);
    __atomic_fetch_add(&s_evaluations, evaluations, __ATOMIC_RELAXED);
    __atomic_fetch_add(&s_deferred, deferred, __ATOMIC_RELAXED);
}

void HostScale::RecordMovement(unsigned queued, unsigned serial)
{
    __atomic_fetch_add(&s_queued, queued, __ATOMIC_RELAXED);
    __atomic_fetch_add(&s_serial, serial, __ATOMIC_RELAXED);
}

void HostScale::RecordBackpressure()
{
    __atomic_fetch_add(&s_backpressure, 1, __ATOMIC_RELAXED);
}

uint64_t HostScale::Clock()
{
    int64_t ticks = 0;
    QueryPerformanceCounter(&ticks);
    return uint64_t(ticks);
}

void HostScale::RecordBotFrame(unsigned thought, unsigned reused, uint64_t brain, uint64_t movement)
{
    __atomic_fetch_add(&s_botFrames, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&s_thought, thought, __ATOMIC_RELAXED);
    __atomic_fetch_add(&s_reused, reused, __ATOMIC_RELAXED);
    __atomic_fetch_add(&s_brainTicks, brain, __ATOMIC_RELAXED);
    __atomic_fetch_add(&s_moveTicks, movement, __ATOMIC_RELAXED);
    // A single server thread produces these samples; the UI only reads them.
    if (brain + movement > __atomic_load_n(&s_peakTicks, __ATOMIC_RELAXED))
        __atomic_store_n(&s_peakTicks, brain + movement, __ATOMIC_RELAXED);
}

extern "C" void SV_HostScale_Frame()
{
    if (!Sys_IsMainThread())
        return;
    if (!s_registered)
    {
        int64_t frequency = 0;
        if (QueryPerformanceFrequency(&frequency))
            __atomic_store_n(&s_frequency, uint64_t(frequency), __ATOMIC_RELAXED);
        Cmd_AddCommandInternal("sv_hostScaleStatus", Status, &s_statusCommand);
        s_registered = true;
    }
}

extern "C" float SV_HostScale_GetSimulationFPS()
{
    // Only the main-thread debug overlay calls this sampler. The producer is
    // the completed server bot/movement tick, independent of render frames.
    const auto frequency = __atomic_load_n(&s_frequency, __ATOMIC_RELAXED);
    const auto frames = Read(s_botFrames);
    if (!SVHS_BotSystemAllocated || !SVHS_LevelClientsAllocated || !frequency)
    {
        s_simulationTick = 0;
        s_simulationFrames = frames;
        s_simulationFPS = 0;
        return -1;
    }
    const uint64_t now = HostScale::Clock();
    if (!s_simulationTick || now < s_simulationTick)
    {
        s_simulationTick = now;
        s_simulationFrames = frames;
        s_simulationFPS = 0;
    }
    else if (now - s_simulationTick >= frequency)
    {
        s_simulationFPS = float(double(uint32_t(frames - s_simulationFrames)) *
                                double(frequency) / double(now - s_simulationTick));
        s_simulationTick = now;
        s_simulationFrames = frames;
    }
    return s_simulationFPS;
}
