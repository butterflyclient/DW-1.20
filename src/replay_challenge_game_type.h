#pragma once
#include <cstdint>
#include <string_view>

// Generated from Replay initchallengeandeventglobals and native operands.
// These are specific game types, distinct from the gamemode family field.
enum class ReplayChallengeGameType : uint32_t
{
    dm = 5,
    war = 6,
    sd = 7,
    dom = 8,
    conf = 9,
    sr = 10,
    grind = 11,
    ball = 12,
    infect = 13,
    tjugg = 14,
    gun = 15,
    grnd = 16,
    siege = 17,
    koth = 18,
    ctf = 19,
    dd = 20,
    tdef = 21,
    front = 22,
    cmd = 23,
    br = 24,
    arena = 25,
    cyber = 26,
    rush = 27,
    esc = 28,
    vip = 29,
    btm = 30,
    rugby = 31,
    arm = 32,
    mtmc = 33,
    snatch = 34,
    hq = 35,
    defcon = 36,
    pill = 37,
    blitz = 38,
    brm = 39,
    hvt = 40,
    trial = 41,
    cp_survival = 42,
    cp_wave_sv = 43,
};

inline std::string_view replayChallengeGameTypeName(uint32_t value)
{
    switch (static_cast<ReplayChallengeGameType>(value))
    {
    case ReplayChallengeGameType::dm: return "dm";
    case ReplayChallengeGameType::war: return "war";
    case ReplayChallengeGameType::sd: return "sd";
    case ReplayChallengeGameType::dom: return "dom";
    case ReplayChallengeGameType::conf: return "conf";
    case ReplayChallengeGameType::sr: return "sr";
    case ReplayChallengeGameType::grind: return "grind";
    case ReplayChallengeGameType::ball: return "ball";
    case ReplayChallengeGameType::infect: return "infect";
    case ReplayChallengeGameType::tjugg: return "tjugg";
    case ReplayChallengeGameType::gun: return "gun";
    case ReplayChallengeGameType::grnd: return "grnd";
    case ReplayChallengeGameType::siege: return "siege";
    case ReplayChallengeGameType::koth: return "koth";
    case ReplayChallengeGameType::ctf: return "ctf";
    case ReplayChallengeGameType::dd: return "dd";
    case ReplayChallengeGameType::tdef: return "tdef";
    case ReplayChallengeGameType::front: return "front";
    case ReplayChallengeGameType::cmd: return "cmd";
    case ReplayChallengeGameType::br: return "br";
    case ReplayChallengeGameType::arena: return "arena";
    case ReplayChallengeGameType::cyber: return "cyber";
    case ReplayChallengeGameType::rush: return "rush";
    case ReplayChallengeGameType::esc: return "esc";
    case ReplayChallengeGameType::vip: return "vip";
    case ReplayChallengeGameType::btm: return "btm";
    case ReplayChallengeGameType::rugby: return "rugby";
    case ReplayChallengeGameType::arm: return "arm";
    case ReplayChallengeGameType::mtmc: return "mtmc";
    case ReplayChallengeGameType::snatch: return "snatch";
    case ReplayChallengeGameType::hq: return "hq";
    case ReplayChallengeGameType::defcon: return "defcon";
    case ReplayChallengeGameType::pill: return "pill";
    case ReplayChallengeGameType::blitz: return "blitz";
    case ReplayChallengeGameType::brm: return "brm";
    case ReplayChallengeGameType::hvt: return "hvt";
    case ReplayChallengeGameType::trial: return "trial";
    case ReplayChallengeGameType::cp_survival: return "cp_survival";
    case ReplayChallengeGameType::cp_wave_sv: return "cp_wave_sv";
    default: return {};
    }
}

namespace replay_challenge_mode_data
{
    inline constexpr uint16_t M19Weapon = 2;
}
