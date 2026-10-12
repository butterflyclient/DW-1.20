#pragma once
#include "DW_BotStyleData.h"

namespace DWBotStyle
{
    inline uint64_t Mix(uint64_t value)
    {
        value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ull;
        value = (value ^ (value >> 27)) * 0x94d049bb133111ebull;
        return value ^ (value >> 31);
    }
    struct Random
    {
        uint64_t state;
        uint64_t Next() { state += 0x9e3779b97f4a7c15ull; return Mix(state); }
        unsigned Bounded(unsigned bound)
        {
            // Rejection preserves the intended weighting for every bound.
            const uint64_t threshold = (uint64_t(0) - bound) % bound;
            uint64_t value;
            do { value = Next(); } while (value < threshold);
            return unsigned(value % bound);
        }
    };

    inline uint64_t ProfileSeed(uint16_t nameIndex, uint16_t skill,
                                const uint32_t modelIndices[3], uint64_t rosterSeed = 0)
    {
        // Use existing native record fields. A roster seed must already be
        // shared by its callers; zero is the portable fallback. No wire writes.
        uint64_t seed = Mix(rosterSeed ^ 0x424f5450524f4649ull);
        seed = Mix(seed ^ (uint64_t(nameIndex) << 32) ^ skill);
        for (unsigned i = 0; i != 3; ++i)
            seed = Mix(seed ^ modelIndices[i] ^ (uint64_t(i + 1) << 56));
        return seed;
    }
    inline Style SelectStyle(uint64_t profileSeed)
    {
        Random random{profileSeed ^ 0x5354594c45444953ull};
        return Style(random.Bounded(unsigned(Style::Count)));
    }
    inline Rank SelectRank(uint64_t profileSeed)
    {
        Random random{profileSeed ^ 0x52414e4b57454947ull};
        unsigned ordinal = 0;
        for (unsigned i = 0; i != 3; ++i)
        {
            const unsigned draw = random.Bounded(unsigned(sizeof(Ranks) / sizeof(*Ranks)));
            if (draw > ordinal)
                ordinal = draw;
        }
        return Ranks[ordinal];
    }
    inline bool Same(const char *left, const char *right)
    {
        while (*left && *left == *right) { ++left; ++right; }
        return *left == *right;
    }
    inline const Weapon *FindWeapon(const char *reference)
    {
        if (reference)
            for (const auto &weapon : Weapons)
                if (Same(reference, weapon.reference) || Same(reference, weapon.nativeAsset))
                    return &weapon;
        return nullptr;
    }
    inline const Weapon *FindWeaponByLoot(uint32_t loot)
    {
        unsigned first = 0, last = unsigned(sizeof(LootWeapons) / sizeof(*LootWeapons));
        while (first < last)
        {
            const unsigned middle = first + (last - first) / 2;
            if (LootWeapons[middle].loot < loot)
                first = middle + 1;
            else
                last = middle;
        }
        return first < sizeof(LootWeapons) / sizeof(*LootWeapons) && LootWeapons[first].loot == loot
            ? &Weapons[LootWeapons[first].weapon] : nullptr;
    }

    inline const Weapon *WeaponForSlot(uint64_t profileSeed, unsigned slot)
    {
        if (slot > 1)
            return nullptr;
        // Weapon choice and attachment choice share one transported identity.
        // Cosmetic operator packages never imply unverified combat bonuses.
        unsigned count = 0;
        for (const auto &weapon : Weapons)
            if (Same(weapon.weaponClass, "weapon_pistol") == bool(slot))
                ++count;
        if (!count)
            return nullptr;
        Random random{profileSeed ^ (0x574541504f4e534cull + slot)};
        unsigned ordinal = random.Bounded(count);
        for (const auto &weapon : Weapons)
            if (Same(weapon.weaponClass, "weapon_pistol") == bool(slot) && !ordinal--)
                return &weapon;
        return nullptr;
    }

    struct Selection
    {
        const char *references[5]{"", "", "", "", ""};
        const char *resolvedReferences[5]{"", "", "", "", ""};
        uint32_t lootIds[5]{};
        uint8_t variants[5]{};
        uint16_t attachmentIndices[5]{};
        unsigned count{};
        int score{};
        Style style{};
    };
    inline bool Compatible(const Attachment &candidate, const Selection &selected)
    {
        for (unsigned i = 0; i < selected.count; ++i)
        {
            const auto &prior = Attachments[selected.attachmentIndices[i]];
            if (prior.category == candidate.category ||
                (prior.blockedCategory && prior.blockedCategory == candidate.category) ||
                (candidate.blockedCategory && candidate.blockedCategory == prior.category))
                return false;
        }
        return true;
    }
    inline Selection Select(const Weapon *weapon, uint64_t profileSeed, Style style)
    {
        Selection result{};
        result.style = style;
        if (!weapon || unsigned(style) >= unsigned(Style::Count))
            return result;
        uint64_t weaponSeed = profileSeed ^ 0x4154544143485641ull;
        for (const unsigned char *p = reinterpret_cast<const unsigned char *>(weapon->reference); *p; ++p)
            weaponSeed = Mix(weaponSeed ^ *p);
        Random random{weaponSeed ^ unsigned(style)};
        const unsigned end = weapon->firstAttachment + weapon->attachmentCount;
        while (result.count < 5)
        {
            int best = 0;
            for (unsigned i = weapon->firstAttachment; i < end; ++i)
                if (Compatible(Attachments[i], result) && Attachments[i].score[unsigned(style)] > best)
                    best = Attachments[i].score[unsigned(style)];
            if (!best)
                break;
            // Keep choices close to the strongest remaining fit, then vary
            // among them with squared score weights. Pros and cons both count.
            const int minimum = best > 3 ? best - 2 : 1;
            unsigned totalWeight = 0;
            for (unsigned i = weapon->firstAttachment; i < end; ++i)
            {
                const int score = Attachments[i].score[unsigned(style)];
                if (score >= minimum && Compatible(Attachments[i], result))
                    totalWeight += unsigned(score * score);
            }
            unsigned choice = random.Bounded(totalWeight);
            for (unsigned i = weapon->firstAttachment; i < end; ++i)
            {
                const auto &candidate = Attachments[i];
                const int score = candidate.score[unsigned(style)];
                if (score < minimum || !Compatible(candidate, result))
                    continue;
                const unsigned weight = unsigned(score * score);
                if (choice >= weight)
                {
                    choice -= weight;
                    continue;
                }
                const unsigned slot = result.count++;
                result.references[slot] = candidate.reference;
                result.resolvedReferences[slot] = candidate.resolvedReference;
                result.lootIds[slot] = candidate.loot;
                result.variants[slot] = candidate.variant;
                result.attachmentIndices[slot] = uint16_t(i);
                result.score += score;
                break;
            }
        }
        return result;
    }
    inline Selection Select(const char *weaponReference, uint64_t profileSeed)
    {
        return Select(FindWeapon(weaponReference), profileSeed, SelectStyle(profileSeed));
    }
}
