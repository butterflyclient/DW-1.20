#include "DW_BotStyleSelection.h"
#include <assert.h>
#include <stdio.h>
#include <set>
#include <string>

namespace
{
    using namespace DWBotStyle;
    std::string Signature(const Selection &selection)
    {
        std::string value;
        for (unsigned i = 0; i < selection.count; ++i)
            value += std::to_string(selection.attachmentIndices[i]) + ":";
        return value;
    }
    void Validate(const Weapon &weapon, const Selection &selection)
    {
        assert(selection.count <= 5);
        int score = 0;
        for (unsigned i = 0; i < selection.count; ++i)
        {
            const unsigned index = selection.attachmentIndices[i];
            assert(index >= weapon.firstAttachment && index < weapon.firstAttachment + weapon.attachmentCount);
            const auto &attachment = Attachments[index];
            assert(Same(selection.references[i], attachment.reference));
            assert(Same(selection.resolvedReferences[i], attachment.resolvedReference));
            assert(selection.variants[i] == attachment.variant && selection.lootIds[i] == attachment.loot);
            assert(attachment.score[unsigned(selection.style)] > 0);
            score += attachment.score[unsigned(selection.style)];
            for (unsigned j = i + 1; j < selection.count; ++j)
            {
                const auto &other = Attachments[selection.attachmentIndices[j]];
                assert(attachment.category != other.category);
                assert(!attachment.blockedCategory || attachment.blockedCategory != other.category);
                assert(!other.blockedCategory || other.blockedCategory != attachment.category);
            }
        }
        assert(score == selection.score);
        for (unsigned i = selection.count; i < 5; ++i)
            assert(selection.references[i] && !*selection.references[i] && !selection.variants[i]);
    }
    const Attachment &Resolved(const Weapon &weapon, const char *reference)
    {
        for (unsigned i = weapon.firstAttachment; i < weapon.firstAttachment + weapon.attachmentCount; ++i)
            if (Same(Attachments[i].resolvedReference, reference))
                return Attachments[i];
        assert(false && "Expected actual target attachment absent");
        return Attachments[0];
    }
}

int main()
{
    using namespace DWBotStyle;
    const uint32_t models[3]{53, 80, 0};
    std::set<uint64_t> identitySeeds;
    std::set<unsigned> styles;
    std::set<std::string> managedSelections;
    const auto *m4 = FindWeapon("iw8_ar_mike4");
    assert(m4 && FindWeapon(m4->nativeAsset) == m4);
    for (unsigned id = 0; id < 150; ++id)
    {
        const auto seed = ProfileSeed(uint16_t(id), 3, models, 0x123456789abcull);
        assert(seed == ProfileSeed(uint16_t(id), 3, models, 0x123456789abcull));
        identitySeeds.insert(seed);
        styles.insert(unsigned(SelectStyle(seed)));
        const auto first = Select(m4->reference, seed), second = Select(m4->reference, seed);
        assert(first.style == second.style && Signature(first) == Signature(second));
        assert(SelectRank(seed).index == SelectRank(seed).index);
        Validate(*m4, first);
        managedSelections.insert(Signature(first));
    }
    assert(identitySeeds.size() == 150 && styles.size() == 6 && managedSelections.size() >= 60);
    assert(ProfileSeed(1, 3, models, 4) != ProfileSeed(1, 3, models, 5));

    unsigned checkedSelections = 0;
    for (const auto &weapon : Weapons)
        for (unsigned style = 0; style < unsigned(Style::Count); ++style)
            for (unsigned id = 0; id < 15; ++id)
            {
                const auto seed = ProfileSeed(uint16_t(id), 3, models);
                const auto selection = Select(&weapon, seed, Style(style));
                Validate(weapon, selection);
                assert(Signature(selection) == Signature(Select(&weapon, seed, Style(style))));
                ++checkedSelections;
            }
    for (const auto &loot : LootWeapons)
        assert(FindWeaponByLoot(loot.loot) == &Weapons[loot.weapon]);
    assert(!FindWeaponByLoot(0xffffffffu) && !FindWeapon("missing") && Select("missing", 1).count == 0);
    assert(Select(m4, 1, Style::Count).count == 0);

    // Target-authored tradeoffs: no stock is fast but hurts recoil/stability;
    // the long barrel adds range/recoil at the cost of mobility/ADS speed.
    const auto &noStock = Resolved(*m4, "stockno_mike4");
    assert(noStock.score[unsigned(Style::Mobility)] > 0);
    assert(noStock.score[unsigned(Style::RecoilControl)] < 0);
    assert(noStock.score[unsigned(Style::AimingStability)] < 0);
    const auto &longBarrel = Resolved(*m4, "barlong_mike4");
    assert(longBarrel.score[unsigned(Style::Range)] > 0 && longBarrel.score[unsigned(Style::Mobility)] < 0);
    std::set<std::string> recoilVariation;
    unsigned negativeModifiersPreserved = 0;
    for (unsigned id = 0; id < 150; ++id)
    {
        const auto selection = Select(m4, ProfileSeed(uint16_t(id), 3, models), Style::RecoilControl);
        recoilVariation.insert(Signature(selection));
        for (unsigned slot = 0; slot < selection.count; ++slot)
        {
            const auto &a = Attachments[selection.attachmentIndices[slot]];
            for (unsigned i = a.firstModifier; i < a.firstModifier + a.modifierCount; ++i)
                negativeModifiersPreserved += Modifiers[i].value < 0;
        }
    }
    assert(recoilVariation.size() >= 20 && negativeModifiersPreserved > 0);

    unsigned topQuarter = 0, lowQuarter = 0, histogram[6]{};
    for (unsigned id = 0; id < 100000; ++id)
    {
        const uint64_t seed = Mix(id);
        const auto rank = SelectRank(seed);
        assert(rank.index <= 154 && rank.displayLevel == rank.index + 1);
        topQuarter += rank.index >= 116;
        lowQuarter += rank.index < 39;
        ++histogram[unsigned(SelectStyle(seed))];
    }
    assert(topQuarter > 55000 && topQuarter < 61000 && lowQuarter > 1000 && lowQuarter < 2200);
    for (const auto count : histogram)
        assert(count > 15000 && count < 18500);
    printf("Passed %u actual weapon/style selections, 150 unique managed identities, %zu managed loadouts, %zu recoil variations.\n",
           checkedSelections, managedSelections.size(), recoilVariation.size());
    printf("Rank distribution: top quarter %.3f%%, bottom quarter %.3f%%; all six styles present.\n",
           double(topQuarter) / 1000.0, double(lowQuarter) / 1000.0);
}
