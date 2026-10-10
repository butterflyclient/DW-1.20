#pragma once
#include <array>
#include <cstdint>
#include "replay_kiosk_purchase_data.h"

// Complete native buy_item packet. Category and item are independent table
// lookups, not a count or payment. Keep all 64 bits, including the operator
// mask, so unknown/oversized values cannot alias a valid purchase.
struct ReplayBuyItemEvent
{
    std::array<uint64_t, 3> parameters;

    const ReplayKioskPurchase *purchase() const
    {
        for (const auto &row : replayKioskPurchases)
            if (parameters[0] == static_cast<uint64_t>(row.category) &&
                parameters[1] == static_cast<uint64_t>(row.id))
                return &row;
        return nullptr;
    }

    uint64_t operatorMask() const { return parameters[2]; }
};
