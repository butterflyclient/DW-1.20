"""Bind Replay's owned-inventory bot equipment operations; never grant weapons."""
import hashlib
from pathlib import Path

NATIVES = (
    ("SVHBE_WeaponMap", "fn_7157638c48429719", 8,
     "be761ff12c28701bdf5e4a807e62c498ba82edcce037c961bc7d86b7bfae3685"),
    ("SVHBE_SwitchWeapon", "fn_db4f095b1f1d63c2", 264,
     "4de784fcb6f2ca9167c5cbab1c8fd6c94ffe74737b45468fe12ff7b82f1e8cea"),
    ("SVHBE_IsMelee", "fn_3d079d6faf147c43", 132,
     "1073629ed95e7c656468c35ec7f6c98504f6dd7c0d3764d62c00b1ac244bc69c"),
    ("SVHBE_IsRanged", "fn_295cb67a71ccce97", 83,
     "30bca501476c98f4148fbe3baf32593d0dbfb5db0019af64b87ba7389750d053"),
    ("SVHBE_WeaponClass", "fn_257a6622bdaec077", 178,
     "8d71c0fef297d9c88caec1d45ba570185b194747f8f97b847929314b133fac63"),
    ("SVHBE_WeaponName", "fn_6c33c5113c183b73", 13,
     "ec8d3e890bd9ac352369b623c1a26081f82a4c342a5528d6c29c2a0dabb2f489"),
)

HEADER = '''#pragma once
namespace HostScale { struct BotWeaponMap; struct BotWeapon; struct BotEquipmentPlayer; struct Entity; }
extern "C" {
HostScale::BotWeaponMap *SVHBE_WeaponMap();
bool SVHBE_SwitchWeapon(HostScale::Entity *, const HostScale::BotWeapon *);
bool SVHBE_IsMelee(const HostScale::BotEquipmentPlayer *, const HostScale::BotWeapon *);
bool SVHBE_IsRanged(const HostScale::BotEquipmentPlayer *, const HostScale::BotWeapon *);
int SVHBE_WeaponClass(const HostScale::BotWeapon *, bool);
const char *SVHBE_WeaponName(const HostScale::BotWeapon *, char *, unsigned);
}
'''


def configure(pe, by_id, funcs, snapshot):
    """Called before the owner's native-import loop, using its hash-bound image."""
    evidence = []
    for symbol, identity, size, expected in NATIVES:
        row = by_id[identity]
        code = pe.get_data(row["rva"], size)
        assert len(code) == size and hashlib.sha256(code).hexdigest() == expected, symbol
        funcs[symbol] = pe.OPTIONAL_HEADER.ImageBase + row["rva"]
        evidence.append(dict(symbol=symbol, identity=identity, original_rva=row["rva"],
                             original_bytes=size, original_sha256=expected))
    (Path(snapshot) / "src/SV_HostBotEquipmentBindings.h").write_text(HEADER, encoding="utf-8")
    return evidence
