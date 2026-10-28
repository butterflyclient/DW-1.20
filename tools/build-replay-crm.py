"""Publish native Replay CRM content for MP, BR and CP, using shipped artwork."""

import argparse
import base64
import json
from pathlib import Path
import zlib

# Location IDs from crmutils.lua: each mode's MOTD (the popup and first tile) and
# its message list (the next tile). Every message opens its own detail page.
# Action locations are CRM.LocationFunctions entries.
MESSAGES = (
    (1, "MULTIPLAYER", "Squad up and jump in",
     "Team up with friends or go solo across Multiplayer playlists. Earn XP, rank up "
     "and unlock new weapons, attachments and Operators as you play.",
     "social", "INVITE FRIENDS"),
    (2, "BATTLE PASS", "Earn tiers as you play",
     "Play matches to progress through the Battle Pass tiers and unlock weapon "
     "blueprints, Operator skins, calling cards and more.",
     "battlepass", "BATTLE PASS"),
    (6, "WARZONE", "Drop in with your squad",
     "Drop into Verdansk with your squad. Loot up, win your way back from the Gulag "
     "and be the last squad standing.",
     "social", "INVITE FRIENDS"),
    (7, "PLUNDER", "Cash is king",
     "Loot, earn and bank cash across Verdansk. The first team to reach the cash "
     "target wins.",
     "social", "SQUAD UP"),
    (11, "SPECIAL OPS", "Team up against the enemy",
     "Join up to three other players in co-op Special Ops. Work together, complete "
     "the objectives and get your squad out alive.",
     "social", "INVITE FRIENDS"),
    (12, "BATTLE PASS", "Earn tiers as you play",
     "Play matches to progress through the Battle Pass tiers and unlock weapon "
     "blueprints, Operator skins, calling cards and more.",
     "battlepass", "BATTLE PASS"),
)


def build():
    # Read from the target game's MarketingCommsManager request and crmutils.lua.
    # The empty metadata object is required by its native JSON substitution pass.
    context = "cod-iw8-bnet-pc"
    messages = []
    for location, title, short, long, action_location, action_title in MESSAGES:
        content = dict(title=title, content_short=short, content_long=long,
                       image="mw_keyart_small", popup_image="mw_keyart", layout_type=0,
                       action="goto_ingame", action_location=action_location,
                       action_title=action_title)
        raw = json.dumps(content, separators=(",", ":")).encode()
        content["checksum"] = str(zlib.crc32(raw))
        raw = json.dumps(content, separators=(",", ":")).encode() + b"\0"
        encode = lambda data: base64.b64encode(data).decode()
        messages.append(dict(id=5800104000 + location, assignment=1, language="en",
                             location=location, enabled=True, starts=0, expires=0,
                             content=encode(raw), metadata=encode(b"{}\0"),
                             payload="", signature=""))
    return dict(schema=1, title=5800, context=context, messages=messages)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(build(), indent=2) + "\n", encoding="utf-8", newline="\n")
    print("Built six player-facing CRM messages with native layout and shipped artwork")


if __name__ == "__main__":
    main()
