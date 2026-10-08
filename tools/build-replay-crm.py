"""Publish native Replay CRM content for MP, BR and CP, using shipped artwork."""

import argparse
import base64
import json
from pathlib import Path
import zlib


def build():
    # Read from the target game's MarketingCommsManager request and crmutils.lua.
    # The empty metadata object is required by its native JSON substitution pass.
    context = "cod-iw8-bnet-pc"
    messages = []
    for location, mode in ((1, "MULTIPLAYER"), (2, "MULTIPLAYER"),
                           (6, "WARZONE"), (7, "WARZONE"),
                           (11, "CO-OP"), (12, "CO-OP")):
        content = dict(title="REPLAY DW", content_short=mode + " WITH FRIENDS",
                       content_long="Add friends in Social, form a party and play together. "
                                    "Replay store bundles are available for zero COD points.",
                       image="mw_keyart_small", popup_image="mw_keyart", layout_type=0,
                       action="goto_ingame", action_location="social", action_title="SOCIAL")
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
    args.output.write_text(json.dumps(build(), indent=2) + "\n", encoding="utf-8")
    print("Built six target-mode CRM messages with native layout and shipped artwork")


if __name__ == "__main__":
    main()
