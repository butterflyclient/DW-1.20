"""Validate and publish Replay's native store configuration.

Stop the backend before publication. Category names refer to separate publisher
objects; this root document selects the native widget, not the purchase catalog.
"""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def validate(source):
    body = source.read_bytes()
    # The original Online_Store root download reserves one 2048-byte buffer.
    if not body or len(body) >= 2048 or b"\0" in body:
        raise ValueError("Store configuration must fit the native 2048-byte buffer")
    document = json.loads(body)
    if not isinstance(document, dict):
        raise ValueError("Store configuration must be an object")
    layout = document.get("layoutType")
    # ui/frontEnd/MPStoreMenu.lua accepts only these two top-level layouts.
    if type(layout) is not int or layout not in (3, 4):
        raise ValueError("Replay requires billboard list (3) or billboard grid (4)")
    categories = document.get("categories")
    # Online_Store holds ten records per root/category/layout group.
    if not isinstance(categories, list) or len(categories) > 10:
        raise ValueError("Replay supports at most ten category objects")
    if any(not isinstance(name, str) or len(name) >= 64 or
           not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or name in (".", "..")
           for name in categories):
        raise ValueError("Invalid category publisher object name")
    if len(set(categories)) != len(categories):
        raise ValueError("Duplicate category publisher object")
    return document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, nargs="?",
                        default=ROOT / "deploy/publisher/store_v2.json")
    parser.add_argument("--data", type=Path, default=ROOT / "data")
    parser.add_argument("--replace", action="store_true")
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    validate(args.source)
    if args.validate_only:
        print("Replay store configuration validated")
        return
    command = [sys.executable, str(ROOT / "tools/publish-publisher-object.py"),
               str(args.source), "--name", "store_v2.json", "--data", str(args.data)]
    if args.replace:
        command.append("--replace")
    subprocess.run(command, check=True)


if __name__ == "__main__":
    main()
