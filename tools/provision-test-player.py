"""Provision one unique private guest account while the backend is stopped."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("profile")
parser.add_argument("player_name")
args = parser.parse_args()
if not re.fullmatch(r"[a-z0-9-]{1,32}", args.profile):
    raise ValueError("Use 1..32 lowercase letters, numbers or hyphens for the profile")
if (not 1 <= len(args.player_name) <= 35 or args.player_name.strip() != args.player_name
        or any(ord(c) < 32 or ord(c) >= 127 or c in "#%" for c in args.player_name)):
    raise ValueError("Use 1..35 printable ASCII characters, without #, %, or edge spaces")
server = ROOT / "build/Release/iw8-dw-server.exe"
processes = subprocess.check_output(
    ["powershell", "-NoProfile", "-Command",
     "@(Get-CimInstance Win32_Process -Filter \"Name='iw8-dw-server.exe'\").Count"],
    text=True,
)
if int(processes.strip()):
    raise RuntimeError("Stop the DW backend before provisioning a guest")
config_path = ROOT / "data/network.json"
config = json.loads(config_path.read_text())
profile_path = ROOT / f"data/platform-profiles/{args.profile}.bin"
if profile_path.exists() or args.profile in config["clients"]:
    raise RuntimeError("This guest already exists; package it with package-remote-guest.py")
retained = ROOT / "data/retained-network-config"
retained.mkdir(exist_ok=True)
old = config_path.read_bytes()
(retained / (hashlib.sha256(old).hexdigest() + ".json")).write_bytes(old)
subprocess.run([str(server), str(ROOT / "data"), "--provision-profile",
                args.profile, args.player_name], check=True)
config["clients"][args.profile] = secrets.token_hex(32)
pending = config_path.with_suffix(".json.pending")
pending.write_text(json.dumps(config, indent=2) + "\n")
os.replace(pending, config_path)
print(f"Provisioned {args.profile} as {args.player_name}; no friendships added.")
