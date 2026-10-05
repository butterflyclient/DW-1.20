"""Publish a temporary bracket for native menu tests, with exact file restoration.

No match is scheduled by this tool and no engine/global memory is written.
The backend's ordinary owned registration handler creates enrollment.
"""

import argparse
import base64
import json
from pathlib import Path
import struct
import time

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("mode", choices=("prepare", "restore"))
parser.add_argument(
    "--observation", default="runtime-tournament-native-before-registration.json"
)
args = parser.parse_args()
receipt_path = root / "data/native-tournament-test-publication.json"
realm = root / "data/tournaments/5800"
paths = [realm / "catalog.json", realm / "enrollments.json"]

if args.mode == "restore":
    receipt = json.loads(receipt_path.read_bytes())
    for entry in receipt["files"]:
        path = Path(entry["path"])
        if path not in paths:
            raise RuntimeError(
                "Restoration manifest escaped the exact tournament realm"
            )
        if entry["existed"]:
            temporary = path.with_suffix(path.suffix + ".pending")
            temporary.write_bytes(base64.b64decode(entry["bytes"], validate=True))
            temporary.replace(path)
        else:
            path.unlink(missing_ok=True)
    receipt["restored"] = True
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
    print("Restored exact pre-test tournament publication/enrollments")
else:
    if receipt_path.exists() and not json.loads(receipt_path.read_bytes()).get(
        "restored"
    ):
        raise RuntimeError("Restore the prior native tournament publication first")
    observation_path = root / "data" / args.observation
    if observation_path.parent.resolve() != (root / "data").resolve():
        raise RuntimeError("Use an observation basename inside data")
    observation = json.loads(observation_path.read_bytes())
    if not observation["native_dw_hsm_connected_state_33"]:
        raise RuntimeError("Native signed-in connection is required")
    native = observation["native_tournament_request"]
    anchor, interval = native["schedule_anchor"], native["schedule_interval"]
    if not 1 <= interval <= 3600 or native["pending_task"]:
        raise RuntimeError("Unexpected native schedule or pending task")
    user = struct.unpack_from(
        "<Q", (root / "data/platform-profile.bin").read_bytes(), 8
    )[0]
    rows = []
    for step in range(8):
        tournament = anchor + (native["schedule_count"] + step) * interval
        teams = [{"teamID": index, "playerIDs": []} for index in range(8)]
        teams[0]["playerIDs"] = [user]
        rows.append(
            {
                "id": tournament,
                "name": str(tournament),
                "data_center": "local",
                "expires": int(time.time()) + 3600,
                "registration_open": True,
                "start_search_offset_seconds": 600.25,
                "state": {
                    "tournamentID": tournament,
                    "tournamentStatus": "FORMING",
                    "tournamentDefinition": {
                        "teamSize": 2,
                        "numTeams": 8,
                        "numPlayers": 16,
                    },
                    "players": [{"playerID": user}],
                    "teams": teams,
                    "rounds": [
                        {
                            "roundID": index,
                            "matches": [
                                {
                                    "teamIDs": (
                                        [2 * match, 2 * match + 1] if index == 0 else []
                                    ),
                                    "readyPlayerIDs": [],
                                    "lobbyID": 0,
                                    "expired": False,
                                    "winningTeamID": -1,
                                }
                                for match in range(8 >> (index + 1))
                            ],
                        }
                        for index in range(3)
                    ],
                },
            }
        )
    realm.mkdir(parents=True, exist_ok=True)
    receipt = {
        "schema": 1,
        "restored": False,
        "owner": user,
        "server_sha256": observation["server_process_verified"]["sha256"],
        "game_sha256": observation["sha256"],
        "files": [
            {
                "path": str(path),
                "existed": path.exists(),
                "bytes": (
                    base64.b64encode(path.read_bytes()).decode()
                    if path.exists()
                    else None
                ),
            }
            for path in paths
        ],
        "published_ids": [row["id"] for row in rows],
        "expected_offset": 600,
    }
    # Record restoration bytes durably before replacing any player publication.
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
    temporary = paths[0].with_suffix(".json.pending")
    temporary.write_text(json.dumps({"schema": 1, "title": 5800, "tournaments": rows}))
    temporary.replace(paths[0])
    print("Published bounded native-menu test brackets with restoration receipt")
