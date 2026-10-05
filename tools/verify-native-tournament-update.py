"""Send a bounded test bracket to a registered native Replay receiver.

The game must register through its own UI first. This fixture explicitly seeds
accepted recipient membership, because native join assignment is a separate
unfinished backend gate. It does not schedule a lobby or start a map. Restore
the publication with prepare-native-tournament-test.py after collecting proof.
"""

import argparse
import hashlib
import json
import struct
from pathlib import Path

from native_wire_client import NativeClient, u64


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--playing",
        action="store_true",
        help="Advance the prior receiver fixture to PLAYING, with no assigned lobby",
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    receipt = json.loads(
        (root / "data/native-tournament-test-publication.json").read_bytes()
    )
    server = json.loads((root / "data/server-process.json").read_bytes())
    game = json.loads((root / "data/current-runtime-launch.json").read_bytes())
    if (
        receipt["restored"]
        or receipt["server_sha256"] != server["sha256"]
        or receipt["game_sha256"] != game["sha256"]
    ):
        raise RuntimeError("Require the current temporary native test publication")
    realm = root / "data/tournaments/5800"
    catalog_path = realm / "catalog.json"
    enrollment_path = realm / "enrollments.json"
    catalog = json.loads(catalog_path.read_bytes())
    enrollments = json.loads(enrollment_path.read_bytes())
    owner = receipt["owner"]
    entry = enrollments["players"][str(owner)]
    tournament = entry["id"]
    if tournament not in receipt["published_ids"] or entry["accepted"] != args.playing:
        raise RuntimeError(
            "Require actual native UI registration, not seeded registration"
        )
    row = next(row for row in catalog["tournaments"] if row["id"] == tournament)
    if any(match["lobbyID"] for r in row["state"]["rounds"] for match in r["matches"]):
        raise RuntimeError("The receiver check must not schedule a match")

    def atomic_write(path, value):
        pending = path.with_suffix(path.suffix + ".pending")
        pending.write_text(json.dumps(value), encoding="utf-8")
        pending.replace(path)

    with NativeClient(root, profile="native-social") as peer:
        if peer.user == owner:
            raise RuntimeError(
                "Use a separate peer; do not supersede the game's identity"
            )
        if args.playing:
            previous = json.loads(
                (root / "data/native-tournament-update-emission.json").read_bytes()
            )
            if (
                previous["game_pid"] != game["pid"]
                or previous["tournament_id"] != tournament
            ):
                raise RuntimeError(
                    "Require the first update from this native receiver session"
                )
            row["state"]["tournamentStatus"] = "PLAYING"
            assert peer.task(145, 22, b"", structured=False) == b""
            enrollments["players"].pop(str(peer.user), None)
        else:
            row["state"]["players"].append({"playerID": peer.user})
        row["state"]["teams"][1]["playerIDs"] = [peer.user]
        atomic_write(catalog_path, catalog)
        entry["accepted"] = True
        atomic_write(enrollment_path, enrollments)
        registration = json.dumps(
            {"data_center": row["data_center"], "tournament_name": row["name"]}
        )
        result = peer.task(
            145, 29, b"\x10" + registration.encode() + b"\0", structured=False
        )
        assert json.loads(result[1:-1])["start_search_offset_seconds"] == 600.25
        assert (
            peer.task(145, 23, u64(tournament) + b"\x01\x01", structured=False) == b""
        )
        assert (
            peer.task(145, 19, u64(tournament) + u64(0xFFFFFFFF), structured=False)
            == b""
        )
        kind, packet = peer.receive()
        assert kind == 2 and packet[:6] == b"\x08\xda\x07\0\0\x10"
        assert packet[-1:] == b"\0"
        bracket = json.loads(packet[6:-1])
        assert bracket["tournamentID"] == tournament
        assert bracket["rounds"][0]["matches"][0]["readyPlayerIDs"] == [peer.user]
    proof = {
        "schema": 1,
        "server_sha256": server["sha256"],
        "game_sha256": game["sha256"],
        "game_pid": game["pid"],
        "tournament_id": tournament,
        "event_id": struct.unpack_from("<I", packet, 1)[0],
        "tournament_status": row["state"]["tournamentStatus"],
        "peer_received_typed_bracket": True,
        "bracket_sha256": hashlib.sha256(packet[6:-1]).hexdigest(),
        "expected_native_counts": {
            "participant_count": 16 if args.playing else 0,
            "team_size": 2 if args.playing else 0,
            "team_count": 8 if args.playing else 0,
            "round_count": 3 if args.playing else 0,
            "local_team": 0 if args.playing else -1,
        },
        "recipient_acceptance_seeded": True,
        "native_join_assignment_verified": False,
        "map_started": False,
        "scope": "Receiver/parser check after actual native registration; accepted enrollment explicitly seeded",
    }
    (root / "data/native-tournament-update-emission.json").write_text(
        json.dumps(proof, indent=2) + "\n"
    )
    print(json.dumps(proof, indent=2))


if __name__ == "__main__":
    main()
