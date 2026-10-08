"""Record cached native reauthentication/renewal separately from disconnect UI."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    folder = args.evidence.resolve()
    assert folder.is_relative_to(ROOT) and args.output.resolve().is_relative_to(ROOT)
    paths = []

    def load(name):
        path = folder / name
        paths.append(path)
        return json.loads(path.read_bytes())

    source = load("source.json")
    linux = load("linux-build.json")
    expected = linux["linux_server_sha256"]
    assert linux["linux_compile_passed"] and source["windows_compile_passed"]
    assert linux["source_archive_sha256"] == source["source_archive_sha256"]
    assert source["changed_cpp"] == ["src/platform.cpp"]
    for system, digest in (
        ("windows", source["windows_server_sha256"]),
        ("linux", expected),
    ):
        for suffix in (
            "persistence.json",
            "renewal.json",
            "continuity.json",
            "startup-verification.json",
        ):
            fixture = load(f"{system}-{suffix}")
            assert fixture["passed"] and fixture["server_sha256"] == digest
    old = load("native-menu-before-restart.json")
    recovered = load("native-after-server-restart.json")
    renewed = load("native-renewal-after-restart.json")
    clean = load("native-clean-menu.json")
    before_server = load("server-before-controlled-restart.json")
    after_server = load("server-after-controlled-restart.json")
    assert before_server["pid"] != after_server["pid"]
    assert before_server["sha256"] == after_server["sha256"] == expected
    assert old["pid"] == recovered["pid"] == renewed["pid"] != clean["pid"]
    for item in (old, recovered, renewed, clean):
        assert item["sha256"] == old["sha256"]
        assert item["server_process_verified"]["sha256"] == expected
        assert (
            item["platform_auth_state"] == 2
            and item["native_dw_hsm_connected_state_33"]
        )
    for item in (old, clean):
        assert len(item["native_fences_controller_0"]) == 27
        assert all(
            row["passing"] and not row["failed"]
            for row in item["native_fences_controller_0"]
        )
        assert item["native_game_connection"]["state"] == 9
        assert item["native_game_connection"]["frontend_scene"]
        assert item["native_relay_transport"]["state"] == 6
        assert item["native_relay_association"]["state"] == 3
        assert (
            item["native_relay_association"]["relay_id"]
            == item["server"]["relay"]["relay_id"]
        )
        assert item["server"]["relay"]["verified_associations"] == 1
    assert old["native_player_progression"] == clean["native_player_progression"]
    assert any(
        "DW_LOCAL_PLATFORM_RENEWED" in line for line in renewed["client_markers"]
    )
    lines = recovered["server_log_since_launch"]
    starts = [
        index
        for index, line in enumerate(lines)
        if " START IW8 Replay120 external server" in line
    ]
    assert len(starts) == 1
    following = lines[starts[0] :]
    assert any("AUTH signed native PC ticket issued" in line for line in following)
    assert any(" TASK service=" in line and "error=0" in line for line in following)
    assert not any(
        "Platform credential pair unknown or expired" in line for line in following
    )
    assert recovered["server_process_verified"]["pid"] == after_server["pid"]
    stores = [
        load(name)
        for name in (
            "native-session-store-before.json",
            "native-session-store-after-start.json",
            "native-session-store-after-reconnect.json",
            "native-session-store-after-renewal.json",
        )
    ]
    assert all(
        item["signature_verified"] and item["private_file_permissions_verified"]
        for item in stores
    )
    assert all(len(item["sessions"]) == 1 for item in stores)
    states = [item["sessions"][0] for item in stores]
    assert len({item["platform_session_token_sha256"] for item in states}) == 1
    assert states[0]["native_key_sha256"] != states[2]["native_key_sha256"]
    assert states[2]["native_key_sha256"] == states[3]["native_key_sha256"]
    assert states[2]["native_ticket_sha256"] == states[3]["native_ticket_sha256"]
    assert states[3]["expires"] > states[2]["expires"]
    for leaf in ("local-progression-before.sha256", "local-progression-after.sha256"):
        paths.append(folder / leaf)
    assert (folder / "local-progression-before.sha256").read_text().strip() == (
        folder / "local-progression-after.sha256"
    ).read_text().strip()
    paths += [
        folder / name
        for name in (
            "native-launch.json",
            "native-clean-launch.json",
            "native-menu-before-restart.jpg",
            "native-disconnect-latch.jpg",
            "native-clean-menu.jpg",
        )
    ]
    paths += [
        Path(__file__).resolve(),
        ROOT / "tools/observe-remote-session-store.py",
        ROOT / "tools/test-platform-session-persistence.py",
    ]
    proof = dict(
        schema=1,
        passed=True,
        generated_utc=datetime.now(timezone.utc).isoformat(),
        backend_sha256=expected,
        game_sha256=old["sha256"],
        backend_pid_before=before_server["pid"],
        backend_pid_after=after_server["pid"],
        native_game_pid_during_restart=old["pid"],
        clean_game_pid=clean["pid"],
        signed_private_session_store_verified=True,
        native_cached_platform_credentials_reauthenticated_after_server_restart=True,
        native_signed_renewal_after_server_restart_verified=True,
        native_reauthentication_rotated_ticket_and_key=True,
        native_renewal_preserved_current_ticket_and_key=True,
        native_clean_multiplayer_relaunch_verified=True,
        local_progression_file_and_restored_xp_rank_preserved=True,
        native_transparent_frontend_recovery_verified=False,
        observed_native_disconnect_error=65538,
        scope="Same game process reauthenticated with its persisted platform token and consumed signed renewal after a real Linux server restart. The game retained its native disconnect/quit popup. A separate clean relaunch verified Multiplayer, all 27 fences, relay establishment and the original locally saved XP/rank. Transparent frontend or in-match recovery is not credited.",
        full_backend_complete=False,
        evidence=[
            dict(
                path=p.resolve().relative_to(ROOT).as_posix(),
                sha256=hashlib.sha256(p.read_bytes()).hexdigest(),
            )
            for p in paths
        ],
    )
    args.output.write_text(json.dumps(proof, indent=2) + "\n", newline="\n")
    print(
        "PASS: native cached reauthentication and signed renewal after restart; clean Multiplayer/XP restored; transparent UI recovery remains open"
    )


if __name__ == "__main__":
    main()
