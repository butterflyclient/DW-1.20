"""Bind native relay completion/keepalives, with a separate expiry-crossing gate."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--observation", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--require-expiry-crossing", action="store_true")
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    before_path = evidence / "native-menu-fixed-observer.json"
    before = json.loads(before_path.read_bytes())
    current = json.loads(args.observation.read_bytes())
    admitted_path = evidence / "native-issued-admission.json"
    admitted = json.loads(admitted_path.read_bytes())
    events_path = evidence / "native-transport-events.json"
    events = json.loads(events_path.read_bytes())
    deployment_path = evidence / "deployment.json"
    deployment = json.loads(deployment_path.read_bytes())
    for item in (before, current):
        server = item["server_process_verified"]
        assert server["verified_live_process"]
        assert (
            server["sha256"] == deployment["sha256"]
            and server["pid"] == deployment["pid"]
        )
        assert (
            item["platform_auth_state"] == 2
            and item["native_dw_hsm_connected_state_33"]
        )
        assert len(item["native_fences_controller_0"]) == 27
        assert all(
            row["passing"] and not row["failed"]
            for row in item["native_fences_controller_0"]
        )
        assert item["native_relay_client_auth"]["state"] == 2
        assert item["native_relay_transport"]["state"] == 6
        assert item["native_relay_association"]["state"] == 3
        assert (
            item["native_relay_client_auth"]["native_wire_sha256"]
            == admitted["native_wire_sha256"]
        )
        assert item["native_relay_association"]["user"] == admitted["user"]
        relay = item["server"]["relay"]
        assert relay["enabled"] and not relay["failure"]
        assert relay["active_associations"] == relay["verified_associations"] == 1
        assert relay["rejected_packets"] == relay["suppressed_rejection_events"] == 0
        assert item["server_counter_changes_since_launch"]["auth_successes"] == 1
        assert item["server_counter_changes_since_launch"]["lobby_authenticated"] == 1
        assert item["server_counter_changes_since_launch"]["lobby_failures"] == 0
    assert before["pid"] == current["pid"] and before["sha256"] == current["sha256"]
    assert before["native_relay_association"] == current["native_relay_association"]
    assert before["native_player_progression"] == current["native_player_progression"]
    association = current["native_relay_association"]
    matching = [
        row
        for row in events
        if row["action"] == "established"
        and row["route"] == association["route"]
        and row["relay_id"] == association["relay_id"]
        and row["user"] == association["user"]
        and row["verification_sha256"] == association["verification_sha256"]
    ]
    assert len(matching) == 1 and matching[0]["expires"] == admitted["expires"]
    observed = datetime.fromisoformat(current["observed_utc"])
    elapsed = (
        observed - datetime.fromisoformat(before["observed_utc"])
    ).total_seconds()
    assert elapsed >= 60
    assert (
        current["server"]["relay"]["ping_replies"]
        > before["server"]["relay"]["ping_replies"]
    )
    crossed = observed.timestamp() > admitted["expires"] + 2
    renewed = any(
        "DW_LOCAL_PLATFORM_RENEWED" in line for line in current["client_markers"]
    )
    if args.require_expiry_crossing:
        assert (
            crossed and renewed
        ), "Original admission deadline and signed renewal must both be observed"
    assert current["native_game_connection"]["state"] == 9
    assert current["native_game_connection"]["frontend_scene"]
    paths = [
        before_path,
        args.observation,
        admitted_path,
        events_path,
        deployment_path,
        evidence / "native-launch.json",
        evidence / "native-multiplayer.jpg",
        ROOT / "validation/20261008-relay-connected-expiry-target.json",
    ]
    for system in ("windows", "linux"):
        paths.extend(
            evidence / f"{system}-{suffix}"
            for suffix in (
                "continuity.json",
                "renewal.json",
                "startup-verification.json",
            )
        )
    references = []
    for path in paths:
        resolved = path.resolve()
        assert resolved.is_relative_to(ROOT)
        references.append(
            dict(
                path=resolved.relative_to(ROOT).as_posix(),
                sha256=hashlib.sha256(resolved.read_bytes()).hexdigest(),
            )
        )
    proof = dict(
        schema=1,
        passed=True,
        generated_utc=datetime.now(timezone.utc).isoformat(),
        backend_sha256=deployment["sha256"],
        backend_pid=deployment["pid"],
        game_sha256=current["sha256"],
        game_pid=current["pid"],
        native_auth_and_multiplayer_frontend_verified=True,
        native_relay_callback_and_server_event_correlated=True,
        native_udp_keepalives_verified=True,
        stable_seconds=elapsed,
        original_admission_expires_utc=datetime.fromtimestamp(
            admitted["expires"], timezone.utc
        ).isoformat(),
        native_original_admission_expiry_crossing_verified=crossed and renewed,
        native_in_match_renewal_verified=False,
        native_two_network_renewal_verified=False,
        native_route_and_keys_preserved=True,
        native_fences_passing=27,
        native_reauth_not_required=True,
        main_identity_xp_rank_preserved=True,
        scope="Original SDK auth/association callbacks, exact issuer token and UDP event match, and advancing authenticated keepalives on the deployed backend. Expiry crossing is credited only after its own gate passes.",
        full_backend_complete=False,
        evidence=references,
    )
    output = args.output.resolve()
    assert output.is_relative_to(ROOT)
    output.write_text(json.dumps(proof, indent=2) + "\n")
    print(
        f"PASS: native relay stability {elapsed:.0f}s; original expiry crossing {crossed and renewed}"
    )


if __name__ == "__main__":
    main()
