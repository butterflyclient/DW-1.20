"""Public dashboard contract checks against an isolated or deployed backend."""

import argparse, hashlib, json, urllib.request, urllib.error
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("--url", required=True)
p.add_argument("--output", type=Path, required=True)
p.add_argument("--windows-fixture", action="store_true")
a = p.parse_args()
checks = []
dashboard_hashes = []
for route in ("/", "/stats"):
    with urllib.request.urlopen(a.url + route, timeout=10) as r:
        html = r.read().decode()
        dashboard_hashes.append(hashlib.sha256(html.encode()).hexdigest())
        assert (
            r.status == 200 and r.headers["Content-Type"] == "text/html; charset=utf-8"
        )
        assert "frame-ancestors" in r.headers["Content-Security-Policy"]
        assert "Server overview" in html and "fetch('/stats.json'" in html
        assert "Server resources" in html and "Droplet resources" not in html
        assert "Published parties" in html and "Matches &amp; lobbies" in html
        assert "setTimeout(refresh,3000)" in html
        assert "requestStart" in html and "X-Replay-Operator" in html
        assert "operator access key" in html and "sessionStorage" not in html
        assert "Number of bots to add" in html and "match.occupied_slots" in html
    checks.append(route + " public HTML, browser policy, no controls")
with urllib.request.urlopen(a.url + "/stats.json", timeout=10) as r:
    stats = json.load(r)
    assert r.headers["Cache-Control"] == "no-store"
expected = set(
    "uptime_seconds online_players activity transport_connections connection_limit logins auth_successes lobby_authentications tasks lobby_frames lobby_failures qos_enabled qos_probes nat_introductions relay_enabled relay_failure relay_associations relay_verified relay_packets relay_pings relay_rejected cpu_seconds resident_bytes host_memory_bytes host_memory_available_bytes load_1m disk_total_bytes disk_available_bytes".split()
)
assert set(stats) == expected
assert (
    stats["uptime_seconds"] > 0
    and 0 <= stats["online_players"] <= stats["connection_limit"]
)
if a.windows_fixture:
    assert all(stats[key] is None for key in ("cpu_seconds", "resident_bytes", "host_memory_bytes",
                                             "host_memory_available_bytes", "load_1m"))
else:
    assert stats["resident_bytes"] > 0 and stats["cpu_seconds"] >= 0
    assert stats["host_memory_bytes"] > 0
assert stats["disk_total_bytes"] >= stats["disk_available_bytes"] > 0
checks.append("Explicit public JSON fields and real Linux resource readings")
activity = stats["activity"]
assert set(activity) == {"available", "players", "parties", "matches"}
assert stats["online_players"] == len(activity["players"])
for player in activity["players"]:
    assert set(player) == {"name", "party", "match", "host", "state"}
for party in activity["parties"]:
    assert set(party) == {"label", "leader", "members", "match", "state"}
for match in activity["matches"]:
    assert set(match) == {
        "label",
        "state",
        "host",
        "capacity",
        "maps",
        "modes",
        "members",
        "teams",
        "start_token",
        "can_start",
        "can_fill_bots",
        "start_requested",
        "bots_requested",
        "bot_count",
        "occupied_slots",
    }
    assert isinstance(match["can_start"], bool) and isinstance(match["can_fill_bots"], bool)
    for player in match["members"]:
        assert set(player) == {"name", "party", "match", "host", "state"}
    for team in match["teams"]:
        assert set(team) == {"label", "members"}
        for player in team["members"]:
            assert set(player) == {"name", "party", "match", "host", "state"}
checks.append("Public player/party/match schemas contain only display fields")
for route in ("/", "/stats", "/stats.json"):
    for method in ("POST", "PUT", "DELETE", "PATCH"):
        try:
            urllib.request.urlopen(
                urllib.request.Request(a.url + route, method=method), timeout=10
            )
        except urllib.error.HTTPError as e:
            assert (
                e.code == 405
                and e.headers["Allow"] == "GET"
                and json.load(e)["error"] == "read_only"
            )
        else:
            raise AssertionError("Dashboard accepted write method")
checks.append("All dashboard paths reject POST, PUT, DELETE and PATCH")
with urllib.request.urlopen(a.url + "/health", timeout=10) as r:
    assert json.load(r)["server"] == "iw8-dw"
checks.append("Existing health route retained")
assert len(set(dashboard_hashes)) == 1
a.output.write_text(
    json.dumps(dict(passed=True, checks=checks, stats=stats,
                    dashboard_sha256=dashboard_hashes[0]), indent=2) + "\n"
)
print("PASS:", len(checks), "public dashboard contract groups")
