"""Connection admission and request-deadline checks against a built server.

Covers the separate listener budgets (HTTP, TLS probe, lobby), the whole-
request HTTP header deadline, release of idle slots and, with --peer-address,
the per-address caps. Loopback peers are exempt from per-address caps, so
--peer-address binds the fixture server to a non-loopback local address and
connects to it from this host.
"""
import argparse
import hashlib
import json
import select
import socket
import subprocess
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--server', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--kdf', type=Path, default=ROOT / 'data/replay-traffic-kdf.bin')
parser.add_argument('--offset', type=int, default=16000)
parser.add_argument('--peer-address')
args = parser.parse_args()

host = args.peer_address or '127.0.0.1'
http_port, auth_port, lobby_port = 8085 + args.offset, 8443 + args.offset, 3075 + args.offset
# Listener totals and per-peer caps compiled into the server.
HTTP_TOTAL, HTTP_PEER, LOBBY_PEER = 64, 16, 24
root = args.output.parent / ('connection-budget-' + str(time.time_ns()))
data = root / 'data'
data.mkdir(parents=True)
if args.kdf.exists():
    (data / 'replay-traffic-kdf.bin').write_bytes(args.kdf.read_bytes())
if args.peer_address:
    base = 20000 + args.offset % 10000
    (data / 'network.json').write_text(json.dumps(dict(
        schema=1, bind_address=host, advertised_address=host, qos_port=base,
        relay_port=base + 1, bandwidth_port=base + 2, bandwidth_port_count=1, clients={})))
checks = []


def check(name, passed, **detail):
    checks.append(dict(name=name, passed=bool(passed), **detail))
    print(('PASS ' if passed else 'FAIL ') + name + ' ' + json.dumps(detail), flush=True)


def get(path):
    with urllib.request.urlopen('http://' + host + ':' + str(http_port) + path, timeout=5) as r:
        return r.status, r.read()


def connect(port):
    return socket.create_connection((host, port), timeout=3)


def closed_within(connection, seconds):
    """True once the server closes the connection; False if still open."""
    connection.settimeout(0.2)
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            if connection.recv(1) == b'':
                return True
        except socket.timeout:
            continue
        except OSError:
            return True
    return False


def open_count(connections, failed=()):
    """Connections the server has not closed (a closed socket reads as ready).

    A send that already failed consumes a reset on Windows, so such sockets
    no longer read as ready; the caller passes them as failed."""
    live = [c for c in connections if c not in failed]
    readable = select.select(live, [], [], 0)[0] if live else []
    return len(live) - len(readable)


class Trickle:
    """Holds HTTP connections the way a slow client does: an unfinished header
    plus one byte per second, so only the whole-request deadline ends them."""

    def __init__(self, connections):
        self.connections, self.stop, self.failed = connections, threading.Event(), set()
        for c in connections:
            c.sendall(b'GET /health HTTP/1.1\r\nHost: fixture\r\n')
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stop.wait(1.0):
            for c in self.connections:
                if c in self.failed:
                    continue
                try:
                    c.sendall(b'X')
                except OSError:
                    self.failed.add(c)

    def close(self):
        self.stop.set()
        self.thread.join()


log = (root / 'stdout.log').open('w')
server = subprocess.Popen([str(args.server), str(data), '--port-offset', str(args.offset)],
                          stdout=log, stderr=log)
held = []
try:
    for _ in range(150):
        try:
            get('/health')
            break
        except OSError:
            time.sleep(0.1)
    else:
        raise RuntimeError('Fixture server did not start')
    stats = json.loads(get('/stats.json')[1])
    check('stats-report-player-connection-limit', stats['connection_limit'] == 160,
          connection_limit=stats['connection_limit'])

    # A peer that trickles header bytes is closed by the whole-request deadline,
    # not kept alive by each recv's short socket timeout.
    slow = connect(http_port)
    slow.sendall(b'GET /health HTTP/1.1\r\nHost: fixture\r\n')
    started = time.monotonic()
    closed_after = None
    slow.settimeout(1.0)
    while time.monotonic() - started < 40:
        try:
            slow.sendall(b'X')
            if slow.recv(1) == b'':
                closed_after = time.monotonic() - started
                break
        except socket.timeout:
            continue
        except OSError:
            closed_after = time.monotonic() - started
            break
    slow.close()
    check('slow-header-closed-by-deadline',
          closed_after is not None and 12 <= closed_after <= 25,
          closed_after_seconds=closed_after and round(closed_after, 1))

    # Fill the HTTP budget with slow clients. Further HTTP connections are
    # refused at once (faster than any socket timeout), while the lobby and
    # TLS probe listeners keep their own budgets.
    capacity = HTTP_PEER if args.peer_address else HTTP_TOTAL
    opened_at = time.monotonic()
    held = [connect(http_port) for _ in range(capacity)]
    trickle = Trickle(held)
    time.sleep(1.5)
    check('http-budget-admits-capacity', open_count(held, trickle.failed) == capacity,
          capacity=capacity, open=open_count(held, trickle.failed))
    extra = connect(http_port)
    probe = time.monotonic()
    refused = closed_within(extra, 1.0)
    check('http-over-budget-refused-immediately', refused,
          capacity=capacity, seconds=round(time.monotonic() - probe, 2))
    extra.close()
    lobby = connect(lobby_port)
    auth = connect(auth_port)
    check('lobby-admitted-while-http-full', not closed_within(lobby, 2))
    check('auth-probe-admitted-while-http-full', not closed_within(auth, 0.5))
    check('http-budget-still-held', open_count(held, trickle.failed) == capacity,
          open=open_count(held, trickle.failed))
    lobby.close()
    auth.close()

    # Even while trickling, the slow clients are ended by the request deadline.
    while open_count(held, trickle.failed) and time.monotonic() - opened_at < 25:
        time.sleep(0.25)
    released_after = time.monotonic() - opened_at
    trickle.close()
    released = capacity - open_count(held, trickle.failed)
    for c in held:
        c.close()
    held = []
    check('slow-http-slots-released-at-deadline', released == capacity and released_after <= 22,
          released=released, held=capacity, seconds=round(released_after, 1))
    for _ in range(50):
        try:
            status = get('/health')[0]
            break
        except OSError:
            time.sleep(0.2)
    else:
        status = None
    check('http-serves-after-release', status == 200, status=status)

    if args.peer_address:
        held = [connect(lobby_port) for _ in range(LOBBY_PEER)]
        time.sleep(1.0)
        check('lobby-peer-cap-admits', open_count(held) == LOBBY_PEER, open=open_count(held))
        extra = connect(lobby_port)
        check('lobby-over-peer-cap-refused-immediately', closed_within(extra, 1.0), cap=LOBBY_PEER)
        extra.close()
        for c in held:
            c.close()
        held = []
finally:
    for c in held:
        c.close()
    server.terminate()
    try:
        server.wait(timeout=30)
    except subprocess.TimeoutExpired:
        server.kill()
    log.close()

server_log = (data / 'server.log').read_text(errors='replace')
check('refusals-logged', 'connection budget exhausted' in server_log)
result = dict(passed=all(c['passed'] for c in checks),
              server_sha256=hashlib.sha256(args.server.read_bytes()).hexdigest(),
              mode='peer ' + host if args.peer_address else 'loopback',
              checks=checks, game_runs_performed=False)
args.output.write_text(json.dumps(result, indent=2) + '\n')
print('PASS' if result['passed'] else 'FAIL', len(checks), 'connection checks')
raise SystemExit(0 if result['passed'] else 1)
