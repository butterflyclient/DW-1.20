"""Manage the primary systemd service without starting a second local realm."""
import argparse
import json
import urllib.request
from remote_backend import connect, live


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['start', 'stop', 'restart', 'status'])
    args = parser.parse_args()
    if args.action != 'status':
        with connect() as client:
            _, output, error = client.exec_command('systemctl ' + args.action + ' replay-dw')
            if output.channel.recv_exit_status():
                raise RuntimeError(error.read().decode())
    current = live()
    if current['active'] == 'active':
        current['health'] = json.load(urllib.request.urlopen(
            'https://162.243.115.160:8443/health', timeout=10))
    print(json.dumps(current, indent=2))


if __name__ == '__main__':
    main()
