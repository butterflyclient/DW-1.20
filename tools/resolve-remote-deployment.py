"""Bind the existing shipping game to the hash-verified primary droplet."""
import hashlib
import json
from pathlib import Path
from remote_backend import ROOT, verify, read_log


def main():
    original = json.loads((ROOT / 'data/deployment.json').read_bytes())
    game = Path(original['executable'])
    if hashlib.sha256(game.read_bytes()).hexdigest() != original['sha256']:
        raise RuntimeError('Shipping game changed after native compilation')
    remote = verify()
    values = {}
    for line in game.with_suffix('.ini').read_text().splitlines():
        if '=' in line and not line.lstrip().startswith(('#', ';')):
            key, value = line.split('=', 1)
            values[key.strip()] = value.strip()
    if values.get('host') != remote['host']:
        raise RuntimeError('Game INI does not select the primary droplet')
    original['server_sha256'] = remote['sha256']
    original['remote_backend'] = remote
    original['remote_log_offset'] = read_log(0)['size']
    target = ROOT / 'data/current-remote-deployment.json'
    target.write_bytes((json.dumps(original, indent=2) + '\n').encode())
    print(target)


if __name__ == '__main__':
    main()
