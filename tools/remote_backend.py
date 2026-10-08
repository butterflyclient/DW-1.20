"""Pinned SSH and live process verification for the primary native Linux server."""
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.toolchains' / 'ssh'))
import paramiko


def connect():
    client = paramiko.SSHClient()
    client.load_host_keys(str(ROOT / 'data' / 'droplet-known-hosts'))
    client.connect('162.243.115.160', username='root',
                   key_filename=str(ROOT / '.toolchains' / 'deploy_ed25519'),
                   timeout=20, look_for_keys=False, allow_agent=False)
    return client


def live():
    command = '''python3 - <<'PY'
import hashlib,json,pathlib,subprocess
fields=subprocess.check_output(['systemctl','show','replay-dw','-p','MainPID','-p','ActiveState','-p','SubState']).decode()
state=dict(line.split('=',1) for line in fields.strip().splitlines())
pid=int(state['MainPID'])
binary=pathlib.Path('/opt/replay-dw/current/iw8-dw-server').resolve()
running=pathlib.Path('/proc/'+str(pid)+'/exe').resolve() if pid else None
print(json.dumps(dict(pid=pid,active=state['ActiveState'],substate=state['SubState'],
 executable=str(binary),process_executable=str(running),
 sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
 process_sha256=hashlib.sha256(pathlib.Path('/proc/'+str(pid)+'/exe').read_bytes()).hexdigest() if pid else None)))
PY'''
    with connect() as client:
        _, output, error = client.exec_command(command, timeout=20)
        payload = output.read()
        if output.channel.recv_exit_status():
            raise RuntimeError('Cannot verify remote backend process: ' + error.read().decode())
    return json.loads(payload)


def verify():
    receipt = json.loads((ROOT / 'data/droplet-deployment.json').read_bytes())
    if receipt['host'] != '162.243.115.160' or not receipt['compile_passed']:
        raise RuntimeError('Unexpected primary backend deployment')
    for reference in receipt['protocol_evidence']:
        path = (ROOT / reference['path']).resolve()
        if not path.is_relative_to(ROOT) or hashlib.sha256(path.read_bytes()).hexdigest() != reference['sha256']:
            raise RuntimeError('Remote protocol evidence changed')
        proof = json.loads(path.read_bytes())
        if not proof['passed'] or proof['server_sha256'] != receipt['sha256']:
            raise RuntimeError('Remote protocol evidence does not bind this binary')
    current = live()
    if current['active'] != 'active' or current['substate'] != 'running' or not current['pid'] or \
       current['sha256'] != receipt['sha256'] or current['process_sha256'] != receipt['sha256'] or \
       current['executable'] != current['process_executable']:
        raise RuntimeError('Remote process differs from the validated native backend')
    return dict(current, host=receipt['host'], verified_live_process=True, remote=True)


def read_log(offset):
    offset = int(offset)
    if offset < 0:
        raise ValueError('Invalid remote log offset')
    command = '''python3 - <<'PY'
import json,pathlib
path=pathlib.Path('/var/lib/replay-dw/server.log')
size=path.stat().st_size
offset=OFFSET
reset=size<offset
with path.open('rb') as f:
 f.seek(0 if reset else offset)
 data=f.read(1024*1024)
print(json.dumps(dict(size=size,reset=reset,text=data.decode(errors='replace'))))
PY'''.replace('OFFSET', str(offset))
    with connect() as client:
        _, output, error = client.exec_command(command, timeout=20)
        payload = output.read()
        if output.channel.recv_exit_status():
            raise RuntimeError('Remote log read failed: ' + error.read().decode())
    return json.loads(payload)


if __name__ == "__main__":
    # Used by controlled native-pair launches, retaining an exact live process
    # and log baseline without routing them through the shipping game's INI.
    print(json.dumps(dict(server=verify(), log_offset=read_log(0)["size"])))
