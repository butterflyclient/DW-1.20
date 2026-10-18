"""Exercise validation barriers, resource ownership, checkpoints and failure drain."""
import argparse
import hashlib
import json
from pathlib import Path
import threading
import time

from dw_validation_scheduler import DEBUG, HOST, SIGHT, NETWORK, ValidationRunError, run_checks

ROOT = Path(__file__).resolve().parents[1]


def gate(name):
    return name, [], name + '.json'


def rejected(action):
    try:
        action()
    except (ValueError, ValidationRunError):
        return
    raise AssertionError('Invalid schedule or failed gate was accepted')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'validation/dw-validation-scheduler.json')
    args = parser.parse_args()
    cases = []
    names = [DEBUG, HOST, SIGHT, *sorted(NETWORK), 'independent-a', 'independent-b', 'independent-c']
    checks = list(map(gate, names))
    lock, debug_done, host_done = threading.Lock(), threading.Event(), threading.Event()
    state = dict(active=0, peak=0, network=0, network_peak=0)
    checkpoints, ended = [], set()

    def run(index, check):
        name = check[0]
        if name != DEBUG:
            assert debug_done.is_set(), 'Work crossed debug barrier'
        if name == SIGHT:
            assert host_done.is_set(), 'Sight started before host proof'
        with lock:
            state['active'] += 1
            state['peak'] = max(state['peak'], state['active'])
            if name in NETWORK:
                state['network'] += 1
                state['network_peak'] = max(state['network_peak'], state['network'])
        time.sleep(0.015 if name == HOST else 0.005)
        with lock:
            state['active'] -= 1
            if name in NETWORK:
                state['network'] -= 1
            ended.add(name)
        if name == DEBUG:
            debug_done.set()
        if name == HOST:
            host_done.set()
        return dict(checker=name, passed=True)

    def checkpoint(proofs):
        assert [row['checker'] for row in proofs] == names[:len(proofs)]
        assert all(row['checker'] in ended for row in proofs)
        checkpoints.append(len(proofs))

    proofs = run_checks(checks, run, checkpoint)
    assert [row['checker'] for row in proofs] == names
    assert state['peak'] == 4 and state['network_peak'] == 1
    assert checkpoints[-1] == len(checks) and checkpoints == sorted(set(checkpoints))
    cases.append('debug barrier, host/sight dependency, max four workers, single network owner, ordered checkpoints')

    started, finished, checkpoints = [], [], []
    first_failed, peer_started = threading.Event(), threading.Event()
    fail_checks = list(map(gate, ['failure', 'active-peer', 'must-not-start']))
    def fail(index, check):
        started.append(check[0])
        if index == 0:
            assert peer_started.wait(2)
            first_failed.set()
            raise RuntimeError('intentional child failure')
        assert index == 1, 'Failure allowed another launch'
        peer_started.set()
        assert first_failed.wait(2)
        time.sleep(0.03)
        finished.append(check[0])
        return dict(checker=check[0])
    rejected(lambda: run_checks(fail_checks, fail, checkpoints.append, max_workers=2))
    assert started == ['failure', 'active-peer'] and finished == ['active-peer']
    assert not checkpoints
    cases.append('failure stops new launches, drains active peer, no complete checkpoint/readiness result')

    calls, validated, resumed_checkpoints = [], [], []
    resume = [dict(checker='a', passed=True)]
    resume_checks = list(map(gate, ['a', 'b', 'c']))
    def validate(index, check, proof):
        assert index == 0 and check[0] == proof['checker'] and proof['passed']
        validated.append(index)
    result = run_checks(resume_checks,
        lambda index,check:(calls.append(index) or dict(checker=check[0], passed=True)),
        resumed_checkpoints.append, completed=resume, validate_completed=validate)
    assert validated == [0] and calls == [1,2] and len(result) == 3
    rejected(lambda: run_checks(resume_checks, None, None, completed=resume))
    def corrupt(*unused):
        raise ValueError('Output/checker/image hash mismatch')
    rejected(lambda: run_checks(resume_checks, lambda *unused: calls.append('BAD'), None,
        completed=resume, validate_completed=corrupt))
    assert 'BAD' not in calls
    cases.append('resume validates prefix before work; missing or failed hash validator rejects')

    for invalid in (0, 5, True):
        rejected(lambda: run_checks([], None, None, max_workers=invalid))
    rejected(lambda: run_checks([gate('a'), gate('a')], None, None))
    rejected(lambda: run_checks([gate('a'), ('b', [], 'a.json')], None, None))
    rejected(lambda: run_checks([gate('a'), gate(DEBUG)], None, None))
    rejected(lambda: run_checks([gate(SIGHT)], None, None))
    cases.append('invalid worker limits, duplicate checkers/outputs and invalid barriers reject before work')
    assert run_checks([], None, None) == []
    cases.append('empty schedule completes without invoking callbacks')

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(dict(passed=True, cases=cases,
        helper_sha256=hashlib.sha256((ROOT / 'tools/dw_validation_scheduler.py').read_bytes()).hexdigest(),
        process_execution=False, game_execution=False), indent=2)+'\n')
    print('PASS', len(cases), 'scheduler contracts', args.output)


if __name__ == '__main__':
    main()
