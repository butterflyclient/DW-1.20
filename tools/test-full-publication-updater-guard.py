"""Mutation checks for the EXE publication guard; no upload or game execution."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proof', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('publication_guard', ROOT / 'tools/publish-full-executable.py')
    publisher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(publisher)
    original = args.proof.read_bytes()
    proof = json.loads(original)
    target = proof['game_sha256']
    checks = []
    with tempfile.TemporaryDirectory(prefix='updater-publication-guard-', dir=ROOT / 'data') as temporary:
        path = Path(temporary) / 'proof.json'

        def accepted(document, label):
            raw = (json.dumps(document, indent=2) + '\n').encode()
            path.write_bytes(raw)
            assert publisher.verify_updater(path, target) == raw
            checks.append(label)

        def rejected(document, label):
            path.write_text(json.dumps(document) + '\n')
            try:
                publisher.verify_updater(path, target)
            except (ValueError, KeyError, TypeError):
                checks.append(label)
            else:
                raise AssertionError('Publication guard accepted mutation: ' + label)

        accepted(proof, 'Fresh compiled asset repair proof accepted')
        legacy = copy.deepcopy(proof)
        legacy.pop('worker_checks')
        for case in legacy['initial_update_checks']:
            if case['bypass_update_restart']:
                case.update(worker_starts=0, final_state=50, bypass_logged=True)
        for case in legacy['checks']:
            case.pop('asset_repair_restart_under_bypass')
            case.pop('asset_failure_fence')
            case['native_data_restart_preserved'] = case['bypass_update_restart']
        accepted(legacy, 'Legacy bypass proof retains its original contract')
        old = copy.deepcopy(legacy)
        old['initial_update_checks'] = [case for case in old['initial_update_checks'] if not case.pop('bypass_update_restart')]
        for case in old['initial_update_checks']:
            case.pop('bypass_logged')
        old['checks'] = [case for case in old['checks'] if not case.pop('bypass_update_restart') and case['state'] != 50]
        accepted(old, 'Legacy proof without bypass remains accepted')
        for field in ('passed', 'game_sha256', 'embedded_helper_sha256'):
            changed = copy.deepcopy(proof)
            changed[field] = False if field == 'passed' else '0' * 64 if field == 'game_sha256' else ''
            rejected(changed, 'Reject invalid ' + field)
        for group in ('initial_update_checks', 'worker_checks', 'checks'):
            for index, case in enumerate(proof[group]):
                changed = copy.deepcopy(proof)
                del changed[group][index]
                rejected(changed, f'Reject missing {group} case {index}')
                changed = copy.deepcopy(proof)
                changed[group].append(copy.deepcopy(case))
                rejected(changed, f'Reject duplicate {group} case {index}')
        for index, case in enumerate(proof['initial_update_checks']):
            for field in ('compiled_initial_state', 'frames', 'worker_starts', 'final_state'):
                changed = copy.deepcopy(proof)
                changed['initial_update_checks'][index][field] += 1
                rejected(changed, f'Reject startup {index} changed {field}')
            changed = copy.deepcopy(proof)
            changed['initial_update_checks'][index]['bypass_logged'] = True
            rejected(changed, f'Reject premature bypass log {index}')
            changed = copy.deepcopy(proof)
            changed['initial_update_checks'][index]['worker_callback'] = None if case['enabled'] else 1
            rejected(changed, f'Reject invalid worker callback {index}')
        for index, case in enumerate(proof['worker_checks']):
            changed = copy.deepcopy(proof)
            changed['worker_checks'][index]['state'] = 99
            rejected(changed, f'Reject worker exit routing {index}')
            for call in range(len(case['calls'])):
                changed = copy.deepcopy(proof)
                del changed['worker_checks'][index]['calls'][call]
                rejected(changed, f'Reject missing worker boundary {index}/{call}')
        for index, case in enumerate(proof['checks']):
            for field in ('native_prerequisite_passes', 'restart_route_correct',
                          'native_data_restart_preserved', 'asset_repair_restart_under_bypass',
                          'asset_failure_fence'):
                changed = copy.deepcopy(proof)
                changed['checks'][index][field] = not case[field]
                rejected(changed, f'Reject fence {index} changed {field}')
            changed = copy.deepcopy(proof)
            changed['checks'][index]['getter_cases'] = 9
            rejected(changed, f'Reject incomplete getter matrix {index}')
        for field in ('worker_checks', 'initial_update_checks', 'checks'):
            changed = copy.deepcopy(proof)
            changed.pop(field)
            rejected(changed, 'Reject removed ' + field)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(dict(passed=True, cases=len(checks), checks=checks,
        proof_sha256=hashlib.sha256(original).hexdigest(), game_sha256=target,
        publisher_sha256=hashlib.sha256((ROOT / 'tools/publish-full-executable.py').read_bytes()).hexdigest(),
        uploaded=False, game_run=False, production_modified=False), indent=2) + '\n')
    print(f'PASS {len(checks)} updater publication guard cases; no upload or game')


if __name__ == '__main__':
    main()
