"""Execute frozen bot movement objects, or explicitly overlay current sources."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--build', type=Path,
                        help='Verify and execute the linked executable for this frozen snapshot.')
    parser.add_argument('--current-source', action='store_true',
                        help='Developer check: overlay current integration sources and headers.')
    args = parser.parse_args()
    if args.build and args.current_source:
        parser.error('--build requires frozen snapshot mode; omit --current-source')
    spec = importlib.util.spec_from_file_location('gpu_movement_navigation', ROOT / 'tools/test-host-navigation.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    build_report = None
    verified_objects = {}
    if args.build:
        build_report = json.loads((args.build / 'build-report.json').read_bytes())
        assert Path(build_report['source_root']).resolve() == args.snapshot.resolve()
        assert build_report['unresolved_symbols'] == 0
        assert hashlib.sha256(Path(build_report['executable']).read_bytes()).hexdigest() == build_report['sha256']
        for name in module.SOURCES:
            rows = [row for row in build_report['cpp']
                    if row['source'].replace('\\', '/').endswith('src/' + name + '.cpp')]
            assert len(rows) == 1, ('Missing/duplicate linked movement dependency', name)
            row = rows[0]
            assert hashlib.sha256((args.snapshot / 'src' / (name + '.cpp')).read_bytes()).hexdigest() == row['source_sha256']
            assert hashlib.sha256(Path(row['object']).read_bytes()).hexdigest() == row['object_sha256']
            for dependency in row['dependencies']:
                assert hashlib.sha256(Path(dependency['path']).read_bytes()).hexdigest() == dependency['sha256']
            verified_objects[name] = row['object_sha256']
    checks = []
    with tempfile.TemporaryDirectory(prefix='gpu-movement-', dir=ROOT / 'data') as temporary:
        fixture = Path(temporary)
        for name in ('src', 'generated', 'tools'):
            (fixture / name).mkdir()
        header_folders = [args.snapshot / 'src']
        if args.current_source:
            header_folders.append(ROOT / 'integration/host-scale')
        for folder in header_folders:
            for path in folder.glob('*.h'):
                shutil.copy2(path, fixture / 'src' / path.name)
        for name in module.SOURCES:
            source_folder = ROOT / 'integration/host-scale' if args.current_source else args.snapshot / 'src'
            shutil.copy2(source_folder / (name + '.cpp'), fixture / 'src' / (name + '.cpp'))
        for name in ('function-catalog.json', 'host-scale-integration.json'):
            os.link(args.snapshot / 'generated' / name, fixture / 'generated' / name)
        shutil.copy2(args.snapshot / 'tools/coff.py', fixture / 'tools/coff.py')
        runner = module.Runner(fixture, args.build)
        bot, command = 0x5b000000, 0x5b060000
        for mode in (1, 2):
            vm = runner.machine(True, mode)
            vm.gas_required = vm.can_fire = True
            vm.gas_center = vm.gas_goal = (2000., 0., 0.)
            vm.loot_goal = (-2000., 0., 0.)
            result = module.mesh_bot(vm, 'normal', goal_type=5,
                native_goal=(-2000., 0., 0.), existing_path=True)
            assert next(e[1] for e in result['events'] if e[0] == 'path-request') == vm.gas_goal
            assert result['events'][-1] == ('steer-path', 127)
            checks.append(f'gas-precedes-critical-and-combat-mode{mode}')
            vm = runner.machine(True, mode)
            module.mesh_bot(vm, 'normal')
            module.map_mesh_bot(vm)
            vm.gpu_enabled = True
            vm.gpu_state = 1
            before = len(vm.events)
            vm.put(vm.symbols['SVHS_LevelTime'], 1016, '<i')
            vm.call('Bot_UpdateMove_OffPathGrid', bot, command)
            assert vm.events[before:] == [('follow-path',)]
            checks.append(f'pending-keeps-native-route-mode{mode}')
            vm.gpu_state = 2
            vm.gpu_waypoint = (320., 0., 0.)
            before = len(vm.events)
            vm.put(vm.symbols['SVHS_LevelTime'], 1032, '<i')
            vm.call('Bot_UpdateMove_OffPathGrid', bot, command)
            assert next(e[1] for e in vm.events[before:] if e[0] == 'path-request') == vm.gpu_waypoint
            checks.append(f'gpu-waypoint-requires-native-path-mode{mode}')
            vm.gpu_state = 2
            vm.put(bot + 516, 5, '<I')
            vm.put(bot + 472, struct.pack('<3f', -1500., 400., 0.))
            vm.put(vm.symbols['SVHS_LevelTime'], 1048, '<i')
            before = len(vm.events)
            vm.call('Bot_UpdateMove_OffPathGrid', bot, command)
            assert vm.gpu_state == 0 and not any(e[0] == 'path-request' for e in vm.events[before:])
            checks.append(f'changed-critical-cancels-stale-patrol-mode{mode}')
            # Submit through the actual compiled movement path so the pending
            # objective/circle identity is populated, then complete a necessary
            # outward first hop. Native path installation remains mandatory.
            vm = runner.machine(True, mode)
            vm.gas_required = vm.can_fire = True
            vm.gas_center = vm.gas_goal = (2000., 0., 0.)
            module.mesh_bot(vm, 'normal');module.map_mesh_bot(vm)
            vm.gpu_enabled = vm.gpu_queue_accept = True
            vm.path_exists = False
            # Let the rotating slot admission wrap after the initial native plan.
            for now in (1800, 1816):
                vm.put(vm.symbols['SVHS_LevelTime'], now, '<i')
                vm.call('Bot_UpdateMove_OffPathGrid', bot, command)
            assert vm.gpu_state == 1
            vm.gpu_state = 2;vm.gpu_waypoint = (-200., 200., 0.)
            vm.put(vm.symbols['SVHS_LevelTime'], 1832, '<i')
            before = len(vm.events)
            vm.call('Bot_UpdateMove_OffPathGrid', bot, command)
            assert next(e[1] for e in vm.events[before:] if e[0] == 'path-request') == vm.gpu_waypoint
            assert vm.events[-1] == ('steer-path', 127)
            checks.append(f'gas-graph-detour-reaches-native-validation-mode{mode}')
            vm.gpu_state = 2;vm.route_success = False
            vm.put(vm.symbols['SVHS_LevelTime'], 1848, '<i')
            before = len(vm.events)
            vm.call('Bot_UpdateMove_OffPathGrid', bot, command)
            assert any(e[0] == 'path-request' for e in vm.events[before:])
            assert not any(e[0] in ('follow-path', 'steer-path') for e in vm.events[before:])
            checks.append(f'gas-detour-native-rejection-never-steers-mode{mode}')
            queued_before = vm.gpu_queues
            vm.route_success = True
            before = len(vm.events)
            for now in (2000, 2016):
                vm.put(vm.symbols['SVHS_LevelTime'], now, '<i')
                vm.call('Bot_UpdateMove_OffPathGrid', bot, command)
            assert next(e[1] for e in vm.events[before:] if e[0] == 'path-request') == vm.gas_goal
            assert vm.gpu_queues == queued_before and vm.gpu_state == 0
            checks.append(f'native-hop-rejection-cools-gpu-and-routes-stable-goal-mode{mode}')
            vm.gpu_state = 2;vm.found = False
            vm.put(vm.symbols['SVHS_LevelTime'], 2048, '<i')
            before = len(vm.events)
            vm.call('Bot_UpdateMove_OffPathGrid', bot, command)
            assert not any(e[0] == 'path-request' for e in vm.events[before:])
            vm.found = True;vm.path_exists = False
            before = len(vm.events)
            for now in (2200, 2216):
                vm.put(vm.symbols['SVHS_LevelTime'], now, '<i')
                vm.call('Bot_UpdateMove_OffPathGrid', bot, command)
            assert next(e[1] for e in vm.events[before:] if e[0] == 'path-request') == vm.gas_goal
            assert vm.gpu_queues == queued_before
            checks.append(f'projection-rejection-cools-gpu-and-routes-stable-goal-mode{mode}')
            # Exhaust this frame's GPU commit budget without a native rejection.
            # An existing route survives; the next admitted attempt may queue.
            vm = runner.machine(True, mode)
            module.mesh_bot(vm, 'normal');module.map_mesh_bot(vm)
            vm.gpu_enabled = vm.gpu_queue_accept = True
            vm.gpu_waypoint = (320., 0., 0.)
            vm.put(vm.symbols['SVHS_LevelTime'], 1032, '<i')
            for _ in range(8):
                vm.gpu_state = 2
                vm.call('Bot_UpdateMove_OffPathGrid', bot, command)
            vm.gpu_state = 2
            before = len(vm.events)
            vm.call('Bot_UpdateMove_OffPathGrid', bot, command)
            assert not any(e[0] == 'path-request' for e in vm.events[before:])
            assert vm.events[-1] == ('follow-path',)
            vm.path_exists = False
            for now in (2000, 2016):
                vm.put(vm.symbols['SVHS_LevelTime'], now, '<i')
                vm.call('Bot_UpdateMove_OffPathGrid', bot, command)
            assert vm.gpu_state == 1 and vm.gpu_queues == 1
            checks.append(f'commit-budget-preserves-route-without-rejection-cooldown-mode{mode}')
            for failure in ('failed', 'unreachable'):
                vm = runner.machine(True, mode)
                actual = module.mesh_bot(vm, failure)
                expected = module.mesh_bot(runner.machine(False), failure)
                assert actual['movement'] == expected['movement']
                assert not any(e[0] in ('follow-path', 'steer-path') for e in actual['events'])
                assert getattr(vm, 'gpu_queues', 0) == 0
                checks.append(f'{failure}-preserves-native-command-mode{mode}')
        receipt = dict(passed=True, checks=checks, case_count=len(checks),
            source_mode='current-source' if args.current_source else 'frozen-snapshot',
            source_snapshot=str(args.snapshot.resolve()),
            linked_executable_sha256=build_report['sha256'] if build_report else None,
            verified_object_sha256=verified_objects,
            target_image_sha256=runner.proof['image_sha256'], native_script_goal_proof=runner.goal_type_proof,
            source_sha256={name: hashlib.sha256((fixture / 'src' / (name + '.cpp')).read_bytes()).hexdigest()
                           for name in module.SOURCES},
            modeled_boundaries=['GPU planner queue/completion', 'Authoritative script circle values',
                                'Native path projection/installation and steering'],
            production_movement_object_executed=True, live_game_tested=False)
        args.output.write_text(json.dumps(receipt, indent=2) + '\n')
    print('PASS', len(checks), 'compiled GPU/gas movement cases; no game launch')


if __name__ == '__main__':
    main()
