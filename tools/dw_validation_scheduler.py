"""Bounded outer-gate scheduling with canonical prefix checkpoints.

The caller owns checker invocation, proof validation and final readiness. This
module never accepts a process exit code in place of a validated proof.
"""
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path


DEBUG = 'test-dw-debug-symbols.py'
HOST = 'test-host-scale.py'
SIGHT = 'test-host-sight-scheduling.py'
NETWORK = frozenset((
    'test-network-diagnostics.py',
    'test-executable-update-integration.py',
    'test-update-maps.py',
    'test-update-client-catchup.py',
    'test-map-publication.py',
))


class ValidationRunError(RuntimeError):
    """A gate failed; active workers have been reaped and no more were launched."""

    def __init__(self, checker, index):
        super().__init__('DW validation gate failed: ' + checker)
        self.checker = checker
        self.index = index


def run_checks(checks, run_one, checkpoint, *, completed=(), validate_completed=None,
               max_workers=4):
    """Return all validated proofs in input order, or raise after draining.

    ``checks`` contains the existing (checker, extra_arguments, output_name)
    tuples. ``run_one(index, check)`` must invoke and validate exactly one gate
    and return its proof. ``checkpoint(proofs)`` persists only a contiguous
    canonical prefix. Resume proofs require ``validate_completed``; the caller
    retains its image/source/checker/output hash checks there.

    Worker functions must synchronously reap their own subprocesses. A failure
    stops new launches; already active workers finish before this returns or
    raises. This function does not publish readiness or deploy anything.
    """
    checks = tuple(checks)
    if not isinstance(max_workers, int) or isinstance(max_workers, bool) or not 1 <= max_workers <= 4:
        raise ValueError('Validation worker count must be between one and four')
    names = [row[0] for row in checks]
    outputs = [str(Path(row[2]).resolve()).casefold() for row in checks]
    if len(names) != len(set(names)) or len(outputs) != len(set(outputs)):
        raise ValueError('Validation checkers and output paths must be unique')
    if DEBUG in names and names.index(DEBUG) != 0:
        raise ValueError('Debugger validation must be the first barrier')
    if SIGHT in names and (HOST not in names or names.index(HOST) >= names.index(SIGHT)):
        raise ValueError('Sight validation requires the preceding host gate')
    completed = tuple(completed)
    if len(completed) > len(checks):
        raise ValueError('Validation resume prefix has extra proofs')
    if completed and validate_completed is None:
        raise ValueError('Validation resume requires proof/hash validation')
    for index, proof in enumerate(completed):
        validate_completed(index, checks[index], proof)
    results = {index:proof for index, proof in enumerate(completed)}
    prefix = len(completed)
    if not checks or prefix == len(checks):
        return list(completed)

    def record(index, proof):
        nonlocal prefix
        results[index] = proof
        previous = prefix
        while prefix in results:
            prefix += 1
        if prefix != previous:
            checkpoint([results[index] for index in range(prefix)])

    # No worker may begin before the debug association/public-symbol gate.
    if DEBUG in names and not prefix:
        try:
            record(0, run_one(0, checks[0]))
        except BaseException as error:
            raise ValidationRunError(DEBUG, 0) from error
    pending = set(range(len(checks))) - results.keys()
    active = {}
    failure = None
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix='dw-validation') as pool:
        while pending or active:
            if failure is None:
                resources = {NETWORK for index in active.values() if names[index] in NETWORK}
                for index in sorted(pending):
                    if len(active) >= max_workers:
                        break
                    name = names[index]
                    if name == SIGHT and names.index(HOST) not in results:
                        continue
                    if name in NETWORK and NETWORK in resources:
                        continue
                    active[pool.submit(run_one, index, checks[index])] = index
                    pending.remove(index)
                    if name in NETWORK:
                        resources.add(NETWORK)
            if not active:
                if failure:
                    break
                raise RuntimeError('Validation dependency schedule made no progress')
            done, _ = wait(active, return_when=FIRST_COMPLETED)
            successes = []
            for future in done:
                index = active.pop(future)
                try:
                    successes.append((index, future.result()))
                except BaseException as error:
                    if failure is None:
                        failure = (index, error)
            # Once failure is observed, no late successes advance checkpoints.
            if failure is None:
                for index, proof in sorted(successes):
                    try:
                        record(index, proof)
                    except BaseException as error:
                        failure = (index, error)
                        break
    if failure:
        index, error = failure
        raise ValidationRunError(names[index], index) from error
    if prefix != len(checks):
        raise RuntimeError('Validation finished without its complete proof prefix')
    return [results[index] for index in range(len(checks))]
