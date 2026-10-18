"""Verify exact Replay bytes supporting the conservative portal graph layout.

No native function calls or persistent graph pointers are introduced. Caller
copies SV_HostNavGraph.cpp/.h into its private build snapshot and invokes
configure before building; failure stops preparation.
"""
import hashlib
from pathlib import Path

EVIDENCE = (
    (0x1FC7250, 188, '3da0ae255a56d4dd0d2cca9eb541b2d3542107812b677c275f684b90fb0d2cb8', 'handle indirection, edge count and adjacency stride'),
    (0x1FC7FD0, 130, '8151d22b868155d4ca75dd0e880f00be3f1cac02921fa2fa16138844a4fa5469', 'local portal vertex and space affine transform'),
    (0x1FAA880, 152, 'c3e9e6baf621f20c521e4e1d95801f1e71c0722ff778040b845f47fd33ec9fec', 'affine point multiplication'),
    (0x1FC9660, 76, 'c08030d3699efa5e1f9b4e15d5a64a7fac4f4a186174904cbdc1d89b3c965d8e', 'obstacle and usage filtering'),
    (0x1FDE130, 101, '3d21b2b2d1efeea7ad930874dc35c76d478d87a34719cfb08978756b5bcfac06', 'dynamic child containers require separate traversal'),
    (0x1FDE030, 112, '700a1ab154582160fdf11e84c4addcc18fff8f3fdf1bbe5702db030e6a3b011a', 'empty child container uses original parent area'),
)


def configure(pe, by_id=None, funcs=None, snapshot=None):
    evidence=[]
    for rva, size, expected, purpose in EVIDENCE:
        actual=hashlib.sha256(pe.get_data(rva,size)).hexdigest()
        if actual != expected:
            raise ValueError(f'Native navigation layout evidence mismatch at {rva:#x}: {purpose}')
        evidence.append(dict(original_rva=rva,original_bytes=size,original_sha256=actual,purpose=purpose))
    return dict(schema=1, evidence=evidence, representation='bounded native portal CSR',
                retains_native_pointers=False, opaque_address_comparison_tokens=True, native_calls=False,
                requires_safe_navigation_phase=True, requires_exact_goal_handle=True,
                excludes=['nonempty dynamic child containers','special traversal links','obstacle-managed areas'],
                completeness='conservative subgraph; unsupported or unreachable goals use native fallback',
                consumer_requires=['matching capture-frame epoch','identical search specification',
                                   'matching live space identity and affine transform','native corridor validation'])
