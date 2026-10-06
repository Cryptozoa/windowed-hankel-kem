#!/usr/bin/env python3
"""Independent generated-input checks and separate old/candidate raw-kernel timing."""
import argparse
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import time

import numpy as np

HERE = Path(__file__).resolve().parent
DEFAULT_OLD = HERE.parent / 'before' / 'libhankel_kem_neon.dylib'
U16 = ctypes.POINTER(ctypes.c_uint16)
S16 = ctypes.POINTER(ctypes.c_int16)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path):
    lib = ctypes.CDLL(str(Path(path).resolve()))
    lib.hankel_neon_forward_mul.argtypes = [U16, S16, S16, U16, ctypes.c_int, ctypes.c_int]
    lib.hankel_neon_forward_mul.restype = None
    lib.hankel_neon_window_project.argtypes = [S16, U16, U16, ctypes.c_int, ctypes.c_int]
    lib.hankel_neon_window_project.restype = None
    return lib


def uniform(count):
    return (np.frombuffer(os.urandom(count * 2), dtype='<u2') & 4095).astype(np.uint16)


def small(count):
    raw = np.frombuffer(os.urandom(count), dtype=np.uint8).astype(np.int16)
    return ((raw & 1) + ((raw >> 1) & 1) - ((raw >> 2) & 1) - ((raw >> 3) & 1)).astype(np.int16)


def forward(lib, a, x, e, n, m):
    out = np.empty(m, dtype=np.uint16)
    lib.hankel_neon_forward_mul(a.ctypes.data_as(U16), x.ctypes.data_as(S16),
        None if e is None else e.ctypes.data_as(S16), out.ctypes.data_as(U16), n, m)
    return out


def project(lib, x, y, n, w):
    out = np.empty(w, dtype=np.uint16)
    lib.hankel_neon_window_project(x.ctypes.data_as(S16), y.ctypes.data_as(U16), out.ctypes.data_as(U16), n, w)
    return out


def metadata(args):
    return {'old_library': str(args.old_library.resolve()), 'candidate_library': str(args.candidate_library.resolve()),
        'sha256': {'old_library': digest(args.old_library), 'candidate_library': digest(args.candidate_library),
                   'candidate_source': digest(HERE / 'hankel_kem_neon.c'),
                   'candidate_header': digest(HERE / 'hankel_kem_neon.h'),
                   'checker': digest(__file__)},
        'machine': platform.machine(), 'platform': platform.platform(),
        'scope': 'Local exact generated-input correctness / kernel measurements only; no cryptographic security claim.'}


def verify(args, old, candidate):
    candidate.hankel_neon_supports_tails.argtypes = []
    candidate.hankel_neon_supports_tails.restype = ctypes.c_int
    marker = candidate.hankel_neon_supports_tails()
    rows = []
    for n in [1, 7, 8, 9, 17, 31, 32, 33, 640]:
        w = 128 if n == 640 else 7
        m = n + w
        for trial in range(5):
            a, x, e, y = uniform(m+n-1), small(n), small(m), uniform(n+w)
            if trial == 3:
                a[:] = 4095; x[:] = 2; e[:] = -2; y[:] = 4095
            elif trial == 4:
                x[:] = np.where(np.arange(n) % 2, -2, 2); e[:] = 2
            ai, xi, yi = a.astype(np.int64), x.astype(np.int64), y.astype(np.int64)
            expected = np.array([np.dot(ai[i:i+n], xi) & 4095 for i in range(m)], dtype=np.uint16)
            expected_fused = ((expected.astype(np.int64)+e) & 4095).astype(np.uint16)
            expected_project = np.array([np.dot(xi, yi[i:i+n]) & 4095 for i in range(w)], dtype=np.uint16)
            got, got_fused = forward(candidate,a,x,None,n,m), forward(candidate,a,x,e,n,m)
            got_project = project(candidate,x,y,n,w)
            # The historical NEON loop lacks tails: scratch zero-padding prevents
            # any historical overread and contributes exactly zero extra terms.
            padded_n = (n+7)//8*8
            old_x = np.zeros(padded_n,dtype=np.int16); old_x[:n] = x
            old_a = np.zeros(m+padded_n-1,dtype=np.uint16); old_a[:len(a)] = a
            old_y = np.zeros(padded_n+w,dtype=np.uint16); old_y[:len(y)] = y
            legacy, legacy_fused = forward(old,old_a,old_x,None,n,m), forward(old,old_a,old_x,e,n,m)
            legacy_project = project(old,old_x,old_y,n,w)
            checks = {'candidate_forward_exact': bool(np.array_equal(got,expected)),
                'candidate_fused_error_exact': bool(np.array_equal(got_fused,expected_fused)),
                'candidate_projection_exact': bool(np.array_equal(got_project,expected_project)),
                'candidate_matches_legacy_forward': bool(np.array_equal(got,legacy)),
                'candidate_matches_legacy_fused': bool(np.array_equal(got_fused,legacy_fused)),
                'candidate_matches_legacy_projection': bool(np.array_equal(got_project,legacy_project))}
            rows.append({'n':n,'m':m,'w':w,'trial':trial,'legacy_zero_padding_used':n%8!=0,'checks':checks})
    result = metadata(args)
    result.update({'tail_capability_marker':marker,'cases':rows,
        'all_passed': marker == 1 and all(all(row['checks'].values()) for row in rows),
        'legacy_tail_qualification':'Historical tail comparisons used zero-padded scratch buffers; candidate used exact-length input arrays. This does not validate historical exact-length tails.'})
    (HERE / 'verification_final.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'verification':str(HERE/'verification_final.json'),'cases':len(rows),'all_passed':result['all_passed']},indent=2))
    if not result['all_passed']:
        raise SystemExit(1)


def benchmark(args, old, candidate):
    # Every raw call has a unique CSPRNG-generated workload; corresponding
    # old/candidate calls share the identical paired workload. All input and
    # pointer preparation is outside the timing clock.
    n, m, w = 640, 768, 128
    warmup_rounds=max(1,math.ceil(args.rounds/9))
    unique_count=(warmup_rounds+args.rounds)*args.batch
    pools={}
    for operation in ['forward','forward_fused','projection']:
        pools[operation+'_x']=small(unique_count*n).reshape(unique_count,n)
        if operation=='projection':
            pools[operation+'_y']=uniform(unique_count*(n+w)).reshape(unique_count,n+w)
        else:
            pools[operation+'_a']=uniform(unique_count*(m+n-1)).reshape(unique_count,m+n-1)
            if operation=='forward_fused':
                pools[operation+'_e']=small(unique_count*m).reshape(unique_count,m)
    pool_path=HERE/'benchmark_unique_pool.npz'
    np.savez(pool_path,**pools)
    outputs={name:{'forward':np.empty(m,dtype=np.uint16),
                   'forward_fused':np.empty(m,dtype=np.uint16),
                   'projection':np.empty(w,dtype=np.uint16)} for name in ['old','candidate']}
    funcs={}
    for name,lib in [('old',old),('candidate',candidate)]:
        for operation in ['forward','forward_fused','projection']:
            entries=[]
            for i in range(unique_count):
                px=pools[operation+'_x'][i].ctypes.data_as(S16)
                po=outputs[name][operation].ctypes.data_as(U16)
                if operation=='projection':
                    py=pools[operation+'_y'][i].ctypes.data_as(U16)
                    fn=lib.hankel_neon_window_project;parameters=(px,py,po,n,w)
                else:
                    pa=pools[operation+'_a'][i].ctypes.data_as(U16)
                    pe=pools[operation+'_e'][i].ctypes.data_as(S16) if operation=='forward_fused' else None
                    fn=lib.hankel_neon_forward_mul;parameters=(pa,px,pe,po,n,m)
                entries.append((fn,parameters))
            funcs[name,operation]=entries
    samples={operation:{'old':[],'candidate':[]} for operation in ['forward','forward_fused','projection']}
    order_bits=np.frombuffer(os.urandom(warmup_rounds+args.rounds),dtype=np.uint8)
    for round_idx in range(warmup_rounds+args.rounds):
        names=['old','candidate'] if int(order_bits[round_idx])&1 else ['candidate','old']
        for operation in samples:
            for name in names:
                entries=funcs[name,operation]
                first=round_idx*args.batch
                start=time.perf_counter_ns()
                for offset in range(args.batch):
                    fn,parameters=entries[first+offset]
                    fn(*parameters)
                elapsed=(time.perf_counter_ns()-start)/args.batch/1000
                if round_idx>=warmup_rounds:
                    samples[operation][name].append(elapsed)
    summaries={}
    for operation,libs in samples.items():
        summaries[operation]={}
        for name,values in libs.items():
            a=np.array(values)
            summaries[operation][name]={'mean_us':float(a.mean()),'median_us':float(np.median(a)),
                'std_us':float(a.std()),'p99_us':float(np.quantile(a,0.99)),'sample_count':len(values)}
        summaries[operation]['median_speedup_old_over_candidate']=summaries[operation]['old']['median_us']/summaries[operation]['candidate']['median_us']
    result=metadata(args)
    result.update({'input_pool':str(pool_path),'input_pool_sha256':digest(pool_path),
        'unique_inputs_per_operation_per_library':unique_count,'measured_unique_inputs_per_operation_per_library':args.rounds*args.batch,
        'measured_rounds':args.rounds,'warmup_rounds':warmup_rounds,
        'warmup_fraction':warmup_rounds/(warmup_rounds+args.rounds),'batch':args.batch,
        'input_use':'Every workload index is used once per operation per library; datasets separated between operations; only paired old/candidate sharing.',
        'order':'CSPRNG randomized old/candidate ordering per round; identical paired workloads',
        'clock':'perf_counter_ns; input generation/allocation/conversion/pointer setup excluded; Python ctypes call overhead included',
        'summaries':summaries,'per_round_samples_us':samples})
    (HERE/'benchmark_unique.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(summaries,indent=2))


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('mode',choices=['verify','benchmark'],nargs='?',default='verify')
    parser.add_argument('--old-library',type=Path,default=DEFAULT_OLD)
    parser.add_argument('--candidate-library',type=Path,default=HERE/'libhankel_kem_neon.dylib')
    parser.add_argument('--rounds',type=int,default=400)
    parser.add_argument('--batch',type=int,default=8)
    args=parser.parse_args()
    old,candidate=load(args.old_library),load(args.candidate_library)
    (verify if args.mode=='verify' else benchmark)(args,old,candidate)

if __name__=='__main__':
    main()
