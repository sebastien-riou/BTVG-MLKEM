#!/usr/bin/env python3
"""Recounts in Python the chunks behind a selection, and compares them with the search logs.

    mlkem-verify.py [--profile v1|test] [--seed HEX16] [--jobs N] LOG_OR_DIR...

The selection takes the smallest index matching each rule. A key missed by the search tool before
the selected one would make it wrong: this recounts, with the counter of mlkem_count.py (hashlib
and numpy, independent of the C tool), every chunk from 0 to the one holding the last selected key,
and requires the same histogram, sum of iterations and hits as the logs. Run it before publishing.
"""
import argparse
import multiprocessing
import os
import sys
import time

import mlkem_count
import mlkem_logs
import mlkem_select
import mlkem_stats


def recount_chunk(args):
    pset, seed, log2_chunk, chunk, min_extra, max_iters = args
    lines = mlkem_count.chunk_lines(args)
    c = lines[-1].split()
    kk = mlkem_stats.K[pset] ** 2
    histogram = tuple(int(x) for x in c[2:kk + 3])
    hits = {}
    for line in lines[:-1]:
        v = [int(x) for x in line.split()[1:]]
        hits[v[0]] = (v[1], v[2], tuple(v[3:]))
    return chunk, histogram, int(c[kk + 3]), hits


def verify(stream, profile, jobs):
    sel = mlkem_select.select(stream, profile)
    selected = [c['index'] for c in sel['cases'] if c['role'] != 'average']
    if not selected:
        print(f'ML-KEM-{stream.pset}: nothing selected from the logs')
        return True
    last_chunk = max(selected) >> stream.log2_chunk
    work = []
    for chunk in range(last_chunk + 1):
        rec = stream.chunks[chunk][0]
        work.append((stream.pset, bytes.fromhex(stream.seed), stream.log2_chunk, chunk, rec.min_extra, rec.max_iters))
    t0 = time.time()
    ok = True
    with multiprocessing.Pool(jobs) as pool:
        for chunk, histogram, sum_t, hits in pool.imap_unordered(recount_chunk, work):
            rec = stream.chunks[chunk][0]
            if (histogram, sum_t, hits) != (rec.histogram, rec.sum_t, rec.hits):
                print(f'ML-KEM-{stream.pset}: chunk {chunk} DIFFERS from {rec.where}')
                ok = False
    print(f'ML-KEM-{stream.pset}: chunks 0 to {last_chunk} ({(last_chunk + 1) << stream.log2_chunk} keys) recounted '
          f'in {time.time() - t0:.0f} s: {"identical to the logs" if ok else "DIFFERENT"}')
    return ok


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--profile', default='v1', choices=mlkem_stats.PROFILES)
    parser.add_argument('--seed', type=mlkem_count.parse_seed, default=mlkem_count.DEFAULT_SEED)
    parser.add_argument('--jobs', type=int, default=os.cpu_count())
    parser.add_argument('paths', nargs='+')
    args = parser.parse_args()
    streams = mlkem_logs.load(args.paths)
    ok = True
    for key in sorted(streams, key=lambda k: k[1]):
        if key[2] == args.seed.hex() and key[0] == mlkem_count.LABEL.decode():
            ok &= verify(streams[key], args.profile, args.jobs)
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
