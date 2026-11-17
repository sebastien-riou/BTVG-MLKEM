#!/usr/bin/env python3
"""Reads, checks and merges search logs (SPEC.md section 6).

Logs can come from any number of processes and machines: they are merged chunk by chunk. A chunk
counts only when its C line is present and consistent with its H lines; the same chunk found
twice must agree. For each rule, the searched range is the gap-free prefix of chunks searched
with thresholds covering that rule.

Usage: mlkem_logs.py [--profile v1|test] LOG_OR_DIR...   prints coverage, gaps and statistics.
"""
import argparse
import glob
import math
import os
import sys

import mlkem_stats

LOG_FORMAT = 1
BLOCK_ITERATIONS = 56
MIN_BLOCKS = 3


class LogError(Exception):
    pass


class Record:
    """One searched chunk, with the thresholds it was searched with."""

    def __init__(self, chunk, min_extra, max_iters, histogram, sum_t, hits, where):
        self.chunk = chunk
        self.min_extra = min_extra
        self.max_iters = max_iters
        self.histogram = histogram
        self.sum_t = sum_t
        self.hits = hits  # {index: (e, t, iterations tuple)}
        self.where = where

    def is_hit(self, e, t):
        return e >= self.min_extra or (e == 0 and t <= self.max_iters)


def parse_log(path, warnings):
    """Returns (stream key, [Record]). Raises LogError on any inconsistency."""
    header = None
    records = []
    pending = {}
    last_index = -1
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            where = f'{path}:{lineno}'
            fields = line.split()
            if not fields:
                continue
            kind = fields[0]
            if kind == 'S':
                if header is not None:
                    raise LogError(f'{where}: second S line')
                if len(fields) != 8 or fields[1] != str(LOG_FORMAT):
                    raise LogError(f'{where}: unsupported header {line.strip()}')
                _, _, label, pset, seed, log2_chunk, min_extra, max_iters = fields
                pset = int(pset)
                if pset not in mlkem_stats.K:
                    raise LogError(f'{where}: unknown parameter set {pset}')
                header = (label, pset, seed, int(log2_chunk), int(min_extra), int(max_iters))
                continue
            if header is None:
                raise LogError(f'{where}: no S line before data')
            label, pset, seed, log2_chunk, min_extra, max_iters = header
            kk = mlkem_stats.K[pset] ** 2
            if kind == 'H':
                values = [int(x) for x in fields[1:]]
                if len(values) != 3 + kk:
                    raise LogError(f'{where}: H line with {len(values)} values')
                index, e, t, its = values[0], values[1], values[2], tuple(values[3:])
                if e != sum(-(-it // BLOCK_ITERATIONS) - MIN_BLOCKS for it in its) or t != sum(its):
                    raise LogError(f'{where}: e or t inconsistent with the iterations')
                if not (e >= min_extra or (e == 0 and t <= max_iters)):
                    raise LogError(f'{where}: key {index} is not a hit')
                if pending and index <= last_index:
                    raise LogError(f'{where}: hits not in increasing order')
                pending[index] = (e, t, its)
                last_index = index
            elif kind == 'C':
                values = [int(x) for x in fields[1:]]
                if len(values) != kk + 4:
                    raise LogError(f'{where}: C line with {len(values)} values')
                chunk, histogram, sum_t, nhits = values[0], tuple(values[1:kk + 2]), values[kk + 2], values[kk + 3]
                first = chunk << log2_chunk
                last = first + (1 << log2_chunk)
                if sum(histogram) != 1 << log2_chunk:
                    raise LogError(f'{where}: histogram of chunk {chunk} does not count {1 << log2_chunk} keys')
                if nhits != len(pending) or any(not first <= i < last for i in pending):
                    raise LogError(f'{where}: chunk {chunk} does not match its {len(pending)} H lines')
                if min_extra <= kk:
                    n_extra = sum(1 for e, _, _ in pending.values() if e >= min_extra)
                    if n_extra != sum(histogram[min_extra:]):
                        raise LogError(f'{where}: chunk {chunk} has {n_extra} H lines with e >= {min_extra}, '
                                       f'its histogram {sum(histogram[min_extra:])}')
                records.append(Record(chunk, min_extra, max_iters, histogram, sum_t, pending, where))
                pending = {}
            elif kind == 'X':
                raise LogError(f'{where}: an entry exceeded 280 iterations: {line.strip()}')
            else:
                raise LogError(f'{where}: unknown line {line.strip()[:40]}')
    if pending:
        warnings.append(f'{path}: {len(pending)} H lines without their C line (interrupted search), ignored')
    if header is None:
        raise LogError(f'{path}: empty log')
    label, pset, seed, log2_chunk, _, _ = header
    return (label, pset, seed, log2_chunk), records


class Stream:
    """The merged chunks of one stream of keys (label, parameter set, seed, chunk size)."""

    def __init__(self, key):
        self.label, self.pset, self.seed, self.log2_chunk = key
        self.k = mlkem_stats.K[self.pset]
        self.chunks = {}  # chunk -> [Record]

    def add(self, rec):
        for other in self.chunks.get(rec.chunk, []):
            if (other.histogram, other.sum_t) != (rec.histogram, rec.sum_t):
                raise LogError(f'chunk {rec.chunk}: {rec.where} and {other.where} disagree')
            for a, b in ((rec, other), (other, rec)):
                for index, value in a.hits.items():
                    if b.is_hit(value[0], value[1]) and b.hits.get(index) != value:
                        raise LogError(f'chunk {rec.chunk}: key {index} is in {a.where} but not in {b.where}')
        self.chunks.setdefault(rec.chunk, []).append(rec)

    def chunk_size(self):
        return 1 << self.log2_chunk

    def prefix(self, covers):
        """Number of keys from index 0 searched with no gap by records satisfying covers(record)."""
        c = 0
        while any(covers(r) for r in self.chunks.get(c, [])):
            c += 1
        return c << self.log2_chunk

    def prefix_best(self, t_max):
        return self.prefix(lambda r: r.max_iters >= t_max)

    def prefix_extra(self, x):
        return self.prefix(lambda r: r.min_extra <= x)

    def hits(self, end):
        """Every logged key below index end: {index: (e, t, iterations)}."""
        out = {}
        for c in range(end >> self.log2_chunk):
            for r in self.chunks[c]:
                out.update(r.hits)
        return out

    def gaps(self):
        """Missing chunks below the last chunk present, as (first, count) ranges."""
        present = set(self.chunks)
        out = []
        c = 0
        top = max(present) if present else -1
        while c <= top:
            if c not in present:
                start = c
                while c not in present:
                    c += 1
                out.append((start, c - start))
            c += 1
        return out

    def statistics(self):
        """Counts of the searched keys against the exact distribution: (nkeys, lines of report, worst |z|)."""
        kk = self.k * self.k
        hist = [0] * (kk + 1)
        sum_t = 0
        for recs in self.chunks.values():
            r = recs[0]
            hist = [a + b for a, b in zip(hist, r.histogram)]
            sum_t += r.sum_t
        n = sum(hist)
        dist = mlkem_stats.key_extra_dist(self.k)
        lines = []
        worst = 0.0
        for x in range(kk + 1):
            p = sum(v for e, v in dist.items() if (e >= kk if x == kk else e == x))
            expected = n * p
            if expected >= 5:  # normal approximation of the binomial count
                z = (hist[x] - expected) / math.sqrt(expected * (1 - p))
                worst = max(worst, abs(z))
                lines.append(f'  e = {x}{"+" if x == kk else ""}: {hist[x]} keys, expected {expected:.1f} (z = {z:+.2f})')
            elif hist[x]:
                lines.append(f'  e = {x}{"+" if x == kk else ""}: {hist[x]} keys, expected {expected:.3g}')
        mean, var = mlkem_stats.entry_moments()
        if n:
            z = (sum_t - n * kk * float(mean)) / math.sqrt(n * kk * float(var))
            worst = max(worst, abs(z))
            lines.append(f'  mean t: {sum_t / n:.4f}, expected {kk * float(mean):.4f} (z = {z:+.2f})')
        return n, lines, worst


def load(paths, warnings=None):
    """Merges the logs found in paths (files or directories): {stream key: Stream}."""
    if warnings is None:
        warnings = []
    files = []
    for p in paths:
        files += sorted(glob.glob(os.path.join(p, '*.log'))) if os.path.isdir(p) else [p]
    streams = {}
    for path in files:
        key, records = parse_log(path, warnings)
        stream = streams.setdefault(key, Stream(key))
        for rec in records:
            stream.add(rec)
    return streams


def report(streams, profile='v1', out=sys.stdout):
    for key in sorted(streams, key=lambda k: (k[1], k[0], k[2], k[3])):
        s = streams[key]
        r = mlkem_stats.rules(s.pset, profile)
        n, lines, worst = s.statistics()
        print(f'ML-KEM-{s.pset}, seed {s.seed}, {s.label}, chunks of 2^{s.log2_chunk} keys: '
              f'{len(s.chunks)} chunks, {n} keys', file=out)
        rules = [('best case', r['best']['t'], s.prefix_best(r['best']['t']),
                  lambda h, t=r['best']['t']: h[0] == 0 and h[1] <= t)]
        for i, tier in enumerate(r['tiers']):
            rules.append((f'worst case tier {i + 1}', tier['x'], s.prefix_extra(tier['x']),
                          lambda h, x=tier['x']: h[0] == x))
        for name, _, prefix, match in rules:
            found = sorted(i for i, h in s.hits(prefix).items() if match(h))
            first = f'first at index {found[0]}' if found else 'not found yet'
            log2 = f'2^{math.log2(prefix):.2f}' if prefix else '0'
            print(f'  {name} ({profile}): searched {prefix} keys ({log2}), {first}', file=out)
        for first, count in s.gaps():
            print(f'  missing chunks {first} to {first + count - 1}: '
                  f'./search {s.pset} {first} {count} JOBS --seed {s.seed}', file=out)
        print('\n'.join(lines), file=out)
        if worst > 5:
            print(f'  WARNING: a count is {worst:.1f} standard deviations away from its expectation', file=out)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--profile', default='v1', choices=mlkem_stats.PROFILES)
    parser.add_argument('paths', nargs='+')
    args = parser.parse_args()
    warnings = []
    try:
        streams = load(args.paths, warnings)
    except LogError as ex:
        print(f'ERROR: {ex}', file=sys.stderr)
        sys.exit(1)
    for w in warnings:
        print(f'WARNING: {w}', file=sys.stderr)
    report(streams, args.profile)
