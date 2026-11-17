#!/usr/bin/env python3
"""Tests of the selection (mlkem_select.py) on a search made with the 'test' profile.

    test/test_select.py LOG_DIR

For each parameter set found in LOG_DIR:
- the best and worst cases are compared with a brute-force scan of every key of the searched range
  by mlkem_count.count_keys, independent of the logs;
- the average set is checked against its definition with the reference counter (the instrumented
  SampleNTT of mlkem_fips203), including that no earlier window qualifies.
"""
import multiprocessing
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import mlkem_count  # noqa: E402
import mlkem_logs  # noqa: E402
import mlkem_select  # noqa: E402

SLICE = 1 << 16


def scan(args):
    """First index of each rule in a slice of keys: {rule: index or None}."""
    pset, seed, first, t_best, xs = args
    e, t, _ = mlkem_count.count_keys(pset, seed, first, SLICE)
    out = {}
    for name, mask in [('best', (e == 0) & (t <= t_best))] + [(f'tier {i}', e == x) for i, x in enumerate(xs, 1)]:
        idx = mask.nonzero()[0]
        out[name] = first + int(idx[0]) if len(idx) else None
    return out


def brute_force(pset, seed, end, r):
    xs = [tier['x'] for tier in r['tiers']]
    work = [(pset, seed, first, r['best']['t'], xs) for first in range(0, end, SLICE)]
    with multiprocessing.Pool(os.cpu_count()) as pool:
        results = pool.map(scan, work)
    first = {}
    for res in results:  # in increasing order of slices
        for name, idx in res.items():
            if idx is not None and name not in first:
                first[name] = idx
    return first


def check_average(pset, seed, r, cases):
    av = [c for c in cases if c['role'] == 'average']
    n, x_avg, s, t_best = r['average']['n'], r['average']['x'], r['average']['s'], r['best']['t']
    start = av[0]['index']
    assert [c['index'] for c in av] == list(range(start, start + n))
    costs = [mlkem_count.key_cost(pset, seed, i) for i in range(start + n)]
    for c in av:
        assert (c['e'], c['t'], c['iterations']) == (costs[c['index']][0], costs[c['index']][1],
                                                      tuple(costs[c['index']][2]))

    def qualifies(a):
        w = costs[a:a + n]
        return (sum(e for e, _, _ in w) == x_avg and sum(t for _, t, _ in w) == s
                and all(e <= 1 and not (e == 0 and t <= t_best) for e, t, _ in w))
    assert qualifies(start)
    assert not any(qualifies(a) for a in range(start))
    return start


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    streams = mlkem_logs.load([sys.argv[1]])
    for key in sorted(streams, key=lambda k: k[1]):
        s = streams[key]
        sel = mlkem_select.select(s, 'test')
        r = sel['rules']
        seed = bytes.fromhex(s.seed)
        assert not sel['missing'], sel['missing']
        selected = {('best' if c['role'] == 'best' else f"tier {c['tier']}"): c['index']
                    for c in sel['cases'] if c['role'] != 'average'}
        ends = set(sel['searched'].values())
        assert len(ends) == 1, 'the test expects one searched range for every rule'
        expected = brute_force(s.pset, seed, ends.pop(), r)
        assert selected == expected, f'ML-KEM-{s.pset}: selection {selected}, brute force {expected}'
        start = check_average(s.pset, seed, r, sel['cases'])
        print(f'ML-KEM-{s.pset}: {selected} confirmed by a brute-force scan of {sel["searched"]["best"]} keys, '
              f'average set from index {start} confirmed')
    print('all tests passed')


if __name__ == '__main__':
    main()
