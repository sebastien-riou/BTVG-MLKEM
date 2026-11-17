"""Selection of the test cases (SPEC.md section 3).

The best and worst cases come from search logs (mlkem_logs.py); the average set is found by
counting the stream from index 0 (mlkem_count.py), it does not depend on any search.
"""
import numpy as np

import mlkem_count
import mlkem_stats

# The table of SPEC.md section 3. The constants computed by mlkem_stats.py must match it: a
# change of mlkem_stats.py cannot silently change the published rules.
RULES_V1 = {
    512: {'best': {'t': 585, 'prob': '2^-28.18'},
          'tiers': ({'x': 4, 'prob': '2^-27.63'},),
          'average': {'n': 30, 'x': 1, 's': 18929}},
    768: {'best': {'t': 1349, 'prob': '2^-28.12'},
          'tiers': ({'x': 5, 'prob': '2^-27.60'}, {'x': 6, 'prob': '2^-35.09'}),
          'average': {'n': 40, 'x': 3, 's': 56787}},
    1024: {'best': {'t': 2428, 'prob': '2^-28.37'},
           'tiers': ({'x': 6, 'prob': '2^-28.58'}, {'x': 7, 'prob': '2^-34.97'}),
           'average': {'n': 15, 'x': 2, 's': 37858}},
}
RULES_VERSION = {'v1': 'v1', 'test': 'test'}
ROLES = {'best': 0, 'worst': 1, 'average': 2}
AVERAGE_SCAN_LIMIT = 1 << 24  # bound of the scan for the average set (found within ~4096 in practice)


class SelectionError(Exception):
    pass


def rules(pset, profile='v1'):
    r = mlkem_stats.rules(pset, profile)
    if profile == 'v1':
        got = {key: r[key] for key in ('best', 'tiers', 'average')}
        if got != RULES_V1[pset]:
            raise SelectionError(f'ML-KEM-{pset}: constants computed by mlkem_stats.py differ from SPEC.md: {got}')
    return r


def case(role, tier, index, e, t, iterations, prob):
    return {'role': role, 'tier': tier, 'index': index, 'e': e, 't': t, 'iterations': tuple(iterations), 'prob': prob}


def average_set(pset, seed, r):
    """The N consecutive keys of the average set: list of cases."""
    n, x_avg, s = r['average']['n'], r['average']['x'], r['average']['s']
    t_best = r['best']['t']
    batch = 1 << 12
    es, ts, its = [], [], []
    start = 0
    while start < AVERAGE_SCAN_LIMIT:
        e, t, it = mlkem_count.count_keys(pset, seed, start, batch)
        es.append(e)
        ts.append(t)
        its.append(it)
        e, t = np.concatenate(es), np.concatenate(ts)
        ok = (e <= 1) & ~((e == 0) & (t <= t_best))
        cum_e = np.concatenate(([0], np.cumsum(e)))
        cum_t = np.concatenate(([0], np.cumsum(t)))
        cum_ok = np.concatenate(([0], np.cumsum(ok)))
        a = np.arange(len(e) - n + 1)
        good = (cum_e[a + n] - cum_e[a] == x_avg) & (cum_t[a + n] - cum_t[a] == s) & (cum_ok[a + n] - cum_ok[a] == n)
        if good.any():
            a0 = int(np.argmax(good))
            it = np.concatenate(its)
            return [case('average', 0, a0 + i, int(e[a0 + i]), int(t[a0 + i]), [int(v) for v in it[a0 + i]], None)
                    for i in range(n)]
        start += batch
    raise SelectionError(f'ML-KEM-{pset}: no average set below index {AVERAGE_SCAN_LIMIT}')


def select(stream, profile='v1'):
    """Selection from the merged logs of one stream (mlkem_logs.Stream).

    Returns {'cases': [...] in the published order, 'searched': {rule: number of keys searched},
    'missing': [rules not found yet]}.
    """
    pset = stream.pset
    r = rules(pset, profile)
    if stream.label != mlkem_count.LABEL.decode():
        raise SelectionError(f'unsupported derivation {stream.label}')
    seed = bytes.fromhex(stream.seed)
    cases, searched, missing = [], {}, []

    def first(prefix, match):
        found = [(i, h) for i, h in stream.hits(prefix).items() if match(h)]
        return min(found) if found else None

    t_best = r['best']['t']
    prefix = stream.prefix_best(t_best)
    searched['best'] = prefix
    hit = first(prefix, lambda h: h[0] == 0 and h[1] <= t_best)
    if hit:
        cases.append(case('best', 0, hit[0], *hit[1], r['best']['prob']))
    else:
        missing.append('best')
    for tier, rule in enumerate(r['tiers'], 1):
        prefix = stream.prefix_extra(rule['x'])
        searched[f'tier {tier}'] = prefix
        hit = first(prefix, lambda h, x=rule['x']: h[0] == x)
        if hit:
            cases.append(case('worst', tier, hit[0], *hit[1], rule['prob']))
        else:
            missing.append(f'tier {tier}')
    cases += average_set(pset, seed, r)
    return {'pset': pset, 'seed': seed, 'profile': profile, 'rules': r, 'cases': cases, 'searched': searched,
            'missing': missing}
