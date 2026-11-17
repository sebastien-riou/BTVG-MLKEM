#!/usr/bin/env python3
"""Tests of the search tool (mlkem-search) against the Python code, and of the merging of logs.

    test/test_search.py [--quick] [--vectors DIR]

--vectors DIR: check the Keccak of mlkem-search against every SHA-3 answer of NIST found in DIR
(default git_ignore/vectors if present, else the built-in answers of kat/kat.json).
"""
import argparse
import os
import random
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import mlkem_count  # noqa: E402
import mlkem_kat  # noqa: E402
import mlkem_logs  # noqa: E402
import mlkem_stats  # noqa: E402

SEARCH = os.path.join(ROOT, 'mlkem-search')
PSETS = mlkem_stats.PSETS


def run(args, **kw):
    return subprocess.run([SEARCH] + [str(a) for a in args], capture_output=True, text=True, check=True, **kw).stdout


def test_selftest():
    assert run(['--selftest']).strip() == 'selftest passed'


def test_hash(vectors):
    tests = mlkem_kat.builtin_tests()[1]
    if vectors and os.path.isdir(vectors):
        tests += mlkem_kat.sha3_tests(vectors)
    inp = ''.join(f"{t['alg']} {len(t['out']) // 2} {t['msg'] or '-'}\n" for t in tests)
    out = run(['--hash'], input=inp).split()
    assert len(out) == len(tests)
    bad = [t['name'] for t, o in zip(tests, out) if o != t['out']]
    assert not bad, f'SHA-3 mismatches: {bad[:5]}'
    print(f'  {len(tests)} SHA-3 answers')


def test_keys(n):
    """mlkem-search --key against mlkem_count.key_report on random keys of random streams."""
    rng = random.Random(1)
    for _ in range(n):
        pset = rng.choice(PSETS)
        seed = bytes(8) if rng.random() < 0.5 else rng.randbytes(8)
        index = rng.choice([rng.randrange(1 << 20), rng.randrange(1 << 64)])
        got = run(['--key', pset, index, '--seed', seed.hex()]).strip()
        assert got == mlkem_count.key_report(pset, seed, index), f'ML-KEM-{pset} seed {seed.hex()} index {index}'
    print(f'  {n} keys')


def test_chunks(log2_chunk, nchunks, first_chunk=0):
    """Logs of mlkem-search and of the Python recount, byte for byte, with thresholds giving many hits."""
    for pset in PSETS:
        r = mlkem_stats.rules(pset, 'test')
        args = ['--min-extra', 1, '--max-iters', r['best']['t'], '--log2-chunk', log2_chunk]
        c = run([pset, first_chunk, nchunks] + args)
        with tempfile.TemporaryFile('w+') as f:
            mlkem_count.recount(pset, bytes(8), first_chunk, nchunks, 1, r['best']['t'], log2_chunk, jobs=os.cpu_count(),
                                out=f)
            f.seek(0)
            py = f.read()
        assert c == py, f'ML-KEM-{pset}: mlkem-search and mlkem_count.py differ'
        print(f"  ML-KEM-{pset}: {nchunks} chunks of 2^{log2_chunk} keys, {c.count('H ')} hits, identical")


def stream_content(streams):
    """Comparable content of merged logs: {key: {chunk: (histogram, sum_t, hits)}}."""
    out = {}
    for key, s in streams.items():
        out[key] = {}
        for c, recs in s.chunks.items():
            hits = {}
            for r in recs:
                hits.update(r.hits)
            out[key][c] = (recs[0].histogram, recs[0].sum_t, hits)
    return out


def test_merge(tmp):
    """One run, a run split over 5 jobs, and overlapping runs with other thresholds merge to the same."""
    pset, log2_chunk, n = 768, 10, 12
    one, split, mixed = (os.path.join(tmp, d) for d in ('one', 'split', 'mixed'))
    for d in (one, split, mixed):
        os.makedirs(d)
    with open(os.path.join(one, 'all.log'), 'w') as f:
        f.write(run([pset, 0, n, '--min-extra', 2, '--max-iters', 1380, '--log2-chunk', log2_chunk]))
    for j in range(5):
        start, end = n * j // 5, n * (j + 1) // 5
        with open(os.path.join(split, f'{j}.log'), 'w') as f:
            f.write(run([pset, start, end - start, '--min-extra', 2, '--max-iters', 1380, '--log2-chunk', log2_chunk]))
    shutil.copy(os.path.join(one, 'all.log'), mixed)
    with open(os.path.join(mixed, 'other.log'), 'w') as f:  # overlapping, stricter thresholds
        f.write(run([pset, 3, 6, '--min-extra', 3, '--max-iters', 1370, '--log2-chunk', log2_chunk]))
    a, b, c = (mlkem_logs.load([d]) for d in (one, split, mixed))
    assert stream_content(a) == stream_content(b) == stream_content(c)
    s = next(iter(b.values()))
    assert s.prefix_extra(2) == n << log2_chunk and s.prefix_best(1380) == n << log2_chunk and not s.gaps()
    assert s.prefix_extra(1) == 0 and s.prefix_best(1381) == 0  # thresholds not covered
    # a missing slice is a gap, and the searched range stops there
    os.remove(os.path.join(split, '2.log'))
    start, end = n * 2 // 5, n * 3 // 5
    s = next(iter(mlkem_logs.load([split]).values()))
    assert s.prefix_extra(2) == start << log2_chunk and s.gaps() == [(start, end - start)]
    print('  merge, thresholds and gaps')


def test_bad_logs(tmp):
    pset, log2_chunk = 512, 10
    good = run([pset, 0, 3, '--min-extra', 1, '--max-iters', 605, '--log2-chunk', log2_chunk])
    lines = good.splitlines(keepends=True)
    c_lines = [i for i, x in enumerate(lines) if x.startswith('C ')]
    path = os.path.join(tmp, 'bad.log')

    def load(text):
        with open(path, 'w') as f:
            f.write(text)
        warnings = []
        return mlkem_logs.load([path], warnings), warnings

    # interrupted: H lines after the last C line are dropped, with a warning
    streams, warnings = load(''.join(lines[:c_lines[1] + 2]))
    s = next(iter(streams.values()))
    assert sorted(s.chunks) == [0, 1] and len(warnings) == 1
    # any corruption is an error
    corruptions = []
    corrupt = list(lines)
    corrupt[c_lines[0]] = corrupt[c_lines[0]].replace('C 0 ', 'C 0 1', 1)  # histogram
    corruptions.append(corrupt)
    h = next(i for i, x in enumerate(lines) if x.startswith('H '))
    corruptions.append(lines[:h] + lines[h + 1:])  # a hit removed
    fields = lines[h].split()
    fields[3] = str(int(fields[3]) + 1)  # t
    corruptions.append(lines[:h] + [' '.join(fields) + '\n'] + lines[h + 1:])
    corruptions.append(lines + ['X 5 3\n'])
    for text in corruptions:
        try:
            load(''.join(text))
        except mlkem_logs.LogError:
            continue
        raise AssertionError('corrupted log accepted')
    # two logs of the same chunk which disagree on what a single log cannot check (sum of t)
    pair = os.path.join(tmp, 'pair')
    os.makedirs(pair)
    fields = lines[c_lines[0]].split()
    fields[-2] = str(int(fields[-2]) + 1)
    for name, text in (('a.log', lines), ('b.log', lines[:c_lines[0]] + [' '.join(fields) + '\n'])):
        with open(os.path.join(pair, name), 'w') as f:
            f.write(''.join(text))
    try:
        mlkem_logs.load([pair])
    except mlkem_logs.LogError:
        pass
    else:
        raise AssertionError('disagreeing logs accepted')
    print('  interrupted, corrupted and disagreeing logs')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--quick', action='store_true')
    parser.add_argument('--vectors', default=os.path.join(ROOT, 'git_ignore', 'vectors'))
    args = parser.parse_args()
    tmp = tempfile.mkdtemp(prefix='btvg-mlkem-test-')
    try:
        print('mlkem-search --selftest')
        test_selftest()
        print('Keccak against NIST')
        test_hash(args.vectors)
        print('keys against Python')
        test_keys(30 if args.quick else 1000)
        print('logs against Python')
        test_chunks(10 if args.quick else 14, 4)
        print('logs')
        test_merge(tmp)
        test_bad_logs(tmp)
    finally:
        shutil.rmtree(tmp)
    print('all tests passed')


if __name__ == '__main__':
    main()
