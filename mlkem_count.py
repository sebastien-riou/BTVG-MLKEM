#!/usr/bin/env python3
"""Stream of keys and cost of a key (SPEC.md sections 1 and 2), in Python.

- derive(): the inputs of the key of an index;
- key_cost(): its cost, counted by the instrumented SampleNTT of mlkem_fips203 (reference);
- count_keys(): the same for many keys at once, with numpy (fast);
- --recount: search log lines (SPEC.md section 6) identical to those of mlkem-search, to check
  the C tool chunk by chunk;
- --key: everything about one key, to compare with `mlkem-search --key`;
- --acvp DIR: the keys of the ACVP sample files needing an extra block (README).
"""
import argparse
import glob
import hashlib
import json
import multiprocessing
import os
import sys

import numpy as np

import mlkem_fips203
import mlkem_stats

LABEL = b'BTVG-MLKEM-v1'
LOG_FORMAT = 1
LOG2_CHUNK = 20
DEFAULT_SEED = bytes(8)
BATCH = 1 << 11  # keys hashed and counted together by count_keys
Q = 3329
BLOCK_ITERATIONS = 56
MIN_BLOCKS = 3


def derive(seed, index):
    """d, z, m and r of the key of an index (SPEC.md section 1)."""
    out = hashlib.shake_256(LABEL + seed + index.to_bytes(8, 'little')).digest(104)
    return out[0:32], out[32:64], out[64:96], int.from_bytes(out[96:104], 'little')


def reject_bit(pset, r):
    return r % (8 * mlkem_fips203.ct_size(pset))


def rho(pset, d):
    return hashlib.sha3_512(d + bytes([mlkem_stats.K[pset]])).digest()[:32]


def cost(iterations):
    """(e, t) from the iterations of the k*k entries."""
    e = sum(mlkem_stats.blocks(it) - MIN_BLOCKS for it in iterations)
    return e, sum(iterations)


def key_cost(pset, seed, index):
    """(e, t, iterations) of a key, with the SampleNTT of mlkem_fips203."""
    d = derive(seed, index)[0]
    _, iterations = mlkem_fips203.gen_matrix(mlkem_stats.K[pset], rho(pset, d))
    return cost(iterations) + (iterations,)


def _iterations(xof, nbytes):
    """Iterations of each row of xof (entries, nbytes) uint8; 0 where 256 coefficients are not reached."""
    b = xof.reshape(len(xof), nbytes // 3, 3).astype(np.uint16)
    d1 = b[:, :, 0] | ((b[:, :, 1] & 0x0F) << 8)
    d2 = (b[:, :, 1] >> 4) | (b[:, :, 2] << 4)
    accepted = np.empty((len(xof), 2 * (nbytes // 3)), dtype=np.uint16)
    accepted[:, 0::2] = d1 < Q
    accepted[:, 1::2] = d2 < Q
    counts = np.cumsum(accepted, axis=1, dtype=np.uint16)
    done = counts[:, -1] >= mlkem_fips203.N
    first = np.argmax(counts >= mlkem_fips203.N, axis=1)  # index of the 256th accepted candidate
    return np.where(done, first // 2 + 1, 0)


def count_keys(pset, seed, first, n):
    """e (n,), t (n,) and iterations (n, k*k) of the keys first .. first+n-1."""
    k = mlkem_stats.K[pset]
    kk = k * k
    suffixes = [bytes([j, i]) for i in range(k) for j in range(k)]
    nbytes = MIN_BLOCKS * 168
    its = np.empty((n, kk), dtype=np.int64)
    for start in range(0, n, BATCH):
        m = min(BATCH, n - start)
        rhos = [rho(pset, derive(seed, first + start + x)[0]) for x in range(m)]
        xof = b''.join(hashlib.shake_128(r + s).digest(nbytes) for r in rhos for s in suffixes)
        it = _iterations(np.frombuffer(xof, dtype=np.uint8).reshape(m * kk, nbytes), nbytes)
        for pos in np.flatnonzero(it == 0):  # needs a 4th block or more: 0.83% of the entries
            r, s = rhos[pos // kk], suffixes[pos % kk]
            nmax = mlkem_stats.MAX_ITERATIONS * 3
            xof_long = np.frombuffer(hashlib.shake_128(r + s).digest(nmax), dtype=np.uint8).reshape(1, nmax)
            it[pos] = _iterations(xof_long, nmax)[0]
            if it[pos] == 0:
                raise OverflowError(f'X {first + start + pos // kk} {pos % kk}')
        its[start:start + m] = it.reshape(m, kk)
    blocks = -(-its // BLOCK_ITERATIONS)
    return (blocks - MIN_BLOCKS).sum(axis=1), its.sum(axis=1), its


# --- search log lines -----------------------------------------------------------------------------

def header_line(pset, seed, log2_chunk, min_extra, max_iters):
    return f'S {LOG_FORMAT} {LABEL.decode()} {pset} {seed.hex()} {log2_chunk} {min_extra} {max_iters}'


def chunk_lines(args):
    """H lines and the C line of a chunk, as mlkem-search writes them."""
    pset, seed, log2_chunk, chunk, min_extra, max_iters = args
    kk = mlkem_stats.K[pset] ** 2
    first = chunk << log2_chunk
    e, t, its = count_keys(pset, seed, first, 1 << log2_chunk)
    hits = np.flatnonzero((e >= min_extra) | ((e == 0) & (t <= max_iters)))
    lines = [f"H {first + int(i)} {int(e[i])} {int(t[i])} {' '.join(str(int(x)) for x in its[i])}" for i in hits]
    histogram = np.bincount(np.minimum(e, kk), minlength=kk + 1)
    lines.append(f"C {chunk} {' '.join(str(int(x)) for x in histogram)} {int(t.sum())} {len(hits)}")
    return lines


def recount(pset, seed, first_chunk, nchunks, min_extra, max_iters, log2_chunk=LOG2_CHUNK, jobs=1, out=sys.stdout):
    print(header_line(pset, seed, log2_chunk, min_extra, max_iters), file=out, flush=True)
    work = [(pset, seed, log2_chunk, c, min_extra, max_iters) for c in range(first_chunk, first_chunk + nchunks)]
    if jobs > 1:
        with multiprocessing.Pool(jobs) as pool:
            for lines in pool.imap(chunk_lines, work):
                print('\n'.join(lines), file=out, flush=True)
    else:
        for w in work:
            print('\n'.join(chunk_lines(w)), file=out, flush=True)


# --- ACVP sample files ---------------------------------------------------------------------------

def acvp_slow_keys(vectors_dir):
    """{(file, function, pset): (number of keys, number with an extra block, largest e)}."""
    out = {}
    for path in sorted(glob.glob(os.path.join(vectors_dir, '**', 'internalProjection.json'), recursive=True)):
        with open(path) as f:
            d = json.load(f)
        if d.get('algorithm') != 'ML-KEM':
            continue
        for g in d['testGroups']:
            fn = g.get('function', 'keyGen')
            if 'KeyCheck' in fn:
                continue
            pset = int(g['parameterSet'].split('-')[-1])
            k = mlkem_stats.K[pset]
            rhos = set()
            for t in g['tests']:
                if fn == 'keyGen':
                    rhos.add(rho(pset, bytes.fromhex(t['d'])))
                else:
                    rhos.add(bytes.fromhex(t['ek'])[384 * k:])
            es = [cost(mlkem_fips203.gen_matrix(k, r)[1])[0] for r in rhos]
            key = (os.path.relpath(os.path.dirname(path), vectors_dir), fn, pset)
            prev = out.get(key, (0, 0, 0))
            out[key] = (prev[0] + len(es), prev[1] + sum(1 for e in es if e), max(prev[2], max(es)))
    return out


def print_acvp(vectors_dir):
    print('| Folder | Function | Parameter set | Keys | Keys with an extra block | Largest number of extra blocks |')
    print('|---|---|---|---|---|---|')
    for (folder, fn, pset), (n, slow, emax) in acvp_slow_keys(vectors_dir).items():
        print(f'| {folder} | {fn} | ML-KEM-{pset} | {n} | {slow} | {emax} |')


# --- checks -------------------------------------------------------------------------------------

def selftest(nkeys=300, seed=DEFAULT_SEED, first=0):
    """count_keys (numpy) against the instrumented SampleNTT of mlkem_fips203, key by key."""
    for pset in mlkem_stats.PSETS:
        e, t, its = count_keys(pset, seed, first, nkeys)
        for x in range(nkeys):
            ref = key_cost(pset, seed, first + x)
            got = (int(e[x]), int(t[x]), [int(v) for v in its[x]])
            if got != ref:
                raise AssertionError(f'ML-KEM-{pset} index {first + x}: numpy {got} != reference {ref}')
        slow = int((e > 0).sum())
        print(f'ML-KEM-{pset}: {nkeys} keys from index {first}, counts identical ({slow} keys with an extra block)')


def key_report(pset, seed, index):
    d, z, m, r = derive(seed, index)
    e, t, its = key_cost(pset, seed, index)
    return '\n'.join([
        f'pset {pset}', f'seed {seed.hex()}', f'index {index}',
        f'd {d.hex()}', f'z {z.hex()}', f'm {m.hex()}', f'reject_bit {reject_bit(pset, r)}',
        f'rho {rho(pset, d).hex()}', f"iterations {' '.join(str(x) for x in its)}", f'e {e}', f't {t}',
    ])


def parse_seed(s):
    seed = bytes.fromhex(s)
    if len(seed) != 8:
        raise argparse.ArgumentTypeError('the seed is 8 bytes, 16 hexadecimal digits')
    return seed


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--seed', type=parse_seed, default=DEFAULT_SEED, help='16 hexadecimal digits')
    parser.add_argument('--profile', default='v1', choices=mlkem_stats.PROFILES,
                        help='rules giving the default thresholds of --recount')
    parser.add_argument('--key', nargs=2, type=int, metavar=('PSET', 'INDEX'))
    parser.add_argument('--recount', nargs=3, type=int, metavar=('PSET', 'FIRST_CHUNK', 'NCHUNKS'))
    parser.add_argument('--min-extra', type=int, help='E: log keys with at least E extra blocks')
    parser.add_argument('--max-iters', type=int, help='T: log keys without extra block and at most T iterations')
    parser.add_argument('--log2-chunk', type=int, default=LOG2_CHUNK)
    parser.add_argument('--jobs', type=int, default=1)
    parser.add_argument('--acvp', metavar='DIR')
    parser.add_argument('--selftest', type=int, nargs='?', const=300, metavar='NKEYS')
    args = parser.parse_args()
    if args.selftest:
        selftest(args.selftest, args.seed)
    if args.key:
        print(key_report(args.key[0], args.seed, args.key[1]))
    if args.recount:
        pset, first_chunk, nchunks = args.recount
        r = mlkem_stats.rules(pset, args.profile)
        e = args.min_extra if args.min_extra is not None else r['tiers'][0]['x']
        t = args.max_iters if args.max_iters is not None else r['best']['t']
        recount(pset, args.seed, first_chunk, nchunks, e, t, args.log2_chunk, args.jobs)
    if args.acvp:
        print_acvp(args.acvp)
