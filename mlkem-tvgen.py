#!/usr/bin/env python3
"""Generates the BTVG-MLKEM test vectors from search logs, or checks published ones.

    mlkem-tvgen.py [--profile v1|test] [--seed HEX16] [--write DIR] LOG_OR_DIR...
        select the test cases from the logs (SPEC.md section 3), compute and cross-check them, and
        write every format of each set in DIR (default: published/, test profile: required).
    mlkem-tvgen.py --check [DIR]
        rebuild every record of DIR (default: published/) from its inputs, check that its test cases
        follow the rules, and compare every file byte for byte. No search is needed; that the best
        and worst cases are the first ones in the stream needs the logs (mlkem-verify.py).
    mlkem-tvgen.py --render RECORD... --write DIR
        rebuild the given records and write every file of their sets in DIR.

The known answer tests run first; nothing is written if one fails.
"""
import argparse
import glob
import os
import sys

import mlkem_count
import mlkem_formats
import mlkem_kat
import mlkem_logs
import mlkem_select
import mlkem_set
import mlkem_stats

HERE = os.path.dirname(os.path.abspath(__file__))
PUBLISHED = os.path.join(HERE, 'published')


def write_files(outdir, rec):
    """Writes the files of a set; an existing file must be identical."""
    os.makedirs(outdir, exist_ok=True)
    for name, text in mlkem_formats.files(rec).items():
        path = os.path.join(outdir, name)
        if os.path.exists(path):
            with open(path) as f:
                if f.read() != text:
                    raise mlkem_set.SetError(f'{path} exists with another content')
            continue
        with open(path, 'w') as f:
            f.write(text)
        print(f'  wrote {path}')


def generate(paths, profile, seed, outdir):
    warnings = []
    streams = mlkem_logs.load(paths, warnings)
    for w in warnings:
        print(f'WARNING: {w}', file=sys.stderr)
    status = 0
    for pset in mlkem_stats.PSETS:
        found = [s for key, s in streams.items() if key[1] == pset and key[2] == seed.hex()
                 and key[0] == mlkem_count.LABEL.decode()]
        if not found:
            print(f'ML-KEM-{pset}: no log of seed {seed.hex()}')
            continue
        if len(found) > 1:
            raise mlkem_logs.LogError(f'ML-KEM-{pset}: logs with several chunk sizes')
        sel = mlkem_select.select(found[0], profile)
        for rule, n in sel['searched'].items():
            print(f'ML-KEM-{pset}: {rule}: {n} keys searched' + (', not found' if rule in sel['missing'] else ''))
        if 'best' in sel['missing'] or 'tier 1' in sel['missing']:
            print(f'ML-KEM-{pset}: the best case and the worst case of tier 1 are required, search further')
            status = 1
            continue
        rec = mlkem_set.build(pset, seed, profile, sel['cases'], sel['searched'], None)
        existing = os.path.join(outdir, rec['name'] + '.py')
        if os.path.exists(existing):  # files state the version which first produced the set
            rec['version'] = mlkem_set.read_record(existing)['version']
        else:
            rec['version'] = mlkem_set.version()
            if rec['version'].endswith('-dirty') and os.path.abspath(outdir) == PUBLISHED:
                raise mlkem_set.SetError(f"ML-KEM-{pset}: new set, but the generator has uncommitted changes "
                                         f"({rec['version']}): commit them first, its files state the version")
        print(f"ML-KEM-{pset}: set {rec['name']}")
        write_files(outdir, rec)
    return status


def check(outdir):
    records = sorted(glob.glob(os.path.join(outdir, 'mlkem*.py')))
    if not records:
        print(f'no record in {outdir}')
        return 1
    status = 0
    for path in records:
        rec = mlkem_set.read_record(path)
        rebuilt = mlkem_set.rebuild(rec)
        if rebuilt != rec:
            diff = [k for k in rec if rec[k] != rebuilt[k]]
            print(f'{path}: FAILED, fields differ when recomputed: {diff}')
            status = 1
            continue
        bad = mlkem_select.check_record(rebuilt)
        for name, text in mlkem_formats.files(rebuilt).items():
            p = os.path.join(outdir, name)
            if not os.path.exists(p):
                bad.append(f'{name} missing')
                continue
            with open(p) as f:
                if f.read() != text:
                    bad.append(f'{name} differs')
        if bad:
            print(f"{rec['name']}: FAILED: {', '.join(bad)}")
            status = 1
        else:
            print(f"{rec['name']}: rules followed, every file reproduced")
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--profile', default='v1', choices=mlkem_stats.PROFILES)
    parser.add_argument('--seed', type=mlkem_count.parse_seed, default=mlkem_count.DEFAULT_SEED)
    parser.add_argument('--write', metavar='DIR')
    parser.add_argument('--check', nargs='?', const=PUBLISHED, metavar='DIR')
    parser.add_argument('--render', action='store_true', help='the arguments are records to render')
    parser.add_argument('logs', nargs='*')
    args = parser.parse_args()
    mlkem_kat.check_builtin(verbose=False)
    for pset in mlkem_stats.PSETS:
        mlkem_select.rules(pset, 'v1')  # the published rules must match SPEC.md
    if args.check:
        return check(args.check)
    if args.render:
        if not args.write or not args.logs:
            parser.error('--render needs records and --write')
        for path in args.logs:
            rec = mlkem_set.read_record(path)
            rebuilt = mlkem_set.rebuild(rec)
            if rebuilt != rec:
                raise mlkem_set.SetError(f'{path}: fields differ when recomputed')
            write_files(args.write, rebuilt)
        return 0
    if not args.logs:
        parser.error('no log given')
    outdir = args.write or (PUBLISHED if args.profile == 'v1' else None)
    if outdir is None:
        parser.error('--write is required with the test profile')
    if args.profile != 'v1' and os.path.abspath(outdir) == PUBLISHED:
        parser.error('only the v1 profile is published')
    return generate(args.logs, args.profile, args.seed, outdir)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (mlkem_logs.LogError, mlkem_select.SelectionError, mlkem_set.SetError) as ex:
        print(f'ERROR: {ex}', file=sys.stderr)
        sys.exit(1)
