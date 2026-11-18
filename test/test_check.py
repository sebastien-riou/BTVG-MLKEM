#!/usr/bin/env python3
"""Tests of the rules check of the records (mlkem_select.check_record, run by mlkem-tvgen.py --check).

    test/test_check.py [RECORD...]   default: the golden records of test/golden

Each record must pass. Then copies of it, each broken in one way, must all be reported: a case
which does not meet its rule, a wrong probability, a case beyond the searched range, a missing or
misplaced case, a shifted average set, changed rules constants.
"""
import copy
import glob
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import mlkem_select  # noqa: E402
import mlkem_set  # noqa: E402


def variants(rec):
    """(description, broken copy of rec)."""
    n = rec['rules_constants']['average']['n']
    head = len(rec['cases']) - n
    out = []

    def variant(what, change):
        r = copy.deepcopy(rec)
        change(r)
        out.append((what, r))

    def best_is_slow(r):
        r['cases'][0]['t'] = r['rules_constants']['best']['t'] + 1
    variant('best case too slow', best_is_slow)

    def worst_is_fast(r):
        r['cases'][1]['e'] -= 1
    variant('worst case with too few extra blocks', worst_is_fast)

    def wrong_probability(r):
        r['cases'][1]['probability'] = '2^-20.00'
    variant('wrong probability', wrong_probability)

    def beyond_search(r):
        r['searched']['tier 1'] = r['cases'][1]['index']
    variant('worst case beyond the searched range', beyond_search)

    def no_worst(r):
        del r['cases'][1]
    variant('tier 1 missing', no_worst)

    def swapped(r):
        r['cases'][0], r['cases'][1] = r['cases'][1], r['cases'][0]
    variant('best and worst swapped', swapped)

    def shifted_average(r):
        for c in r['cases'][head:]:
            c['index'] += 1
    variant('average set shifted', shifted_average)

    def average_moved(r):
        r['cases'].append(r['cases'].pop(head))
    variant('average set reordered', average_moved)

    def constants(r):
        r['rules_constants']['best']['t'] += 1
    variant('rules constants changed', constants)

    def searched_keys(r):
        r['searched']['tier 9'] = 0
    variant('unknown searched range', searched_keys)
    return out


def main():
    paths = sys.argv[1:] or sorted(glob.glob(os.path.join(HERE, 'golden', 'mlkem*.py')))
    failures = 0
    for path in paths:
        rec = mlkem_set.read_record(path)
        problems = mlkem_select.check_record(rec)
        if problems:
            print(f"{rec['name']}: FAILED, the record itself is reported: {problems}")
            failures += 1
        for what, broken in variants(rec):
            if not mlkem_select.check_record(broken):
                print(f"{rec['name']}: FAILED, not reported: {what}")
                failures += 1
        print(f"{rec['name']}: passes, {len(variants(rec))} broken copies reported")
    if failures:
        print(f'{failures} failures')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
