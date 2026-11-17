#!/usr/bin/env python3
"""Tests of the output files of every set found in a folder (published/ by default).

    test/test_formats.py [DIR]

- C: the data files are compiled with -Wpedantic -Werror; the program dumps the memory of each set,
  which must be the image of SPEC.md section 5 (little-endian host) and give the digest of its name.
- JSON: run through the same ACVP runner as NIST's files (mlkem_kat.py) on both implementations,
  and the annotations compared with the record.
- SystemVerilog: compiled by pyslang without any diagnostic, every parameter read back and
  compared with the record.
- Python: the record read without executing it.
"""
import glob
import hashlib
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import mlkem_formats  # noqa: E402
import mlkem_kat  # noqa: E402
import mlkem_set  # noqa: E402


def check_c(directory, recs):
    with tempfile.TemporaryDirectory() as tmp:
        prog = os.path.join(tmp, 'dump.c')
        lines = ['#include <stdio.h>', f'#include "{mlkem_formats.C_HEADER}"']
        for rec in recs:
            lines.append(f'#include "{rec["name"]}.c"')
        lines += ['static void dump(const mlkem_test_vectors_t *tv) {',
                  '  const unsigned char *p = (const unsigned char *)tv->cases;',
                  '  size_t i;',
                  '  printf("%s %u %u %u ", tv->name, tv->mlkem_pset, tv->ncases, (unsigned)sizeof(mlkem_test_case_t));',
                  '  for (i = 0; i < tv->ncases * sizeof(mlkem_test_case_t); i++) printf("%02x", p[i]);',
                  '  printf("\\n");', '}', 'int main(void) {']
        for rec in recs:
            lines.append(f'  dump(&mlkem{rec["pset"]}_test_vectors);')
        lines += ['  return 0;', '}']
        with open(prog, 'w') as f:
            f.write('\n'.join(lines) + '\n')
        exe = os.path.join(tmp, 'dump')
        subprocess.run(['gcc', '-std=c99', '-Wall', '-Wextra', '-Wpedantic', '-Werror', '-I', directory, '-o', exe, prog],
                       check=True)
        out = subprocess.run([exe], capture_output=True, text=True, check=True).stdout.splitlines()
    assert sys.byteorder == 'little', 'the memory image is checked on little-endian hosts only'
    for rec, line in zip(recs, out):
        name, pset, ncases, size, memory = line.split()
        assert (name, int(pset), int(ncases), int(size)) == (rec['name'], rec['pset'], len(rec['cases']), 260)
        memory = bytes.fromhex(memory)
        assert memory == b''.join(mlkem_set.image(c) for c in rec['cases'])
        d = hashlib.sha256(mlkem_set.SET_LABEL + b'\x00' + rec['pset'].to_bytes(2, 'little')
                           + len(rec['cases']).to_bytes(2, 'little') + memory).digest()
        assert name == f"mlkem{rec['pset']}-n{len(rec['cases'])}-h{d[:4].hex().upper()}"
    print(f'  C: {len(recs)} sets compiled, memory images give their names')


def check_json(directory, rec):
    paths = [os.path.join(directory, f"{rec['name']}-{m}.json") for m in ('keyGen', 'encapDecap')]
    tests = mlkem_kat.acvp_tests(None, paths)
    n = len(rec['cases'])
    assert len(tests) == 4 * n, f'{len(tests)} tests'
    assert mlkem_kat.run_all(tests, [], verbose=False) == 0
    keygen, encdec = (json.load(open(p)) for p in paths)
    for doc in (keygen, encdec):
        assert doc['source']['set'] == rec['name'] and doc['source']['digest'] == rec['digest'].upper()
        assert doc['source']['version'] == rec['version']
    for t, c in zip(keygen['testGroups'][0]['tests'], rec['cases']):
        assert (t['d'], t['z']) == (c['d'].upper(), c['z'].upper())
        assert (t['role'], t['tier'], t['index'], t['probability']) == (c['role'], c['tier'], c['index'], c['probability'])
        assert (t['extraBlocks'], t['iterations'], t['entryIterations']) == (c['e'], c['t'], list(c['iterations']))
        assert hashlib.sha256(bytes.fromhex(t['ek'])).hexdigest() == c['pk_sha256']
        assert hashlib.sha256(bytes.fromhex(t['dk'])).hexdigest() == c['sk_sha256']
    enc, dec = encdec['testGroups']
    for i, c in enumerate(rec['cases']):
        t = enc['tests'][i]
        assert (t['m'], t['k'], t['case']) == (c['m'].upper(), c['ss'].upper(), i)
        assert hashlib.sha256(bytes.fromhex(t['c'])).hexdigest() == c['ct_sha256']
        valid, modified = dec['tests'][2 * i], dec['tests'][2 * i + 1]
        assert (valid['k'], modified['k']) == (c['ss'].upper(), c['ss_reject'].upper())
        assert valid['c'] == t['c'] and modified['rejectBit'] == c['reject_bit']
        assert bytes.fromhex(modified['c']) == mlkem_set.flip(bytes.fromhex(t['c']), c['reject_bit'])
    print(f"  JSON {rec['name']}: {len(tests)} ACVP tests passed on both implementations, annotations match")


def check_sv(directory, rec):
    import pyslang
    from pyslang.ast import Compilation
    from pyslang.syntax import SyntaxTree
    tree = SyntaxTree.fromFile(os.path.join(directory, f"{rec['name']}.sv"))
    comp = Compilation()
    comp.addSyntaxTree(tree)
    diags = list(comp.getAllDiagnostics())
    assert not diags, [str(d.code) for d in diags]
    pkg = comp.getPackage(rec['name'].replace('-', '_'))

    def value(name):
        return pkg.lookupName(name).value.value

    def byte_strings(name, size):
        return [int(v.value.toString(pyslang.LiteralBase.Hex, False), 16).to_bytes(size, 'little')
                for v in value(name)]

    def ints(name):
        return [int(v.value) for v in value(name)]

    cases = rec['cases']
    full = [mlkem_set.full_values(rec['pset'], c) for c in cases]
    assert int(value('MLKEM_PSET')) == rec['pset'] and int(value('N_CASES')) == len(cases)
    for name, key in (('D', 'd'), ('Z', 'z'), ('M', 'm'), ('SS', 'ss'), ('SS_REJECT', 'ss_reject'),
                      ('PK_SHA256', 'pk_sha256'), ('SK_SHA256', 'sk_sha256'), ('CT_SHA256', 'ct_sha256')):
        assert byte_strings(name, 32) == [bytes.fromhex(c[key]) for c in cases], name
    for name, key in (('EK', 'ek'), ('DK', 'dk'), ('CT', 'c')):
        assert byte_strings(name, len(full[0][key])) == [f[key] for f in full], name
    roles = {'best': 0, 'worst': 1, 'average': 2}
    assert ints('REJECT_BIT') == [c['reject_bit'] for c in cases]
    assert ints('ROLE') == [roles[c['role']] for c in cases]
    assert ints('TIER') == [c['tier'] for c in cases]
    assert ints('EXTRA_BLOCKS') == [c['e'] for c in cases]
    assert ints('ITERATIONS') == [c['t'] for c in cases]
    assert [[int(x.value) for x in row.value] for row in value('ENTRY_ITERATIONS')] == \
        [list(c['iterations']) for c in cases]
    print(f"  SystemVerilog {rec['name']}: no diagnostic, every parameter matches")


def main():
    directory = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, 'published')
    recs = [mlkem_set.read_record(p) for p in sorted(glob.glob(os.path.join(directory, 'mlkem*.py')))]
    assert recs, f'no record in {directory}'
    by_pset = {}
    for rec in recs:
        by_pset.setdefault(rec['pset'], []).append(rec)
    for group in zip(*by_pset.values()):  # one set of each parameter set per program
        check_c(directory, list(group))
    for rec in recs:
        check_json(directory, rec)
        check_sv(directory, rec)
    print('all tests passed')


if __name__ == '__main__':
    main()
