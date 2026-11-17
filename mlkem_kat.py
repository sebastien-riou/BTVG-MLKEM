#!/usr/bin/env python3
"""Known answer tests of the ML-KEM implementations and of SHA-3.

Two levels:
- built-in (kat/kat.json, committed): the ML-KEM known answers of wolfSSL, a few test cases
  extracted from NIST's ACVP sample files (implicit rejection included), and SHA-3 / SHAKE
  answers from NIST's response files. They run before anything is generated.
- full (--full DIR): every ACVP sample test (keyGen, encapsulation, decapsulation), every valid
  Wycheproof test and every byte-oriented SHA-3 / SHAKE answer found under DIR, normally
  git_ignore/vectors (not part of the repository).

--extract DIR rebuilds kat/kat.json from DIR.
"""
import argparse
import glob
import hashlib
import json
import multiprocessing
import os
import sys

from mlkem_impls import IMPLS

HERE = os.path.dirname(os.path.abspath(__file__))
KAT_FILE = os.path.join(HERE, 'kat', 'kat.json')
PSET_OF = {'ML-KEM-512': 512, 'ML-KEM-768': 768, 'ML-KEM-1024': 1024}
SHA3 = {
    'SHA3-256': lambda m, n: hashlib.sha3_256(m).digest(),
    'SHA3-512': lambda m, n: hashlib.sha3_512(m).digest(),
    'SHAKE128': lambda m, n: hashlib.shake_128(m).digest(n),
    'SHAKE256': lambda m, n: hashlib.shake_256(m).digest(n),
}

# wolfSSL ML-KEM known answers (wolfcrypt/test/test.c, mlkem*_kat), as in crypto-benchmark gen-tv.py
WOLFSSL = {
    'd': '7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d',
    'z': '8626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f',
    'm': '147c03f7a5bebba406c8fae1874d7f13c80efe79a3a9a874cc09fe76f6997615',
    512: {
        'ek_sha256': '852523749efd2b78d1074e5de629060312cd9397933a19ddb7482cfda5e92614',
        'dk_sha256': '937a781daf1928b86a64f69dada5feff8b8ade060f298d187090a46c0d205cb7',
        'c_sha256': 'bc29d7df8bc5465d980601d800259793e2603825a572da6cd198a512cc6d1a34',
        'k': '319839e82ab6b222de7b619e80da8391522bbb37677018494a4742c53f9abfdf',
    },
    768: {
        'ek_sha256': '86adbca81f4fee893e2fb58fb98aa2fe188f501fed268d7f4056f8c05c4e53c4',
        'dk_sha256': '8757e8aee5e441aee07a43af40467d32f80aee5c51aae4ebd2bdb844c038aac7',
        'c_sha256': '36829a2f35cbf4deb62c0a12a15c22dae9f8d2c252566fc24f88abe805cb575e',
        'k': 'e7184a0975ee3470878d2d159ec83129c8aec253d4ee17b4810311d198cd0368',
    },
    1024: {
        'ek_sha256': '61b95ec8c32ae85ad7a17ae5b9c2dfb083e05f767da3ba9a0a8092ea6b4cbf7a',
        'dk_sha256': '926ce3868d8fd192e03410d405e61fb32697a532d7ca7d9ba9b296111df3af74',
        'c_sha256': '508136a13f8a7920e3434498c6975cbbab457d809309eb2f92453e7409738210',
        'k': '489dd1e9c2be4af3482bdb35bb26ce760e6e414da6ecbe489985748a825f1cd6',
    },
}


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def h(s):
    return bytes.fromhex(s)


# --- ML-KEM tests ------------------------------------------------------------------------------
# A test is a dict with 'op' in keygen / encaps / decaps / full, 'pset', inputs and expected
# outputs as hexadecimal strings. Large outputs are given by their SHA-256 ('*_sha256').

OUTPUTS = {'keygen': ('ek', 'dk'), 'encaps': ('c', 'k'), 'decaps': ('k',), 'full': ('ek', 'dk', 'c', 'k'),
           'seed_decaps': ('ek', 'dk', 'k')}


def expect(test, key, value):
    if key in test and test[key] != value.hex():
        return f'{key}: got {value.hex()[:16]}...'
    if key + '_sha256' in test and test[key + '_sha256'] != sha256(value):
        return f'{key}: wrong SHA-256'
    return None


def unchecked(test):
    """Expected values which the operation of the test does not produce: a malformed test."""
    inputs = {'keygen': ('d', 'z'), 'encaps': ('ek', 'm'), 'decaps': ('dk', 'c'), 'full': ('d', 'z', 'm'),
              'seed_decaps': ('d', 'z', 'c')}[test['op']]
    known = set(inputs) | set(OUTPUTS[test['op']]) | {o + '_sha256' for o in OUTPUTS[test['op']]}
    extra = [key for key in test if key not in known and key not in ('name', 'op', 'pset', 'reason')]
    present = [o for o in OUTPUTS[test['op']] if o in test or o + '_sha256' in test]
    if extra or not present:
        return f'malformed test: unexpected {extra}, outputs present {present}'
    return None


def run_mlkem_test(impl, test):
    """Returns None when the test passes, else a short description of the failure.

    op: keygen (d, z -> ek, dk), encaps (ek, m -> c, k), decaps (dk, c -> k),
        full (d, z, m -> ek, dk, c, k, then decapsulation of c),
        seed_decaps (d, z, c -> ek, k: decapsulation with the key generated from the seed).
    """
    pset = test['pset']
    op = test['op']
    errors = [unchecked(test)]
    try:
        if op in ('keygen', 'full', 'seed_decaps'):
            ek, dk = impl.keygen(pset, h(test['d']), h(test['z']))
            errors += [expect(test, 'ek', ek), expect(test, 'dk', dk)]
        if op == 'encaps':
            ek = h(test['ek'])
        if op in ('encaps', 'full'):
            K, c = impl.encaps(pset, ek, h(test['m']))
            errors += [expect(test, 'c', c), expect(test, 'k', K)]
        if op == 'decaps':
            dk = h(test['dk'])
        if op in ('decaps', 'seed_decaps'):
            c = h(test['c'])
        if op in ('decaps', 'full', 'seed_decaps'):
            errors.append(expect(test, 'k', impl.decaps(pset, dk, c)))
    except Exception as ex:  # an exception is a failure of the test, not of the tool
        return f'exception {type(ex).__name__}: {ex}'
    errors = [e for e in errors if e]
    return '; '.join(errors) if errors else None


def run_sha3_test(test):
    out = SHA3[test['alg']](h(test['msg']), len(test['out']) // 2)
    return None if out.hex() == test['out'] else 'wrong output'


def _job(args):
    kind, impl_index, test = args
    if kind == 'sha3':
        return run_sha3_test(test)
    return run_mlkem_test(IMPLS[impl_index], test)


def run_all(mlkem_tests, sha3_tests, jobs=1, verbose=True):
    """Runs every test on every implementation. Returns the number of failures."""
    work = [('sha3', None, t) for t in sha3_tests]
    work += [('mlkem', i, t) for i in range(len(IMPLS)) for t in mlkem_tests]
    if jobs > 1:
        with multiprocessing.Pool(jobs) as pool:
            results = pool.map(_job, work, chunksize=1)
    else:
        results = [_job(w) for w in work]
    failures = 0
    for (kind, i, test), res in zip(work, results):
        if res:
            failures += 1
            who = 'hashlib' if kind == 'sha3' else IMPLS[i].name
            print(f'FAIL {who}: {test.get("name", test.get("alg"))}: {res}', file=sys.stderr)
    if verbose:
        print(f'{len(sha3_tests)} SHA-3 tests, {len(mlkem_tests)} ML-KEM tests on {len(IMPLS)} implementations: '
              f'{failures} failures')
    return failures


def builtin_tests():
    with open(KAT_FILE) as f:
        kat = json.load(f)
    return kat['mlkem'], kat['sha3']


def check_builtin(verbose=True):
    """The checks done before generating anything. Raises if one fails."""
    mlkem_tests, sha3_tests = builtin_tests()
    if run_all(mlkem_tests, sha3_tests, verbose=verbose):
        raise RuntimeError('known answer tests failed')


# --- readers of the reference files -------------------------------------------------------------

def wolfssl_tests():
    tests = []
    for pset in (512, 768, 1024):
        w = WOLFSSL[pset]
        tests.append({'name': f'wolfSSL ML-KEM-{pset}', 'op': 'full', 'pset': pset,
                      'd': WOLFSSL['d'], 'z': WOLFSSL['z'], 'm': WOLFSSL['m'],
                      'ek_sha256': w['ek_sha256'], 'dk_sha256': w['dk_sha256'],
                      'c_sha256': w['c_sha256'], 'k': w['k']})
    return tests


def acvp_tests(vectors_dir, paths=None):
    """Every ML-KEM keyGen, encapsulation and decapsulation test of the ACVP sample files found
    under vectors_dir, or of the given files (same layout: internalProjection.json)."""
    tests = []
    if paths is None:
        paths = sorted(glob.glob(os.path.join(vectors_dir, '**', 'internalProjection.json'), recursive=True))
    for path in paths:
        with open(path) as f:
            d = json.load(f)
        if d.get('algorithm') != 'ML-KEM':
            continue
        where = f"ACVP {d['mode']} {d.get('revision')} vsId {d.get('vsId')}"
        for g in d['testGroups']:
            fn = g.get('function', 'keyGen')
            pset = PSET_OF[g['parameterSet']]
            for t in g['tests']:
                name = f"{where} tcId {t['tcId']} ({g['parameterSet']} {fn})"
                low = {key: v.lower() for key, v in t.items() if isinstance(v, str)}
                if fn == 'keyGen':
                    tests.append({'name': name, 'op': 'keygen', 'pset': pset, 'd': low['d'], 'z': low['z'],
                                  'ek': low['ek'], 'dk': low['dk']})
                elif fn == 'encapsulation':
                    tests.append({'name': name, 'op': 'encaps', 'pset': pset, 'ek': low['ek'], 'm': low['m'],
                                  'c': low['c'], 'k': low['k']})
                elif fn == 'decapsulation':
                    tests.append({'name': name + ' ' + t.get('reason', ''), 'op': 'decaps', 'pset': pset,
                                  'dk': low['dk'], 'c': low['c'], 'k': low['k'], 'reason': t.get('reason', '')})
    return tests


def wycheproof_tests(vectors_dir):
    """The valid tests of the Wycheproof ML-KEM files (invalid ones test input checks, out of scope)."""
    tests = []
    for path in sorted(glob.glob(os.path.join(vectors_dir, '**', 'mlkem_*.json'), recursive=True)):
        with open(path) as f:
            d = json.load(f)
        base = os.path.basename(path)
        for g in d['testGroups']:
            pset = PSET_OF[g['parameterSet']]
            for t in g['tests']:
                if t['result'] != 'valid':
                    continue
                name = f"Wycheproof {base} tcId {t['tcId']}"
                if g['type'] == 'MLKEMKeyGen':
                    tests.append({'name': name, 'op': 'keygen', 'pset': pset, 'd': t['seed'][:64],
                                  'z': t['seed'][64:], 'ek': t['ek'], 'dk': t['dk']})
                elif g['type'] == 'MLKEMTest':
                    tests.append({'name': name, 'op': 'seed_decaps', 'pset': pset, 'd': t['seed'][:64],
                                  'z': t['seed'][64:], 'ek': t['ek'], 'c': t['c'], 'k': t['K']})
                elif g['type'] == 'MLKEMEncapsTest':
                    tests.append({'name': name, 'op': 'encaps', 'pset': pset, 'ek': t['ek'], 'm': t['m'],
                                  'c': t['c'], 'k': t['K']})
                elif g['type'] == 'MLKEMDecapsValidationTest':
                    tests.append({'name': name, 'op': 'decaps', 'pset': pset, 'dk': t['dk'], 'c': t['c'], 'k': t['K']})
    return tests


def parse_rsp(path):
    """Byte-oriented entries of a NIST SHA-3 response file: [{'msg', 'out'}]."""
    alg = os.path.basename(path).split('ShortMsg')[0].split('LongMsg')[0].split('VariableOut')[0]
    alg = alg.replace('SHA3_', 'SHA3-')
    entries = []
    cur = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if ' = ' not in line or line.startswith('['):
                continue
            key, value = (x.strip() for x in line.split(' = ', 1))
            cur[key] = value
            if key in ('MD', 'Output'):
                bits = int(cur.get('Len', 8 * (len(cur['Msg']) // 2)))
                if bits % 8 == 0 and int(cur.get('Outputlen', 0)) % 8 == 0:
                    msg = cur['Msg'] if bits else ''
                    entries.append({'name': f'{os.path.basename(path)} {len(entries)}', 'alg': alg,
                                    'msg': msg.lower(), 'out': value.lower()})
                cur = {}
    return entries


def sha3_tests(vectors_dir):
    tests = []
    for path in sorted(glob.glob(os.path.join(vectors_dir, '**', '*.rsp'), recursive=True)):
        if 'Monte' not in path:
            tests += parse_rsp(path)
    return tests


# --- built-in selection --------------------------------------------------------------------------

def extract(vectors_dir):
    """Builds the content of kat/kat.json from the reference files."""
    acvp = acvp_tests(vectors_dir)
    picked = []
    for pset in (512, 768, 1024):
        for op, reason in (('keygen', None), ('encaps', None), ('decaps', 'valid decapsulation'),
                           ('decaps', 'modified ciphertext')):
            for t in acvp:
                if t['pset'] == pset and t['op'] == op and 'FIPS203 ' in t['name'] and \
                        (reason is None or t['reason'] == reason):
                    t = dict(t)
                    # large outputs are kept as their SHA-256, inputs in full
                    outputs = {'keygen': ('ek', 'dk'), 'encaps': ('c',), 'decaps': ()}[op]
                    for key in outputs:
                        t[key + '_sha256'] = sha256(h(t.pop(key)))
                    picked.append(t)
                    break
            else:
                raise RuntimeError(f'no ACVP {op} {reason} test for ML-KEM-{pset} in {vectors_dir}')
    sha3 = []
    by_file = {}
    for t in sha3_tests(vectors_dir):
        by_file.setdefault(t['name'].rsplit(' ', 1)[0], []).append(t)
    for name in ('SHA3_512ShortMsg.rsp', 'SHAKE128ShortMsg.rsp', 'SHAKE256ShortMsg.rsp',
                 'SHAKE128VariableOut.rsp', 'SHAKE256VariableOut.rsp'):
        entries = by_file[name]
        # the empty message, one byte, and the longest message (several blocks absorbed)
        sha3 += [entries[0], entries[1], max(entries, key=lambda t: (len(t['msg']), len(t['out'])))]
    return {
        'comment': 'Built-in known answer tests, extracted by mlkem_kat.py --extract from wolfSSL (ML-KEM), '
                   "NIST's ACVP sample files (ML-KEM, revision FIPS203) and NIST's SHA-3 response files. "
                   'Values are hexadecimal; *_sha256 is the SHA-256 of a large output.',
        'mlkem': wolfssl_tests() + picked,
        'sha3': sha3,
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--full', metavar='DIR', help='run every test found under DIR (e.g. git_ignore/vectors)')
    parser.add_argument('--extract', metavar='DIR', help='rebuild kat/kat.json from DIR')
    parser.add_argument('--jobs', type=int, default=os.cpu_count(), help='processes for --full (default: all CPUs)')
    args = parser.parse_args()
    if args.extract:
        content = extract(args.extract)
        os.makedirs(os.path.dirname(KAT_FILE), exist_ok=True)
        with open(KAT_FILE, 'w') as f:
            json.dump(content, f, indent=1)
            f.write('\n')
        print(f"{KAT_FILE}: {len(content['mlkem'])} ML-KEM tests, {len(content['sha3'])} SHA-3 tests")
    if args.full:
        mlkem = wolfssl_tests() + acvp_tests(args.full) + wycheproof_tests(args.full)
        sys.exit(1 if run_all(mlkem, sha3_tests(args.full), jobs=args.jobs) else 0)
    if not args.extract:
        mlkem, sha3 = builtin_tests()
        sys.exit(1 if run_all(mlkem, sha3) else 0)
