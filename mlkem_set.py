"""A set of test vectors: computation of its test cases, image, digest, name and record.

See SPEC.md sections 4, 5 and 7.
"""
import ast
import hashlib
import os
import subprocess

import mlkem_count
import mlkem_fips203
import mlkem_select
from mlkem_impls import IMPLS

SET_LABEL = b'BTVG-MLKEM set v1'
RECORD_FORMAT = 1
ROLE_CODES = {'best': 0, 'worst': 1, 'average': 2}
HERE = os.path.dirname(os.path.abspath(__file__))


class SetError(Exception):
    pass


def version():
    """Version of the generator, from the git release tags (SPEC.md section 8): 1.2.3 on the commit
    tagged v1.2.3, 1.2.3-4-gabcdef0 four commits after it, -dirty appended for uncommitted changes."""
    try:
        out = subprocess.run(['git', 'describe', '--tags', '--match', 'v[0-9]*', '--dirty'], cwd=HERE,
                             capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as ex:
        raise SetError(f'no version: git describe finds no release tag ({ex})')
    return out[1:]


def flip(c, reject_bit):
    c = bytearray(c)
    c[reject_bit >> 3] ^= 1 << (reject_bit & 7)
    return bytes(c)


def compute_case(pset, seed, role, tier, index, probability):
    """Every value of a test case, computed and cross-checked (SPEC.md section 4)."""
    d, z, m, r = mlkem_count.derive(seed, index)
    reject_bit = mlkem_count.reject_bit(pset, r)
    outputs = []
    for impl in IMPLS:
        ek, dk = impl.keygen(pset, d, z)
        K, c = impl.encaps(pset, ek, m)
        K_dec = impl.decaps(pset, dk, c)
        K_rej = impl.decaps(pset, dk, flip(c, reject_bit))
        if K_dec != K:
            raise SetError(f'ML-KEM-{pset} index {index}: {impl.name}: decapsulation does not give K')
        outputs.append((ek, dk, c, K, K_rej))
    if any(o != outputs[0] for o in outputs):
        raise SetError(f'ML-KEM-{pset} index {index}: the implementations disagree')
    ek, dk, c, K, K_rej = outputs[0]
    if K_rej != mlkem_fips203.J(z + flip(c, reject_bit)) or K_rej == K:
        raise SetError(f'ML-KEM-{pset} index {index}: wrong implicit rejection')
    # cost: the generation of A run by the operations on this key, and the fast counter
    iterations = mlkem_fips203.matrix_iterations(pset, ek)
    e, t = mlkem_count.cost(iterations)
    ne, nt, nits = mlkem_count.count_keys(pset, seed, index, 1)
    if (int(ne[0]), int(nt[0]), [int(x) for x in nits[0]]) != (e, t, iterations):
        raise SetError(f'ML-KEM-{pset} index {index}: the counters disagree')
    sha = lambda b: hashlib.sha256(b).hexdigest()  # noqa: E731
    return {
        'role': role, 'tier': tier, 'index': index, 'probability': probability,
        'e': e, 't': t, 'iterations': iterations,
        'd': d.hex(), 'z': z.hex(), 'm': m.hex(), 'reject_bit': reject_bit,
        'pk_sha256': sha(ek), 'sk_sha256': sha(dk), 'ct_sha256': sha(c), 'ss': K.hex(), 'ss_reject': K_rej.hex(),
    }


def full_values(pset, case):
    """ek, dk, c, c' of a test case (for the formats which carry them in full)."""
    d, z, m = (bytes.fromhex(case[x]) for x in ('d', 'z', 'm'))
    ek, dk = mlkem_fips203.keygen(pset, d, z)
    _, c = mlkem_fips203.encaps(pset, ek, m)
    return {'ek': ek, 'dk': dk, 'c': c, 'c_reject': flip(c, case['reject_bit'])}


def image(case):
    """The 260 bytes of a test case in a firmware (SPEC.md section 5)."""
    out = bytes.fromhex(case['d'] + case['z'] + case['m'] + case['pk_sha256'] + case['sk_sha256'] + case['ct_sha256']
                        + case['ss'] + case['ss_reject'])
    out += case['reject_bit'].to_bytes(2, 'little') + bytes([ROLE_CODES[case['role']], case['tier']])
    assert len(out) == 260
    return out


def digest(pset, cases):
    h = hashlib.sha256(SET_LABEL + b'\x00' + pset.to_bytes(2, 'little') + len(cases).to_bytes(2, 'little'))
    for c in cases:
        h.update(image(c))
    return h.digest()


def set_name(pset, cases):
    return f'mlkem{pset}-n{len(cases)}-h{digest(pset, cases)[:4].hex().upper()}'


def build(pset, seed, profile, selected, searched, generator_version):
    """A set from selected cases (mlkem_select): {record fields}."""
    cases = []
    for sel in selected:
        c = compute_case(pset, seed, sel['role'], sel['tier'], sel['index'], sel['prob'])
        if (c['e'], c['t'], tuple(c['iterations'])) != (sel['e'], sel['t'], tuple(sel['iterations'])):
            raise SetError(f"ML-KEM-{pset} index {sel['index']}: cost differs from the search log")
        cases.append(c)
    r = mlkem_select.rules(pset, profile)
    return {
        'format': RECORD_FORMAT,
        'name': set_name(pset, cases),
        'version': generator_version,
        'derivation': mlkem_count.LABEL.decode(),
        'seed': seed.hex(),
        'pset': pset,
        'rules': profile,
        'rules_constants': {key: r[key] for key in ('best', 'tiers', 'average')},
        'searched': dict(searched),
        'digest': digest(pset, cases).hex(),
        'cases': cases,
    }


RECORD_KEYS = ('format', 'name', 'version', 'derivation', 'seed', 'pset', 'rules', 'rules_constants', 'searched',
               'digest', 'cases')
CASE_KEYS = ('role', 'tier', 'index', 'probability', 'e', 't', 'iterations', 'd', 'z', 'm', 'reject_bit',
             'pk_sha256', 'sk_sha256', 'ct_sha256', 'ss', 'ss_reject')


def record_text(rec):
    """The record as a Python file of assignments of literals (deterministic)."""
    lines = [
        f"# BTVG-MLKEM test vectors: record of the set {rec['name']} (SPEC.md section 7).",
        f"# Generated by BTVG-MLKEM {rec['version']}, do not edit. Python literals only.",
    ]
    for key in RECORD_KEYS[:-1]:
        lines.append(f'{key} = {rec[key]!r}')
    lines.append('cases = [')
    for c in rec['cases']:
        lines.append('    {')
        for key in CASE_KEYS:
            lines.append(f'        {key!r}: {c[key]!r},')
        lines.append('    },')
    lines.append(']')
    return '\n'.join(lines) + '\n'


def read_record(path):
    """Reads a record without executing it: only assignments of literals are accepted."""
    with open(path) as f:
        tree = ast.parse(f.read(), path)
    rec = {}
    for node in tree.body:
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)):
            raise SetError(f'{path}: only assignments of literals are allowed')
        rec[node.targets[0].id] = ast.literal_eval(node.value)
    if tuple(rec) != RECORD_KEYS or any(tuple(c) != CASE_KEYS for c in rec['cases']):
        raise SetError(f'{path}: unexpected content')
    return rec


def rebuild(rec):
    """The set recomputed from the inputs of a record (SPEC.md section 7), its version kept."""
    if rec['format'] != RECORD_FORMAT or rec['derivation'] != mlkem_count.LABEL.decode():
        raise SetError(f"{rec['name']}: unsupported record")
    selected = []
    for c in rec['cases']:
        selected.append({'role': c['role'], 'tier': c['tier'], 'index': c['index'], 'prob': c['probability'],
                         'e': c['e'], 't': c['t'], 'iterations': c['iterations']})
    return build(rec['pset'], bytes.fromhex(rec['seed']), rec['rules'], selected, rec['searched'], rec['version'])
