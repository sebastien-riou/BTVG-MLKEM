#!/usr/bin/env python3
"""Runs the test cases of a set through an ML-KEM implementation, here kyber-py.

    .venv/bin/python example.py published/mlkem768-n42-h........py

Replace the three calls marked IMPLEMENTATION by those of the implementation to test. The record
is a file of Python literals: mlkem_set.read_record reads it without executing it.
"""
import hashlib
import sys

from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

import mlkem_set

rec = mlkem_set.read_record(sys.argv[1])
impl = {512: ML_KEM_512, 768: ML_KEM_768, 1024: ML_KEM_1024}[rec['pset']]
failures = 0
for i, case in enumerate(rec['cases']):
    d, z, m = (bytes.fromhex(case[x]) for x in ('d', 'z', 'm'))
    ek, dk = impl._keygen_internal(d, z)  # IMPLEMENTATION: ML-KEM.KeyGen_internal(d, z)
    K, c = impl._encaps_internal(ek, m)  # IMPLEMENTATION: ML-KEM.Encaps_internal(ek, m)
    K_dec = impl._decaps_internal(dk, c)  # IMPLEMENTATION: ML-KEM.Decaps_internal(dk, c)
    # the invalid ciphertext: bit reject_bit of c flipped
    c_reject = bytearray(c)
    c_reject[case['reject_bit'] >> 3] ^= 1 << (case['reject_bit'] & 7)
    K_reject = impl._decaps_internal(dk, bytes(c_reject))  # IMPLEMENTATION: ML-KEM.Decaps_internal(dk, c')
    ok = (hashlib.sha256(ek).hexdigest() == case['pk_sha256'] and hashlib.sha256(dk).hexdigest() == case['sk_sha256']
          and hashlib.sha256(c).hexdigest() == case['ct_sha256'] and K.hex() == case['ss'] and K_dec == K
          and K_reject.hex() == case['ss_reject'])
    if not ok:
        failures += 1
        print(f"case {i} ({case['role']}, index {case['index']}) FAILED")
print(f"{rec['name']}: {len(rec['cases']) - failures} of {len(rec['cases'])} test cases passed")
sys.exit(1 if failures else 0)
