"""The two independent ML-KEM implementations used to compute expected values.

Both expose the internal (derandomized) algorithms of FIPS 203 section 6 with the same interface:
    keygen(pset, d, z) -> (ek, dk)
    encaps(pset, ek, m) -> (K, c)
    decaps(pset, dk, c) -> K'

They share Python's hashlib for SHA-3 and SHAKE: they are independent for the arithmetic and the
encodings only. SHA-3 itself is checked against NIST's known answers (mlkem_kat.py).
"""
import mlkem_fips203


class Fips203:
    name = 'mlkem_fips203'

    @staticmethod
    def keygen(pset, d, z):
        return mlkem_fips203.keygen(pset, d, z)

    @staticmethod
    def encaps(pset, ek, m):
        return mlkem_fips203.encaps(pset, ek, m)

    @staticmethod
    def decaps(pset, dk, c):
        return mlkem_fips203.decaps(pset, dk, c)


class KyberPy:
    name = 'kyber-py'

    @staticmethod
    def _impl(pset):
        from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024
        return {512: ML_KEM_512, 768: ML_KEM_768, 1024: ML_KEM_1024}[pset]

    @classmethod
    def keygen(cls, pset, d, z):
        return cls._impl(pset)._keygen_internal(d, z)

    @classmethod
    def encaps(cls, pset, ek, m):
        return cls._impl(pset)._encaps_internal(ek, m)

    @classmethod
    def decaps(cls, pset, dk, c):
        return cls._impl(pset)._decaps_internal(dk, c)


IMPLS = (Fips203, KyberPy)
