"""Straightforward implementation of ML-KEM (FIPS 203), Python standard library only.

Slow and not constant time: it computes expected values, nothing else. SampleNTT reports its
number of iterations, so that the cost of a key (SPEC.md section 2) can be counted by the same
code which generates the keys.

Ported from crypto-benchmark/libmlkem-lbmk/gen-tv.py (same author, Apache-2.0).
"""
import hashlib

Q = 3329
N = 256

PARAMS = {
    512: {'k': 2, 'eta1': 3, 'eta2': 2, 'du': 10, 'dv': 4},
    768: {'k': 3, 'eta1': 2, 'eta2': 2, 'du': 10, 'dv': 4},
    1024: {'k': 4, 'eta1': 2, 'eta2': 2, 'du': 11, 'dv': 5},
}


def ek_size(pset):
    return 384 * PARAMS[pset]['k'] + 32


def dk_size(pset):
    return 768 * PARAMS[pset]['k'] + 96


def ct_size(pset):
    p = PARAMS[pset]
    return 32 * (p['du'] * p['k'] + p['dv'])


def bitrev7(i):
    return int(f'{i:07b}'[::-1], 2)


ZETAS = [pow(17, bitrev7(i), Q) for i in range(128)]
GAMMAS = [pow(17, 2 * bitrev7(i) + 1, Q) for i in range(128)]


def H(s):
    return hashlib.sha3_256(s).digest()


def J(s):
    return hashlib.shake_256(s).digest(32)


def G(s):
    d = hashlib.sha3_512(s).digest()
    return d[:32], d[32:]


def PRF(eta, s, b):
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


def bytes_to_bits(b):
    return [(byte >> i) & 1 for byte in b for i in range(8)]


def bits_to_bytes(bits):
    return bytes(sum(bits[i + j] << j for j in range(8)) for i in range(0, len(bits), 8))


def byte_encode(d, f):
    bits = [(a >> j) & 1 for a in f for j in range(d)]
    return bits_to_bytes(bits)


def byte_decode(d, b):
    m = Q if d == 12 else 1 << d
    bits = bytes_to_bits(b)
    return [sum(bits[i * d + j] << j for j in range(d)) % m for i in range(N)]


def compress(d, f):
    # round(2^d/q * x) mod 2^d, rounding half up
    return [((x << (d + 1)) + Q) // (2 * Q) % (1 << d) for x in f]


def decompress(d, f):
    # round(q/2^d * y), rounding half up
    return [(y * Q * 2 + (1 << d)) >> (d + 1) for y in f]


def sample_ntt(b):
    """Algorithm 7. Returns the coefficients and the number of iterations of the loop."""
    size = 3 * 168
    while True:
        c = hashlib.shake_128(b).digest(size)
        a = []
        pos = 0
        while len(a) < N and pos + 3 <= size:
            d1 = c[pos] + 256 * (c[pos + 1] % 16)
            d2 = c[pos + 1] // 16 + 16 * c[pos + 2]
            pos += 3
            if d1 < Q:
                a.append(d1)
            if d2 < Q and len(a) < N:
                a.append(d2)
        if len(a) == N:
            return a, pos // 3
        size += 168


def sample_cbd(eta, b):
    bits = bytes_to_bits(b)
    f = []
    for i in range(N):
        x = sum(bits[2 * i * eta + j] for j in range(eta))
        y = sum(bits[2 * i * eta + eta + j] for j in range(eta))
        f.append((x - y) % Q)
    return f


def ntt(f):
    f = list(f)
    i = 1
    length = 128
    while length >= 2:
        for start in range(0, N, 2 * length):
            zeta = ZETAS[i]
            i += 1
            for j in range(start, start + length):
                t = zeta * f[j + length] % Q
                f[j + length] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
        length //= 2
    return f


def ntt_inv(f):
    f = list(f)
    i = 127
    length = 2
    while length <= 128:
        for start in range(0, N, 2 * length):
            zeta = ZETAS[i]
            i -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = zeta * (f[j + length] - t) % Q
        length *= 2
    return [x * 3303 % Q for x in f]


def multiply_ntts(f, g):
    h = [0] * N
    for i in range(128):
        a0, a1 = f[2 * i], f[2 * i + 1]
        b0, b1 = g[2 * i], g[2 * i + 1]
        h[2 * i] = (a0 * b0 + a1 * b1 * GAMMAS[i]) % Q
        h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return h


def poly_add(f, g):
    return [(a + b) % Q for a, b in zip(f, g)]


def poly_sub(f, g):
    return [(a - b) % Q for a, b in zip(f, g)]


def gen_matrix(k, rho):
    """a_hat[i][j] = SampleNTT(rho || j || i), and the iterations of each entry, row-major."""
    a_hat = []
    iterations = []
    for i in range(k):
        row = []
        for j in range(k):
            a, it = sample_ntt(rho + bytes([j, i]))
            row.append(a)
            iterations.append(it)
        a_hat.append(row)
    return a_hat, iterations


def dot(u, v):
    acc = [0] * N
    for a, b in zip(u, v):
        acc = poly_add(acc, multiply_ntts(a, b))
    return acc


def kpke_keygen(p, d):
    k = p['k']
    rho, sigma = G(d + bytes([k]))
    a_hat, _ = gen_matrix(k, rho)
    s = [sample_cbd(p['eta1'], PRF(p['eta1'], sigma, i)) for i in range(k)]
    e = [sample_cbd(p['eta1'], PRF(p['eta1'], sigma, k + i)) for i in range(k)]
    s_hat = [ntt(x) for x in s]
    e_hat = [ntt(x) for x in e]
    t_hat = [poly_add(dot(a_hat[i], s_hat), e_hat[i]) for i in range(k)]
    ek = b''.join(byte_encode(12, x) for x in t_hat) + rho
    dk = b''.join(byte_encode(12, x) for x in s_hat)
    return ek, dk


def kpke_encrypt(p, ek, m, r):
    k = p['k']
    t_hat = [byte_decode(12, ek[384 * i:384 * (i + 1)]) for i in range(k)]
    rho = ek[384 * k:384 * k + 32]
    a_hat, _ = gen_matrix(k, rho)
    y = [sample_cbd(p['eta1'], PRF(p['eta1'], r, i)) for i in range(k)]
    e1 = [sample_cbd(p['eta2'], PRF(p['eta2'], r, k + i)) for i in range(k)]
    e2 = sample_cbd(p['eta2'], PRF(p['eta2'], r, 2 * k))
    y_hat = [ntt(x) for x in y]
    u = [poly_add(ntt_inv(dot([a_hat[j][i] for j in range(k)], y_hat)), e1[i]) for i in range(k)]
    mu = decompress(1, byte_decode(1, m))
    v = poly_add(poly_add(ntt_inv(dot(t_hat, y_hat)), e2), mu)
    c1 = b''.join(byte_encode(p['du'], compress(p['du'], x)) for x in u)
    c2 = byte_encode(p['dv'], compress(p['dv'], v))
    return c1 + c2


def kpke_decrypt(p, dk, c):
    k = p['k']
    du = p['du']
    dv = p['dv']
    c1 = c[:32 * du * k]
    c2 = c[32 * du * k:]
    u = [decompress(du, byte_decode(du, c1[32 * du * i:32 * du * (i + 1)])) for i in range(k)]
    v = decompress(dv, byte_decode(dv, c2))
    s_hat = [byte_decode(12, dk[384 * i:384 * (i + 1)]) for i in range(k)]
    w = poly_sub(v, ntt_inv(dot(s_hat, [ntt(x) for x in u])))
    return byte_encode(1, compress(1, w))


def keygen(pset, d, z):
    """ML-KEM.KeyGen_internal (Algorithm 16): returns (ek, dk)."""
    p = PARAMS[pset]
    ek, dk_pke = kpke_keygen(p, d)
    return ek, dk_pke + ek + H(ek) + z


def encaps(pset, ek, m):
    """ML-KEM.Encaps_internal (Algorithm 17): returns (K, c)."""
    p = PARAMS[pset]
    K, r = G(m + H(ek))
    return K, kpke_encrypt(p, ek, m, r)


def decaps(pset, dk, c):
    """ML-KEM.Decaps_internal (Algorithm 18): returns K'."""
    p = PARAMS[pset]
    k = p['k']
    dk_pke = dk[:384 * k]
    ek = dk[384 * k:768 * k + 32]
    h = dk[768 * k + 32:768 * k + 64]
    z = dk[768 * k + 64:768 * k + 96]
    m = kpke_decrypt(p, dk_pke, c)
    K, r = G(m + h)
    K_bar = J(z + c)
    if c != kpke_encrypt(p, ek, m, r):
        return K_bar
    return K


def matrix_iterations(pset, ek):
    """Iterations of the k*k entries of A (row-major), as run by the operations on that key."""
    k = PARAMS[pset]['k']
    _, iterations = gen_matrix(k, ek[384 * k:384 * k + 32])
    return iterations
