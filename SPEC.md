# BTVG-MLKEM specification

This document defines the test vectors precisely: how the keys are derived, how their cost is counted, how the test cases are selected, and how a set is named and recorded. [README.md](README.md) explains why.

Every definition carries a version label (`BTVG-MLKEM-v1`, rules `v1`, set `v1`, log format `1`). Once a set has been published with a definition, that definition never changes: a change takes a new label, and sets made with it get new names.

## 1. Stream of keys

All the inputs of a test case derive from a 64-bit index:

```
out = SHAKE256("BTVG-MLKEM-v1" || seed || index, 104 bytes)
      "BTVG-MLKEM-v1": 13 ASCII bytes, no terminator
      seed:  8 bytes
      index: 8 bytes, little-endian
d = out[0:32]    z = out[32:64]    m = out[64:96]    r = out[96:104] as an unsigned 64-bit integer, little-endian
```

- `seed` is written as 16 hexadecimal digits. The published sets use `0000000000000000`.
- The same stream serves the three parameter sets. Their keys are unrelated anyway, since ρ depends on k (section 2).
- Searches are split by ranges of indices, never by seed, so that "the first index" means the same thing on every machine.

A test case uses:
- `keygen_seed = d || z`, the input of `ML-KEM.KeyGen_internal(d, z)`;
- `encaps_seed = m`, the input of `ML-KEM.Encaps_internal(ek, m)`;
- `reject_bit = r mod (8 * |c|)`, where `|c|` is the size of the ciphertext: 768, 1088 or 1568 bytes. The invalid ciphertext `c'` is the ciphertext `c` with bit `reject_bit mod 8` (0 is the least significant bit) of byte `floor(reject_bit / 8)` flipped. Its decapsulation shall output the implicit rejection value `J(z || c')`.

## 2. Cost of a key

- `ρ = SHA3-512(d || k)[0:32]`, with k = 2, 3 or 4 as one byte (step 1 of K-PKE.KeyGen).
- The entry (i, j) of Â, i its row and j its column, is `SampleNTT(ρ || j || i)` (FIPS 203 Algorithm 7). Its number of iterations `it(i, j)` is the number of executions of the loop of Algorithm 7, i.e. the number of 3-byte groups read from SHAKE128.
- Its number of SHAKE128 blocks is `ceil(it(i, j) / 56)`: 3, 4 or 5.
- For a key: `e` = the number of extra blocks, i.e. the sum over the k² entries of (blocks − 3), and `t` = the sum of the iterations of the k² entries.
- Per entry counts are listed in row-major order: the entry (i, j) comes at position i·k + j.

FIPS 203 Appendix B allows an implementation to stop after 280 iterations (5 blocks). An entry needing more has a probability of 2^-261. The search tool reports it as an error rather than continuing.

## 3. Selection rules v1

The rules depend on the parameter set only through the constants below. `mlkem_stats.py` computes them from the exact distribution of `it`, and the generator recomputes them and refuses to run if they differ from this table.

| Rules v1 | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|---|---|---|---|
| Best case: T, P(e = 0 and t ≤ T) | 585, 2^-28.18 | 1349, 2^-28.12 | 2428, 2^-28.37 |
| Worst case tier 1: X, P(e ≥ X) | 4, 2^-27.63 | 5, 2^-27.60 | 6, 2^-28.58 |
| Worst case tier 2: X, P(e ≥ X) | none | 6, 2^-35.09 | 7, 2^-34.97 |
| Average set: N, X_avg, S | 30, 1, 18929 | 40, 3, 56787 | 15, 2, 37858 |
| Test cases, with tier 2 | 32 | 43 | 18 |

How the constants are defined:
- **T** is the largest value with P(e = 0 and t ≤ T) ≤ 2^-28.
- **X** of a tier is the value whose tail probability P(e ≥ X) is the nearest to the target of the tier, measured on the base 2 logarithm. The targets are 2^-28 for tier 1 and 2^-35 for tier 2. A tier with the same X as the previous one does not exist.
- **N** is the smallest number of keys such that N·k² is a multiple of 120. An entry needs a 4th block with probability 1/120.08, so N keys hold X_avg = N·k²/120 extra blocks on average.
- **S** = round(N·k²·μ), with μ = 157.7411 the expected number of iterations of an entry.

The selection reads the keys whose index is below P, the end of a searched range starting at index 0 with no gap (section 6):

```
best        = the smallest index i < P with e(i) = 0 and t(i) <= T
worst[tier] = the smallest index i < P with e(i) = X[tier]
average     = the N consecutive keys a, a+1, ..., a+N-1, where a is the smallest index such that:
                - the sum of e over these keys is X_avg,
                - the sum of t over these keys is S,
                - every one of these keys has e <= 1 and is not eligible as the best case (e = 0 and t <= T).
```

- The average set does not depend on any search: it is found by scanning the stream from index 0, and in practice starts within a few thousand indices. Its keys are distinct from the best and worst cases by construction.
- Extending a search never changes a selected key, since every rule takes the smallest index. A rarer tier, once found, adds one test case.
- A tier is published only once found; its absence is visible in the set (section 4).

Order of the test cases in a set: the best case, the worst case of tier 1, then of tier 2 if present, then the keys of the average set by increasing index. Any prefix of a set is a usable smaller benchmark.

Stated probability of a test case: P(e = 0 and t ≤ T) for the best case, P(e ≥ X) for a worst case, none for the average set. They are printed as in the table above, with 2 decimals.

The `test` profile of `mlkem_stats.py` uses the same rules with targets of 2^-10 for the best case and tier 1 and 2^-16 for tier 2. Its only purpose is to test the tools end to end on a short search: its sets are never published.

## 4. Content of a test case

| Field | Size (bytes) | Value |
|---|---|---|
| `keygen_seed` | 64 | `d \|\| z` |
| `encaps_seed` | 32 | `m` |
| `pk_sha256` | 32 | SHA-256 of `ek` |
| `sk_sha256` | 32 | SHA-256 of `dk` |
| `ct_sha256` | 32 | SHA-256 of `c` |
| `ss` | 32 | shared secret `K` from encapsulation, also the output of decapsulation of `c` |
| `ss_reject` | 32 | output of decapsulation of `c'`, i.e. `J(z \|\| c')` |
| `reject_bit` | 2 | section 1 |
| `role` | 1 | 0 best case, 1 worst case, 2 average set |
| `tier` | 1 | 1 or 2 for a worst case, 0 otherwise |

`ek`, `dk`, `c` and the shared secrets are the byte strings of FIPS 203: `(ek, dk) = ML-KEM.KeyGen_internal(d, z)`, `(K, c) = ML-KEM.Encaps_internal(ek, m)`.

The other data of a test case (index, stated probability, per entry counts, `e`, `t`) are annotations: they are in the record and in the output files, but not in the image of the test case below.

## 5. Name and digest of a set

The image of a test case is the concatenation of its fields in the order of the table of section 4, `reject_bit` as 2 bytes little-endian: 260 bytes.

```
digest = SHA-256("BTVG-MLKEM set v1" || 0x00 || pset || ncases || image(case 0) || ... || image(case ncases-1))
         "BTVG-MLKEM set v1": 17 ASCII bytes
         pset:   2 bytes little-endian (512, 768 or 1024)
         ncases: 2 bytes little-endian
name   = "mlkem" <pset> "-n" <ncases> "-h" <first 4 bytes of digest, upper-case hexadecimal>
```

For example `mlkem768-n42-h1A2B3C4D` (made up). The name changes with any change of what a firmware embeds, the order of the test cases included. It does not change when only an annotation is corrected.

## 6. Search log, format 1

The search tool writes text lines of space-separated fields, decimal unless stated otherwise:

```
S 1 BTVG-MLKEM-v1 <pset> <seed hex> <log2 chunk> <E> <T>     header
H <index> <e> <t> <it_0> ... <it_k²-1>                      a hit
C <chunk> <n_0> ... <n_k²> <sum_t> <nhits>                  end of a chunk
X <index> <entry>                                           an entry exceeded 280 iterations
```

- A chunk is 2^20 consecutive indices (`log2 chunk` = 20): chunk c holds the indices c·2^20 to (c+1)·2^20 − 1.
- A key is a hit when `e ≥ E`, or when `e = 0` and `t ≤ T`. The hits of a chunk come in increasing index, before its `C` line.
- `n_x` is the number of keys of the chunk with `e = x`, the last one counting `e ≥ k²`. `sum_t` is the sum of `t` over the chunk. `nhits` is the number of `H` lines of the chunk.
- On an `X` line the tool stops with an error status, without closing the chunk.

A chunk counts as searched only when its `C` line is present and consistent with its `H` lines. The same chunk found in several logs must have identical lines. The searched range for a rule is the largest P = c·2^20 such that every chunk below c is searched with thresholds covering the rule: `T` of the log at least `T` of the rule for the best case, `E` of the log at most `X` of the tier for a worst case. The generator lists the missing chunks.

## 7. Record of a set

A published set is recorded in `published/<name>.py`, a file of Python literals only, read with `ast.literal_eval`. The inputs of the regeneration are the derivation label, the seed, the parameter set, the rules version and, for each test case, its role, tier and index. The record also holds every derived value and annotation, which the generator recomputes and compares.

`./generate --check` rebuilds every published file from the records and compares them byte for byte, without any search.

## 8. Version

The file `VERSION` holds the version of the generator, `x.y.z`. Each generated file states the version which first produced its set; a later version must reproduce it byte for byte. A version is never reused: a release is tagged `v<version>`, and `./release-check` refuses to run when that tag exists or when the working tree has uncommitted changes.
