# BTVG-MLKEM
Benchmarking Test Vectors Generator for ML-KEM (FIPS 203).

This is the sibling of [BTVG-MLDSA](https://github.com/sebastien-riou/BTVG-MLDSA), which does the same for ML-DSA signing.

**Status:** definition stage. This README states what the project shall deliver, nothing is implemented yet.

## Why dedicated test vectors

ML-KEM benchmark results are hard to compare, for two reasons.

### The measured operation is ambiguous
FIPS 203 leaves several choices open, and each of them moves work in or out of the measured operation:
- **Randomness.** `ML-KEM.KeyGen` and `ML-KEM.Encaps` draw random bytes, their internal versions take them as inputs (section 6).
- **Decapsulation key.** The seed `(d, z)` can be stored instead of the decapsulation key and expanded later (section 3.3): decapsulation then starts with a key generation.
- **Input checks.** The checks of the encapsulation key and of the decapsulation key are mandatory, but neither at every execution nor by the party which runs the operation (sections 7.2 and 7.3).
- **Stored matrix.** The matrix Â can be stored rather than generated again by each operation (section 3.3).
- **Key pair check.** Some modules complete key generation with a pair-wise consistency check, which is an encapsulation followed by a decapsulation (section 7.1).

Two implementations measured under different choices are not comparable.

### The execution time depends on the key
Even in a constant-time implementation, one step has a duration which depends on its input: the generation of the matrix Â from the public seed ρ (`SampleNTT`, FIPS 203 Algorithm 7). It is a rejection sampler, so the amount of SHAKE128 output it consumes depends on ρ.

- Key generation, encapsulation and decapsulation all generate the same k² entries of Â, so a slow key is slow for the three operations. If Â is stored, only the operation which builds it is affected.
- ρ is part of the encapsulation key: the cost depends on the key only, not on the message `m` nor on the ciphertext.

An entry of Â needs 3 SHAKE128 blocks, or 4 with a probability of 0.83%. A 5th block has a probability of 2^-105. For a random key, this gives:

|                           | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|---------------------------|------------|------------|-------------|
| Entries in Â (k²)         | 4          | 9          | 16          |
| Blocks in the best case   | 12         | 27         | 48          |
| P(no extra block)         | 96.7%      | 92.8%      | 87.5%       |
| P(at least 1 extra block) | 2^-4.9     | 2^-3.8     | 2^-3.0      |
| P(at least 2)             | 2^-11.2    | 2^-8.7     | 2^-7.0      |
| P(at least 3)             | 2^-18.7    | 2^-14.4    | 2^-11.7     |
| P(at least 4)             | **2^-27.6**| 2^-20.7    | 2^-16.9     |
| P(at least 5)             | 2^-123.9   | **2^-27.6**| 2^-22.6     |
| P(at least 6)             | 2^-221.5   | 2^-35.1    | **2^-28.6** |
| P(at least 7)             | 2^-320.4   | 2^-43.2    | 2^-35.0     |
| P(at least 8)             | 2^-420.6   | 2^-52.1    | 2^-41.7     |

These are exact binomial tails: a block carries 112 candidates, each is accepted with probability 3329/4096, and an entry needs 256 of them. The cells in bold are the first worst case target, see the goals.

What this means for benchmarking:
- Most keys are the best case.
- The long term average is only 0.28% above the best case, counted in blocks.
- 4 blocks per entry (33% more than the best case) is a worst case for all practical purposes. Only for ML-KEM-512 is a key reaching it within reach of a search (2^-27.6, against 2^-62 for ML-KEM-768 and 2^-110 for ML-KEM-1024).
- A benchmark on random keys gives a result which depends on the draw. Among 16 random keys there is at least one slow key in 41% of the draws for ML-KEM-512 and in 88% of them for ML-KEM-1024, and the rare cases are never met.

Measurements made with crypto-benchmark on Cortex-M33 microcontrollers agree with this. For every library measured so far, the time of an operation is a constant, plus a cost per iteration of the `SampleNTT` loop, plus a cost per extra block, and both outcomes of decapsulation take the same time. An extra block costs as much as several hundred iterations, but no more than a few percent of an operation, which is the order of the measurement noise on some boards. A key with a single extra block is easy to miss, hence a worst case with several of them.

The spread is much smaller than for ML-DSA signing, where the slowest signature takes more than 20 times longer than the fastest. The purpose is the same: published numbers shall be the best case, the true average and a worst case of known probability, not whatever a few random keys happened to give.

## Goals

1. **Comparable results.** One public set of test cases per parameter set (ML-KEM-512, ML-KEM-768, ML-KEM-1024), usable unchanged by software, hardware and mixed implementations. Each set has a unique name which includes a digest of its content, so that a result can state exactly which test vectors produced it. The name is short and safe to use in a file name.

2. **Unambiguous operations.** The test cases are defined on the deterministic interfaces of FIPS 203 section 6: `ML-KEM.KeyGen_internal(d, z)`, `ML-KEM.Encaps_internal(ek, m)` and `ML-KEM.Decaps_internal(dk, c)`. A test case provides `d`, `z` and `m`, and what is needed to check `ek`, `dk`, `c` and the shared secret. All of them are the byte strings specified by FIPS 203. Section 3.3 reserves these interfaces for testing, so a module may not expose them: it can still use the test cases if its random source can be replaced and if it uses the random bytes as they are, `d` then `z` for key generation and `m` for encapsulation.

3. **Both outcomes of decapsulation.** Each test case covers the decapsulation of the valid ciphertext and of an invalid one, for which the expected output is the implicit rejection value. A real time budget has to hold for both, and they are expected to take the same time. The test vectors define the invalid ciphertext, as a modification of the valid one so that it does not have to be stored: it is not a convention left to each benchmark.

4. **Controlled key dependent cost.** The cost of a key is the number of SHAKE128 blocks needed to generate Â, then the number of iterations of the `SampleNTT` loop (each consumes 3 bytes) to separate keys with the same number of blocks. For each parameter set, the test cases include:
   - **the best case**: a key without extra block and with few iterations. Such a key is rarer than the typical one, so its occurrence probability is stated, with the same target as for the worst case;
   - **the worst case**: a key whose number of extra blocks has a stated occurrence probability, the same for the three parameter sets as far as the distribution allows. The first target is about 2^-28, which is 4, 5 and 6 extra blocks for ML-KEM-512, ML-KEM-768 and ML-KEM-1024. ML-KEM-512 has nothing rarer to offer; for the two others, rarer cases are added when the search effort allows;
   - **the average set**: more keys, selected so that their mean number of blocks and their mean number of iterations equal the long term expectations. The average is then a plain mean of measurements, which does not assume how the time depends on these counts. The best and the worst cases are reported on their own and are not part of it: diluting the worst case would take 45 keys for ML-KEM-1024 and up to 120 keys for ML-KEM-512.

   Keys of equal cost are not equivalent for every implementation, as their slow entries fall on different rows and columns of Â. The rule which picks one of them is fixed in advance and published, for instance the first one in the search order, so that the selection is visibly not tuned.

5. **Annotated test cases.** Each test case comes with its role (best case, worst case, average set), its occurrence probability, and the number of blocks and iterations of every entry of Â. The role lets a benchmark report the three separately. The per entry counts serve the implementations which generate several entries at once (4-way SHAKE128 for example) and do not pay the plain sum of the blocks: anyone can work out the cost for their own architecture and extrapolate. Apart from the role, the annotations are for the host and do not have to be embedded in a firmware.

6. **Small.** A few tens of keys per parameter set, so that a run is short enough to be part of the development loop, on a microcontroller as well as in an RTL simulation. The order makes any prefix useful: the best case, the worst case, then the average set, so that a slow simulation can stop after the first test cases.

7. **Compact and checkable.** A test case has to fit in the firmware of a small microcontroller: seeds as inputs and digests of the expected outputs, rather than complete keys and ciphertexts. Each output of each test case has its own expected value: it can be checked right after its measurement, a failure names the test case and the output, and a subset of the test cases can be run. The digests are SHA-256, so that the check does not rely on the Keccak of the implementation under test.

8. **Four formats.** JSON following the layout of ACVP, Python, C and SystemVerilog, as for BTVG-MLDSA. The C format is the one used by [crypto-benchmark](https://github.com/sebastien-riou/crypto-benchmark), where these test vectors shall replace the interim ones of `libmlkem-lbmk/gen-tv.py` (16 cases per parameter set, 2 of them picked to need a 4th block, without a known probability or a matched average). It uses a single type for the three parameter sets.

9. **Reproducible and extensible.** The generator is open source and everything derives from seeds recorded in the test vectors: anyone can regenerate the published sets bit for bit. The search for rare keys can be split across processes and machines and its results merged, so that a rarer worst case can be published later without redoing the work.

10. **Checked.** The generator checks itself against known answer tests before it produces anything, and every published test case is confirmed by two independent implementations of ML-KEM.

## Non-goals

1. **Conformance testing.** No malformed inputs (keys failing the checks of FIPS 203 sections 7.2 and 7.3, wrong lengths), no edge cases, no coverage claim. Passing these test vectors does not show conformance to FIPS 203: ACVP and Wycheproof are the tools for that. A benchmark which wants to verify that the input checks are present can derive bad keys from a valid one, as crypto-benchmark does.

2. **Side channel evaluation.** The test vectors exercise the time variation caused by public data only. They are not designed to reveal secret dependent timing, power or electromagnetic leakage, or the effect of faults. Comparing the two outcomes of decapsulation is a sanity check, not a leakage assessment.

3. **A benchmark.** No measurement code, no platform support, no results: this is the role of [crypto-benchmark](https://github.com/sebastien-riou/crypto-benchmark). What belongs to the measured operation (input checks, decoding of the keys), what else is measured (memory footprints) and how the results are aggregated and reported is decided there. The test vectors only have to make every such choice possible.

4. **The randomized interfaces.** `ML-KEM.KeyGen()` and `ML-KEM.Encaps(ek)` draw their own randomness, so their outputs cannot be checked and the cost of the random source is not part of ML-KEM.

5. **An absolute worst case.** FIPS 203 does not bound the `SampleNTT` loop, and its Appendix B forbids an implementation to bound it below 280 iterations, which is 5 blocks per entry. The test vectors give the worst case found for a stated probability, 4 blocks per entry at most: they are not a proof of worst case execution time, and they cannot exercise such a bound.

6. **Tuning for one implementation.** The selection relies on counts which do not depend on the implementation. There is no search for the worst key of a given batching strategy, cache or pipeline.

7. **Other schemes.** Kyber as submitted to the NIST competition and the drafts of FIPS 203 (their outputs differ), hybrid KEMs, and protocols using ML-KEM (TLS, HPKE). ML-DSA is covered by BTVG-MLDSA.

8. **Component level test vectors.** Nothing for K-PKE alone, the NTT, Keccak or the samplers.

9. **A usable ML-KEM implementation.** The instrumented implementations in this repository are search tools: not constant time, not hardened, not meant to be used for anything else.
