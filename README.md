# BTVG-MLKEM
Benchmarking Test Vectors Generator for ML-KEM (FIPS 203).

This is the sibling of [BTVG-MLDSA](https://github.com/sebastien-riou/BTVG-MLDSA), which does the same for ML-DSA signing.

**Status:** the sets of the rules v1 are published, with a worst case of tier 1 (probability about 2^-28); tier 2 (about 2^-35) needs a longer search. This README states what the project delivers and how to use it, [SPEC.md](SPEC.md) defines the test vectors precisely.

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
| P(no extra block)         | 96.7%      | 92.7%      | 87.5%       |
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

### Why not the CAVP test vectors
The test vectors of NIST's validation program (CAVP, produced by the ACVP server) are the right tool to check conformance, and the generator of this repository checks itself against them. They are not suited to benchmarking:

- **They are not one set.** The ACVP server draws new vectors for each validation session, and its published sample files come in several revisions (`FIPS203` and `FIPS203-tr1` for encapsulation and decapsulation, for instance). Two parties who used "the CAVP vectors" did not necessarily run the same inputs.
- **The cost of their keys is left to chance.** Each parameter set has 25 keys for key generation, 25 other keys for encapsulation and 10 other keys for decapsulation. Keys needing an extra block in the `FIPS203` sample files:

  | Keys with an extra block | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
  |--------------------------|------------|------------|-------------|
  | Key generation, 25 keys  | 3          | 1          | 5           |
  | Encapsulation, 25 keys   | 3          | 4          | 4           |
  | Decapsulation, 10 keys   | 0          | 1          | 1           |
  | Expected among 25 keys   | 0.8        | 1.8        | 3.1         |
  | Expected among 10 keys   | 0.3        | 0.7        | 1.3         |

  In the `FIPS203-tr1` revision, the encapsulation keys give 1, 1 and 3. Whether the worst case measured for an operation includes the slow path depends on the operation and on the revision. No key of either revision has more than 2 extra blocks, when the worst case targeted here has 4 to 6.
- **Each operation runs on its own keys**, and so does each outcome of decapsulation: its 5 valid and 5 modified ciphertexts come with 10 different keys. Comparing two operations, or the two outcomes, also compares keys.
- **Nothing says what a test case is.** No cost, no probability, no role: a minimum, an average or a worst case measured with them describes the keys which happened to be drawn.
- **They are large.** Encapsulation and decapsulation take complete keys and ciphertexts as inputs: 45 KB for ML-KEM-512 and 87 KB for ML-KEM-1024, before any expected output, against a few hundred bytes per test case here, expected outputs included.

The average measured with them is close to the true one, since the spread is small. What they cannot give is the same inputs for everyone, a defined best case and a worst case of known probability.

## Goals

1. **Comparable results.** One public set of test cases per parameter set (ML-KEM-512, ML-KEM-768, ML-KEM-1024), usable unchanged by software, hardware and mixed implementations. Each set has a unique name which includes a digest of its content, so that a result can state exactly which test vectors produced it. The name is short and safe to use in a file name.

2. **Unambiguous operations.** The test cases are defined on the deterministic interfaces of FIPS 203 section 6: `ML-KEM.KeyGen_internal(d, z)`, `ML-KEM.Encaps_internal(ek, m)` and `ML-KEM.Decaps_internal(dk, c)`. A test case provides `d`, `z` and `m`, and what is needed to check `ek`, `dk`, `c` and the shared secret. All of them are the byte strings specified by FIPS 203. Section 3.3 reserves these interfaces for testing, so a module may not expose them: it can still use the test cases if its random source can be replaced and if it uses the random bytes as they are, `d` then `z` for key generation and `m` for encapsulation.

3. **Both outcomes of decapsulation.** Each test case covers the decapsulation of the valid ciphertext and of an invalid one, for which the expected output is the implicit rejection value. A real time budget has to hold for both, and they are expected to take the same time. The test vectors define the invalid ciphertext, as a modification of the valid one so that it does not have to be stored: it is not a convention left to each benchmark.

4. **Controlled key dependent cost.** The cost of a key is the number of SHAKE128 blocks needed to generate Â, then the number of iterations of the `SampleNTT` loop (each consumes 3 bytes) to separate keys with the same number of blocks. For each parameter set, the test cases include:
   - **the best case**: a key without extra block and with few iterations. Such a key is rarer than the typical one, so its occurrence probability is stated, with the same target as for the worst case;
   - **the worst case**: a key whose number of extra blocks has a stated occurrence probability, the same for the three parameter sets as far as the distribution allows. The first target is about 2^-28, which is 4, 5 and 6 extra blocks for ML-KEM-512, ML-KEM-768 and ML-KEM-1024. ML-KEM-512 has nothing rarer to offer; for the two others, rarer cases are added when the search effort allows;
   - **the average set**: more keys, selected so that their mean number of blocks and their mean number of iterations equal the long term expectations. The average is then a plain mean of measurements, which does not assume how the time depends on these counts. The best and the worst cases are reported on their own and are not part of it: diluting the worst case would take 45 keys for ML-KEM-1024 and up to 120 keys for ML-KEM-512.

   Keys of equal cost are not equivalent for every implementation, as their slow entries fall on different rows and columns of Â. The rule which picks one of them is fixed in advance and published, for instance the first one in the search order, so that the selection is visibly not tuned.

5. **Annotated test cases.** Each test case comes with its role (best case, worst case, average set), the number of blocks and iterations of every entry of Â, and, for the best and worst cases, their occurrence probability. The role lets a benchmark report the three separately. The per entry counts serve the implementations which generate several entries at once (4-way SHAKE128 for example) and do not pay the plain sum of the blocks: anyone can work out the cost for their own architecture and extrapolate. Apart from the role, the annotations are for the host and do not have to be embedded in a firmware.

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

## Published sets

In [published/](published/), made with the rules v1 and the seed `0000000000000000` from a search of 2^31 keys per parameter set:

| Set | Best case | Worst case, tier 1 | Average set |
|-----|-----------|--------------------|-------------|
| `mlkem512-n32-h2F3BDE49` | key 131449516, 584 iterations, 2^-28.18 | key 115564382, 4 extra blocks, 2^-27.63 | 30 keys from key 105 |
| `mlkem768-n42-h523BACDC` | key 698949843, 1348 iterations, 2^-28.12 | key 79661803, 5 extra blocks, 2^-27.60 | 40 keys from key 522 |
| `mlkem1024-n17-hFD044788` | key 474427888, 2426 iterations, 2^-28.37 | key 477098591, 6 extra blocks, 2^-28.58 | 15 keys from key 208 |

The probability of the best case is that of a key with no extra block and at most as many iterations as the limit of the rules (585, 1349 and 2428); that of the worst case is the probability of at least as many extra blocks. Before publication, every chunk up to the last selected key was counted again by the Python counter, independently of the search tool, with identical results, and the counts of the 2^31 keys match their exact distribution.

No key of tier 2 was found in 2^31 keys for ML-KEM-768 and ML-KEM-1024, as expected: it takes about 2^35. Once found, it adds one test case to each of these two sets, which therefore get new names.

## Setup

Requirements: a Linux machine with `gcc`, Python 3 (tested with 3.14) and `pipenv`. Then:

```
./init
```

This creates the Python environment in `.venv/` (kyber-py, numpy, and pyslang for the tests), builds the search tool `mlkem-search` and runs the quick tests.

## How to generate the test vectors

The published sets are in `published/`. Generating them again, or rarer ones, takes four steps.

1. **Search** the stream of keys for rare ones. The stream is cut in chunks of 2^20 keys:
   ```
   ./search PSET FIRST_CHUNK NCHUNKS JOBS
   ```
   For example `./search 768 0 4096 24` searches the first 2^32 keys of ML-KEM-768 with 24 processes. Each process writes a log in `results/`. The logs of other runs or other machines are merged by copying them into `results/`: a range searched twice must give the same log, and the chunks can be searched in any order. On a laptop CPU (Ryzen AI 9 HX PRO 370), a core searches 250k, 125k and 75k keys per second for ML-KEM-512, ML-KEM-768 and ML-KEM-1024. The worst case of tier 1 needs about 2^30 to 2^32 keys.
2. **Check** the progress: `.venv/bin/python mlkem_logs.py results/` prints, for each rule, the number of keys searched without gap and the first key found, the missing chunks as commands to run, and the counts against their exact distribution.
3. **Verify**: `.venv/bin/python mlkem-verify.py results/` recounts in Python, independently of the search tool, every chunk up to the last selected key, and requires the same counts and hits as the logs. A key missed by the search tool would otherwise make the selection wrong.
4. **Generate**: `./generate` selects the test cases from `results/` and writes every format in `published/`. It refuses to run if a known answer test fails, and stops for a parameter set whose best case or worst case of tier 1 is not found yet.

`./generate --check` rebuilds every published file from its record and compares it byte for byte: no search is needed to check a published set.

`./testit` runs every test in about 3 minutes, including a short search with the `test` profile. `./testit --quick` takes seconds. `./release-check` runs before a release: it refuses uncommitted changes and a version already tagged.

## How to use the test vectors

A set is named like `mlkem768-n42-h1A2B3C4D`: parameter set, number of test cases, and the first bytes of the digest of its content. Its test cases come in this order: the best case, the worst cases (tier 1, then tier 2 if found), then the average set. Every format gives the role of each test case, so that the three can be reported separately: minimum on the best case, mean over the average set, maximum on the worst case with its probability.

For each test case, a benchmark runs:
1. `ML-KEM.KeyGen_internal(d, z)`, and checks the SHA-256 of `ek` and of `dk`;
2. `ML-KEM.Encaps_internal(ek, m)`, and checks the SHA-256 of `c` and the shared secret `ss`;
3. `ML-KEM.Decaps_internal(dk, c)`, and checks `ss`;
4. `ML-KEM.Decaps_internal(dk, c')`, where `c'` is `c` with bit `reject_bit` flipped, and checks `ss_reject`.

The formats:
- **C**: `mlkem_test_vectors.h` defines the type `mlkem_test_case_t`, the same for every set; `<name>.c` defines `mlkem<pset>_test_vectors`. A test case takes 260 bytes: seeds, SHA-256 digests and shared secrets.
- **JSON**: `<name>-keyGen.json` and `<name>-encapDecap.json` follow the layout of the ACVP files `internalProjection.json`, with complete keys and ciphertexts. Each test also carries its test case number, role and tier, and the key generation tests the cost annotations.
- **Python**: `<name>.py` is the record of the set, a file of Python literals. [example.py](example.py) runs a set through kyber-py: replace its marked calls by those of the implementation to test.
- **SystemVerilog**: `<name>.sv` is a package with the complete values, since a testbench cannot easily compute SHA-256. Byte i of a value is element `[i]` of its packed array.

## How the test vectors are checked

- The two ML-KEM implementations, [mlkem_fips203.py](mlkem_fips203.py) and kyber-py, pass the known answer tests of wolfSSL and of NIST's ACVP sample files, implicit rejection included, before anything is generated. Every value of every test case is computed by both and must be identical.
- Both use Python's `hashlib` for SHA-3: they are independent for the arithmetic and the encodings only. `hashlib` is checked against NIST's SHA-3 answers, and the search tool, which has its own Keccak, against the same answers. The libraries benchmarked by crypto-benchmark check every digest again.
- The cost of a key is counted three times: by the search tool in C, by a numpy counter, and by the SampleNTT of mlkem_fips203.py run on the key. They must agree.
- The tests compare the logs of the search tool with those of the Python counter, check the merging of logs, confirm the selection by a brute-force scan, and read every output format back: the C files are compiled and give the digest of their name, the JSON files go through the same runner as NIST's, the SystemVerilog files are compiled by pyslang.
