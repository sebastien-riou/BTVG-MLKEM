/*
 * mlkem-search: search the stream of keys of BTVG-MLKEM for keys whose matrix A is rare to
 * generate, see SPEC.md (sections 1, 2 and 6).
 *
 * Usage:
 *   mlkem-search PSET FIRST_CHUNK NCHUNKS [--seed HEX16] [--min-extra E] [--max-iters T] [--log2-chunk L]
 *       count the keys of chunks FIRST_CHUNK .. FIRST_CHUNK+NCHUNKS-1 and write the search log
 *       on stdout. A key is logged when it needs at least E extra SHAKE128 blocks, or none and
 *       at most T iterations of SampleNTT. Defaults: the rules v1 of SPEC.md (E = X of tier 1,
 *       T = T of the best case).
 *   mlkem-search --key PSET INDEX [--seed HEX16]
 *       print the inputs and the cost of one key (same output as mlkem_count.py --key).
 *   mlkem-search --hash
 *       read lines "ALG OUTLEN HEXMSG" on stdin (ALG: SHA3-256, SHA3-512, SHAKE128, SHAKE256;
 *       HEXMSG "-" for the empty message) and write the hexadecimal digests on stdout, to check
 *       this Keccak against NIST's answers.
 *   mlkem-search --selftest
 *
 * The work is bounded: the number of keys is fixed by the command line and an entry of A is
 * abandoned after 280 iterations (FIPS 203 Appendix B), which stops the tool with an X line.
 * There is no timeout. Exit status: 0 success, 1 usage, 2 X line, 3 self test failure.
 *
 * Portable C99; the state is accessed byte by byte, so the output does not depend on the host.
 */
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LABEL "BTVG-MLKEM-v1"
#define LABEL_LEN 13
#define LOG_FORMAT 1
#define DEFAULT_LOG2_CHUNK 20
#define Q 3329
#define NCOEFFS 256
#define BLOCK_ITERATIONS 56 /* 168-byte SHAKE128 block, 3 bytes per iteration */
#define MIN_BLOCKS 3
#define MAX_ITERATIONS 280 /* 5 blocks */
#define MAX_K 4
#define MAX_HASH_LINE (1u << 20)

/* ---- Keccak-f[1600] -------------------------------------------------------------------------
 * KeccakF1600_StatePermute from the pq-crystals reference implementation of Kyber (fips202.c),
 * "based on the public domain implementation in crypto_hash/keccakc512/simple/ from
 * http://bench.cr.yp.to/supercop.html by Ronny Van Keer and the public domain "TweetFips202"
 * implementation from https://twitter.com/tweetfips202 by Gilles Van Assche, Daniel J. Bernstein,
 * and Peter Schwabe". Public domain. */
#define NROUNDS 24
#define ROL(a, offset) ((a << offset) ^ (a >> (64 - offset)))

static const uint64_t KeccakF_RoundConstants[NROUNDS] = {
    (uint64_t)0x0000000000000001ULL, (uint64_t)0x0000000000008082ULL, (uint64_t)0x800000000000808aULL,
    (uint64_t)0x8000000080008000ULL, (uint64_t)0x000000000000808bULL, (uint64_t)0x0000000080000001ULL,
    (uint64_t)0x8000000080008081ULL, (uint64_t)0x8000000000008009ULL, (uint64_t)0x000000000000008aULL,
    (uint64_t)0x0000000000000088ULL, (uint64_t)0x0000000080008009ULL, (uint64_t)0x000000008000000aULL,
    (uint64_t)0x000000008000808bULL, (uint64_t)0x800000000000008bULL, (uint64_t)0x8000000000008089ULL,
    (uint64_t)0x8000000000008003ULL, (uint64_t)0x8000000000008002ULL, (uint64_t)0x8000000000000080ULL,
    (uint64_t)0x000000000000800aULL, (uint64_t)0x800000008000000aULL, (uint64_t)0x8000000080008081ULL,
    (uint64_t)0x8000000000008080ULL, (uint64_t)0x0000000080000001ULL, (uint64_t)0x8000000080008008ULL};

static void KeccakF1600_StatePermute(uint64_t state[25]) {
  int round;

  uint64_t Aba, Abe, Abi, Abo, Abu;
  uint64_t Aga, Age, Agi, Ago, Agu;
  uint64_t Aka, Ake, Aki, Ako, Aku;
  uint64_t Ama, Ame, Ami, Amo, Amu;
  uint64_t Asa, Ase, Asi, Aso, Asu;
  uint64_t BCa, BCe, BCi, BCo, BCu;
  uint64_t Da, De, Di, Do, Du;
  uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
  uint64_t Ega, Ege, Egi, Ego, Egu;
  uint64_t Eka, Eke, Eki, Eko, Eku;
  uint64_t Ema, Eme, Emi, Emo, Emu;
  uint64_t Esa, Ese, Esi, Eso, Esu;

  Aba = state[0];
  Abe = state[1];
  Abi = state[2];
  Abo = state[3];
  Abu = state[4];
  Aga = state[5];
  Age = state[6];
  Agi = state[7];
  Ago = state[8];
  Agu = state[9];
  Aka = state[10];
  Ake = state[11];
  Aki = state[12];
  Ako = state[13];
  Aku = state[14];
  Ama = state[15];
  Ame = state[16];
  Ami = state[17];
  Amo = state[18];
  Amu = state[19];
  Asa = state[20];
  Ase = state[21];
  Asi = state[22];
  Aso = state[23];
  Asu = state[24];

  for (round = 0; round < NROUNDS; round += 2) {
    BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
    BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
    BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
    BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
    BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

    Da = BCu ^ ROL(BCe, 1);
    De = BCa ^ ROL(BCi, 1);
    Di = BCe ^ ROL(BCo, 1);
    Do = BCi ^ ROL(BCu, 1);
    Du = BCo ^ ROL(BCa, 1);

    Aba ^= Da;
    BCa = Aba;
    Age ^= De;
    BCe = ROL(Age, 44);
    Aki ^= Di;
    BCi = ROL(Aki, 43);
    Amo ^= Do;
    BCo = ROL(Amo, 21);
    Asu ^= Du;
    BCu = ROL(Asu, 14);
    Eba = BCa ^ ((~BCe) & BCi);
    Eba ^= (uint64_t)KeccakF_RoundConstants[round];
    Ebe = BCe ^ ((~BCi) & BCo);
    Ebi = BCi ^ ((~BCo) & BCu);
    Ebo = BCo ^ ((~BCu) & BCa);
    Ebu = BCu ^ ((~BCa) & BCe);

    Abo ^= Do;
    BCa = ROL(Abo, 28);
    Agu ^= Du;
    BCe = ROL(Agu, 20);
    Aka ^= Da;
    BCi = ROL(Aka, 3);
    Ame ^= De;
    BCo = ROL(Ame, 45);
    Asi ^= Di;
    BCu = ROL(Asi, 61);
    Ega = BCa ^ ((~BCe) & BCi);
    Ege = BCe ^ ((~BCi) & BCo);
    Egi = BCi ^ ((~BCo) & BCu);
    Ego = BCo ^ ((~BCu) & BCa);
    Egu = BCu ^ ((~BCa) & BCe);

    Abe ^= De;
    BCa = ROL(Abe, 1);
    Agi ^= Di;
    BCe = ROL(Agi, 6);
    Ako ^= Do;
    BCi = ROL(Ako, 25);
    Amu ^= Du;
    BCo = ROL(Amu, 8);
    Asa ^= Da;
    BCu = ROL(Asa, 18);
    Eka = BCa ^ ((~BCe) & BCi);
    Eke = BCe ^ ((~BCi) & BCo);
    Eki = BCi ^ ((~BCo) & BCu);
    Eko = BCo ^ ((~BCu) & BCa);
    Eku = BCu ^ ((~BCa) & BCe);

    Abu ^= Du;
    BCa = ROL(Abu, 27);
    Aga ^= Da;
    BCe = ROL(Aga, 36);
    Ake ^= De;
    BCi = ROL(Ake, 10);
    Ami ^= Di;
    BCo = ROL(Ami, 15);
    Aso ^= Do;
    BCu = ROL(Aso, 56);
    Ema = BCa ^ ((~BCe) & BCi);
    Eme = BCe ^ ((~BCi) & BCo);
    Emi = BCi ^ ((~BCo) & BCu);
    Emo = BCo ^ ((~BCu) & BCa);
    Emu = BCu ^ ((~BCa) & BCe);

    Abi ^= Di;
    BCa = ROL(Abi, 62);
    Ago ^= Do;
    BCe = ROL(Ago, 55);
    Aku ^= Du;
    BCi = ROL(Aku, 39);
    Ama ^= Da;
    BCo = ROL(Ama, 41);
    Ase ^= De;
    BCu = ROL(Ase, 2);
    Esa = BCa ^ ((~BCe) & BCi);
    Ese = BCe ^ ((~BCi) & BCo);
    Esi = BCi ^ ((~BCo) & BCu);
    Eso = BCo ^ ((~BCu) & BCa);
    Esu = BCu ^ ((~BCa) & BCe);

    BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
    BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
    BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
    BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
    BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

    Da = BCu ^ ROL(BCe, 1);
    De = BCa ^ ROL(BCi, 1);
    Di = BCe ^ ROL(BCo, 1);
    Do = BCi ^ ROL(BCu, 1);
    Du = BCo ^ ROL(BCa, 1);

    Eba ^= Da;
    BCa = Eba;
    Ege ^= De;
    BCe = ROL(Ege, 44);
    Eki ^= Di;
    BCi = ROL(Eki, 43);
    Emo ^= Do;
    BCo = ROL(Emo, 21);
    Esu ^= Du;
    BCu = ROL(Esu, 14);
    Aba = BCa ^ ((~BCe) & BCi);
    Aba ^= (uint64_t)KeccakF_RoundConstants[round + 1];
    Abe = BCe ^ ((~BCi) & BCo);
    Abi = BCi ^ ((~BCo) & BCu);
    Abo = BCo ^ ((~BCu) & BCa);
    Abu = BCu ^ ((~BCa) & BCe);

    Ebo ^= Do;
    BCa = ROL(Ebo, 28);
    Egu ^= Du;
    BCe = ROL(Egu, 20);
    Eka ^= Da;
    BCi = ROL(Eka, 3);
    Eme ^= De;
    BCo = ROL(Eme, 45);
    Esi ^= Di;
    BCu = ROL(Esi, 61);
    Aga = BCa ^ ((~BCe) & BCi);
    Age = BCe ^ ((~BCi) & BCo);
    Agi = BCi ^ ((~BCo) & BCu);
    Ago = BCo ^ ((~BCu) & BCa);
    Agu = BCu ^ ((~BCa) & BCe);

    Ebe ^= De;
    BCa = ROL(Ebe, 1);
    Egi ^= Di;
    BCe = ROL(Egi, 6);
    Eko ^= Do;
    BCi = ROL(Eko, 25);
    Emu ^= Du;
    BCo = ROL(Emu, 8);
    Esa ^= Da;
    BCu = ROL(Esa, 18);
    Aka = BCa ^ ((~BCe) & BCi);
    Ake = BCe ^ ((~BCi) & BCo);
    Aki = BCi ^ ((~BCo) & BCu);
    Ako = BCo ^ ((~BCu) & BCa);
    Aku = BCu ^ ((~BCa) & BCe);

    Ebu ^= Du;
    BCa = ROL(Ebu, 27);
    Ega ^= Da;
    BCe = ROL(Ega, 36);
    Eke ^= De;
    BCi = ROL(Eke, 10);
    Emi ^= Di;
    BCo = ROL(Emi, 15);
    Eso ^= Do;
    BCu = ROL(Eso, 56);
    Ama = BCa ^ ((~BCe) & BCi);
    Ame = BCe ^ ((~BCi) & BCo);
    Ami = BCi ^ ((~BCo) & BCu);
    Amo = BCo ^ ((~BCu) & BCa);
    Amu = BCu ^ ((~BCa) & BCe);

    Ebi ^= Di;
    BCa = ROL(Ebi, 62);
    Ego ^= Do;
    BCe = ROL(Ego, 55);
    Eku ^= Du;
    BCi = ROL(Eku, 39);
    Ema ^= Da;
    BCo = ROL(Ema, 41);
    Ese ^= De;
    BCu = ROL(Ese, 2);
    Asa = BCa ^ ((~BCe) & BCi);
    Ase = BCe ^ ((~BCi) & BCo);
    Asi = BCi ^ ((~BCo) & BCu);
    Aso = BCo ^ ((~BCu) & BCa);
    Asu = BCu ^ ((~BCa) & BCe);
  }

  state[0] = Aba;
  state[1] = Abe;
  state[2] = Abi;
  state[3] = Abo;
  state[4] = Abu;
  state[5] = Aga;
  state[6] = Age;
  state[7] = Agi;
  state[8] = Ago;
  state[9] = Agu;
  state[10] = Aka;
  state[11] = Ake;
  state[12] = Aki;
  state[13] = Ako;
  state[14] = Aku;
  state[15] = Ama;
  state[16] = Ame;
  state[17] = Ami;
  state[18] = Amo;
  state[19] = Amu;
  state[20] = Asa;
  state[21] = Ase;
  state[22] = Asi;
  state[23] = Aso;
  state[24] = Asu;
}

/* ---- sponge, byte-wise ---------------------------------------------------------------------- */
#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72
#define PAD_SHAKE 0x1F
#define PAD_SHA3 0x06

static void xor_byte(uint64_t s[25], unsigned pos, uint8_t b) { s[pos / 8] ^= (uint64_t)b << (8 * (pos % 8)); }

static uint8_t get_byte(const uint64_t s[25], unsigned pos) { return (uint8_t)(s[pos / 8] >> (8 * (pos % 8))); }

/* absorbs in (padded) into a zero state; the state is then ready for squeeze_block */
static void absorb(uint64_t s[25], unsigned rate, uint8_t pad, const uint8_t *in, size_t inlen) {
  unsigned pos = 0;
  memset(s, 0, 25 * sizeof s[0]);
  while (inlen--) {
    xor_byte(s, pos++, *in++);
    if (pos == rate) {
      KeccakF1600_StatePermute(s);
      pos = 0;
    }
  }
  xor_byte(s, pos, pad);
  xor_byte(s, rate - 1, 0x80);
}

static void keccak(unsigned rate, uint8_t pad, const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
  uint64_t s[25];
  unsigned pos = rate;
  absorb(s, rate, pad, in, inlen);
  while (outlen--) {
    if (pos == rate) {
      KeccakF1600_StatePermute(s);
      pos = 0;
    }
    *out++ = get_byte(s, pos++);
  }
}

/* ---- stream of keys and cost of a key (SPEC.md sections 1 and 2) ----------------------------- */
typedef struct {
  unsigned pset;
  unsigned k;
  unsigned ct_bytes;
  unsigned default_min_extra; /* X of tier 1, rules v1 */
  unsigned default_max_iters; /* T of the best case, rules v1 */
} pset_t;

static const pset_t PSETS[] = {{512, 2, 768, 4, 585}, {768, 3, 1088, 5, 1349}, {1024, 4, 1568, 6, 2428}};

static const pset_t *find_pset(unsigned long pset) {
  unsigned i;
  for (i = 0; i < sizeof PSETS / sizeof PSETS[0]; i++)
    if (PSETS[i].pset == pset) return &PSETS[i];
  return NULL;
}

/* out = d || z || m || r */
static void derive(const uint8_t seed[8], uint64_t index, uint8_t out[104]) {
  uint8_t in[LABEL_LEN + 16];
  unsigned i;
  memcpy(in, LABEL, LABEL_LEN);
  memcpy(in + LABEL_LEN, seed, 8);
  for (i = 0; i < 8; i++) in[LABEL_LEN + 8 + i] = (uint8_t)(index >> (8 * i));
  keccak(SHAKE256_RATE, PAD_SHAKE, in, sizeof in, out, 104);
}

static void compute_rho(unsigned k, const uint8_t d[32], uint8_t rho[32]) {
  uint8_t in[33];
  memcpy(in, d, 32);
  in[32] = (uint8_t)k;
  keccak(SHA3_512_RATE, PAD_SHA3, in, sizeof in, rho, 32);
}

/* iterations of SampleNTT(rho || j || i), 0 if more than MAX_ITERATIONS */
static unsigned entry_iterations(const uint8_t rho[32], unsigned i, unsigned j) {
  uint64_t s[25];
  uint8_t in[34], buf[SHAKE128_RATE];
  unsigned pos, accepted = 0, it = 0;
  memcpy(in, rho, 32);
  in[32] = (uint8_t)j;
  in[33] = (uint8_t)i;
  absorb(s, SHAKE128_RATE, PAD_SHAKE, in, sizeof in);
  while (it < MAX_ITERATIONS) {
    KeccakF1600_StatePermute(s);
    for (pos = 0; pos < SHAKE128_RATE; pos++) buf[pos] = get_byte(s, pos);
    for (pos = 0; pos < SHAKE128_RATE; pos += 3) {
      unsigned d1 = buf[pos] | ((unsigned)(buf[pos + 1] & 0x0F) << 8);
      unsigned d2 = (buf[pos + 1] >> 4) | ((unsigned)buf[pos + 2] << 4);
      it++;
      if (d1 < Q) accepted++;
      if (d2 < Q && accepted < NCOEFFS) accepted++;
      if (accepted == NCOEFFS) return it;
    }
  }
  return 0;
}

/* iterations of the k*k entries (row-major), e and t; returns -1 - entry if an entry exceeds
 * MAX_ITERATIONS, else 0 */
static int key_cost(const pset_t *p, const uint8_t d[32], unsigned its[MAX_K * MAX_K], unsigned *e, unsigned *t) {
  uint8_t rho[32];
  unsigned i, j;
  compute_rho(p->k, d, rho);
  *e = 0;
  *t = 0;
  for (i = 0; i < p->k; i++) {
    for (j = 0; j < p->k; j++) {
      unsigned it = entry_iterations(rho, i, j);
      if (0 == it) return -1 - (int)(i * p->k + j);
      its[i * p->k + j] = it;
      *e += (it + BLOCK_ITERATIONS - 1) / BLOCK_ITERATIONS - MIN_BLOCKS;
      *t += it;
    }
  }
  return 0;
}

/* ---- search --------------------------------------------------------------------------------- */
static int search(const pset_t *p, const uint8_t seed[8], uint64_t first_chunk, uint64_t nchunks, unsigned log2_chunk,
                  unsigned min_extra, unsigned max_iters) {
  const unsigned kk = p->k * p->k;
  uint64_t chunk, x;
  unsigned i;
  printf("S %u %s %u ", LOG_FORMAT, LABEL, p->pset);
  for (i = 0; i < 8; i++) printf("%02x", seed[i]);
  printf(" %u %u %u\n", log2_chunk, min_extra, max_iters);
  fflush(stdout);
  for (chunk = first_chunk; chunk < first_chunk + nchunks; chunk++) {
    uint64_t histogram[MAX_K * MAX_K + 1] = {0};
    uint64_t sum_t = 0, nhits = 0;
    for (x = 0; x < ((uint64_t)1 << log2_chunk); x++) {
      const uint64_t index = (chunk << log2_chunk) + x;
      uint8_t out[104];
      unsigned its[MAX_K * MAX_K], e, t;
      int err;
      derive(seed, index, out);
      err = key_cost(p, out, its, &e, &t);
      if (err) {
        printf("X %" PRIu64 " %d\n", index, -1 - err);
        fflush(stdout);
        return 2;
      }
      histogram[e < kk ? e : kk]++;
      sum_t += t;
      if (e >= min_extra || (0 == e && t <= max_iters)) {
        printf("H %" PRIu64 " %u %u", index, e, t);
        for (i = 0; i < kk; i++) printf(" %u", its[i]);
        printf("\n");
        nhits++;
      }
    }
    printf("C %" PRIu64, chunk);
    for (i = 0; i <= kk; i++) printf(" %" PRIu64, histogram[i]);
    printf(" %" PRIu64 " %" PRIu64 "\n", sum_t, nhits);
    fflush(stdout);
  }
  return 0;
}

static void print_hex(const char *name, const uint8_t *b, size_t n) {
  size_t i;
  printf("%s ", name);
  for (i = 0; i < n; i++) printf("%02x", b[i]);
  printf("\n");
}

static int key_report(const pset_t *p, const uint8_t seed[8], uint64_t index) {
  uint8_t out[104], rho[32];
  unsigned its[MAX_K * MAX_K], e, t, i;
  uint64_t r = 0;
  int err;
  derive(seed, index, out);
  for (i = 0; i < 8; i++) r |= (uint64_t)out[96 + i] << (8 * i);
  compute_rho(p->k, out, rho);
  err = key_cost(p, out, its, &e, &t);
  printf("pset %u\n", p->pset);
  print_hex("seed", seed, 8);
  printf("index %" PRIu64 "\n", index);
  print_hex("d", out, 32);
  print_hex("z", out + 32, 32);
  print_hex("m", out + 64, 32);
  printf("reject_bit %" PRIu64 "\n", r % (8 * (uint64_t)p->ct_bytes));
  print_hex("rho", rho, 32);
  if (err) {
    printf("X %" PRIu64 " %d\n", index, -1 - err);
    return 2;
  }
  printf("iterations");
  for (i = 0; i < p->k * p->k; i++) printf(" %u", its[i]);
  printf("\ne %u\nt %u\n", e, t);
  return 0;
}

/* ---- parsing -------------------------------------------------------------------------------- */
static int parse_u64(const char *s, uint64_t *v) {
  char *end;
  unsigned long long x;
  if (!s || !*s || *s == '-') return 0;
  x = strtoull(s, &end, 10);
  if (*end) return 0;
  *v = (uint64_t)x;
  return 1;
}

static int hex_digit(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* hexadecimal string of exactly 2*n digits */
static int parse_hex(const char *s, uint8_t *out, size_t n) {
  size_t i;
  if (strlen(s) != 2 * n) return 0;
  for (i = 0; i < n; i++) {
    int hi = hex_digit(s[2 * i]), lo = hex_digit(s[2 * i + 1]);
    if (hi < 0 || lo < 0) return 0;
    out[i] = (uint8_t)(16 * hi + lo);
  }
  return 1;
}

/* ---- known answers -------------------------------------------------------------------------- */
static int check_hex(const char *what, const uint8_t *got, size_t n, const char *expected) {
  uint8_t exp[256];
  if (n > sizeof exp || !parse_hex(expected, exp, n) || memcmp(got, exp, n)) {
    fprintf(stderr, "selftest FAILED: %s\n", what);
    return 1;
  }
  return 0;
}

typedef struct {
  unsigned pset;
  uint64_t index;
  unsigned e, t;
  unsigned its[MAX_K * MAX_K];
} key_kat_t;

/* computed by mlkem_count.py (seed 0) */
static const key_kat_t KEY_KATS[] = {
    {512, 0, 0, 631, {158, 161, 159, 153}},
    {512, 21, 1, 637, {170, 153, 156, 158}},
    {768, 0, 0, 1414, {157, 158, 156, 155, 156, 156, 162, 157, 157}},
    {768, 5, 1, 1427, {157, 169, 159, 152, 162, 160, 157, 151, 160}},
    {1024, 0, 0, 2510, {166, 160, 162, 156, 154, 153, 156, 160, 152, 167, 154, 152, 154, 153, 152, 159}},
    {1024, 1, 1, 2522, {149, 158, 154, 164, 155, 157, 154, 154, 157, 159, 153, 159, 158, 168, 154, 169}},
};

static int selftest(void) {
  int fails = 0;
  uint8_t out[840], in[34];
  unsigned i, j, its[MAX_K * MAX_K], e, t;
  static const uint8_t seed0[8] = {0}, seed1[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
  /* NIST SHA-3 response files */
  in[0] = 0xe5;
  keccak(SHA3_512_RATE, PAD_SHA3, in, 1, out, 64);
  fails += check_hex("SHA3-512(e5)", out, 64,
                     "150240baf95fb36f8ccb87a19a41767e7aed95125075a2b2dbba6e565e1ce8575f2b042b62e29a04e9440314a821c622"
                     "4182964d8b557b16a492b3806f4c39c1");
  keccak(SHAKE128_RATE, PAD_SHAKE, in, 0, out, 16);
  fails += check_hex("SHAKE128()", out, 16, "7f9c2ba4e88f827d616045507605853e");
  keccak(SHAKE256_RATE, PAD_SHAKE, in, 0, out, 32);
  fails += check_hex("SHAKE256()", out, 32, "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
  /* 5 blocks squeezed: the last 32 of 840 bytes of SHAKE128(00 01 .. 21), computed by hashlib */
  for (i = 0; i < 34; i++) in[i] = (uint8_t)i;
  keccak(SHAKE128_RATE, PAD_SHAKE, in, 34, out, 840);
  fails += check_hex("SHAKE128 840 bytes", out + 808, 32,
                     "b612a205f0511fa2bb82fa8facfb91d48b4b24c76dc79152d1aeab616942512a");
  /* stream of keys, computed by mlkem_count.py */
  derive(seed1, ((uint64_t)1 << 40) + 7, out);
  fails += check_hex("derive d", out, 32, "10e76c8412fb25e68d125ea9fe3001a5d1b949ceb002a79f8deb9cd81293cdb4");
  fails += check_hex("derive z", out + 32, 32, "6e328d2223c325ce3805261bda4c5fca3dda4e3895c082f96d5da54c399283b2");
  fails += check_hex("derive m", out + 64, 32, "de848ba6f120e12b527f7039b8fd6be3efba430fb72d21b923b8dfe9a44db9a7");
  compute_rho(4, out, in);
  fails += check_hex("rho", in, 32, "c1ec8acfb6ccaaa77e70ad99d08c7ccad6849a1668bd3e8e16a057b083f5b9bb");
  for (i = 0; i < sizeof KEY_KATS / sizeof KEY_KATS[0]; i++) {
    const key_kat_t *kat = &KEY_KATS[i];
    const pset_t *p = find_pset(kat->pset);
    derive(seed0, kat->index, out);
    if (key_cost(p, out, its, &e, &t) || e != kat->e || t != kat->t) {
      fprintf(stderr, "selftest FAILED: cost of key %" PRIu64 " of ML-KEM-%u\n", kat->index, kat->pset);
      fails++;
      continue;
    }
    for (j = 0; j < p->k * p->k; j++) {
      if (its[j] != kat->its[j]) {
        fprintf(stderr, "selftest FAILED: entry %u of key %" PRIu64 " of ML-KEM-%u\n", j, kat->index, kat->pset);
        fails++;
        break;
      }
    }
  }
  if (fails) return 3;
  printf("selftest passed\n");
  return 0;
}

/* lines "ALG OUTLEN HEXMSG" on stdin, digests on stdout */
static int hash_lines(void) {
  char *line = malloc(MAX_HASH_LINE);
  uint8_t *msg = malloc(MAX_HASH_LINE / 2), *out = malloc(MAX_HASH_LINE / 2);
  int status = 0;
  if (!line || !msg || !out) {
    fprintf(stderr, "out of memory\n");
    status = 1;
  }
  while (!status && fgets(line, MAX_HASH_LINE, stdin)) {
    char alg[16], hexmsg_first;
    unsigned long outlen;
    int consumed = 0;
    size_t msglen = 0, i;
    unsigned rate;
    uint8_t pad;
    char *hexmsg;
    if (!strchr(line, '\n')) {
      fprintf(stderr, "line too long\n");
      status = 1;
      break;
    }
    if (2 != sscanf(line, "%15s %lu %n", alg, &outlen, &consumed) || !consumed || outlen > MAX_HASH_LINE / 2) {
      fprintf(stderr, "malformed line: %s", line);
      status = 1;
      break;
    }
    hexmsg = line + consumed;
    hexmsg[strcspn(hexmsg, " \r\n")] = 0;
    hexmsg_first = hexmsg[0];
    if (!(hexmsg_first == '-' && hexmsg[1] == 0)) {
      msglen = strlen(hexmsg) / 2;
      if (!parse_hex(hexmsg, msg, msglen)) {
        fprintf(stderr, "malformed message: %s\n", hexmsg);
        status = 1;
        break;
      }
    }
    if (!strcmp(alg, "SHA3-256")) {
      rate = SHA3_256_RATE, pad = PAD_SHA3, outlen = 32;
    } else if (!strcmp(alg, "SHA3-512")) {
      rate = SHA3_512_RATE, pad = PAD_SHA3, outlen = 64;
    } else if (!strcmp(alg, "SHAKE128")) {
      rate = SHAKE128_RATE, pad = PAD_SHAKE;
    } else if (!strcmp(alg, "SHAKE256")) {
      rate = SHAKE256_RATE, pad = PAD_SHAKE;
    } else {
      fprintf(stderr, "unknown algorithm: %s\n", alg);
      status = 1;
      break;
    }
    keccak(rate, pad, msg, msglen, out, outlen);
    for (i = 0; i < outlen; i++) printf("%02x", out[i]);
    printf("\n");
  }
  free(line);
  free(msg);
  free(out);
  return status;
}

static int usage(void) {
  fprintf(stderr,
          "usage: mlkem-search PSET FIRST_CHUNK NCHUNKS [--seed HEX16] [--min-extra E] [--max-iters T] "
          "[--log2-chunk L]\n"
          "       mlkem-search --key PSET INDEX [--seed HEX16]\n"
          "       mlkem-search --hash\n"
          "       mlkem-search --selftest\n");
  return 1;
}

int main(int argc, char *argv[]) {
  uint8_t seed[8] = {0};
  uint64_t pos[3], v;
  unsigned npos = 0, log2_chunk = DEFAULT_LOG2_CHUNK;
  int key_mode = 0, have_e = 0, have_t = 0, i;
  uint64_t min_extra = 0, max_iters = 0;
  const pset_t *p;
  if (argc == 2 && !strcmp(argv[1], "--selftest")) return selftest();
  if (argc == 2 && !strcmp(argv[1], "--hash")) return hash_lines();
  for (i = 1; i < argc; i++) {
    const char *a = argv[i];
    if (!strcmp(a, "--key")) {
      key_mode = 1;
    } else if (!strcmp(a, "--seed") && i + 1 < argc) {
      if (!parse_hex(argv[++i], seed, 8)) return usage();
    } else if (!strcmp(a, "--min-extra") && i + 1 < argc) {
      if (!parse_u64(argv[++i], &min_extra)) return usage();
      have_e = 1;
    } else if (!strcmp(a, "--max-iters") && i + 1 < argc) {
      if (!parse_u64(argv[++i], &max_iters)) return usage();
      have_t = 1;
    } else if (!strcmp(a, "--log2-chunk") && i + 1 < argc) {
      if (!parse_u64(argv[++i], &v) || v > 32) return usage();
      log2_chunk = (unsigned)v;
    } else if (npos < 3 && parse_u64(a, &pos[npos])) {
      npos++;
    } else {
      return usage();
    }
  }
  if (npos < 2 || !(p = find_pset((unsigned long)pos[0]))) return usage();
  if (key_mode) return npos == 2 ? key_report(p, seed, pos[1]) : usage();
  if (npos != 3) return usage();
  /* every index must fit in 64 bits */
  if (pos[2] == 0 || pos[1] > (UINT64_MAX >> log2_chunk) || pos[2] > (UINT64_MAX >> log2_chunk) - pos[1]) return usage();
  if (!have_e) min_extra = p->default_min_extra;
  if (!have_t) max_iters = p->default_max_iters;
  if (min_extra > 2 * MAX_K * MAX_K || max_iters > MAX_K * MAX_K * MAX_ITERATIONS) return usage();
  return search(p, seed, pos[1], pos[2], log2_chunk, (unsigned)min_extra, (unsigned)max_iters);
}
