/*
 * Native Windowed Hankel KEM: key generation, encapsulation and decapsulation.
 *
 * Arithmetic. Every Hankel product has the form out[i] = sum_{j<n} a[i+j] x[j] (+ e[i]) mod q.
 * Because q = 2^12 divides 2^16, the products are accumulated in 16-bit lanes with natural
 * wraparound and reduced once by masking with 0x0FFF. This is exact for any 16-bit inputs.
 * The NEON kernel computes 64 outputs at a time: for each secret coefficient x[j] it adds
 * x[j] * a[i+j .. i+j+63] to eight 8-lane accumulators (vmlaq_laneq_u16), so the secret only
 * ever enters as a multiplication operand.
 *
 * Constant time. Secret values (s, r, e, e1, e2, the message, K_bar, coins, s_reject) are
 * never used as branch conditions or memory addresses. The all-zero-secret fix-up, the
 * ciphertext comparison and the implicit-rejection selection use masks, guarded by a value
 * barrier so that the compiler cannot turn them back into branches. Branches depend only on
 * public data: buffer lengths and the public-key header.
 *
 * Every step that touches secret values is a separate non-inlined function with external
 * linkage (hankel_kernel_*), so that the compiled code can be checked by the static branch
 * audit in ct_branch_audit.py, as can hk_keccakf1600.
 */

#include "hankel_kem_native.h"
#include "hankel_hash.h"

#include <string.h>
#if defined(__APPLE__)
#include <stdlib.h>
#else
#include <unistd.h>
#endif

#if (defined(__ARM_NEON) || defined(__aarch64__)) && !defined(HK_FORCE_SCALAR)
#include <arm_neon.h>
#define HK_USE_NEON 1
#endif

#define HK_N 640
#define HK_W 128
#define HK_M (HK_N + HK_W)              /* 768 */
#define HK_A_LEN (2 * HK_N + HK_W - 1)  /* 1407 */
#define HK_MASK 0x0FFF
#define HK_Q 4096

#define HK_HDR 12
#define HK_SEED 32
#define HK_PACK_M ((HK_M * 3) / 2)      /* 1152 */
#define HK_PACK_W ((HK_W * 3) / 2)      /* 192 */

static const uint8_t TAG_CCA_SEED[] = "_hankel_cca_keygen_seed";
static const uint8_t TAG_CPA_SEED[] = "_hankel_cpa_keygen_seed";
static const uint8_t TAG_NOISE[] = "_hankel_noise";
static const uint8_t TAG_REJECT[] = "_hankel_cca_reject";
static const uint8_t TAG_ENC_ENTROPY[] = "_hankel_encaps_entropy";
static const uint8_t TAG_ENC_COINS[] = "_hankel_encaps_coins";
#define TAGLEN(t) (sizeof(t) - 1)

#define HK_KERNEL __attribute__((noinline))

/* Secret-handling kernels (exported for the static audit; not part of the public API). */
void hankel_kernel_mul(uint16_t *out, const uint16_t *a, const int16_t *x, const int16_t *e, int m);
void hankel_kernel_cbd2(int16_t *out, const uint8_t *buf, int count);
void hankel_kernel_fix_zero_secret(int16_t *s);
void hankel_kernel_load_secret(int16_t *s, const uint8_t *sk);
void hankel_kernel_store_secret(uint8_t *sk, const int16_t *s);
void hankel_kernel_encode_add(uint16_t *v, const uint16_t *k, const uint8_t *msg, const int16_t *e2);
void hankel_kernel_decode(uint8_t *msg, const uint16_t *v, const uint16_t *k);
void hankel_kernel_verify_select(uint8_t *k_sel, const uint8_t *ct, const uint8_t *ct2,
                                 const uint8_t *k_bar, const uint8_t *s_reject);

/* ---------------------------------------------------------------------------------------------
 * Constant-time helpers
 * ------------------------------------------------------------------------------------------- */

static inline uint32_t hk_value_barrier_u32(uint32_t x) {
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("" : "+r"(x));
#endif
    return x;
}

static void hk_zeroize(void *p, size_t len) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (len--) *v++ = 0;
}

/* Returns 0xFFFFFFFF if a and b are equal, 0 otherwise. */
static uint32_t hk_ct_equal_mask(const uint8_t *a, const uint8_t *b, size_t len) {
    uint32_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= (uint32_t)(a[i] ^ b[i]);
    diff = hk_value_barrier_u32(diff);
    /* diff in [0, 255]: (diff - 1) >> 31 is 1 iff diff == 0. */
    return (uint32_t)0 - ((diff - 1) >> 31);
}

/* out = mask ? a : b, with mask in {0, 0xFFFFFFFF}. */
static void hk_ct_select(uint8_t *out, const uint8_t *a, const uint8_t *b, size_t len,
                         uint32_t mask) {
    uint8_t m = (uint8_t)hk_value_barrier_u32(mask);
    for (size_t i = 0; i < len; i++) out[i] = (uint8_t)((a[i] & m) | (b[i] & (uint8_t)~m));
}

/* ---------------------------------------------------------------------------------------------
 * Hankel product: out[i] = (sum_{j<640} a[i+j] x[j] + e[i]) & 0x0FFF for 0 <= i < m.
 * Requires m to be a multiple of 64 and a to hold at least m + 639 coefficients.
 * ------------------------------------------------------------------------------------------- */

HK_KERNEL void hankel_kernel_mul(uint16_t *out, const uint16_t *a, const int16_t *x,
                                 const int16_t *e, int m) {
#if defined(HK_USE_NEON)
    const uint16x8_t vmask = vdupq_n_u16(HK_MASK);
    for (int i = 0; i < m; i += 64) {
        uint16x8_t acc0, acc1, acc2, acc3, acc4, acc5, acc6, acc7;
        if (e != NULL) {
            const uint16_t *eu = (const uint16_t *)e + i;
            acc0 = vld1q_u16(eu);      acc1 = vld1q_u16(eu + 8);
            acc2 = vld1q_u16(eu + 16); acc3 = vld1q_u16(eu + 24);
            acc4 = vld1q_u16(eu + 32); acc5 = vld1q_u16(eu + 40);
            acc6 = vld1q_u16(eu + 48); acc7 = vld1q_u16(eu + 56);
        } else {
            acc0 = acc1 = acc2 = acc3 = acc4 = acc5 = acc6 = acc7 = vdupq_n_u16(0);
        }
        const uint16_t *ai = a + i;
        for (int j = 0; j < HK_N; j += 8) {
            const uint16x8_t xs = vld1q_u16((const uint16_t *)x + j);
            const uint16_t *p = ai + j;
#define HK_STEP(L)                                                         \
            acc0 = vmlaq_laneq_u16(acc0, vld1q_u16(p + (L)), xs, L);       \
            acc1 = vmlaq_laneq_u16(acc1, vld1q_u16(p + (L) + 8), xs, L);   \
            acc2 = vmlaq_laneq_u16(acc2, vld1q_u16(p + (L) + 16), xs, L);  \
            acc3 = vmlaq_laneq_u16(acc3, vld1q_u16(p + (L) + 24), xs, L);  \
            acc4 = vmlaq_laneq_u16(acc4, vld1q_u16(p + (L) + 32), xs, L);  \
            acc5 = vmlaq_laneq_u16(acc5, vld1q_u16(p + (L) + 40), xs, L);  \
            acc6 = vmlaq_laneq_u16(acc6, vld1q_u16(p + (L) + 48), xs, L);  \
            acc7 = vmlaq_laneq_u16(acc7, vld1q_u16(p + (L) + 56), xs, L);
            HK_STEP(0) HK_STEP(1) HK_STEP(2) HK_STEP(3)
            HK_STEP(4) HK_STEP(5) HK_STEP(6) HK_STEP(7)
#undef HK_STEP
        }
        vst1q_u16(out + i, vandq_u16(acc0, vmask));
        vst1q_u16(out + i + 8, vandq_u16(acc1, vmask));
        vst1q_u16(out + i + 16, vandq_u16(acc2, vmask));
        vst1q_u16(out + i + 24, vandq_u16(acc3, vmask));
        vst1q_u16(out + i + 32, vandq_u16(acc4, vmask));
        vst1q_u16(out + i + 40, vandq_u16(acc5, vmask));
        vst1q_u16(out + i + 48, vandq_u16(acc6, vmask));
        vst1q_u16(out + i + 56, vandq_u16(acc7, vmask));
    }
#else
    for (int i = 0; i < m; i++) {
        uint16_t acc = (e != NULL) ? (uint16_t)e[i] : 0;
        for (int j = 0; j < HK_N; j++) acc = (uint16_t)(acc + a[i + j] * (uint16_t)x[j]);
        out[i] = acc & HK_MASK;
    }
#endif
}

/* ---------------------------------------------------------------------------------------------
 * Sampling, encoding and serialization
 * ------------------------------------------------------------------------------------------- */

/* Public sequence: SHAKE-256(seed_a) read as little-endian 16-bit words, masked to 12 bits. */
static void hk_expand_a(uint16_t a[HK_A_LEN], const uint8_t seed_a[HK_SEED]) {
    uint8_t buf[2 * HK_A_LEN];
    hk_shake256_2(buf, sizeof(buf), seed_a, HK_SEED, NULL, 0);
    for (int i = 0; i < HK_A_LEN; i++) {
        a[i] = (uint16_t)((buf[2 * i] | ((uint16_t)buf[2 * i + 1] << 8)) & HK_MASK);
    }
}

/* CBD_2 from the low four bits of each byte: (b0 + b1) - (b2 + b3). */
HK_KERNEL void hankel_kernel_cbd2(int16_t *out, const uint8_t *buf, int count) {
    for (int i = 0; i < count; i++) {
        uint32_t t = buf[i];
        out[i] = (int16_t)((int)((t & 1) + ((t >> 1) & 1)) - (int)(((t >> 2) & 1) + ((t >> 3) & 1)));
    }
}

static void hk_pack12(uint8_t *out, const uint16_t *in, int count) {
    for (int i = 0; i < count; i += 2) {
        uint16_t x0 = in[i] & HK_MASK, x1 = in[i + 1] & HK_MASK;
        uint8_t *o = out + (i / 2) * 3;
        o[0] = (uint8_t)x0;
        o[1] = (uint8_t)((x0 >> 8) | ((x1 & 0x0F) << 4));
        o[2] = (uint8_t)(x1 >> 4);
    }
}

static void hk_unpack12(uint16_t *out, const uint8_t *in, int count) {
    for (int i = 0; i < count; i += 2) {
        const uint8_t *p = in + (i / 2) * 3;
        out[i] = (uint16_t)(p[0] | ((uint16_t)(p[1] & 0x0F) << 8));
        out[i + 1] = (uint16_t)((p[1] >> 4) | ((uint16_t)p[2] << 4));
    }
}

static void hk_write_header(uint8_t hdr[HK_HDR], const char magic[4]) {
    memcpy(hdr, magic, 4);
    const uint16_t f[4] = {HK_N, HK_W, HK_Q, 0};
    for (int i = 0; i < 4; i++) {
        hdr[4 + 2 * i] = (uint8_t)f[i];
        hdr[5 + 2 * i] = (uint8_t)(f[i] >> 8);
    }
}

/* Public-key header check (public data). */
static int hk_check_pk(const uint8_t *pk) {
    uint8_t hdr[HK_HDR];
    hk_write_header(hdr, "HNPK");
    return memcmp(pk, hdr, HK_HDR) == 0 ? 0 : -1;
}

/* If every secret coefficient is zero, set s[0] = 1 (as the reference does), without branching. */
HK_KERNEL void hankel_kernel_fix_zero_secret(int16_t *s) {
    uint32_t any = 0;
    for (int i = 0; i < HK_N; i++) any |= (uint16_t)s[i];
    any = hk_value_barrier_u32(any);
    s[0] = (int16_t)(s[0] | (int16_t)(1 ^ ((any | (0u - any)) >> 31)));
}

/* The secret key stores s as signed bytes. */
HK_KERNEL void hankel_kernel_load_secret(int16_t *s, const uint8_t *sk) {
    for (int i = 0; i < HK_N; i++) s[i] = (int16_t)(int8_t)sk[i];
}

HK_KERNEL void hankel_kernel_store_secret(uint8_t *sk, const int16_t *s) {
    for (int i = 0; i < HK_N; i++) sk[i] = (uint8_t)(int8_t)s[i];
}

/* v = K + PAM(msg) + e2 mod q. Symbol i is bits 2(i mod 4)..2(i mod 4)+1 of byte i/4, times q/4. */
HK_KERNEL void hankel_kernel_encode_add(uint16_t *v, const uint16_t *k, const uint8_t *msg,
                                        const int16_t *e2) {
    for (int i = 0; i < HK_W; i++) {
        uint16_t sym = (uint16_t)((msg[i >> 2] >> (2 * (i & 3))) & 3);
        v[i] = (uint16_t)((k[i] + (sym << 10) + (uint16_t)e2[i]) & HK_MASK);
    }
}

/* 4-PAM decision: the symbol of v - K is ((v - K + q/8) mod q) / (q/4). */
HK_KERNEL void hankel_kernel_decode(uint8_t *msg, const uint16_t *v, const uint16_t *k) {
    for (int i = 0; i < 32; i++) msg[i] = 0;
    for (int i = 0; i < HK_W; i++) {
        uint16_t w = (uint16_t)((v[i] - k[i]) & HK_MASK);
        uint8_t sym = (uint8_t)(((w + 512) & HK_MASK) >> 10);
        msg[i >> 2] |= (uint8_t)(sym << (2 * (i & 3)));
    }
}

/* k_sel = (ct == ct2) ? k_bar : s_reject, in constant time. */
HK_KERNEL void hankel_kernel_verify_select(uint8_t *k_sel, const uint8_t *ct, const uint8_t *ct2,
                                           const uint8_t *k_bar, const uint8_t *s_reject) {
    uint32_t ok = hk_ct_equal_mask(ct, ct2, HANKEL_KEM_CIPHERTEXTBYTES);
    hk_ct_select(k_sel, k_bar, s_reject, 32, ok);
}

/* ---------------------------------------------------------------------------------------------
 * CPA encryption (hankel_kem/cpa.py) followed by ciphertext serialization
 * ------------------------------------------------------------------------------------------- */

static void hk_cpa_enc(uint8_t ct[HANKEL_KEM_CIPHERTEXTBYTES], const uint16_t a[HK_A_LEN],
                       const uint16_t b[HK_M], const uint8_t msg[32], const uint8_t coins[32]) {
    uint8_t buf[HK_N + HK_M + HK_W];
    int16_t r[HK_N], e1[HK_M], e2[HK_W];
    uint16_t u[HK_M], k[HK_W], v[HK_W];

    hk_shake256_2(buf, sizeof(buf), coins, 32, TAG_ENC_COINS, TAGLEN(TAG_ENC_COINS));
    hankel_kernel_cbd2(r, buf, HK_N);
    hankel_kernel_cbd2(e1, buf + HK_N, HK_M);
    hankel_kernel_cbd2(e2, buf + HK_N + HK_M, HK_W);

    hankel_kernel_mul(u, a, r, e1, HK_M);   /* u = H(a) r + e1 */
    hankel_kernel_mul(k, b, r, NULL, HK_W); /* K = Project(r, b) */
    hankel_kernel_encode_add(v, k, msg, e2); /* v = K + PAM(msg) + e2 */

    hk_write_header(ct, "HNCT");
    hk_pack12(ct + HK_HDR, u, HK_M);
    hk_pack12(ct + HK_HDR + HK_PACK_M, v, HK_W);

    hk_zeroize(buf, sizeof(buf));
    hk_zeroize(r, sizeof(r));
    hk_zeroize(e1, sizeof(e1));
    hk_zeroize(e2, sizeof(e2));
    hk_zeroize(k, sizeof(k));
    hk_zeroize(v, sizeof(v));
}

/* ---------------------------------------------------------------------------------------------
 * KEM
 * ------------------------------------------------------------------------------------------- */

static int hk_randombytes(uint8_t *out, size_t len) {
#if defined(__APPLE__)
    arc4random_buf(out, len);
    return 0;
#else
    while (len) {
        size_t chunk = len > 256 ? 256 : len;
        if (getentropy(out, chunk) != 0) return -1;
        out += chunk;
        len -= chunk;
    }
    return 0;
#endif
}

int hankel_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed, size_t seed_len) {
    uint8_t seed64[64], cpa_seed[64], noise[HK_N + HK_M], s_reject[32];
    int16_t s[HK_N], e[HK_M];
    uint16_t a[HK_A_LEN], b[HK_M];
    const uint8_t *seed_cpa, *seed_rest;
    size_t rest_len;

    if (seed_len < 64) {
        hk_shake256_2(seed64, 64, seed, seed_len, TAG_CCA_SEED, TAGLEN(TAG_CCA_SEED));
        seed_cpa = seed64;
        seed_rest = seed64 + 32;
        rest_len = 32;
    } else {
        seed_cpa = seed;
        seed_rest = seed + 32;
        rest_len = seed_len - 32;
    }

    /* CPA key generation; the 32-byte CPA seed is always expanded to 64 bytes. */
    hk_shake256_2(cpa_seed, 64, seed_cpa, 32, TAG_CPA_SEED, TAGLEN(TAG_CPA_SEED));
    const uint8_t *seed_a = cpa_seed, *seed_noise = cpa_seed + 32;
    hk_expand_a(a, seed_a);
    hk_shake256_2(noise, sizeof(noise), seed_noise, 32, TAG_NOISE, TAGLEN(TAG_NOISE));
    hankel_kernel_cbd2(s, noise, HK_N);
    hankel_kernel_cbd2(e, noise + HK_N, HK_M);

    hankel_kernel_fix_zero_secret(s);

    hankel_kernel_mul(b, a, s, e, HK_M); /* b = H(a) s + e */

    hk_write_header(pk, "HNPK");
    memcpy(pk + HK_HDR, seed_a, HK_SEED);
    hk_pack12(pk + HK_HDR + HK_SEED, b, HK_M);

    hk_shake256_2(s_reject, 32, seed_rest, rest_len, TAG_REJECT, TAGLEN(TAG_REJECT));
    hankel_kernel_store_secret(sk, s);
    memcpy(sk + HK_N, s_reject, 32);
    memcpy(sk + HK_N + 32, pk, HANKEL_KEM_PUBLICKEYBYTES);

    hk_zeroize(seed64, sizeof(seed64));
    hk_zeroize(cpa_seed + 32, 32);
    hk_zeroize(noise, sizeof(noise));
    hk_zeroize(s_reject, sizeof(s_reject));
    hk_zeroize(s, sizeof(s));
    hk_zeroize(e, sizeof(e));
    return 0;
}

int hankel_kem_keypair(uint8_t *pk, uint8_t *sk) {
    uint8_t seed[64];
    if (hk_randombytes(seed, sizeof(seed)) != 0) return -1;
    int rc = hankel_kem_keypair_derand(pk, sk, seed, sizeof(seed));
    hk_zeroize(seed, sizeof(seed));
    return rc;
}

static int hk_enc_msg(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t msg[32]) {
    uint8_t h_pk[32], kc[64], h_ct[32];
    uint16_t a[HK_A_LEN], b[HK_M];

    if (hk_check_pk(pk) != 0) return -1;
    hk_sha256(h_pk, pk, HANKEL_KEM_PUBLICKEYBYTES);
    hk_shake256_2(kc, 64, msg, 32, h_pk, 32); /* (K_bar, coins) */

    hk_expand_a(a, pk + HK_HDR);
    hk_unpack12(b, pk + HK_HDR + HK_SEED, HK_M);
    hk_cpa_enc(ct, a, b, msg, kc + 32);

    hk_sha256(h_ct, ct, HANKEL_KEM_CIPHERTEXTBYTES);
    hk_shake256_2(ss, 32, kc, 32, h_ct, 32);

    hk_zeroize(kc, sizeof(kc));
    return 0;
}

int hankel_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                          const uint8_t *entropy, size_t entropy_len) {
    uint8_t msg[32];
    hk_shake256_2(msg, 32, entropy, entropy_len, TAG_ENC_ENTROPY, TAGLEN(TAG_ENC_ENTROPY));
    int rc = hk_enc_msg(ct, ss, pk, msg);
    hk_zeroize(msg, sizeof(msg));
    return rc;
}

int hankel_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    uint8_t msg[32];
    if (hk_randombytes(msg, sizeof(msg)) != 0) return -1;
    int rc = hk_enc_msg(ct, ss, pk, msg);
    hk_zeroize(msg, sizeof(msg));
    return rc;
}

int hankel_kem_dec(uint8_t *ss, const uint8_t *ct, size_t ct_len, const uint8_t *sk) {
    const uint8_t *s_reject = sk + HK_N;
    const uint8_t *pk = sk + HK_N + 32;
    uint8_t h_pk[32], h_ct[32], msg[32], kc[64], k_sel[32];
    uint8_t ct2[HANKEL_KEM_CIPHERTEXTBYTES];
    int16_t s[HK_N];
    uint16_t a[HK_A_LEN], b[HK_M], u[HK_M], v[HK_W], k[HK_W];

    if (hk_check_pk(pk) != 0) return -1;
    hk_sha256(h_ct, ct, ct_len);

    /* A ciphertext of the wrong length can never match a re-encryption (public condition). */
    if (ct_len != HANKEL_KEM_CIPHERTEXTBYTES) {
        hk_shake256_2(ss, 32, s_reject, 32, h_ct, 32);
        return 0;
    }

    /* CPA decryption: m' = Decode(v - Project(s, u)). */
    hankel_kernel_load_secret(s, sk);
    hk_unpack12(u, ct + HK_HDR, HK_M);
    hk_unpack12(v, ct + HK_HDR + HK_PACK_M, HK_W);
    hankel_kernel_mul(k, u, s, NULL, HK_W);
    hankel_kernel_decode(msg, v, k);

    /* Re-encryption check (Fujisaki-Okamoto). The header is part of the comparison. */
    hk_sha256(h_pk, pk, HANKEL_KEM_PUBLICKEYBYTES);
    hk_shake256_2(kc, 64, msg, 32, h_pk, 32);
    hk_expand_a(a, pk + HK_HDR);
    hk_unpack12(b, pk + HK_HDR + HK_SEED, HK_M);
    hk_cpa_enc(ct2, a, b, msg, kc + 32);

    hankel_kernel_verify_select(k_sel, ct, ct2, kc, s_reject);
    hk_shake256_2(ss, 32, k_sel, 32, h_ct, 32);

    hk_zeroize(s, sizeof(s));
    hk_zeroize(k, sizeof(k));
    hk_zeroize(msg, sizeof(msg));
    hk_zeroize(kc, sizeof(kc));
    hk_zeroize(k_sel, sizeof(k_sel));
    hk_zeroize(ct2, sizeof(ct2));
    return 0;
}
