/*
 * Native Windowed Hankel KEM -- parameter-set template.
 *
 * Included by hankel_kem_native.c once per parameter set, with:
 *   HK_PREFIX  symbol prefix (hankel_ for WH-640, hankel936_, hankel1208_)
 *   HK_N       dimension n (a multiple of 8)
 *   HK_LOGQ    log2 q (12 or 13); every q here divides 2^16
 *   HK_DOM     domain string appended to every derivation tag ("" for WH-640)
 * The window is W = 128 (a 256-bit message by 4-PAM) and the distribution CBD_2 for every set.
 * Bit-exact with the Python reference hankel_kem/generic.py.
 */

#ifndef HK_CAT2
#define HK_CAT2(a, b) a##b
#define HK_CAT(a, b) HK_CAT2(a, b)
#endif
#define HK_FN(name) HK_CAT(HK_PREFIX, name)

#define HK_W 128
#define HK_M (HK_N + HK_W)
#define HK_A_LEN (2 * HK_N + HK_W - 1)
#define HK_Q (1u << HK_LOGQ)
#define HK_MASK ((uint16_t)(HK_Q - 1))
#define HK_PACK_M (HK_M * HK_LOGQ / 8)
#define HK_PACK_W (HK_W * HK_LOGQ / 8)
#define HK_PKB (HK_HDR + HK_SEED + HK_PACK_M)
#define HK_CTB (HK_HDR + HK_PACK_M + HK_PACK_W)

_Static_assert(HK_N % 8 == 0 && HK_M % 8 == 0, "n and m must be multiples of 8");
_Static_assert((HK_M * HK_LOGQ) % 8 == 0 && (HK_W * HK_LOGQ) % 8 == 0, "packing must fill whole bytes");
_Static_assert(HK_LOGQ >= 3 && HK_LOGQ <= 16, "q must divide 2^16");

/* Secret-handling kernels (exported for the static audit; not part of the public API). */
void HK_FN(kernel_mul)(uint16_t *out, const uint16_t *a, const int16_t *x, const int16_t *e, int m);
void HK_FN(kernel_cbd2)(int16_t *out, const uint8_t *buf, int count);
void HK_FN(kernel_fix_zero_secret)(int16_t *s);
void HK_FN(kernel_load_secret)(int16_t *s, const uint8_t *sk);
void HK_FN(kernel_store_secret)(uint8_t *sk, const int16_t *s);
void HK_FN(kernel_encode_add)(uint16_t *v, const uint16_t *k, const uint8_t *msg, const int16_t *e2);
void HK_FN(kernel_decode)(uint8_t *msg, const uint16_t *v, const uint16_t *k);
void HK_FN(kernel_verify_select)(uint8_t *k_sel, const uint8_t *ct, const uint8_t *ct2,
                                 const uint8_t *k_bar, const uint8_t *s_reject);

/* ---------------------------------------------------------------------------------------------
 * Hankel product: out[i] = (sum_{j<n} a[i+j] x[j] + e[i]) mod q for 0 <= i < m (m a multiple of 8;
 * a must hold m + n - 1 coefficients). Computed modulo 2^16 with wraparound, then masked.
 * ------------------------------------------------------------------------------------------- */

HK_KERNEL void HK_FN(kernel_mul)(uint16_t *out, const uint16_t *a, const int16_t *x,
                                 const int16_t *e, int m) {
#if defined(HK_USE_NEON)
    const uint16x8_t vmask = vdupq_n_u16(HK_MASK);
    int i = 0;
    for (; i + 64 <= m; i += 64) { /* 64 outputs per pass, eight accumulators */
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
    for (; i + 8 <= m; i += 8) { /* tail: 8 outputs per pass */
        uint16x8_t acc = (e != NULL) ? vld1q_u16((const uint16_t *)e + i) : vdupq_n_u16(0);
        for (int j = 0; j < HK_N; j += 8) {
            const uint16x8_t xs = vld1q_u16((const uint16_t *)x + j);
            const uint16_t *p = a + i + j;
            acc = vmlaq_laneq_u16(acc, vld1q_u16(p), xs, 0);
            acc = vmlaq_laneq_u16(acc, vld1q_u16(p + 1), xs, 1);
            acc = vmlaq_laneq_u16(acc, vld1q_u16(p + 2), xs, 2);
            acc = vmlaq_laneq_u16(acc, vld1q_u16(p + 3), xs, 3);
            acc = vmlaq_laneq_u16(acc, vld1q_u16(p + 4), xs, 4);
            acc = vmlaq_laneq_u16(acc, vld1q_u16(p + 5), xs, 5);
            acc = vmlaq_laneq_u16(acc, vld1q_u16(p + 6), xs, 6);
            acc = vmlaq_laneq_u16(acc, vld1q_u16(p + 7), xs, 7);
        }
        vst1q_u16(out + i, vandq_u16(acc, vmask));
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
 * Sampling and encoding
 * ------------------------------------------------------------------------------------------- */

/* Public sequence: SHAKE-256(seed_a) read as little-endian 16-bit words, masked to log2 q bits. */
static void HK_FN(expand_a)(uint16_t a[HK_A_LEN], const uint8_t seed_a[HK_SEED]) {
    uint8_t buf[2 * HK_A_LEN];
    hk_shake256_2(buf, sizeof(buf), seed_a, HK_SEED, NULL, 0);
    for (int i = 0; i < HK_A_LEN; i++) {
        a[i] = (uint16_t)((buf[2 * i] | ((uint16_t)buf[2 * i + 1] << 8)) & HK_MASK);
    }
}

/* CBD_2 from the low four bits of each byte: (b0 + b1) - (b2 + b3). */
HK_KERNEL void HK_FN(kernel_cbd2)(int16_t *out, const uint8_t *buf, int count) {
    for (int i = 0; i < count; i++) {
        uint32_t t = buf[i];
        out[i] = (int16_t)((int)((t & 1) + ((t >> 1) & 1)) - (int)(((t >> 2) & 1) + ((t >> 3) & 1)));
    }
}

/* If every secret coefficient is zero, set s[0] = 1 (as the reference does), without branching. */
HK_KERNEL void HK_FN(kernel_fix_zero_secret)(int16_t *s) {
    uint32_t any = 0;
    for (int i = 0; i < HK_N; i++) any |= (uint16_t)s[i];
    any = hk_value_barrier_u32(any);
    s[0] = (int16_t)(s[0] | (int16_t)(1 ^ ((any | (0u - any)) >> 31)));
}

/* The secret key stores s as signed bytes. */
HK_KERNEL void HK_FN(kernel_load_secret)(int16_t *s, const uint8_t *sk) {
    for (int i = 0; i < HK_N; i++) s[i] = (int16_t)(int8_t)sk[i];
}

HK_KERNEL void HK_FN(kernel_store_secret)(uint8_t *sk, const int16_t *s) {
    for (int i = 0; i < HK_N; i++) sk[i] = (uint8_t)(int8_t)s[i];
}

/* v = K + PAM(msg) + e2 mod q. Symbol i is bits 2(i mod 4)..2(i mod 4)+1 of byte i/4, times q/4. */
HK_KERNEL void HK_FN(kernel_encode_add)(uint16_t *v, const uint16_t *k, const uint8_t *msg,
                                        const int16_t *e2) {
    for (int i = 0; i < HK_W; i++) {
        uint16_t sym = (uint16_t)((msg[i >> 2] >> (2 * (i & 3))) & 3);
        v[i] = (uint16_t)((k[i] + (sym << (HK_LOGQ - 2)) + (uint16_t)e2[i]) & HK_MASK);
    }
}

/* 4-PAM decision: the symbol of v - K is ((v - K + q/8) mod q) / (q/4). */
HK_KERNEL void HK_FN(kernel_decode)(uint8_t *msg, const uint16_t *v, const uint16_t *k) {
    for (int i = 0; i < 32; i++) msg[i] = 0;
    for (int i = 0; i < HK_W; i++) {
        uint16_t w = (uint16_t)((v[i] - k[i]) & HK_MASK);
        uint8_t sym = (uint8_t)(((w + (HK_Q >> 3)) & HK_MASK) >> (HK_LOGQ - 2));
        msg[i >> 2] |= (uint8_t)(sym << (2 * (i & 3)));
    }
}

/* k_sel = (ct == ct2) ? k_bar : s_reject, in constant time. */
HK_KERNEL void HK_FN(kernel_verify_select)(uint8_t *k_sel, const uint8_t *ct, const uint8_t *ct2,
                                           const uint8_t *k_bar, const uint8_t *s_reject) {
    uint32_t ok = hk_ct_equal_mask(ct, ct2, HK_CTB);
    hk_ct_select(k_sel, k_bar, s_reject, 32, ok);
}

/* Public-key header check (public data). */
static int HK_FN(check_pk)(const uint8_t *pk) {
    uint8_t hdr[HK_HDR];
    hk_write_header(hdr, "HNPK", HK_N, HK_W, HK_Q);
    return memcmp(pk, hdr, HK_HDR) == 0 ? 0 : -1;
}

/* ---------------------------------------------------------------------------------------------
 * CPA encryption followed by ciphertext serialization
 * ------------------------------------------------------------------------------------------- */

static void HK_FN(cpa_enc)(uint8_t ct[HK_CTB], const uint16_t a[HK_A_LEN], const uint16_t b[HK_M],
                           const uint8_t msg[32], const uint8_t coins[32]) {
    static const char tag[] = "_hankel_encaps_coins" HK_DOM;
    uint8_t buf[HK_N + HK_M + HK_W];
    int16_t r[HK_N], e1[HK_M], e2[HK_W];
    uint16_t u[HK_M], k[HK_W], v[HK_W];

    hk_shake256_2(buf, sizeof(buf), coins, 32, (const uint8_t *)tag, sizeof(tag) - 1);
    HK_FN(kernel_cbd2)(r, buf, HK_N);
    HK_FN(kernel_cbd2)(e1, buf + HK_N, HK_M);
    HK_FN(kernel_cbd2)(e2, buf + HK_N + HK_M, HK_W);

    HK_FN(kernel_mul)(u, a, r, e1, HK_M);   /* u = H(a) r + e1 */
    HK_FN(kernel_mul)(k, b, r, NULL, HK_W); /* K = Project(r, b) */
    HK_FN(kernel_encode_add)(v, k, msg, e2); /* v = K + PAM(msg) + e2 */

    hk_write_header(ct, "HNCT", HK_N, HK_W, HK_Q);
    hk_pack_bits(ct + HK_HDR, u, HK_M, HK_LOGQ);
    hk_pack_bits(ct + HK_HDR + HK_PACK_M, v, HK_W, HK_LOGQ);

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

int HK_FN(kem_keypair_derand)(uint8_t *pk, uint8_t *sk, const uint8_t *seed, size_t seed_len) {
    static const char tag_cca[] = "_hankel_cca_keygen_seed" HK_DOM;
    static const char tag_cpa[] = "_hankel_cpa_keygen_seed" HK_DOM;
    static const char tag_noise[] = "_hankel_noise" HK_DOM;
    static const char tag_reject[] = "_hankel_cca_reject" HK_DOM;
    uint8_t seed64[64], cpa_seed[64], noise[HK_N + HK_M], s_reject[32];
    int16_t s[HK_N], e[HK_M];
    uint16_t a[HK_A_LEN], b[HK_M];
    const uint8_t *seed_cpa, *seed_rest;
    size_t rest_len;

    if (seed_len < 64) {
        hk_shake256_2(seed64, 64, seed, seed_len, (const uint8_t *)tag_cca, sizeof(tag_cca) - 1);
        seed_cpa = seed64;
        seed_rest = seed64 + 32;
        rest_len = 32;
    } else {
        seed_cpa = seed;
        seed_rest = seed + 32;
        rest_len = seed_len - 32;
    }

    /* CPA key generation; the 32-byte CPA seed is always expanded to 64 bytes. */
    hk_shake256_2(cpa_seed, 64, seed_cpa, 32, (const uint8_t *)tag_cpa, sizeof(tag_cpa) - 1);
    const uint8_t *seed_a = cpa_seed, *seed_noise = cpa_seed + 32;
    HK_FN(expand_a)(a, seed_a);
    hk_shake256_2(noise, sizeof(noise), seed_noise, 32, (const uint8_t *)tag_noise, sizeof(tag_noise) - 1);
    HK_FN(kernel_cbd2)(s, noise, HK_N);
    HK_FN(kernel_cbd2)(e, noise + HK_N, HK_M);

    HK_FN(kernel_fix_zero_secret)(s);

    HK_FN(kernel_mul)(b, a, s, e, HK_M); /* b = H(a) s + e */

    hk_write_header(pk, "HNPK", HK_N, HK_W, HK_Q);
    memcpy(pk + HK_HDR, seed_a, HK_SEED);
    hk_pack_bits(pk + HK_HDR + HK_SEED, b, HK_M, HK_LOGQ);

    hk_shake256_2(s_reject, 32, seed_rest, rest_len, (const uint8_t *)tag_reject, sizeof(tag_reject) - 1);
    HK_FN(kernel_store_secret)(sk, s);
    memcpy(sk + HK_N, s_reject, 32);
    memcpy(sk + HK_N + 32, pk, HK_PKB);

    hk_zeroize(seed64, sizeof(seed64));
    hk_zeroize(cpa_seed + 32, 32);
    hk_zeroize(noise, sizeof(noise));
    hk_zeroize(s_reject, sizeof(s_reject));
    hk_zeroize(s, sizeof(s));
    hk_zeroize(e, sizeof(e));
    return 0;
}

int HK_FN(kem_keypair)(uint8_t *pk, uint8_t *sk) {
    uint8_t seed[64];
    if (hk_randombytes(seed, sizeof(seed)) != 0) return -1;
    int rc = HK_FN(kem_keypair_derand)(pk, sk, seed, sizeof(seed));
    hk_zeroize(seed, sizeof(seed));
    return rc;
}

static int HK_FN(enc_msg)(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t msg[32]) {
    uint8_t h_pk[32], kc[64], h_ct[32];
    uint16_t a[HK_A_LEN], b[HK_M];

    if (HK_FN(check_pk)(pk) != 0) return -1;
    hk_sha256(h_pk, pk, HK_PKB);
    hk_shake256_2(kc, 64, msg, 32, h_pk, 32); /* (K_bar, coins) */

    HK_FN(expand_a)(a, pk + HK_HDR);
    hk_unpack_bits(b, pk + HK_HDR + HK_SEED, HK_M, HK_LOGQ);
    HK_FN(cpa_enc)(ct, a, b, msg, kc + 32);

    hk_sha256(h_ct, ct, HK_CTB);
    hk_shake256_2(ss, 32, kc, 32, h_ct, 32);

    hk_zeroize(kc, sizeof(kc));
    return 0;
}

int HK_FN(kem_enc_derand)(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                          const uint8_t *entropy, size_t entropy_len) {
    static const char tag[] = "_hankel_encaps_entropy" HK_DOM;
    uint8_t msg[32];
    hk_shake256_2(msg, 32, entropy, entropy_len, (const uint8_t *)tag, sizeof(tag) - 1);
    int rc = HK_FN(enc_msg)(ct, ss, pk, msg);
    hk_zeroize(msg, sizeof(msg));
    return rc;
}

int HK_FN(kem_enc)(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    uint8_t msg[32];
    if (hk_randombytes(msg, sizeof(msg)) != 0) return -1;
    int rc = HK_FN(enc_msg)(ct, ss, pk, msg);
    hk_zeroize(msg, sizeof(msg));
    return rc;
}

int HK_FN(kem_dec)(uint8_t *ss, const uint8_t *ct, size_t ct_len, const uint8_t *sk) {
    const uint8_t *s_reject = sk + HK_N;
    const uint8_t *pk = sk + HK_N + 32;
    uint8_t h_pk[32], h_ct[32], msg[32], kc[64], k_sel[32];
    uint8_t ct2[HK_CTB];
    int16_t s[HK_N];
    uint16_t a[HK_A_LEN], b[HK_M], u[HK_M], v[HK_W], k[HK_W];

    if (HK_FN(check_pk)(pk) != 0) return -1;
    hk_sha256(h_ct, ct, ct_len);

    /* A ciphertext of the wrong length can never match a re-encryption (public condition). */
    if (ct_len != HK_CTB) {
        hk_shake256_2(ss, 32, s_reject, 32, h_ct, 32);
        return 0;
    }

    /* CPA decryption: m' = Decode(v - Project(s, u)). */
    HK_FN(kernel_load_secret)(s, sk);
    hk_unpack_bits(u, ct + HK_HDR, HK_M, HK_LOGQ);
    hk_unpack_bits(v, ct + HK_HDR + HK_PACK_M, HK_W, HK_LOGQ);
    HK_FN(kernel_mul)(k, u, s, NULL, HK_W);
    HK_FN(kernel_decode)(msg, v, k);

    /* Re-encryption check (Fujisaki-Okamoto). The header is part of the comparison. */
    hk_sha256(h_pk, pk, HK_PKB);
    hk_shake256_2(kc, 64, msg, 32, h_pk, 32);
    HK_FN(expand_a)(a, pk + HK_HDR);
    hk_unpack_bits(b, pk + HK_HDR + HK_SEED, HK_M, HK_LOGQ);
    HK_FN(cpa_enc)(ct2, a, b, msg, kc + 32);

    HK_FN(kernel_verify_select)(k_sel, ct, ct2, kc, s_reject);
    hk_shake256_2(ss, 32, k_sel, 32, h_ct, 32);

    hk_zeroize(s, sizeof(s));
    hk_zeroize(k, sizeof(k));
    hk_zeroize(msg, sizeof(msg));
    hk_zeroize(kc, sizeof(kc));
    hk_zeroize(k_sel, sizeof(k_sel));
    hk_zeroize(ct2, sizeof(ct2));
    return 0;
}

#undef HK_FN
#undef HK_W
#undef HK_M
#undef HK_A_LEN
#undef HK_Q
#undef HK_MASK
#undef HK_PACK_M
#undef HK_PACK_W
#undef HK_PKB
#undef HK_CTB
