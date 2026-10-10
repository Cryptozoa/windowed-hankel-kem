/*
 * Native Windowed Hankel KEM: key generation, encapsulation and decapsulation for every parameter
 * set (WH-640, Category 1; WH-936 and WH-1208, candidate Category 3 and 5 sets of Appendix D).
 * The per-set code is the template hankel_kem_native_impl.h, included once per set below.
 *
 * Arithmetic. Every Hankel product has the form out[i] = sum_{j<n} a[i+j] x[j] (+ e[i]) mod q.
 * Because each q here (2^12 or 2^13) divides 2^16, the products are accumulated in 16-bit lanes
 * with natural wraparound and reduced once by masking; this is exact for any 16-bit inputs. The
 * NEON kernel computes 64 outputs at a time (then 8 at a time for the remainder): for each secret
 * coefficient x[j] it adds x[j] * a[i+j ..] to 8-lane accumulators (vmlaq_laneq_u16), so the
 * secret only ever enters as a multiplication operand.
 *
 * Constant time. Secret values (s, r, e, e1, e2, the message, K_bar, coins, s_reject) are
 * never used as branch conditions or memory addresses. The all-zero-secret fix-up, the
 * ciphertext comparison and the implicit-rejection selection use masks, guarded by a value
 * barrier so that the compiler cannot turn them back into branches. Branches depend only on
 * public data: buffer lengths and the public-key header.
 *
 * Every step that touches secret values is a separate non-inlined function with external
 * linkage (<prefix>kernel_*), so that the compiled code can be checked by the static branch
 * audit in ct_branch_audit.py, as can hk_keccakf1600.
 */

/* getentropy() is outside C99; glibc declares it only on request. Must precede every include. */
#if !defined(__APPLE__) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

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

#define HK_HDR 12
#define HK_SEED 32
#define HK_KERNEL __attribute__((noinline))

/* ---------------------------------------------------------------------------------------------
 * Shared helpers
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

/* Little-endian bit stream: value i occupies bits [i*bits, (i+1)*bits), least significant bit
 * first. For bits = 12 this is the original layout (two coefficients in three bytes); for
 * bits = 13, eight coefficients fill thirteen bytes. Both have dedicated loops; the generic loop
 * covers any other width. count is a multiple of 8 for every use. Applied only to public data
 * (b, u, v). */
static void hk_pack12(uint8_t *out, const uint16_t *in, int count) {
    for (int i = 0; i < count; i += 2, out += 3) {
        const uint16_t x0 = in[i] & 0x0FFF, x1 = in[i + 1] & 0x0FFF;
        out[0] = (uint8_t)x0;
        out[1] = (uint8_t)((x0 >> 8) | ((x1 & 0x0F) << 4));
        out[2] = (uint8_t)(x1 >> 4);
    }
}

static void hk_unpack12(uint16_t *out, const uint8_t *in, int count) {
    for (int i = 0; i < count; i += 2, in += 3) {
        out[i] = (uint16_t)(in[0] | ((uint16_t)(in[1] & 0x0F) << 8));
        out[i + 1] = (uint16_t)((in[1] >> 4) | ((uint16_t)in[2] << 4));
    }
}

/* Eight 13-bit values as a 64-bit low word (values 0-3 and the low 12 bits of value 4) and a
 * 40-bit high word (the top bit of value 4 and values 5-7). */
static void hk_pack13(uint8_t *out, const uint16_t *in, int count) {
    for (int i = 0; i < count; i += 8, in += 8, out += 13) {
        uint64_t x[8];
        for (int j = 0; j < 8; j++) x[j] = in[j] & 0x1FFF;
        const uint64_t lo = x[0] | x[1] << 13 | x[2] << 26 | x[3] << 39 | x[4] << 52;
        const uint64_t hi = x[4] >> 12 | x[5] << 1 | x[6] << 14 | x[7] << 27;
        for (int j = 0; j < 8; j++) out[j] = (uint8_t)(lo >> (8 * j));
        for (int j = 0; j < 5; j++) out[8 + j] = (uint8_t)(hi >> (8 * j));
    }
}

static void hk_unpack13(uint16_t *out, const uint8_t *in, int count) {
    for (int i = 0; i < count; i += 8, in += 13, out += 8) {
        uint64_t lo = 0, hi = 0;
        for (int j = 0; j < 8; j++) lo |= (uint64_t)in[j] << (8 * j);
        for (int j = 0; j < 5; j++) hi |= (uint64_t)in[8 + j] << (8 * j);
        out[0] = (uint16_t)(lo & 0x1FFF);
        out[1] = (uint16_t)((lo >> 13) & 0x1FFF);
        out[2] = (uint16_t)((lo >> 26) & 0x1FFF);
        out[3] = (uint16_t)((lo >> 39) & 0x1FFF);
        out[4] = (uint16_t)((lo >> 52) | ((hi & 1) << 12));
        out[5] = (uint16_t)((hi >> 1) & 0x1FFF);
        out[6] = (uint16_t)((hi >> 14) & 0x1FFF);
        out[7] = (uint16_t)((hi >> 27) & 0x1FFF);
    }
}

static void hk_pack_bits(uint8_t *out, const uint16_t *in, int count, int bits) {
    if (bits == 12) { hk_pack12(out, in, count); return; }
    if (bits == 13) { hk_pack13(out, in, count); return; }
    const uint32_t mask = (1u << bits) - 1;
    uint32_t acc = 0;
    int nb = 0;
    for (int i = 0; i < count; i++) {
        acc |= (in[i] & mask) << nb;
        nb += bits;
        while (nb >= 8) {
            *out++ = (uint8_t)acc;
            acc >>= 8;
            nb -= 8;
        }
    }
}

static void hk_unpack_bits(uint16_t *out, const uint8_t *in, int count, int bits) {
    if (bits == 12) { hk_unpack12(out, in, count); return; }
    if (bits == 13) { hk_unpack13(out, in, count); return; }
    const uint32_t mask = (1u << bits) - 1;
    uint32_t acc = 0;
    int nb = 0;
    for (int i = 0; i < count; i++) {
        while (nb < bits) {
            acc |= (uint32_t)(*in++) << nb;
            nb += 8;
        }
        out[i] = (uint16_t)(acc & mask);
        acc >>= bits;
        nb -= bits;
    }
}

/* Header: magic, then n, W, q and 0 as little-endian 16-bit integers. */
static void hk_write_header(uint8_t hdr[HK_HDR], const char magic[4], unsigned n, unsigned w, unsigned q) {
    memcpy(hdr, magic, 4);
    const uint16_t f[4] = {(uint16_t)n, (uint16_t)w, (uint16_t)q, 0};
    for (int i = 0; i < 4; i++) {
        hdr[4 + 2 * i] = (uint8_t)f[i];
        hdr[5 + 2 * i] = (uint8_t)(f[i] >> 8);
    }
}

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

/* ---------------------------------------------------------------------------------------------
 * Parameter sets
 * ------------------------------------------------------------------------------------------- */

/* WH-640 (Category 1): q = 2^12; symbol names unchanged (hankel_kem_*, hankel_kernel_*). */
#define HK_PREFIX hankel_
#define HK_N 640
#define HK_LOGQ 12
#define HK_DOM ""
#include "hankel_kem_native_impl.h"
#undef HK_PREFIX
#undef HK_N
#undef HK_LOGQ
#undef HK_DOM

/* WH-936 (candidate Category 3): q = 2^13. */
#define HK_PREFIX hankel936_
#define HK_N 936
#define HK_LOGQ 13
#define HK_DOM "_wh936"
#include "hankel_kem_native_impl.h"
#undef HK_PREFIX
#undef HK_N
#undef HK_LOGQ
#undef HK_DOM

/* WH-1208 (candidate Category 5): q = 2^13. */
#define HK_PREFIX hankel1208_
#define HK_N 1208
#define HK_LOGQ 13
#define HK_DOM "_wh1208"
#include "hankel_kem_native_impl.h"
#undef HK_PREFIX
#undef HK_N
#undef HK_LOGQ
#undef HK_DOM
