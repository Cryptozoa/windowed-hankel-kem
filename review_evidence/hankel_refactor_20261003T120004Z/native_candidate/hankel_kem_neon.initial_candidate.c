/*
 * Windowed Hankel LWE KEM: Native ARM64 NEON Acceleration Engine
 * -------------------------------------------------------------
 * Implementation of linear algebra primitives, bitpacking, and decoding
 * strictly optimized for ARM64 NEON with branchless constant-time execution.
 */

#include "hankel_kem_neon.h"
#include <string.h>

#if defined(__ARM_NEON) || defined(__aarch64__)
#include <arm_neon.h>
#define USE_NEON 1
#endif

/* Dot-product inputs use the existing canonical coefficient/secret bounds.
 * Public-length loops handle 32, then 8, then scalar coefficients exactly.
 */
static inline int32_t hankel_dot_u16_s16(
    const uint16_t *a,
    const int16_t *x,
    int n
) {
    int j = 0;
    int32_t sum = 0;
#if defined(USE_NEON)
    int32x4_t acc0 = vdupq_n_s32(0);
    int32x4_t acc1 = vdupq_n_s32(0);
    int32x4_t acc2 = vdupq_n_s32(0);
    int32x4_t acc3 = vdupq_n_s32(0);
    int32x4_t acc4 = vdupq_n_s32(0);
    int32x4_t acc5 = vdupq_n_s32(0);
    int32x4_t acc6 = vdupq_n_s32(0);
    int32x4_t acc7 = vdupq_n_s32(0);

    for (; j + 31 < n; j += 32) {
        int16x8_t va0 = vreinterpretq_s16_u16(vld1q_u16(a + j));
        int16x8_t vx0 = vld1q_s16(x + j);
        int16x8_t va1 = vreinterpretq_s16_u16(vld1q_u16(a + j + 8));
        int16x8_t vx1 = vld1q_s16(x + j + 8);
        int16x8_t va2 = vreinterpretq_s16_u16(vld1q_u16(a + j + 16));
        int16x8_t vx2 = vld1q_s16(x + j + 16);
        int16x8_t va3 = vreinterpretq_s16_u16(vld1q_u16(a + j + 24));
        int16x8_t vx3 = vld1q_s16(x + j + 24);

        acc0 = vmlal_s16(acc0, vget_low_s16(va0), vget_low_s16(vx0));
        acc1 = vmlal_s16(acc1, vget_high_s16(va0), vget_high_s16(vx0));
        acc2 = vmlal_s16(acc2, vget_low_s16(va1), vget_low_s16(vx1));
        acc3 = vmlal_s16(acc3, vget_high_s16(va1), vget_high_s16(vx1));
        acc4 = vmlal_s16(acc4, vget_low_s16(va2), vget_low_s16(vx2));
        acc5 = vmlal_s16(acc5, vget_high_s16(va2), vget_high_s16(vx2));
        acc6 = vmlal_s16(acc6, vget_low_s16(va3), vget_low_s16(vx3));
        acc7 = vmlal_s16(acc7, vget_high_s16(va3), vget_high_s16(vx3));
    }
    for (; j + 7 < n; j += 8) {
        int16x8_t va = vreinterpretq_s16_u16(vld1q_u16(a + j));
        int16x8_t vx = vld1q_s16(x + j);
        acc0 = vmlal_s16(acc0, vget_low_s16(va), vget_low_s16(vx));
        acc1 = vmlal_s16(acc1, vget_high_s16(va), vget_high_s16(vx));
    }
    int32x4_t sum01 = vaddq_s32(acc0, acc1);
    int32x4_t sum23 = vaddq_s32(acc2, acc3);
    int32x4_t sum45 = vaddq_s32(acc4, acc5);
    int32x4_t sum67 = vaddq_s32(acc6, acc7);
    int32x4_t sum4 = vaddq_s32(vaddq_s32(sum01, sum23), vaddq_s32(sum45, sum67));
#if defined(__aarch64__)
    sum = vaddvq_s32(sum4);
#else
    int32x2_t sum2 = vadd_s32(vget_low_s32(sum4), vget_high_s32(sum4));
    sum = vget_lane_s32(vpadd_s32(sum2, sum2), 0);
#endif
#endif
    for (; j < n; j++) {
        sum += (int32_t)a[j] * (int32_t)x[j];
    }
    return sum;
}

int hankel_neon_supports_tails(void) {
    return 1;
}


/* -----------------------------------------------------------------------------
 * 1. Forward Operator: H(a) * s + e mod 4096
 * -----------------------------------------------------------------------------
 * For each row i in [0, m-1]:
 * y_i = ( e_i + sum_{j=0}^{n-1} a_{i+j} * s_j ) & 0x0FFF
 *
 * Sizing verification:
 * Max accumulated product: 640 * 4095 * 2 = 5,241,600.
 * Maximum signed 32-bit integer: 2,147,483,647.
 * Headroom: > 409x before overflow. No reduction needed in accumulation loop.
 */
void hankel_neon_forward_mul(
    const uint16_t *a_seq,
    const int16_t *s,
    const int16_t *e,
    uint16_t *out_y,
    int n,
    int m
) {
    for (int i = 0; i < m; i++) {
        int32_t sum = hankel_dot_u16_s16(a_seq + i, s, n);

        if (e != NULL) {
            sum += e[i];
        }

        out_y[i] = (uint16_t)(sum & HANKEL_Q_MASK);
    }
}


/* -----------------------------------------------------------------------------
 * 2. Windowed Projection: K_w = (sum_j x_j * y_{j+w}) mod 4096
 * -----------------------------------------------------------------------------
 * Computes w_len inner products across sliding slices of y_ext.
 */
void hankel_neon_window_project(
    const int16_t *x,
    const uint16_t *y_ext,
    uint16_t *out_k,
    int n,
    int w_len
) {
    for (int w = 0; w < w_len; w++) {
        int32_t sum = hankel_dot_u16_s16(y_ext + w, x, n);

        out_k[w] = (uint16_t)(sum & HANKEL_Q_MASK);
    }
}


/* -----------------------------------------------------------------------------
 * 3. 4-PAM Message Modulation & Branchless Voronoi Decoder
 * -----------------------------------------------------------------------------
 */

void hankel_neon_encode_4pam(
    const uint8_t *msg_32b,
    uint16_t *out_m,
    int w_len
) {
    /* Each byte yields 4 symbols of 2 bits each. 32 bytes * 4 = 128 symbols. */
    for (int i = 0; i < 32; i++) {
        uint8_t byte = msg_32b[i];
        out_m[4 * i + 0] = (uint16_t)((byte & 0x03) << 10);
        out_m[4 * i + 1] = (uint16_t)(((byte >> 2) & 0x03) << 10);
        out_m[4 * i + 2] = (uint16_t)(((byte >> 4) & 0x03) << 10);
        out_m[4 * i + 3] = (uint16_t)(((byte >> 6) & 0x03) << 10);
    }
}

void hankel_neon_decode_4pam(
    const uint16_t *in_w,
    uint8_t *out_msg_32b,
    int w_len
) {
    memset(out_msg_32b, 0, 32);

#if defined(USE_NEON)
    uint16x8_t v512 = vdupq_n_u16(512);
    uint16x8_t vmask = vdupq_n_u16(HANKEL_Q_MASK);

    for (int i = 0; i < w_len; i += 8) {
        uint16x8_t vw = vld1q_u16(in_w + i);
        vw = vaddq_u16(vw, v512);
        vw = vandq_u16(vw, vmask);
        vw = vshrq_n_u16(vw, 10);

        uint16_t buf[8];
        vst1q_u16(buf, vw);

        uint8_t b0 = (uint8_t)((buf[0]) | (buf[1] << 2) | (buf[2] << 4) | (buf[3] << 6));
        uint8_t b1 = (uint8_t)((buf[4]) | (buf[5] << 2) | (buf[6] << 4) | (buf[7] << 6));

        int byte_idx = (i * 2) / 8;
        out_msg_32b[byte_idx + 0] = b0;
        out_msg_32b[byte_idx + 1] = b1;
    }
#else
    for (int i = 0; i < w_len; i++) {
        uint16_t w = in_w[i];
        uint8_t sym = (uint8_t)(((w + 512) & HANKEL_Q_MASK) >> 10);
        int bit_idx = (i * 2) & 7;
        int byte_idx = (i * 2) >> 3;
        out_msg_32b[byte_idx] |= (uint8_t)(sym << bit_idx);
    }
#endif
}


/* -----------------------------------------------------------------------------
 * 4. SIMD Modular Vector Addition & Subtraction
 * -----------------------------------------------------------------------------
 */

void hankel_neon_vec_add(
    const uint16_t *a,
    const uint16_t *b,
    uint16_t *out,
    int len
) {
    int i = 0;
#if defined(USE_NEON)
    uint16x8_t vmask = vdupq_n_u16(HANKEL_Q_MASK);
    for (; i <= len - 8; i += 8) {
        uint16x8_t va = vld1q_u16(a + i);
        uint16x8_t vb = vld1q_u16(b + i);
        uint16x8_t vres = vandq_u16(vaddq_u16(va, vb), vmask);
        vst1q_u16(out + i, vres);
    }
#endif
    for (; i < len; i++) {
        out[i] = (a[i] + b[i]) & HANKEL_Q_MASK;
    }
}

void hankel_neon_vec_sub(
    const uint16_t *a,
    const uint16_t *b,
    uint16_t *out,
    int len
) {
    int i = 0;
#if defined(USE_NEON)
    uint16x8_t vmask = vdupq_n_u16(HANKEL_Q_MASK);
    uint16x8_t vq = vdupq_n_u16(HANKEL_Q);
    for (; i <= len - 8; i += 8) {
        uint16x8_t va = vld1q_u16(a + i);
        uint16x8_t vb = vld1q_u16(b + i);
        uint16x8_t vres = vandq_u16(vsubq_u16(vaddq_u16(va, vq), vb), vmask);
        vst1q_u16(out + i, vres);
    }
#endif
    for (; i < len; i++) {
        out[i] = (a[i] + HANKEL_Q - b[i]) & HANKEL_Q_MASK;
    }
}


/* -----------------------------------------------------------------------------
 * 5. Canonical 12-Bit Packing and Unpacking
 * -----------------------------------------------------------------------------
 */

void hankel_neon_pack_12bit(
    const uint16_t *in,
    uint8_t *out,
    int count
) {
    /* Every 2 words (24 bits) map to 3 bytes */
    for (int i = 0; i < count; i += 2) {
        uint16_t x0 = in[i + 0] & HANKEL_Q_MASK;
        uint16_t x1 = in[i + 1] & HANKEL_Q_MASK;
        int byte_idx = (i * 3) / 2;

        out[byte_idx + 0] = (uint8_t)(x0 & 0xFF);
        out[byte_idx + 1] = (uint8_t)(((x0 >> 8) & 0x0F) | ((x1 & 0x0F) << 4));
        out[byte_idx + 2] = (uint8_t)((x1 >> 4) & 0xFF);
    }
}

int hankel_neon_unpack_12bit(
    const uint8_t *in,
    uint16_t *out,
    int count
) {
    uint32_t invalid_accum = 0;

    for (int i = 0; i < count; i += 2) {
        int byte_idx = (i * 3) / 2;
        uint32_t b0 = in[byte_idx + 0];
        uint32_t b1 = in[byte_idx + 1];
        uint32_t b2 = in[byte_idx + 2];

        uint16_t x0 = (uint16_t)(b0 | ((b1 & 0x0F) << 8));
        uint16_t x1 = (uint16_t)((b1 >> 4) | (b2 << 4));

        out[i + 0] = x0;
        out[i + 1] = x1;

        invalid_accum |= (x0 >> 12) | (x1 >> 12);
    }

    /* Returns 1 if all coefficients < 4096, 0 on canonical bounds violation */
    return (int)(1 ^ (invalid_accum != 0));
}


/* -----------------------------------------------------------------------------
 * 6. Constant-Time Utilities (No branches, no ternary)
 * -----------------------------------------------------------------------------
 */

void hankel_ct_select(
    uint8_t cond,
    const uint8_t *a,
    const uint8_t *b,
    uint8_t *out,
    size_t len
) {
    /* cond is expected to be 0 or 1. Derive 8-bit all-ones or all-zeros mask. */
    uint8_t mask = (uint8_t)(-(int8_t)(cond & 1));
    size_t i = 0;

#if defined(USE_NEON)
    uint8x16_t vmask = vdupq_n_u8(mask);
    for (; i <= len - 16; i += 16) {
        uint8x16_t va = vld1q_u8(a + i);
        uint8x16_t vb = vld1q_u8(b + i);
        uint8x16_t vres = vbslq_u8(vmask, va, vb);
        vst1q_u8(out + i, vres);
    }
#endif

    uint8_t inv_mask = (uint8_t)(~mask);
    for (; i < len; i++) {
        out[i] = (uint8_t)((a[i] & mask) | (b[i] & inv_mask));
    }
}

int hankel_ct_compare(
    const uint8_t *a,
    const uint8_t *b,
    size_t len
) {
    uint8_t diff = 0;
    size_t i = 0;

#if defined(USE_NEON)
    uint8x16_t vdiff = vdupq_n_u8(0);
    for (; i <= len - 16; i += 16) {
        uint8x16_t va = vld1q_u8(a + i);
        uint8x16_t vb = vld1q_u8(b + i);
        vdiff = vorrq_u8(vdiff, veorq_u8(va, vb));
    }
#if defined(__aarch64__)
    diff = vmaxvq_u8(vdiff);
#else
    uint8x8_t d2 = vorr_u8(vget_low_u8(vdiff), vget_high_u8(vdiff));
    diff = vget_lane_u8(d2, 0) | vget_lane_u8(d2, 1) | vget_lane_u8(d2, 2) | vget_lane_u8(d2, 3) |
           vget_lane_u8(d2, 4) | vget_lane_u8(d2, 5) | vget_lane_u8(d2, 6) | vget_lane_u8(d2, 7);
#endif
#endif

    for (; i < len; i++) {
        diff |= (a[i] ^ b[i]);
    }

    /* Branchless check: returns 1 if diff == 0, else 0 */
    return (int)(1 ^ (((uint32_t)diff | (uint32_t)(-(int32_t)diff)) >> 31));
}
