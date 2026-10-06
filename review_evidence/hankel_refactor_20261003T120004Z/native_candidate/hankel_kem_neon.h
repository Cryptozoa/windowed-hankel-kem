/*
 * Windowed Hankel LWE KEM: Native ARM64 NEON Acceleration Engine
 * -------------------------------------------------------------
 * Academic Research Prototype (Exploratory Implementation)
 * Platform: Apple Silicon (ARM64) / Clang & GCC
 *
 * Mathematical Foundations:
 * - Modulus q = 4096 (2^12, Power-of-two, branchless bitwise masking 0x0FFF)
 * - Lattice Dimension n = 640
 * - Window Size W = 128 (4-PAM constellation mapping 2 bits per coordinate)
 * - Extended Dimension m = n + W = 768
 * - Public Sequence a length = 2n + W - 1 = 1407
 *
 * Features:
 * - Fully unrolled 8-way SIMD dot products via vmlal_s16
 * - L1-cache resident continuous slide across public sequence a
 * - Branchless 4-PAM Voronoi constellation decoder
 * - Branchless constant-time key multiplexer (vbslq_u8) and memory comparison
 * - Vectorized 12-bit modular bitpacking and unpacking with canonical bounds verification
 */

#ifndef HANKEL_KEM_NEON_H
#define HANKEL_KEM_NEON_H

#include <stdint.h>
#include <stddef.h>

#define HANKEL_Q 4096
#define HANKEL_Q_MASK 0x0FFF
#define HANKEL_N 640
#define HANKEL_W 128
#define HANKEL_M 768
#define HANKEL_TOTAL_A 1407

#ifdef __cplusplus
extern "C" {
#endif

/* Forward operator: computes y = (H(a) * s + e) mod 4096 */
/* Capability marker for exact 8-wide and scalar dot-product tails. */
int hankel_neon_supports_tails(void);

void hankel_neon_forward_mul(
    const uint16_t *a_seq,
    const int16_t *s,
    const int16_t *e,
    uint16_t *out_y,
    int n,
    int m
);

/* Windowed projection: computes K_w = (sum_j x_j * y_{j+w}) mod 4096 for w in [0, w_len-1] */
void hankel_neon_window_project(
    const int16_t *x,
    const uint16_t *y_ext,
    uint16_t *out_k,
    int n,
    int w_len
);

/* Encodes 32 bytes (256 bits) into w_len coordinates using 4-PAM */
void hankel_neon_encode_4pam(
    const uint8_t *msg_32b,
    uint16_t *out_m,
    int w_len
);

/* Decodes w_len coordinates into 32 bytes using branchless Voronoi slicing */
void hankel_neon_decode_4pam(
    const uint16_t *in_w,
    uint8_t *out_msg_32b,
    int w_len
);

/* Vector addition modulo 4096: out = (a + b) & 0x0FFF */
void hankel_neon_vec_add(
    const uint16_t *a,
    const uint16_t *b,
    uint16_t *out,
    int len
);

/* Vector subtraction modulo 4096: out = (a - b) & 0x0FFF */
void hankel_neon_vec_sub(
    const uint16_t *a,
    const uint16_t *b,
    uint16_t *out,
    int len
);

/* 12-bit Little-Endian packing: count elements into (count * 3) / 2 bytes */
void hankel_neon_pack_12bit(
    const uint16_t *in,
    uint8_t *out,
    int count
);

/* 12-bit Little-Endian unpacking: returns 1 if all < 4096, 0 on non-canonical */
int hankel_neon_unpack_12bit(
    const uint8_t *in,
    uint16_t *out,
    int count
);

/* Branchless constant-time multiplexer: if cond == 1 out = a else out = b */
void hankel_ct_select(
    uint8_t cond,
    const uint8_t *a,
    const uint8_t *b,
    uint8_t *out,
    size_t len
);

/* Branchless constant-time memory comparison: returns 1 if equal, 0 if different */
int hankel_ct_compare(
    const uint8_t *a,
    const uint8_t *b,
    size_t len
);

#ifdef __cplusplus
}
#endif

#endif /* HANKEL_KEM_NEON_H */
