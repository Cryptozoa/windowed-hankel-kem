#include "hankel_hash.h"
#include <string.h>

/* ---------------------------------------------------------------------------------------------
 * SHAKE-256 (FIPS 202)
 * ------------------------------------------------------------------------------------------- */

static const uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int KECCAK_ROTC[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const int KECCAK_PILN[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

static inline uint64_t rotl64(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}

void hk_keccakf1600(uint64_t st[25]) {
    uint64_t bc[5];
    for (int round = 0; round < 24; round++) {
        /* theta */
        for (int i = 0; i < 5; i++) {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        for (int i = 0; i < 5; i++) {
            uint64_t t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) {
                st[j + i] ^= t;
            }
        }
        /* rho + pi */
        uint64_t t = st[1];
        for (int i = 0; i < 24; i++) {
            int j = KECCAK_PILN[i];
            uint64_t tmp = st[j];
            st[j] = rotl64(t, KECCAK_ROTC[i]);
            t = tmp;
        }
        /* chi */
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++) {
                bc[i] = st[j + i];
            }
            for (int i = 0; i < 5; i++) {
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }
        /* iota */
        st[0] ^= KECCAK_RC[round];
    }
}

void hk_shake256_init(hk_shake256_ctx *ctx) {
    memset(ctx, 0, sizeof(*ctx));
}

void hk_shake256_absorb(hk_shake256_ctx *ctx, const uint8_t *in, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx->s[ctx->pos >> 3] ^= (uint64_t)in[i] << (8 * (ctx->pos & 7));
        if (++ctx->pos == HK_SHAKE256_RATE) {
            hk_keccakf1600(ctx->s);
            ctx->pos = 0;
        }
    }
}

void hk_shake256_finalize(hk_shake256_ctx *ctx) {
    ctx->s[ctx->pos >> 3] ^= (uint64_t)0x1F << (8 * (ctx->pos & 7));
    ctx->s[(HK_SHAKE256_RATE - 1) >> 3] ^= (uint64_t)0x80 << (8 * ((HK_SHAKE256_RATE - 1) & 7));
    hk_keccakf1600(ctx->s);
    ctx->pos = 0;
    ctx->squeezing = 1;
}

void hk_shake256_squeeze(hk_shake256_ctx *ctx, uint8_t *out, size_t len) {
    while (len) {
        if (ctx->pos == HK_SHAKE256_RATE) {
            hk_keccakf1600(ctx->s);
            ctx->pos = 0;
        }
        if (ctx->pos == 0 && len >= HK_SHAKE256_RATE) {
            /* whole rate block: 17 little-endian lanes */
            for (int i = 0; i < HK_SHAKE256_RATE / 8; i++) {
                uint64_t lane = ctx->s[i];
                for (int b = 0; b < 8; b++) out[8 * i + b] = (uint8_t)(lane >> (8 * b));
            }
            ctx->pos = HK_SHAKE256_RATE;
            out += HK_SHAKE256_RATE;
            len -= HK_SHAKE256_RATE;
            continue;
        }
        *out++ = (uint8_t)(ctx->s[ctx->pos >> 3] >> (8 * (ctx->pos & 7)));
        ctx->pos++;
        len--;
    }
}

void hk_shake256_2(uint8_t *out, size_t outlen,
                   const uint8_t *in1, size_t len1, const uint8_t *in2, size_t len2) {
    hk_shake256_ctx ctx;
    hk_shake256_init(&ctx);
    hk_shake256_absorb(&ctx, in1, len1);
    if (len2) hk_shake256_absorb(&ctx, in2, len2);
    hk_shake256_finalize(&ctx);
    hk_shake256_squeeze(&ctx, out, outlen);
    memset(&ctx, 0, sizeof(ctx));
}

void hankel_shake256(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
    hk_shake256_2(out, outlen, in, inlen, NULL, 0);
}

/* ---------------------------------------------------------------------------------------------
 * SHA-256 (FIPS 180-4). Public inputs only.
 * ------------------------------------------------------------------------------------------- */

static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline uint32_t rotr32(uint32_t x, int r) {
    return (x >> r) | (x << (32 - r));
}

static void sha256_block_portable(uint32_t h[8], const uint8_t blk[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)blk[4 * i] << 24) | ((uint32_t)blk[4 * i + 1] << 16) |
               ((uint32_t)blk[4 * i + 2] << 8) | (uint32_t)blk[4 * i + 3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + S1 + ch + SHA256_K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

#if defined(__ARM_FEATURE_SHA2) && !defined(HK_FORCE_SCALAR)
#include <arm_neon.h>
/* ARMv8 SHA-256 instructions: four rounds per SHA256H/SHA256H2 pair. */
static void sha256_block_hw(uint32_t h[8], const uint8_t blk[64]) {
    uint32x4_t abcd = vld1q_u32(h), efgh = vld1q_u32(h + 4);
    const uint32x4_t abcd0 = abcd, efgh0 = efgh;
    uint32x4_t w[4];
    for (int i = 0; i < 4; i++) w[i] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(blk + 16 * i)));
    for (int i = 0; i < 16; i++) {
        uint32x4_t wk = vaddq_u32(w[i & 3], vld1q_u32(SHA256_K + 4 * i));
        uint32x4_t prev = abcd;
        abcd = vsha256hq_u32(abcd, efgh, wk);
        efgh = vsha256h2q_u32(efgh, prev, wk);
        if (i < 12) {
            w[i & 3] = vsha256su1q_u32(vsha256su0q_u32(w[i & 3], w[(i + 1) & 3]),
                                       w[(i + 2) & 3], w[(i + 3) & 3]);
        }
    }
    vst1q_u32(h, vaddq_u32(abcd, abcd0));
    vst1q_u32(h + 4, vaddq_u32(efgh, efgh0));
}
#endif

typedef void (*sha256_block_fn)(uint32_t h[8], const uint8_t blk[64]);

static void sha256_with(sha256_block_fn block, uint8_t out[32], const uint8_t *in, size_t len) {
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    size_t full = len / 64;
    for (size_t i = 0; i < full; i++) block(h, in + 64 * i);

    uint8_t tail[128];
    size_t rem = len - 64 * full;
    memset(tail, 0, sizeof(tail));
    memcpy(tail, in + 64 * full, rem);
    tail[rem] = 0x80;
    size_t tail_len = (rem < 56) ? 64 : 128;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) tail[tail_len - 1 - i] = (uint8_t)(bits >> (8 * i));
    block(h, tail);
    if (tail_len == 128) block(h, tail + 64);

    for (int i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(h[i] >> 8);
        out[4 * i + 3] = (uint8_t)h[i];
    }
}

void hk_sha256_portable(uint8_t out[32], const uint8_t *in, size_t len) {
    sha256_with(sha256_block_portable, out, in, len);
}

void hk_sha256(uint8_t out[32], const uint8_t *in, size_t len) {
#if defined(__ARM_FEATURE_SHA2) && !defined(HK_FORCE_SCALAR)
    sha256_with(sha256_block_hw, out, in, len);
#else
    sha256_with(sha256_block_portable, out, in, len);
#endif
}

void hankel_sha256(const uint8_t *in, size_t inlen, uint8_t out[32]) {
    hk_sha256(out, in, inlen);
}
