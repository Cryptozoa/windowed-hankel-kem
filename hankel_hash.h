#ifndef HANKEL_HASH_H
#define HANKEL_HASH_H

/*
 * Hash functions for the native Windowed Hankel KEM.
 *
 * - SHAKE-256 (FIPS 202) with incremental absorb/squeeze. Keccak-f[1600] uses fixed loop
 *   counts and no data-dependent branches or table lookups, so it may process secrets.
 * - SHA-256 (FIPS 180-4). It is applied only to public data (the public key and ciphertext).
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HK_SHAKE256_RATE 136

typedef struct {
    uint64_t s[25];
    size_t pos;      /* byte position within the current rate block */
    int squeezing;
} hk_shake256_ctx;

void hk_keccakf1600(uint64_t st[25]);
void hk_shake256_init(hk_shake256_ctx *ctx);
void hk_shake256_absorb(hk_shake256_ctx *ctx, const uint8_t *in, size_t len);
void hk_shake256_finalize(hk_shake256_ctx *ctx);
void hk_shake256_squeeze(hk_shake256_ctx *ctx, uint8_t *out, size_t len);

/* One-shot SHAKE-256 of in1 || in2 (in2 may be NULL with len2 = 0). */
void hk_shake256_2(uint8_t *out, size_t outlen,
                   const uint8_t *in1, size_t len1, const uint8_t *in2, size_t len2);

/* One-shot SHA-256 (ARMv8 SHA-256 instructions when available). */
void hk_sha256(uint8_t out[32], const uint8_t *in, size_t len);
/* Portable SHA-256, always compiled; used to cross-check the hardware path. */
void hk_sha256_portable(uint8_t out[32], const uint8_t *in, size_t len);

/* Exported for testing against hashlib. */
void hankel_shake256(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);
void hankel_sha256(const uint8_t *in, size_t inlen, uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif /* HANKEL_HASH_H */
