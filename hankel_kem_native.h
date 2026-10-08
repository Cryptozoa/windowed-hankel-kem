#ifndef HANKEL_KEM_NATIVE_H
#define HANKEL_KEM_NATIVE_H

/*
 * Native Windowed Hankel KEM (n = 640, W = 128, q = 4096, CBD_2).
 *
 * Bit-exact with the Python reference (hankel_kem/fo.py) and its KAT fixtures, including the
 * wire format and every derivation tag. Secret-dependent data never selects a branch or a
 * memory address: the Hankel products, sampling, encoding, decoding, re-encryption check and
 * implicit-rejection selection run in time independent of secret values.
 *
 * Return values: 0 on success, -1 on a malformed public key or secret key (public data).
 * A malformed ciphertext never produces an error; it yields the implicit-rejection key.
 */

#include <stddef.h>
#include <stdint.h>

#define HANKEL_KEM_PUBLICKEYBYTES 1196
#define HANKEL_KEM_SECRETKEYBYTES 1868
#define HANKEL_KEM_CIPHERTEXTBYTES 1356
#define HANKEL_KEM_BYTES 32

#ifdef __cplusplus
extern "C" {
#endif

/* Key generation from system randomness (64 bytes). */
int hankel_kem_keypair(uint8_t *pk, uint8_t *sk);

/*
 * Deterministic key generation, as hankel_kem_keygen(seed) in Python: a seed shorter than
 * 64 bytes is first expanded with SHAKE-256(seed || "_hankel_cca_keygen_seed", 64).
 */
int hankel_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed, size_t seed_len);

/* Encapsulation with a uniformly random 32-byte message from system randomness. */
int hankel_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

/*
 * Deterministic encapsulation, as hankel_kem_encaps(pk, entropy) in Python: the message is
 * SHAKE-256(entropy || "_hankel_encaps_entropy", 32).
 */
int hankel_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                          const uint8_t *entropy, size_t entropy_len);

/*
 * Decapsulation with implicit rejection. ct_len may differ from HANKEL_KEM_CIPHERTEXTBYTES;
 * such a ciphertext is rejected, as in the Python reference.
 */
int hankel_kem_dec(uint8_t *ss, const uint8_t *ct, size_t ct_len, const uint8_t *sk);

/*
 * Candidate Category 3 and 5 sets (paper, Appendix D): q = 2^13, CBD_2, W = 128, with n = 936 and
 * n = 1208. Same API and semantics as above, under the prefixes hankel936_ and hankel1208_; every
 * derivation tag carries the set's domain string ("_wh936", "_wh1208").
 */
#define HANKEL936_KEM_PUBLICKEYBYTES 1773
#define HANKEL936_KEM_SECRETKEYBYTES 2741
#define HANKEL936_KEM_CIPHERTEXTBYTES 1949
#define HANKEL1208_KEM_PUBLICKEYBYTES 2215
#define HANKEL1208_KEM_SECRETKEYBYTES 3455
#define HANKEL1208_KEM_CIPHERTEXTBYTES 2391

int hankel936_kem_keypair(uint8_t *pk, uint8_t *sk);
int hankel936_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed, size_t seed_len);
int hankel936_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int hankel936_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy, size_t entropy_len);
int hankel936_kem_dec(uint8_t *ss, const uint8_t *ct, size_t ct_len, const uint8_t *sk);

int hankel1208_kem_keypair(uint8_t *pk, uint8_t *sk);
int hankel1208_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed, size_t seed_len);
int hankel1208_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int hankel1208_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy, size_t entropy_len);
int hankel1208_kem_dec(uint8_t *ss, const uint8_t *ct, size_t ct_len, const uint8_t *sk);

#ifdef __cplusplus
}
#endif

#endif /* HANKEL_KEM_NATIVE_H */
