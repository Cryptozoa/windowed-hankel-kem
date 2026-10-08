/*
 * Standalone test of the native Windowed Hankel KEM.
 *
 * 1. Hash known answers (SHA-256 "abc" and empty string, SHAKE-256 empty string).
 * 2. For each parameter set (WH-640, WH-936, WH-1208), every vector of its KAT file: pk, sk,
 *    ct and ss must match byte for byte, and decapsulation must recover ss.
 * 3. Implicit rejection: tampered and wrong-length ciphertexts must yield
 *    SHAKE-256(s_reject || SHA-256(ct), 32).
 *
 * Usage: test_hankel_native [path/to/WH-640.rsp]   (no argument: all three sets)
 */

#include "hankel_kem_native.h"
#include "hankel_hash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

static void check(int ok, const char *what, int count) {
    if (!ok) {
        failures++;
        if (count >= 0) printf("  [FAIL] vector %d: %s\n", count, what);
        else printf("  [FAIL] %s\n", what);
    }
}

static int hex_decode(uint8_t *out, size_t outlen, const char *hex) {
    size_t n = strlen(hex);
    while (n && (hex[n - 1] == '\n' || hex[n - 1] == '\r' || hex[n - 1] == ' ')) n--;
    if (n != 2 * outlen) return -1;
    for (size_t i = 0; i < outlen; i++) {
        unsigned int v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

static void test_hashes(void) {
    static const uint8_t sha_abc[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    static const uint8_t sha_empty[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
    static const uint8_t shake_empty[16] = {
        0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb, 0x24};
    uint8_t out[32];
    hk_sha256(out, (const uint8_t *)"abc", 3);
    check(memcmp(out, sha_abc, 32) == 0, "SHA-256(\"abc\")", -1);
    hk_sha256(out, (const uint8_t *)"", 0);
    check(memcmp(out, sha_empty, 32) == 0, "SHA-256(\"\")", -1);
    hankel_shake256((const uint8_t *)"", 0, out, 16);
    check(memcmp(out, shake_empty, 16) == 0, "SHAKE-256(\"\")", -1);

    /* The selected SHA-256 path agrees with the portable one on every length up to 300. */
    uint8_t msg[300], ref[32];
    for (int i = 0; i < 300; i++) msg[i] = (uint8_t)(i * 131 + 7);
    for (size_t len = 0; len <= sizeof(msg); len++) {
        hk_sha256(out, msg, len);
        hk_sha256_portable(ref, msg, len);
        check(memcmp(out, ref, 32) == 0, "SHA-256 differs from portable path", (int)len);
    }
}

static void expected_reject(uint8_t ss[32], const uint8_t *sk, size_t n, const uint8_t *ct, size_t ct_len) {
    uint8_t h_ct[32];
    hk_sha256(h_ct, ct, ct_len);
    hk_shake256_2(ss, 32, sk + n, 32, h_ct, 32);
}

/* One parameter set: its API, sizes and KAT file. */
typedef struct {
    const char *name, *rsp;
    size_t n, pk_bytes, sk_bytes, ct_bytes;
    int (*keypair)(uint8_t *, uint8_t *);
    int (*keypair_derand)(uint8_t *, uint8_t *, const uint8_t *, size_t);
    int (*enc)(uint8_t *, uint8_t *, const uint8_t *);
    int (*enc_derand)(uint8_t *, uint8_t *, const uint8_t *, const uint8_t *, size_t);
    int (*dec)(uint8_t *, const uint8_t *, size_t, const uint8_t *);
} kem_set;

#define KAT_DIR "nist_analysis_kit/kat/test_vectors/"
#define SET(label, file, n, P, U)                                                                \
    {label, KAT_DIR file, n, U##_KEM_PUBLICKEYBYTES, U##_KEM_SECRETKEYBYTES,                    \
     U##_KEM_CIPHERTEXTBYTES, P##kem_keypair, P##kem_keypair_derand, P##kem_enc,                 \
     P##kem_enc_derand, P##kem_dec}

static const kem_set SETS[] = {
    SET("WH-640", "WINDOWED_HANKEL_640_RESEARCH_v2.rsp", 640, hankel_, HANKEL),
    SET("WH-936", "WINDOWED_HANKEL_936_v1.rsp", 936, hankel936_, HANKEL936),
    SET("WH-1208", "WINDOWED_HANKEL_1208_v1.rsp", 1208, hankel1208_, HANKEL1208),
};

#define MAX_PK HANKEL1208_KEM_PUBLICKEYBYTES
#define MAX_SK HANKEL1208_KEM_SECRETKEYBYTES
#define MAX_CT HANKEL1208_KEM_CIPHERTEXTBYTES

/* Returns the number of complete KAT vectors checked, or -1 if the file cannot be opened. */
static int test_set(const kem_set *k, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        printf("cannot open %s\n", path);
        return -1;
    }

    static char line[16384];
    uint8_t seed[48], entropy[32];
    static uint8_t pk_exp[MAX_PK], sk_exp[MAX_SK], ct_exp[MAX_CT];
    static uint8_t pk[MAX_PK], sk[MAX_SK], ct[MAX_CT + 1];
    uint8_t ss_exp[32], ss[32], ss_dec[32], ss_rej[32];
    const size_t CTB = k->ct_bytes;
    int count = -1, have = 0, vectors = 0;

    while (fgets(line, sizeof(line), f)) {
        char *eq = strstr(line, " = ");
        if (!eq) continue;
        *eq = '\0';
        const char *val = eq + 3;
        if (strcmp(line, "count") == 0) { count = atoi(val); have = 0; }
        else if (strcmp(line, "seed") == 0) have |= hex_decode(seed, sizeof(seed), val) == 0 ? 1 : 0;
        else if (strcmp(line, "entropy") == 0) have |= hex_decode(entropy, sizeof(entropy), val) == 0 ? 2 : 0;
        else if (strcmp(line, "pk") == 0) have |= hex_decode(pk_exp, k->pk_bytes, val) == 0 ? 4 : 0;
        else if (strcmp(line, "sk") == 0) have |= hex_decode(sk_exp, k->sk_bytes, val) == 0 ? 8 : 0;
        else if (strcmp(line, "ct") == 0) have |= hex_decode(ct_exp, CTB, val) == 0 ? 16 : 0;
        else if (strcmp(line, "ss") == 0) have |= hex_decode(ss_exp, sizeof(ss_exp), val) == 0 ? 32 : 0;
        if (have != 63) continue;
        have = 0;
        vectors++;

        /* The fixture generators pass the first 32 bytes of each seed to key generation. */
        check(k->keypair_derand(pk, sk, seed, 32) == 0, "keypair returned error", count);
        check(memcmp(pk, pk_exp, k->pk_bytes) == 0, "pk mismatch", count);
        check(memcmp(sk, sk_exp, k->sk_bytes) == 0, "sk mismatch", count);
        check(k->enc_derand(ct, ss, pk, entropy, sizeof(entropy)) == 0, "enc returned error", count);
        check(memcmp(ct, ct_exp, CTB) == 0, "ct mismatch", count);
        check(memcmp(ss, ss_exp, 32) == 0, "ss mismatch", count);
        check(k->dec(ss_dec, ct, CTB, sk) == 0, "dec returned error", count);
        check(memcmp(ss_dec, ss_exp, 32) == 0, "decapsulated ss mismatch", count);

        /* Implicit rejection: flip one bit in u, in v and in the header; truncate; extend. */
        const size_t flips[3] = {100, CTB - 5, 2};
        for (int t = 0; t < 3; t++) {
            ct[flips[t]] ^= 0x10;
            k->dec(ss_dec, ct, CTB, sk);
            expected_reject(ss_rej, sk, k->n, ct, CTB);
            check(memcmp(ss_dec, ss_rej, 32) == 0 && memcmp(ss_dec, ss_exp, 32) != 0,
                  "tampered ciphertext not rejected", count);
            ct[flips[t]] ^= 0x10;
        }
        k->dec(ss_dec, ct, CTB - 1, sk);
        expected_reject(ss_rej, sk, k->n, ct, CTB - 1);
        check(memcmp(ss_dec, ss_rej, 32) == 0, "truncated ciphertext not rejected", count);
        ct[CTB] = 0;
        k->dec(ss_dec, ct, CTB + 1, sk);
        expected_reject(ss_rej, sk, k->n, ct, CTB + 1);
        check(memcmp(ss_dec, ss_rej, 32) == 0, "extended ciphertext not rejected", count);
    }
    fclose(f);

    /* Malformed public key is reported as an error. */
    pk[0] ^= 1;
    check(k->enc_derand(ct, ss, pk, entropy, sizeof(entropy)) == -1, "bad pk header accepted", -1);

    /* Random keys round-trip. */
    for (int i = 0; i < 200; i++) {
        k->keypair(pk, sk);
        k->enc(ct, ss, pk);
        k->dec(ss_dec, ct, CTB, sk);
        check(memcmp(ss, ss_dec, 32) == 0, "random round trip failed", i);
    }
    return vectors;
}

int main(int argc, char **argv) {
    test_hashes();
    if (failures) {
        printf("[FAIL] hash known answers\n");
        return 1;
    }

    /* With a path argument, test only WH-640 against that file (as before). */
    const int nsets = argc > 1 ? 1 : (int)(sizeof(SETS) / sizeof(SETS[0]));
    int status = 0;
    for (int s = 0; s < nsets; s++) {
        const kem_set *k = &SETS[s];
        const int before = failures;
        const int vectors = test_set(k, argc > 1 ? argv[1] : k->rsp);
        if (vectors <= 0) {
            printf("[FAIL] %s: no complete vectors found\n", k->name);
            status = 2;
        } else if (failures != before) {
            printf("[FAIL] %s: %d failures (%d KAT vectors)\n", k->name, failures - before, vectors);
            status = 1;
        } else {
            printf("[PASS] %s native KEM: %d/%d KAT vectors (pk, sk, ct, ss, decapsulation), "
                   "implicit rejection, 200 random round trips\n", k->name, vectors, vectors);
        }
    }
    if (status == 0) printf("[PASS] hash known answers (SHA-256, SHAKE-256, SHA-256 paths agree)\n");
    return status;
}
