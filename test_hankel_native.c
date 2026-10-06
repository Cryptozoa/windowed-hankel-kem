/*
 * Standalone test of the native Windowed Hankel KEM.
 *
 * 1. Hash known answers (SHA-256 "abc" and empty string, SHAKE-256 empty string).
 * 2. Every vector of the KAT file: pk, sk, ct and ss must match byte for byte, and
 *    decapsulation must recover ss.
 * 3. Implicit rejection: tampered and wrong-length ciphertexts must yield
 *    SHAKE-256(s_reject || SHA-256(ct), 32).
 *
 * Usage: test_hankel_native [path/to/file.rsp]
 */

#include "hankel_kem_native.h"
#include "hankel_hash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_RSP "nist_analysis_kit/kat/test_vectors/WINDOWED_HANKEL_640_RESEARCH_v2.rsp"

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

static void expected_reject(uint8_t ss[32], const uint8_t *sk, const uint8_t *ct, size_t ct_len) {
    uint8_t h_ct[32];
    hk_sha256(h_ct, ct, ct_len);
    hk_shake256_2(ss, 32, sk + 640, 32, h_ct, 32);
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : DEFAULT_RSP;
    FILE *f = fopen(path, "r");
    if (!f) {
        printf("cannot open %s\n", path);
        return 2;
    }

    test_hashes();

    static char line[8192];
    uint8_t seed[48], entropy[32];
    uint8_t pk_exp[HANKEL_KEM_PUBLICKEYBYTES], sk_exp[HANKEL_KEM_SECRETKEYBYTES];
    uint8_t ct_exp[HANKEL_KEM_CIPHERTEXTBYTES], ss_exp[32];
    uint8_t pk[HANKEL_KEM_PUBLICKEYBYTES], sk[HANKEL_KEM_SECRETKEYBYTES];
    uint8_t ct[HANKEL_KEM_CIPHERTEXTBYTES + 1], ss[32], ss_dec[32], ss_rej[32];
    int count = -1, have = 0, vectors = 0;

    while (fgets(line, sizeof(line), f)) {
        char *eq = strstr(line, " = ");
        if (!eq) continue;
        *eq = '\0';
        const char *val = eq + 3;
        if (strcmp(line, "count") == 0) { count = atoi(val); have = 0; }
        else if (strcmp(line, "seed") == 0) have |= hex_decode(seed, sizeof(seed), val) == 0 ? 1 : 0;
        else if (strcmp(line, "entropy") == 0) have |= hex_decode(entropy, sizeof(entropy), val) == 0 ? 2 : 0;
        else if (strcmp(line, "pk") == 0) have |= hex_decode(pk_exp, sizeof(pk_exp), val) == 0 ? 4 : 0;
        else if (strcmp(line, "sk") == 0) have |= hex_decode(sk_exp, sizeof(sk_exp), val) == 0 ? 8 : 0;
        else if (strcmp(line, "ct") == 0) have |= hex_decode(ct_exp, sizeof(ct_exp), val) == 0 ? 16 : 0;
        else if (strcmp(line, "ss") == 0) have |= hex_decode(ss_exp, sizeof(ss_exp), val) == 0 ? 32 : 0;
        if (have != 63) continue;
        have = 0;
        vectors++;

        /* The fixture generator passes the first 32 bytes of each seed to key generation. */
        check(hankel_kem_keypair_derand(pk, sk, seed, 32) == 0, "keypair returned error", count);
        check(memcmp(pk, pk_exp, sizeof(pk)) == 0, "pk mismatch", count);
        check(memcmp(sk, sk_exp, sizeof(sk)) == 0, "sk mismatch", count);
        check(hankel_kem_enc_derand(ct, ss, pk, entropy, sizeof(entropy)) == 0, "enc returned error", count);
        check(memcmp(ct, ct_exp, HANKEL_KEM_CIPHERTEXTBYTES) == 0, "ct mismatch", count);
        check(memcmp(ss, ss_exp, 32) == 0, "ss mismatch", count);
        check(hankel_kem_dec(ss_dec, ct, HANKEL_KEM_CIPHERTEXTBYTES, sk) == 0, "dec returned error", count);
        check(memcmp(ss_dec, ss_exp, 32) == 0, "decapsulated ss mismatch", count);

        /* Implicit rejection: flip one bit in u, in v and in the header; truncate; extend. */
        const size_t flips[3] = {100, HANKEL_KEM_CIPHERTEXTBYTES - 5, 2};
        for (int t = 0; t < 3; t++) {
            ct[flips[t]] ^= 0x10;
            hankel_kem_dec(ss_dec, ct, HANKEL_KEM_CIPHERTEXTBYTES, sk);
            expected_reject(ss_rej, sk, ct, HANKEL_KEM_CIPHERTEXTBYTES);
            check(memcmp(ss_dec, ss_rej, 32) == 0 && memcmp(ss_dec, ss_exp, 32) != 0,
                  "tampered ciphertext not rejected", count);
            ct[flips[t]] ^= 0x10;
        }
        hankel_kem_dec(ss_dec, ct, HANKEL_KEM_CIPHERTEXTBYTES - 1, sk);
        expected_reject(ss_rej, sk, ct, HANKEL_KEM_CIPHERTEXTBYTES - 1);
        check(memcmp(ss_dec, ss_rej, 32) == 0, "truncated ciphertext not rejected", count);
        ct[HANKEL_KEM_CIPHERTEXTBYTES] = 0;
        hankel_kem_dec(ss_dec, ct, HANKEL_KEM_CIPHERTEXTBYTES + 1, sk);
        expected_reject(ss_rej, sk, ct, HANKEL_KEM_CIPHERTEXTBYTES + 1);
        check(memcmp(ss_dec, ss_rej, 32) == 0, "extended ciphertext not rejected", count);
    }
    fclose(f);

    /* Malformed public key is reported as an error. */
    pk[0] ^= 1;
    check(hankel_kem_enc_derand(ct, ss, pk, entropy, sizeof(entropy)) == -1, "bad pk header accepted", -1);

    /* Random keys round-trip. */
    for (int i = 0; i < 200; i++) {
        hankel_kem_keypair(pk, sk);
        hankel_kem_enc(ct, ss, pk);
        hankel_kem_dec(ss_dec, ct, HANKEL_KEM_CIPHERTEXTBYTES, sk);
        check(memcmp(ss, ss_dec, 32) == 0, "random round trip failed", i);
    }

    if (vectors == 0) {
        printf("no complete vectors found in %s\n", path);
        return 2;
    }
    if (failures) {
        printf("[FAIL] native KEM: %d failures (%d KAT vectors)\n", failures, vectors);
        return 1;
    }
    printf("[PASS] native KEM: hash KATs, %d/%d KAT vectors (pk, sk, ct, ss, decapsulation), "
           "implicit rejection, 200 random round trips\n", vectors, vectors);
    return 0;
}
