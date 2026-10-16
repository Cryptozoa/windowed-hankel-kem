/*
 * Local baselines for the paper's Section 8.4: ML-KEM-512 and FrodoKEM-640 from liboqs, timed exactly
 * like bench_hankel_native.c times Windowed Hankel KEM (median of n calls after n/10 warm-up calls,
 * CLOCK_UPTIME_RAW, one core, inputs prepared before timing). liboqs draws its randomness from a
 * callback; a cheap deterministic generator (splitmix64) stands in for the system generator, so that,
 * as in our derandomized benchmark, the timings do not include the cost of the operating system's RNG.
 *
 * Build liboqs 0.16.0 (https://github.com/open-quantum-safe/liboqs, tag 0.16.0) with
 *   cmake -GNinja -DCMAKE_BUILD_TYPE=Release -DOQS_DIST_BUILD=OFF -DOQS_USE_OPENSSL=OFF \
 *         -DOQS_MINIMAL_BUILD="KEM_ml_kem_512;KEM_frodokem_640_shake;KEM_frodokem_640_aes" <src> && ninja
 * then, from this repository's root, with LIBOQS pointing at that build directory:
 *   cc -O3 -std=c11 -I$LIBOQS/include -o bench_liboqs review_evidence/hankel_fo_v03_20261016/bench_liboqs.c \
 *      $LIBOQS/lib/liboqs.a && ./bench_liboqs 5000
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <oqs/oqs.h>

static uint64_t now_ns(void) { return clock_gettime_nsec_np(CLOCK_UPTIME_RAW); }

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static void report(const char *name, uint64_t *t, int n) {
    qsort(t, (size_t)n, sizeof(uint64_t), cmp_u64);
    printf("  %-9s  median %7.1f us   p90 %7.1f us\n", name, t[n / 2] / 1e3, t[(9 * n) / 10] / 1e3);
}

static uint64_t rng_state = 0x243F6A8885A308D3ull;
static void cheap_rng(uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i += 8) {
        uint64_t z = (rng_state += 0x9E3779B97F4A7C15ull);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        z ^= z >> 31;
        for (size_t j = 0; j < 8 && i + j < len; j++) out[i + j] = (uint8_t)(z >> (8 * j));
    }
}

static int bench(const char *alg, int n) {
    OQS_KEM *k = OQS_KEM_new(alg);
    if (!k) { printf("%s not available\n", alg); return 1; }
    const int warm = n / 10;
    uint8_t *pks = malloc((size_t)(n + warm) * k->length_public_key);
    uint8_t *sks = malloc((size_t)(n + warm) * k->length_secret_key);
    uint8_t *cts = malloc((size_t)(n + warm) * k->length_ciphertext);
    uint8_t *ss = malloc(k->length_shared_secret), *ss2 = malloc(k->length_shared_secret);
    uint64_t *t = malloc((size_t)n * sizeof(uint64_t));
    if (!pks || !sks || !cts || !ss || !ss2 || !t) return 2;
#define PK(i) (pks + (size_t)(i) * k->length_public_key)
#define SK(i) (sks + (size_t)(i) * k->length_secret_key)
#define CT(i) (cts + (size_t)(i) * k->length_ciphertext)
    printf("%s (pk %zu B, ct %zu B)\n", alg, k->length_public_key, k->length_ciphertext);
    for (int i = 0; i < n + warm; i++) {
        uint64_t s = now_ns();
        OQS_KEM_keypair(k, PK(i), SK(i));
        if (i >= warm) t[i - warm] = now_ns() - s;
    }
    report("keygen", t, n);
    for (int i = 0; i < n + warm; i++) {
        uint64_t s = now_ns();
        OQS_KEM_encaps(k, CT(i), ss, PK(i));
        if (i >= warm) t[i - warm] = now_ns() - s;
    }
    report("encaps", t, n);
    for (int i = 0; i < n + warm; i++) {
        uint64_t s = now_ns();
        OQS_KEM_decaps(k, ss2, CT(i), SK(i));
        if (i >= warm) t[i - warm] = now_ns() - s;
    }
    report("decaps", t, n);
    int bad = 0;
    for (int i = 0; i < n + warm; i++) {
        uint64_t s = now_ns();
        OQS_KEM_keypair(k, PK(i), SK(i));
        OQS_KEM_encaps(k, CT(i), ss, PK(i));
        OQS_KEM_decaps(k, ss2, CT(i), SK(i));
        if (i >= warm) t[i - warm] = now_ns() - s;
        bad |= memcmp(ss, ss2, k->length_shared_secret) != 0;
    }
    report("handshake", t, n);
    printf("  (%d iterations after %d warm-up calls; all handshakes %s)\n", n, warm, bad ? "DID NOT AGREE" : "agreed");
#undef PK
#undef SK
#undef CT
    free(pks); free(sks); free(cts); free(ss); free(ss2); free(t);
    OQS_KEM_free(k);
    return bad;
}

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 5000;
    OQS_init();
    OQS_randombytes_custom_algorithm(cheap_rng);
    int rc = 0;
    rc |= bench(OQS_KEM_alg_ml_kem_512, n);
    rc |= bench(OQS_KEM_alg_frodokem_640_aes, n);
    rc |= bench(OQS_KEM_alg_frodokem_640_shake, n);
    OQS_destroy();
    return rc;
}
