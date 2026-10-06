/*
 * Latency of the native Windowed Hankel KEM. Each measured call uses a distinct seed,
 * entropy or ciphertext, generated before timing. Reports median and 90th percentile.
 *
 * Usage: bench_hankel_native [iterations]   (default 5000)
 */

#include "hankel_kem_native.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t now_ns(void) {
#if defined(__APPLE__)
    return clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
#endif
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static void report(const char *name, uint64_t *t, int n) {
    qsort(t, (size_t)n, sizeof(uint64_t), cmp_u64);
    printf("%-10s median %7.1f us   p90 %7.1f us\n", name, t[n / 2] / 1000.0, t[(n * 9) / 10] / 1000.0);
}

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 5000;
    if (n < 10) n = 10;
    const int warm = n / 10;
    uint8_t *seeds = malloc((size_t)(n + warm) * 64);
    uint8_t *ents = malloc((size_t)(n + warm) * 32);
    uint8_t *pks = malloc((size_t)(n + warm) * HANKEL_KEM_PUBLICKEYBYTES);
    uint8_t *sks = malloc((size_t)(n + warm) * HANKEL_KEM_SECRETKEYBYTES);
    uint8_t *cts = malloc((size_t)(n + warm) * HANKEL_KEM_CIPHERTEXTBYTES);
    uint64_t *t = malloc((size_t)n * sizeof(uint64_t));
    uint8_t ss[32], ss2[32];
    if (!seeds || !ents || !pks || !sks || !cts || !t) return 2;
    for (int i = 0; i < (n + warm) * 64; i++) seeds[i] = (uint8_t)rand();
    for (int i = 0; i < (n + warm) * 32; i++) ents[i] = (uint8_t)rand();

#define PK(i) (pks + (size_t)(i) * HANKEL_KEM_PUBLICKEYBYTES)
#define SK(i) (sks + (size_t)(i) * HANKEL_KEM_SECRETKEYBYTES)
#define CT(i) (cts + (size_t)(i) * HANKEL_KEM_CIPHERTEXTBYTES)

    for (int i = 0; i < n + warm; i++) {
        uint64_t s = now_ns();
        hankel_kem_keypair_derand(PK(i), SK(i), seeds + 64 * i, 64);
        if (i >= warm) t[i - warm] = now_ns() - s;
    }
    report("keygen", t, n);

    for (int i = 0; i < n + warm; i++) {
        uint64_t s = now_ns();
        hankel_kem_enc_derand(CT(i), ss, PK(i), ents + 32 * i, 32);
        if (i >= warm) t[i - warm] = now_ns() - s;
    }
    report("encaps", t, n);

    int bad = 0;
    for (int i = 0; i < n + warm; i++) {
        uint64_t s = now_ns();
        hankel_kem_dec(ss2, CT(i), HANKEL_KEM_CIPHERTEXTBYTES, SK(i));
        if (i >= warm) t[i - warm] = now_ns() - s;
    }
    report("decaps", t, n);

    for (int i = 0; i < n + warm; i++) {
        uint64_t s = now_ns();
        hankel_kem_keypair_derand(PK(i), SK(i), seeds + 64 * i, 64);
        hankel_kem_enc_derand(CT(i), ss, PK(i), ents + 32 * i, 32);
        hankel_kem_dec(ss2, CT(i), HANKEL_KEM_CIPHERTEXTBYTES, SK(i));
        if (i >= warm) t[i - warm] = now_ns() - s;
        bad |= memcmp(ss, ss2, 32) != 0;
    }
    report("handshake", t, n);
    printf("(%d iterations after %d warm-up calls; all handshakes %s)\n", n, warm,
           bad ? "DID NOT AGREE" : "agreed");
    return bad;
}
