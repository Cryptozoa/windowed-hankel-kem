/*
 * Latency of the native Windowed Hankel KEM, for each parameter set. Each measured call uses a
 * distinct seed, entropy or ciphertext, generated before timing. Reports median and 90th
 * percentile.
 *
 * Usage: bench_hankel_native [iterations [set]]   (default 5000, all sets; set = 640, 936, 1208)
 */

/* clock_gettime() is POSIX, not C99; glibc declares it only on request. Must precede every include. */
#if !defined(__APPLE__) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 199309L
#endif

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
    printf("  %-10s median %7.1f us   p90 %7.1f us\n", name, t[n / 2] / 1000.0, t[(n * 9) / 10] / 1000.0);
}

typedef struct {
    const char *name;
    size_t pk_bytes, sk_bytes, ct_bytes;
    int (*keypair_derand)(uint8_t *, uint8_t *, const uint8_t *, size_t);
    int (*enc_derand)(uint8_t *, uint8_t *, const uint8_t *, const uint8_t *, size_t);
    int (*dec)(uint8_t *, const uint8_t *, size_t, const uint8_t *);
} kem_set;

#define SET(label, P, U)                                                                         \
    {label, U##_KEM_PUBLICKEYBYTES, U##_KEM_SECRETKEYBYTES, U##_KEM_CIPHERTEXTBYTES,            \
     P##kem_keypair_derand, P##kem_enc_derand, P##kem_dec}

static const kem_set SETS[] = {
    SET("WH-640", hankel_, HANKEL),
    SET("WH-936", hankel936_, HANKEL936),
    SET("WH-1208", hankel1208_, HANKEL1208),
};

static int bench_set(const kem_set *k, int n) {
    const int warm = n / 10;
    uint8_t *seeds = malloc((size_t)(n + warm) * 64);
    uint8_t *ents = malloc((size_t)(n + warm) * 32);
    uint8_t *pks = malloc((size_t)(n + warm) * k->pk_bytes);
    uint8_t *sks = malloc((size_t)(n + warm) * k->sk_bytes);
    uint8_t *cts = malloc((size_t)(n + warm) * k->ct_bytes);
    uint64_t *t = malloc((size_t)n * sizeof(uint64_t));
    uint8_t ss[32], ss2[32];
    if (!seeds || !ents || !pks || !sks || !cts || !t) return 2;
    for (int i = 0; i < (n + warm) * 64; i++) seeds[i] = (uint8_t)rand();
    for (int i = 0; i < (n + warm) * 32; i++) ents[i] = (uint8_t)rand();

#define PK(i) (pks + (size_t)(i) * k->pk_bytes)
#define SK(i) (sks + (size_t)(i) * k->sk_bytes)
#define CT(i) (cts + (size_t)(i) * k->ct_bytes)

    printf("%s (pk %zu B, ct %zu B)\n", k->name, k->pk_bytes, k->ct_bytes);
    for (int i = 0; i < n + warm; i++) {
        uint64_t s = now_ns();
        k->keypair_derand(PK(i), SK(i), seeds + 64 * i, 64);
        if (i >= warm) t[i - warm] = now_ns() - s;
    }
    report("keygen", t, n);

    for (int i = 0; i < n + warm; i++) {
        uint64_t s = now_ns();
        k->enc_derand(CT(i), ss, PK(i), ents + 32 * i, 32);
        if (i >= warm) t[i - warm] = now_ns() - s;
    }
    report("encaps", t, n);

    int bad = 0;
    for (int i = 0; i < n + warm; i++) {
        uint64_t s = now_ns();
        k->dec(ss2, CT(i), k->ct_bytes, SK(i));
        if (i >= warm) t[i - warm] = now_ns() - s;
    }
    report("decaps", t, n);

    for (int i = 0; i < n + warm; i++) {
        uint64_t s = now_ns();
        k->keypair_derand(PK(i), SK(i), seeds + 64 * i, 64);
        k->enc_derand(CT(i), ss, PK(i), ents + 32 * i, 32);
        k->dec(ss2, CT(i), k->ct_bytes, SK(i));
        if (i >= warm) t[i - warm] = now_ns() - s;
        bad |= memcmp(ss, ss2, 32) != 0;
    }
    report("handshake", t, n);
    printf("  (%d iterations after %d warm-up calls; all handshakes %s)\n", n, warm,
           bad ? "DID NOT AGREE" : "agreed");
#undef PK
#undef SK
#undef CT
    free(seeds); free(ents); free(pks); free(sks); free(cts); free(t);
    return bad;
}

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 5000;
    if (n < 10) n = 10;
    int bad = 0;
    for (size_t s = 0; s < sizeof(SETS) / sizeof(SETS[0]); s++) {
        if (argc > 2 && strcmp(SETS[s].name + 3, argv[2]) != 0) continue;
        bad |= bench_set(&SETS[s], n);
    }
    return bad;
}
