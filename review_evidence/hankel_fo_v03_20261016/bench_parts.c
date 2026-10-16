/*
 * Where WH-640 encapsulation spends its time (paper, Section 8.4): the two Hankel products of
 * CPA encryption, u = H_768(a) r + e1 and K = H_128(b) r, and the SHAKE256 calls of one
 * encapsulation: expanding the public sequence (2L = 2814 bytes), the CPA coins (n + m + W = 1536
 * bytes), G(M) and H(M, ct) (32 + 1356 bytes absorbed). Each sample times a batch of 100 calls (the
 * monotonic clock has microsecond resolution); medians of 1,000 samples after 100 warm-up calls.
 *
 * Build and run from the repository root:
 *   cc -O3 -std=c99 -arch arm64 -o bench_parts review_evidence/hankel_fo_v03_20261016/bench_parts.c \
 *      hankel_kem_native.c hankel_hash.c && ./bench_parts
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "hankel_kem_native.h"
#include "hankel_hash.h"

void hankel_kernel_mul(uint16_t *out, const uint16_t *a, const int16_t *x, const int16_t *e, int m);

#define N 640
#define W 128
#define M (N + W)
#define L (2 * N + W - 1)
#define CTB HANKEL_KEM_CIPHERTEXTBYTES
#define REPS 1000
#define WARM 100
#define BATCH 100

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static int cmp(const void *x, const void *y) {
    double a = *(const double *)x, b = *(const double *)y;
    return (a > b) - (a < b);
}

static double median(double *t) {
    qsort(t, REPS, sizeof(double), cmp);
    return t[REPS / 2];
}

static volatile uint8_t sink;

int main(void) {
    static uint16_t a[L], b[L], u[M], k[W];
    static int16_t r[N], e1[M];
    static uint8_t buf[2 * L], ct[CTB], msg[32], out[32];
    static double t[REPS];
    for (int i = 0; i < L; i++) a[i] = (uint16_t)((i * 2654435761u) >> 20), b[i] = (uint16_t)(i * 40503u >> 4);
    for (int i = 0; i < N; i++) r[i] = (int16_t)((i % 5) - 2);
    for (int i = 0; i < M; i++) e1[i] = (int16_t)((i % 3) - 1);
    for (int i = 0; i < CTB; i++) ct[i] = (uint8_t)i;
    for (int i = 0; i < 32; i++) msg[i] = (uint8_t)(7 * i);

#define TIME(label, stmt)                                                    \
    do {                                                                     \
        for (int it = 0; it < WARM; it++) { stmt; }                          \
        for (int it = 0; it < REPS; it++) {                                  \
            double s = now_us();                                             \
            for (int bt = 0; bt < BATCH; bt++) { stmt; }                     \
            t[it] = (now_us() - s) / BATCH;                                  \
        }                                                                    \
        printf("  %-46s median %6.2f us\n", label, median(t));               \
    } while (0)

    printf("WH-640 encapsulation, parts (Apple clang, -O3)\n");
    TIME("Hankel product u = H_768(a) r + e1", hankel_kernel_mul(u, a, r, e1, M));
    TIME("Hankel product K = H_128(b) r", hankel_kernel_mul(k, b, r, NULL, W));
    TIME("SHAKE256: public sequence (2814 bytes out)", hk_shake256_2(buf, 2 * L, msg, 32, msg, 0));
    TIME("SHAKE256: CPA coins (1536 bytes out)", hk_shake256_2(buf, N + M + W, msg, 32, msg, 0));
    TIME("SHAKE256: G(M) (32 bytes in, 32 out)", hk_shake256_2(out, 32, msg, 32, msg, 0));
    TIME("SHAKE256: H(M, ct) (1388 bytes in, 32 out)", hk_shake256_2(out, 32, msg, 32, ct, CTB));
    sink = (uint8_t)(u[0] ^ k[0] ^ buf[0] ^ out[0]);
    return 0;
}
