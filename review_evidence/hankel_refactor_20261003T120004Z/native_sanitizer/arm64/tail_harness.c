/* Exact-allocation tail checks against an independent int64 modular oracle.
 * Inputs are bounded canonical coefficients and synthetic CBD2-range secrets.
 * This is a spatial-memory and arithmetic-correctness check, not a benchmark.
 */
#include "hankel_kem_neon.h"
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static uint32_t state = UINT32_C(0x65829701);
static size_t compared = 0;
static size_t forward_cases = 0;
static size_t project_cases = 0;

static uint32_t next_word(void) {
    state = state * UINT32_C(1664525) + UINT32_C(1013904223);
    return state;
}

static void *exact_alloc(size_t count, size_t width) {
    void *result = malloc(count * width);
    if (result == NULL) {
        fputs("Allocation failed\n", stderr);
        exit(2);
    }
    return result;
}

static uint16_t reduce_mod_q(int64_t value) {
    int64_t result = value % HANKEL_Q;
    if (result < 0) {
        result += HANKEL_Q;
    }
    return (uint16_t)result;
}

static int16_t small_value(int pattern) {
    if (pattern == 1) {
        return 2;
    }
    if (pattern == 2) {
        return -2;
    }
    return (int16_t)((int)(next_word() % 5) - 2);
}

static uint16_t field_value(int pattern) {
    return pattern == 0 ? (uint16_t)(next_word() & HANKEL_Q_MASK)
                        : HANKEL_Q_MASK;
}

static void check_forward(int n, int m, int pattern, int with_error) {
    const size_t a_len = (size_t)n + (size_t)m - 1;
    uint16_t *a = exact_alloc(a_len, sizeof(*a));
    int16_t *x = exact_alloc((size_t)n, sizeof(*x));
    int16_t *e = with_error ? exact_alloc((size_t)m, sizeof(*e)) : NULL;
    uint16_t *out = exact_alloc((size_t)m, sizeof(*out));
    for (size_t i = 0; i < a_len; ++i) {
        a[i] = field_value(pattern);
    }
    for (int j = 0; j < n; ++j) {
        x[j] = small_value(pattern);
    }
    for (int i = 0; i < m; ++i) {
        if (with_error) {
            e[i] = small_value(pattern);
        }
        out[i] = UINT16_MAX;
    }
    hankel_neon_forward_mul(a, x, e, out, n, m);
    for (int i = 0; i < m; ++i) {
        int64_t sum = with_error ? e[i] : 0;
        for (int j = 0; j < n; ++j) {
            sum += (int64_t)a[i + j] * (int64_t)x[j];
        }
        const uint16_t expected = reduce_mod_q(sum);
        if (out[i] != expected) {
            fprintf(stderr, "Forward mismatch n=%d m=%d pattern=%d error=%d i=%d: got=%u expected=%u\n",
                    n, m, pattern, with_error, i, out[i], expected);
            exit(1);
        }
        ++compared;
    }
    ++forward_cases;
    free(out);
    free(e);
    free(x);
    free(a);
}

static void check_project(int n, int w, int pattern) {
    /* The C operator consumes exactly n+w-1 coefficients: the final slice
     * is y[w-1 .. w+n-2]. No padding or unused trailing word is allocated. */
    const size_t y_len = (size_t)n + (size_t)w - 1;
    int16_t *x = exact_alloc((size_t)n, sizeof(*x));
    uint16_t *y = exact_alloc(y_len, sizeof(*y));
    uint16_t *out = exact_alloc((size_t)w, sizeof(*out));
    for (int j = 0; j < n; ++j) {
        x[j] = small_value(pattern);
    }
    for (size_t i = 0; i < y_len; ++i) {
        y[i] = field_value(pattern);
    }
    for (int i = 0; i < w; ++i) {
        out[i] = UINT16_MAX;
    }
    hankel_neon_window_project(x, y, out, n, w);
    for (int i = 0; i < w; ++i) {
        int64_t sum = 0;
        for (int j = 0; j < n; ++j) {
            sum += (int64_t)x[j] * (int64_t)y[i + j];
        }
        const uint16_t expected = reduce_mod_q(sum);
        if (out[i] != expected) {
            fprintf(stderr, "Projection mismatch n=%d w=%d pattern=%d i=%d: got=%u expected=%u\n",
                    n, w, pattern, i, out[i], expected);
            exit(1);
        }
        ++compared;
    }
    ++project_cases;
    free(out);
    free(y);
    free(x);
}

int main(void) {
    const int lengths[] = {1, 7, 8, 9, 17, 31, 32, 33, 640};
    if (hankel_neon_supports_tails() != 1) {
        fputs("Candidate did not advertise tail support\n", stderr);
        return 1;
    }
    for (size_t index = 0; index < sizeof(lengths) / sizeof(lengths[0]); ++index) {
        const int n = lengths[index];
        const int rows[] = {1, 9, n + 128};
        const int windows[] = {1, 9, 128};
        for (int pattern = 0; pattern < 3; ++pattern) {
            for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); ++i) {
                check_forward(n, rows[i], pattern, 0);
                check_forward(n, rows[i], pattern, 1);
            }
            for (size_t i = 0; i < sizeof(windows) / sizeof(windows[0]); ++i) {
                check_project(n, windows[i], pattern);
            }
        }
        printf("PASS n=%d exact-length forward/project allocations\n", n);
    }
#if defined(__ARM_NEON) || defined(__aarch64__)
    const char *path = "ARM_NEON";
#else
    const char *path = "scalar";
#endif
    printf("{\"pass\":true,\"native_path\":\"%s\",\"forward_cases\":%zu,\"project_cases\":%zu,\"compared_coefficients\":%zu}\n",
           path, forward_cases, project_cases, compared);
    return 0;
}
