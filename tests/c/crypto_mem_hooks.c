/*
 * Conformance test for CRYPTO_set_mem_functions (OPENSSL_malloc(3)), in TAP format: an
 * application's allocator receives every allocation, OpenSSL's own included.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4). It installs its
 * allocator first, before anything allocates.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/buffer.h>
#include <openssl/crypto.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static int mallocs, reallocs, frees, located;
static size_t last;

static void *counting_malloc(size_t num, const char *file, int line)
{
    mallocs++;
    last = num;
    located += file != NULL && line > 0;
    return num == 0 ? NULL : malloc(num);
}

static void *counting_realloc(void *ptr, size_t num, const char *file, int line)
{
    reallocs++;
    last = num;
    located += file != NULL && line > 0;
    if (num == 0) {
        free(ptr);
        return NULL;
    }
    return realloc(ptr, num);
}

static void counting_free(void *ptr, const char *file, int line)
{
    frees++;
    located += file != NULL && line > 0;
    free(ptr);
}

static void counts(int m, int r, int f, const char *what)
{
    char line[160];

    snprintf(line, sizeof(line), "%s (mallocs %d, reallocs %d, frees %d)", what, m, r, f);
    check(mallocs == m && reallocs == r && frees == f, line);
}

int main(void)
{
    CRYPTO_malloc_fn m;
    CRYPTO_realloc_fn r;
    CRYPTO_free_fn f;
    unsigned char *p, *z;
    void *freeptr;
    BUF_MEM *b;
    CRYPTO_RWLOCK *lock;

    check(CRYPTO_set_mem_functions(counting_malloc, counting_realloc, counting_free) == 1,
          "CRYPTO_set_mem_functions: installs the application's allocator");
    CRYPTO_get_mem_functions(&m, &r, &f);
    check(m == counting_malloc && r == counting_realloc && f == counting_free,
          "CRYPTO_get_mem_functions: reports it");

    p = OPENSSL_malloc(10);
    counts(1, 0, 0, "OPENSSL_malloc goes to the application");
    check(p != NULL && last == 10 && located == 1, "OPENSSL_malloc: passes the size, file, and line");
    z = OPENSSL_zalloc(16);
    counts(2, 0, 0, "OPENSSL_zalloc goes to the application's malloc");
    check(z != NULL && z[0] == 0 && z[15] == 0, "OPENSSL_zalloc: zeroes what it gets");
    check(OPENSSL_malloc(0) == NULL, "OPENSSL_malloc(0): the application decides");
    counts(3, 0, 0, "OPENSSL_malloc(0) goes to the application too");

    p = OPENSSL_realloc(p, 20);
    counts(3, 1, 0, "OPENSSL_realloc goes to the application");
    OPENSSL_free(OPENSSL_realloc(NULL, 5));
    counts(3, 2, 1, "OPENSSL_realloc(NULL) goes to the application's realloc");
    OPENSSL_free(NULL);
    counts(3, 2, 2, "OPENSSL_free(NULL) goes to the application");
    OPENSSL_clear_free(NULL, 5);
    counts(3, 2, 2, "OPENSSL_clear_free(NULL) does nothing");
    OPENSSL_clear_free(z, 16);
    OPENSSL_free(p);
    counts(3, 2, 4, "OPENSSL_clear_free and OPENSSL_free free through the application");

    p = CRYPTO_aligned_alloc(100, 64, &freeptr, OPENSSL_FILE, OPENSSL_LINE);
    counts(4, 2, 4, "CRYPTO_aligned_alloc over-allocates with the application's malloc");
    check(p != NULL && (uintptr_t)p % 64 == 0 && last == 164,
          "CRYPTO_aligned_alloc: rounds up inside a block of size + alignment");
    OPENSSL_free(freeptr);

    b = BUF_MEM_new();
    counts(5, 2, 5, "BUF_MEM_new allocates through the application");
    BUF_MEM_grow(b, 10);
    counts(5, 3, 5, "BUF_MEM_grow reallocates through the application");
    BUF_MEM_free(b);
    counts(5, 3, 7, "BUF_MEM_free frees the data and the buffer through the application");

    lock = CRYPTO_THREAD_lock_new();
    counts(6, 3, 7, "CRYPTO_THREAD_lock_new allocates through the application");
    CRYPTO_THREAD_lock_free(lock);
    counts(6, 3, 8, "CRYPTO_THREAD_lock_free frees through the application");

    check(CRYPTO_set_mem_functions(NULL, NULL, NULL) == 1,
          "CRYPTO_set_mem_functions: still allowed while the default allocator is unused");
    CRYPTO_get_mem_functions(&m, NULL, NULL);
    check(m == counting_malloc, "CRYPTO_set_mem_functions: null arguments keep the current ones");
    check(CRYPTO_set_mem_functions(CRYPTO_malloc, CRYPTO_realloc, CRYPTO_free) == 1,
          "CRYPTO_set_mem_functions: the defaults can be restored");
    CRYPTO_get_mem_functions(&m, &r, &f);
    check(m == CRYPTO_malloc && r == CRYPTO_realloc && f == CRYPTO_free,
          "CRYPTO_get_mem_functions: reports the defaults again");
    p = OPENSSL_malloc(8);
    OPENSSL_free(p);
    counts(6, 3, 8, "the default allocator doesn't call the application's");
    check(CRYPTO_set_mem_functions(counting_malloc, NULL, NULL) == 0,
          "CRYPTO_set_mem_functions: refused once the default allocator has allocated");
    printf("1..%d\n", number);
    return failures != 0;
}
