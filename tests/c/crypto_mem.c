/*
 * Conformance test for the default allocator (crypto.h, OPENSSL_malloc(3)), OPENSSL_cleanse,
 * CRYPTO_memcmp, and CRYPTO_aligned_alloc, in TAP format.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4). Lines starting
 * with "#" record platform-dependent results, which must also match.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

static int all(const unsigned char *data, size_t from, size_t to, unsigned char byte)
{
    for (size_t i = from; i < to; i++)
        if (data[i] != byte)
            return 0;
    return 1;
}

static void functions(void)
{
    CRYPTO_malloc_fn m = NULL;
    CRYPTO_realloc_fn r = NULL;
    CRYPTO_free_fn f = NULL;

    CRYPTO_get_mem_functions(&m, &r, &f);
    check(m == CRYPTO_malloc && r == CRYPTO_realloc && f == CRYPTO_free,
          "CRYPTO_get_mem_functions: the defaults are CRYPTO_malloc, _realloc, and _free");
    CRYPTO_get_mem_functions(NULL, NULL, NULL);
    check(1, "CRYPTO_get_mem_functions: null pointers are skipped");
    check(CRYPTO_set_mem_functions(NULL, NULL, NULL) == 1,
          "CRYPTO_set_mem_functions: allowed before the first allocation");
    check(OPENSSL_malloc(0) == NULL && OPENSSL_zalloc(0) == NULL,
          "zero-byte allocations are null");
    check(CRYPTO_set_mem_functions(NULL, NULL, NULL) == 1,
          "CRYPTO_set_mem_functions: a zero-byte allocation doesn't count");
    OPENSSL_free(OPENSSL_malloc(1));
    check(CRYPTO_set_mem_functions(NULL, NULL, NULL) == 0,
          "CRYPTO_set_mem_functions: refused after an allocation");
}

static void allocating(void)
{
    unsigned char *p = OPENSSL_malloc(100);
    unsigned char *z = OPENSSL_zalloc(64);
    unsigned char *q;

    check(p != NULL, "OPENSSL_malloc: 100 bytes");
    check(z != NULL && all(z, 0, 64, 0), "OPENSSL_zalloc: 64 zero bytes");
    memset(p, 'x', 100);
    q = OPENSSL_realloc(p, 200);
    check(q != NULL && all(q, 0, 100, 'x'), "OPENSSL_realloc: growing keeps the contents");
    p = OPENSSL_realloc(q, 10);
    check(p != NULL && all(p, 0, 10, 'x'), "OPENSSL_realloc: shrinking keeps the contents");
    check(OPENSSL_realloc(p, 0) == NULL, "OPENSSL_realloc: zero bytes frees");
    p = OPENSSL_realloc(NULL, 16);
    check(p != NULL, "OPENSSL_realloc: null allocates");
    q = OPENSSL_realloc(p, SIZE_MAX);
    check(q == NULL, "OPENSSL_realloc: an impossible size fails");
    check(OPENSSL_malloc(SIZE_MAX) == NULL && OPENSSL_zalloc(SIZE_MAX) == NULL,
          "OPENSSL_malloc, OPENSSL_zalloc: an impossible size fails");
    OPENSSL_free(p);
    OPENSSL_free(z);
    OPENSSL_free(NULL);
    OPENSSL_clear_free(NULL, 10);
    check(1, "OPENSSL_free, OPENSSL_clear_free: null does nothing");
}

static void clearing(void)
{
    unsigned char *p = OPENSSL_malloc(32);
    unsigned char *q;

    memset(p, 'y', 32);
    q = OPENSSL_clear_realloc(p, 32, 8);
    check(q == p && all(p, 0, 8, 'y') && all(p, 8, 32, 0),
          "OPENSSL_clear_realloc: shrinking zeroes the tail in place");
    q = OPENSSL_clear_realloc(p, 32, 64);
    check(q != NULL && q != p && all(q, 0, 8, 'y') && all(q, 8, 32, 0),
          "OPENSSL_clear_realloc: growing moves to a new block");
    p = OPENSSL_clear_realloc(NULL, 0, 16);
    check(p != NULL, "OPENSSL_clear_realloc: null allocates");
    check(OPENSSL_clear_realloc(p, 16, 0) == NULL, "OPENSSL_clear_realloc: zero bytes frees");
    OPENSSL_clear_free(q, 64);
    check(1, "OPENSSL_clear_free: frees");
}

static void cleansing(void)
{
    unsigned char buffer[48];
    char what[96];

    for (size_t start = 0; start < 9; start++) {
        for (size_t len = 0; len < 34; len += 11) {
            memset(buffer, 0xff, sizeof(buffer));
            OPENSSL_cleanse(buffer + start, len);
            snprintf(what, sizeof(what), "OPENSSL_cleanse: %zu bytes at offset %zu", len, start);
            check(all(buffer, 0, start, 0xff) && all(buffer, start, start + len, 0)
                  && all(buffer, start + len, sizeof(buffer), 0xff), what);
        }
    }
}

static void comparing(void)
{
    unsigned char a[64], b[64];
    size_t lengths[] = { 1, 7, 15, 16, 17, 64 };
    char what[96];

    for (size_t i = 0; i < 64; i++)
        a[i] = b[i] = (unsigned char)(i * 7);
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        size_t n = lengths[i];

        snprintf(what, sizeof(what), "CRYPTO_memcmp: %zu equal bytes give 0", n);
        check(CRYPTO_memcmp(a, b, n) == 0, what);
        b[n - 1] ^= 0x80;
        snprintf(what, sizeof(what), "CRYPTO_memcmp: %zu bytes, the last differing, give 1", n);
        check(CRYPTO_memcmp(a, b, n) == 1, what);
        b[n - 1] ^= 0x80;
        b[0] ^= 1;
        snprintf(what, sizeof(what), "CRYPTO_memcmp: %zu bytes, the first differing, give 1", n);
        check(CRYPTO_memcmp(a, b, n) == 1, what);
        b[0] ^= 1;
    }
    check(CRYPTO_memcmp("a", "b", 0) == 0, "CRYPTO_memcmp: zero bytes are equal");
}

static void aligning(void)
{
    size_t good[] = { 8, 16, 64, 4096 };
    size_t odd[] = { 0, 1, 2, 3, 4, 24 };
    char what[96];
    void *freeptr, *p;

    for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
        freeptr = NULL;
        p = CRYPTO_aligned_alloc(100, good[i], &freeptr, OPENSSL_FILE, OPENSSL_LINE);
        snprintf(what, sizeof(what), "CRYPTO_aligned_alloc: alignment %zu", good[i]);
        check(p != NULL && freeptr != NULL && (uintptr_t)p % good[i] == 0
              && (char *)p >= (char *)freeptr, what);
        OPENSSL_free(freeptr);
    }
    /* Which of these fail depends on the platform (posix_memalign on Linux). */
    for (size_t i = 0; i < sizeof(odd) / sizeof(odd[0]); i++) {
        freeptr = (void *)&freeptr;
        p = CRYPTO_aligned_alloc(100, odd[i], &freeptr, OPENSSL_FILE, OPENSSL_LINE);
        printf("# CRYPTO_aligned_alloc(100, %zu): %s, freeptr %s\n", odd[i],
               p == NULL ? "null" : "a block", freeptr == NULL ? "null" : "set");
        OPENSSL_free(freeptr);
    }
    p = CRYPTO_aligned_alloc(0, 16, &freeptr, OPENSSL_FILE, OPENSSL_LINE);
    printf("# CRYPTO_aligned_alloc(0, 16): %s, freeptr %s\n",
           p == NULL ? "null" : "a block", freeptr == NULL ? "null" : "set");
    OPENSSL_free(freeptr);
    check(1, "CRYPTO_aligned_alloc: unusual alignments and sizes behave as on the reference");
}

int main(void)
{
    functions();
    allocating();
    clearing();
    cleansing();
    comparing();
    aligning();
    printf("1..%d\n", number);
    return failures != 0;
}
