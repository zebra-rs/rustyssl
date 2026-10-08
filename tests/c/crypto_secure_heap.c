/*
 * Conformance test for the secure heap (CRYPTO_secure_malloc(3)), in TAP format.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustssl: it must pass on both with the same output (TEST_PLAN.md, layer L4). Lines starting
 * with "#" trace where blocks land, as offsets from the start of the arena: the two allocators
 * must place them identically.
 *
 * CRYPTO_secure_used and CRYPTO_secure_actual_size are only called while a heap exists: without
 * one, OpenSSL's dereference a null lock (docs/DEVIATIONS.md).
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/buffer.h>
#include <openssl/crypto.h>

#define ARENA 4096

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static int zero(const unsigned char *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
        if (data[i] != 0)
            return 0;
    return 1;
}

/* The start of the arena: the only place a block of the whole arena can go. */
static unsigned char *start(void)
{
    unsigned char *whole = CRYPTO_secure_malloc(ARENA, OPENSSL_FILE, OPENSSL_LINE);
    unsigned char *base = whole;

    CRYPTO_secure_free(whole, OPENSSL_FILE, OPENSSL_LINE);
    return base;
}

static void without_a_heap(void)
{
    unsigned char *p = OPENSSL_secure_malloc(10);
    unsigned char *z = OPENSSL_secure_zalloc(8);

    check(CRYPTO_secure_malloc_initialized() == 0, "no secure heap at first");
    check(p != NULL && CRYPTO_secure_allocated(p) == 0,
          "CRYPTO_secure_malloc: falls back to the ordinary allocator");
    check(z != NULL && zero(z, 8), "CRYPTO_secure_zalloc: falls back to OPENSSL_zalloc");
    OPENSSL_secure_free(p);
    OPENSSL_secure_clear_free(z, 8);
    OPENSSL_secure_free(NULL);
    OPENSSL_secure_clear_free(NULL, 4);
    check(1, "CRYPTO_secure_free and CRYPTO_secure_clear_free: ordinary memory and null");
    check(CRYPTO_secure_malloc_done() == 1, "CRYPTO_secure_malloc_done: 1 without a heap");
    check(CRYPTO_secure_malloc_init(32, 16) == 0 && CRYPTO_secure_malloc_initialized() == 0,
          "CRYPTO_secure_malloc_init: fewer than four blocks fails");
}

static void setting_up(void)
{
    int ret = CRYPTO_secure_malloc_init(ARENA, 16);

    /* 2 means the arena isn't fully locked or guarded, which depends on the environment. */
    printf("# CRYPTO_secure_malloc_init(%d, 16) returns %d\n", ARENA, ret);
    check(ret == 1 || ret == 2, "CRYPTO_secure_malloc_init: sets up a heap");
    check(CRYPTO_secure_malloc_initialized() == 1, "CRYPTO_secure_malloc_initialized: 1");
    check(CRYPTO_secure_malloc_init(ARENA, 16) == 0, "CRYPTO_secure_malloc_init: only once");
}

static void placing(unsigned char *base)
{
    size_t sizes[] = { 0, 17, 100, 16, 200, 33, 1000, 5, 4097 };
    unsigned char *blocks[sizeof(sizes) / sizeof(sizes[0])];
    size_t n = sizeof(sizes) / sizeof(sizes[0]);

    for (size_t i = 0; i < n; i++) {
        blocks[i] = OPENSSL_secure_malloc(sizes[i]);
        if (blocks[i] == NULL)
            printf("# malloc %zu: null\n", sizes[i]);
        else
            printf("# malloc %zu: offset %ld, size %zu, used %zu\n", sizes[i],
                   (long)(blocks[i] - base), CRYPTO_secure_actual_size(blocks[i]),
                   CRYPTO_secure_used());
    }
    for (size_t i = 0; i < n; i += 2) {
        OPENSSL_secure_free(blocks[i]);
        printf("# free block %zu: used %zu\n", i, CRYPTO_secure_used());
    }
    for (size_t i = 1; i < n; i += 2)
        OPENSSL_secure_free(blocks[i]);
    check(CRYPTO_secure_used() == 0, "CRYPTO_secure_used: 0 after freeing everything");
}

static void tracing(unsigned char *base)
{
    unsigned char *live[64] = { NULL };
    uint32_t state = 12345;

    for (int step = 0; step < 300; step++) {
        size_t slot;

        state = state * 1103515245u + 12345u;
        slot = (state >> 16) % 64;
        if (live[slot] == NULL) {
            size_t size = (state >> 8) % 300;

            live[slot] = OPENSSL_secure_malloc(size);
            printf("# %d: malloc %zu -> %ld (used %zu)\n", step, size,
                   live[slot] == NULL ? -1L : (long)(live[slot] - base), CRYPTO_secure_used());
        } else {
            OPENSSL_secure_free(live[slot]);
            live[slot] = NULL;
            printf("# %d: free slot %zu (used %zu)\n", step, slot, CRYPTO_secure_used());
        }
    }
    for (size_t slot = 0; slot < 64; slot++)
        OPENSSL_secure_free(live[slot]);
    check(CRYPTO_secure_used() == 0, "a random trace places blocks as the reference does");
}

static void filling(unsigned char *base)
{
    unsigned char *blocks[ARENA / 16];
    int all = 1;

    for (size_t i = 0; i < ARENA / 16; i++) {
        blocks[i] = OPENSSL_secure_malloc(16);
        all = all && blocks[i] != NULL;
    }
    check(all && CRYPTO_secure_used() == ARENA, "the arena holds 256 16-byte blocks");
    check(OPENSSL_secure_malloc(1) == NULL, "CRYPTO_secure_malloc: null when the arena is full");
    check(CRYPTO_secure_malloc_done() == 0, "CRYPTO_secure_malloc_done: 0 while blocks are used");
    for (size_t i = 0; i < ARENA / 16; i++)
        OPENSSL_secure_free(blocks[i]);
    check(start() == base, "freed blocks merge back into the whole arena");
}

static void zeroing(unsigned char *base)
{
    unsigned char *p = OPENSSL_secure_malloc(64);
    unsigned char *q;
    unsigned char *z;

    check(p != NULL && CRYPTO_secure_allocated(p) && p >= base && p < base + ARENA,
          "CRYPTO_secure_malloc: a block in the arena");
    memset(p, 0xaa, 64);
    OPENSSL_secure_free(p);
    q = OPENSSL_secure_malloc(64);
    check(q == p && zero(q, 64), "freed blocks are zeroed: the next one starts out zero");
    z = OPENSSL_secure_zalloc(100);
    check(z != NULL && CRYPTO_secure_actual_size(z) == 128 && zero(z, 128),
          "CRYPTO_secure_zalloc: a zero block in the arena");
    memset(z, 0xbb, 128);
    OPENSSL_secure_clear_free(z, 1);
    z = OPENSSL_secure_malloc(100);
    check(zero(z, 128), "CRYPTO_secure_clear_free: zeroes the whole block");
    OPENSSL_secure_free(z);
    OPENSSL_secure_free(q);

    p = OPENSSL_malloc(16);
    memset(p, 0xcc, 16);
    check(CRYPTO_secure_allocated(p) == 0, "CRYPTO_secure_allocated: 0 for ordinary memory");
    OPENSSL_secure_clear_free(p, 16);
    check(CRYPTO_secure_allocated(base) == 1 && CRYPTO_secure_allocated(base + ARENA - 1) == 1
          && CRYPTO_secure_allocated(base + ARENA) == 0,
          "CRYPTO_secure_allocated: exactly the arena");
}

static void buffers(void)
{
    BUF_MEM *secure = BUF_MEM_new_ex(BUF_MEM_FLAG_SECURE);
    BUF_MEM *plain = BUF_MEM_new();

    BUF_MEM_grow(secure, 10);
    BUF_MEM_grow(plain, 10);
    check(CRYPTO_secure_allocated(secure->data) && !CRYPTO_secure_allocated(plain->data)
          && CRYPTO_secure_used() == 16,
          "BUF_MEM_FLAG_SECURE: the data lives in the secure heap");
    memcpy(secure->data, "0123456789", 10);
    BUF_MEM_grow(secure, 100);
    check(CRYPTO_secure_allocated(secure->data) && memcmp(secure->data, "0123456789", 10) == 0
          && CRYPTO_secure_used() == 256,
          "BUF_MEM_grow: secure data moves to a bigger secure block");
    BUF_MEM_free(secure);
    BUF_MEM_free(plain);
    check(CRYPTO_secure_used() == 0, "BUF_MEM_free: frees secure data");
}

static void tearing_down(unsigned char *base)
{
    check(CRYPTO_secure_malloc_done() == 1 && CRYPTO_secure_malloc_initialized() == 0,
          "CRYPTO_secure_malloc_done: tears down an unused heap");
    check(CRYPTO_secure_allocated(base) == 0, "after teardown nothing is secure");
    check(CRYPTO_secure_malloc_init(ARENA, 64) != 0, "CRYPTO_secure_malloc_init: again, larger blocks");
    base = start();
    {
        unsigned char *p = OPENSSL_secure_malloc(1);

        check(p != NULL && CRYPTO_secure_actual_size(p) == 64, "the minimum block size is kept");
        printf("# 64-byte blocks: malloc 1 -> offset %ld\n", (long)(p - base));
        OPENSSL_secure_free(p);
    }
    check(CRYPTO_secure_malloc_done() == 1, "CRYPTO_secure_malloc_done: again");
}

int main(void)
{
    unsigned char *base;

    without_a_heap();
    setting_up();
    base = start();
    check(base != NULL && CRYPTO_secure_used() == 0, "the whole arena can be allocated");
    placing(base);
    tracing(base);
    filling(base);
    zeroing(base);
    buffers();
    tearing_down(base);
    printf("1..%d\n", number);
    return failures != 0;
}
