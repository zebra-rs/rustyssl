/*
 * Conformance test for BUF_MEM (buffer.h, BUF_MEM_new(3)), in TAP format.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both (TEST_PLAN.md, layer L4). It only calls the functions under
 * test, since anything rustyssl doesn't implement yet aborts.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/buffer.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static int all(const char *data, size_t from, size_t to, char byte)
{
    for (size_t i = from; i < to; i++)
        if (data[i] != byte)
            return 0;
    return 1;
}

static void growing(unsigned long flags, size_t (*grow)(BUF_MEM *, size_t), const char *name)
{
    char what[128];
    BUF_MEM *b = BUF_MEM_new_ex(flags);

    snprintf(what, sizeof(what), "%s flags=%lu: new buffer is empty", name, flags);
    check(b != NULL && b->length == 0 && b->max == 0 && b->data == NULL && b->flags == flags, what);

    snprintf(what, sizeof(what), "%s flags=%lu: growing to 10 allocates 16 zero bytes", name, flags);
    check(grow(b, 10) == 10 && b->length == 10 && b->max == 16 && all(b->data, 0, 10, 0), what);
    memset(b->data, 'A', 10);

    snprintf(what, sizeof(what), "%s flags=%lu: growing within max zeroes the new bytes", name, flags);
    check(grow(b, 14) == 14 && b->length == 14 && b->max == 16
          && all(b->data, 0, 10, 'A') && all(b->data, 10, 14, 0), what);

    snprintf(what, sizeof(what), "%s flags=%lu: growing past max keeps the contents", name, flags);
    check(grow(b, 100) == 100 && b->length == 100 && b->max == 136
          && all(b->data, 0, 10, 'A') && all(b->data, 10, 100, 0), what);

    snprintf(what, sizeof(what), "%s flags=%lu: a length past the limit fails", name, flags);
    check(grow(b, 0x5ffffffd) == 0 && b->length == 100 && b->max == 136, what);

    BUF_MEM_free(b);
}

static void shrinking(void)
{
    BUF_MEM *b = BUF_MEM_new();

    BUF_MEM_grow(b, 8);
    memset(b->data, 'A', 8);
    check(BUF_MEM_grow(b, 3) == 3 && b->length == 3 && b->max == 12 && all(b->data, 3, 8, 'A'),
          "BUF_MEM_grow: shrinking keeps the memory and its contents");
    BUF_MEM_grow(b, 8);
    memset(b->data, 'A', 8);
    check(BUF_MEM_grow_clean(b, 3) == 3 && b->length == 3 && b->max == 12
          && all(b->data, 0, 3, 'A') && all(b->data, 3, 8, 0),
          "BUF_MEM_grow_clean: shrinking zeroes the cut-off bytes");
    BUF_MEM_free(b);
}

static void reversing(void)
{
    unsigned char in[6], out[6] = { 0 }, odd[5];

    memcpy(in, "abcdef", sizeof(in));
    memcpy(odd, "abcde", sizeof(odd));
    BUF_reverse(out, in, sizeof(out));
    check(memcmp(out, "fedcba", 6) == 0, "BUF_reverse: copies backwards");
    BUF_reverse(odd, NULL, sizeof(odd));
    check(memcmp(odd, "edcba", 5) == 0, "BUF_reverse: reverses in place");
    BUF_reverse(out, in, 0);
    check(memcmp(out, "fedcba", 6) == 0, "BUF_reverse: zero bytes does nothing");
}

int main(void)
{
    growing(0, BUF_MEM_grow, "BUF_MEM_grow");
    growing(0, BUF_MEM_grow_clean, "BUF_MEM_grow_clean");
    growing(BUF_MEM_FLAG_SECURE, BUF_MEM_grow, "BUF_MEM_grow");
    growing(BUF_MEM_FLAG_SECURE, BUF_MEM_grow_clean, "BUF_MEM_grow_clean");
    shrinking();
    reversing();
    BUF_MEM_free(NULL);
    check(1, "BUF_MEM_free(NULL) does nothing");
    printf("1..%d\n", number);
    return failures != 0;
}
