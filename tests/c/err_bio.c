/*
 * Conformance test for the error functions that take a BIO (ERR_print_errors(3),
 * ERR_add_error_mem_bio), in TAP format.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/bnerr.h>
#include <openssl/err.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static int same(const char *a, const char *b)
{
    return a != NULL && b != NULL && strcmp(a, b) == 0;
}

/* What ERR_print_errors prints before the error string: the thread ID's bytes in hex. */
static void thread_prefix(char *out, size_t size)
{
    pthread_t self = pthread_self();
    const unsigned char *bytes = (const unsigned char *)&self;
    size_t used = 0;

    for (size_t i = 0; i < sizeof(self) && used + 3 < size; i++)
        used += (size_t)snprintf(out + used, size - used, "%02X", bytes[i]);
}

static int raised_line;

static void raise_bn_error(void)
{
    raised_line = __LINE__ + 1;
    ERR_raise(ERR_LIB_BN, BN_R_DIV_BY_ZERO);
}

int main(void)
{
    BIO *out = BIO_new(BIO_s_mem()), *text;
    char prefix[64], expected[512];
    char *data = NULL;
    const char *got = NULL;
    long len;
    int flags = 0;

    thread_prefix(prefix, sizeof(prefix));
    raise_bn_error();
    ERR_add_error_data(1, "some data");
    raise_bn_error();
    ERR_print_errors(out);
    len = BIO_get_mem_data(out, &data);
    snprintf(expected, sizeof(expected),
             "%s:error:01800067:bignum routines:raise_bn_error:div by zero:%s:%d:some data\n"
             "%s:error:01800067:bignum routines:raise_bn_error:div by zero:%s:%d:\n",
             prefix, __FILE__, raised_line, prefix, __FILE__, raised_line);
    check(len == (long)strlen(expected) && memcmp(data, expected, len) == 0,
          "ERR_print_errors: one line per error, to the BIO");
    check(ERR_peek_error() == 0, "ERR_print_errors empties the queue");

    text = BIO_new(BIO_s_mem());
    BIO_puts(text, "from a BIO");
    raise_bn_error();
    ERR_add_error_mem_bio(" - ", text);
    check(ERR_peek_last_error_data(&got, &flags) != 0 && same(got, "from a BIO"),
          "ERR_add_error_mem_bio adds the BIO's text");
    check(BIO_get_mem_data(text, &data) == 11 && data[10] == '\0',
          "it NUL-terminates the BIO's data");
    ERR_add_error_mem_bio(" - ", text);
    check(ERR_peek_last_error_data(&got, &flags) != 0 && same(got, "from a BIO - from a BIO"),
          "again, after the separator");
    (void)BIO_reset(text);
    ERR_add_error_mem_bio(" - ", text);
    ERR_add_error_mem_bio(" - ", NULL);
    check(ERR_peek_last_error_data(&got, &flags) != 0 && same(got, "from a BIO - from a BIO"),
          "an empty BIO and a null one add nothing");
    ERR_clear_error();
    BIO_free(text);
    BIO_free(out);
    printf("1..%d\n", number);
    return failures != 0;
}
