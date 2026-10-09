/*
 * Conformance test for the base64 filter (BIO_f_base64(3)), in TAP format: encoding writes of
 * every size, with and without BIO_FLAGS_BASE64_NO_NL, finished by BIO_flush; decoding text
 * with leading non-base64 lines, overlong lines, CR LF, bad characters, and truncation, read in
 * chunks of several sizes; reads that must be retried (a memory BIO returning -1 when empty);
 * and the controls. Every output is printed, so the results are compared byte for byte.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static void show(const char *what, const unsigned char *p, long n)
{
    long i;

    printf("# %s (%ld): \"", what, n);
    for (i = 0; i < n; i++) {
        if (p[i] == '\n')
            printf("\\n");
        else if (p[i] < 0x20 || p[i] > 0x7e)
            printf("\\x%02x", p[i]);
        else
            putchar(p[i]);
    }
    printf("\"\n");
}

/* Encodes `len` octets written in pieces of `piece`, with `flags`, and prints the text. */
static long encode(const char *what, const unsigned char *data, int len, int piece, int flags)
{
    BIO *mem = BIO_new(BIO_s_mem()), *b64 = BIO_new(BIO_f_base64());
    char *text;
    long n;
    int i, w, total = 0;

    BIO_set_flags(b64, flags);
    BIO_push(b64, mem);
    for (i = 0; i < len; i += piece) {
        w = BIO_write(b64, data + i, len - i < piece ? len - i : piece);
        total += w > 0 ? w : 0;
    }
    printf("# %s: wrote %d, wpending %ld, flush %d\n", what, total, (long)BIO_wpending(b64), BIO_flush(b64));
    n = BIO_get_mem_data(mem, &text);
    show(what, (unsigned char *)text, n);
    BIO_free_all(b64);
    return n;
}

/* Decodes `text` read in chunks of `chunk`, with `flags`, and prints the octets and returns. */
static int decode(const char *what, const char *text, int chunk, int flags)
{
    BIO *mem = BIO_new_mem_buf(text, -1), *b64 = BIO_new(BIO_f_base64());
    unsigned char out[4096];
    int total = 0, r;

    BIO_set_flags(b64, flags);
    BIO_push(b64, mem);
    printf("# %s (chunks of %d):", what, chunk);
    while ((r = BIO_read(b64, out + total, chunk)) > 0) {
        total += r;
        if (total > (int)sizeof(out) - chunk)
            break;
    }
    printf(" last %d, eof %d, retry %d\n", r, (int)BIO_eof(b64), BIO_should_retry(b64));
    show(what, out, total);
    BIO_free_all(b64);
    return total;
}

static void encoding(void)
{
    unsigned char data[5000];
    static const int sizes[] = { 0, 1, 2, 3, 47, 48, 49, 100, 5000 };
    size_t i;
    char what[64];
    BIO *mem, *b64;
    char *text;
    long n;

    for (i = 0; i < sizeof(data); i++)
        data[i] = (unsigned char)(i * 31 + 3);
    for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        snprintf(what, sizeof(what), "encode %d", sizes[i]);
        encode(what, data, sizes[i], 7, 0);
        snprintf(what, sizeof(what), "encode %d no newlines", sizes[i]);
        encode(what, data, sizes[i], 2, BIO_FLAGS_BASE64_NO_NL);
    }
    check(encode("one write", data, 100, 100, 0) == encode("bytewise", data, 100, 1, 0),
          "the encoding doesn't depend on the writes");
    check(encode("no-nl one write", data, 100, 100, BIO_FLAGS_BASE64_NO_NL)
              == encode("no-nl bytewise", data, 100, 1, BIO_FLAGS_BASE64_NO_NL),
          "nor without newlines");

    mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(BIO_new(BIO_f_base64()), mem);
    check(BIO_puts(b64, "hello") == 5 && BIO_flush(b64) == 1, "BIO_puts");
    n = BIO_get_mem_data(mem, &text);
    show("puts", (unsigned char *)text, n);
    check(BIO_method_type(b64) == BIO_TYPE_BASE64 && strcmp(BIO_method_name(b64), "base64 encoding") == 0,
          "type and name");
    BIO_free_all(b64);
}

static void decoding(void)
{
    char longline[3000];
    int chunk;

    memset(longline, 'x', 2000);
    strcpy(longline + 2000, "\naGVsbG8gd29ybGQ=\n");
    for (chunk = 1; chunk <= 1000; chunk *= 10) {
        decode("plain", "aGVsbG8gd29ybGQ=\n", chunk, 0);
        decode("header first", "-----BEGIN THING-----\nnot base64 here\naGVsbG8g\nd29ybGQ=\n-----END-----\n",
               chunk, 0);
        decode("crlf", "aGVs\r\nbG8g\r\nd29y\r\nbGQ=\r\n", chunk, 0);
        decode("no final newline", "aGVsbG8gd29ybGQ=", chunk, 0);
        decode("unpadded", "aGVsbG8gd29ybGQ\n", chunk, 0);
        decode("bad char later", "aGVsbG8g\nd2*ybGQ=\n", chunk, 0);
        decode("no newlines flag", "aGVsbG8gd29ybGQ=", chunk, BIO_FLAGS_BASE64_NO_NL);
        decode("long junk line first", longline, chunk, 0);
        decode("nothing decodes", "-----\njunk\n", chunk, 0);
        decode("empty", "", chunk, 0);
    }
    check(decode("check", "aGVsbG8gd29ybGQ=\n", 5, 0) == 11, "decodes \"hello world\"");
}

static void retries(void)
{
    BIO *mem = BIO_new(BIO_s_mem()), *b64 = BIO_new(BIO_f_base64());
    unsigned char out[64];
    int r;

    BIO_set_mem_eof_return(mem, -1);
    BIO_push(b64, mem);
    BIO_puts(mem, "aGVsbG8g");
    r = BIO_read(b64, out, sizeof(out));
    printf("# partial: %d retry %d\n", r, BIO_should_retry(b64));
    BIO_puts(mem, "\nd29ybGQ=\n");
    r = BIO_read(b64, out, sizeof(out));
    printf("# more: %d retry %d\n", r, BIO_should_retry(b64));
    show("retried", out, r > 0 ? r : 0);
    r = BIO_read(b64, out, sizeof(out));
    printf("# end: %d retry %d eof %d pending %ld\n", r, BIO_should_retry(b64), (int)BIO_eof(b64),
           (long)BIO_pending(b64));
    check(BIO_reset(b64) == 1 && BIO_eof(b64) == 1, "BIO_reset passes to the memory BIO");
    BIO_free_all(b64);

    b64 = BIO_new(BIO_f_base64());
    check(BIO_read(b64, out, 4) == 0 && BIO_write(b64, "x", 1) == 0 && BIO_flush(b64) == 0 && BIO_pending(b64) == 0,
          "without a next BIO, nothing happens");
    BIO_free(b64);
    ERR_clear_error();
}

int main(void)
{
    encoding();
    decoding();
    retries();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
