/*
 * Conformance test for COMP (COMP_CTX_new(3), BIO_f_zlib(3)): OpenSSL's default build has no
 * zlib, brotli, or zstd, so every method and compression BIO is NULL, no context can be made,
 * and the generic functions answer NULL arguments as documented.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>

#include <openssl/bio.h>
#include <openssl/comp.h>
#include <openssl/err.h>
#include <openssl/objects.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

int main(void)
{
    COMP_METHOD *methods[6];
    const char *names[] = { "zlib", "zlib one-shot", "brotli", "brotli one-shot", "zstd", "zstd one-shot" };
    COMP_CTX *ctx;
    unsigned char in[8] = "abcdefg", out[64];
    size_t i;

    setvbuf(stdout, NULL, _IONBF, 0);
    methods[0] = COMP_zlib();
    methods[1] = COMP_zlib_oneshot();
    methods[2] = COMP_brotli();
    methods[3] = COMP_brotli_oneshot();
    methods[4] = COMP_zstd();
    methods[5] = COMP_zstd_oneshot();
    for (i = 0; i < 6; i++) {
        printf("  %s: %s, type %d, name %s\n", names[i], methods[i] == NULL ? "none" : "available",
               COMP_get_type(methods[i]), COMP_get_name(methods[i]) == NULL ? "(null)" : COMP_get_name(methods[i]));
        check(methods[i] == NULL, names[i]);
    }
    check(BIO_f_zlib() == NULL && BIO_f_brotli() == NULL && BIO_f_zstd() == NULL, "no compression BIOs");
    check(COMP_get_type(NULL) == NID_undef && COMP_get_name(NULL) == NULL, "a NULL method");
    ctx = COMP_CTX_new(methods[0]);
    check(ctx == NULL, "no context without a method");
    if (ctx != NULL) {
        /* Never reached in the default build; the calls are what a method would get. */
        printf("  %d %d %d %d\n", COMP_CTX_get_type(ctx), COMP_get_type(COMP_CTX_get_method(ctx)),
               COMP_compress_block(ctx, out, (int)sizeof(out), in, (int)sizeof(in)),
               COMP_expand_block(ctx, in, (int)sizeof(in), out, (int)sizeof(out)));
    }
    COMP_CTX_free(ctx);
    COMP_CTX_free(NULL);
    check(ERR_peek_error() == 0, "no errors");
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
