/*
 * CVE regression checks for lengths near INT_MAX: the functions whose int lengths overflowed
 * when given about 2 GiB. Buffers that size are allocated but left untouched where the fixed
 * functions refuse the length before reading (the system maps them lazily), and written where
 * the function must do the work to find out (EVP_EncodeUpdate encodes about 1.6 GB before its
 * output passes INT_MAX). Each prints what both libraries must agree on: the result, the
 * reported length, and the error.
 */
#include "cve.h"

#include <limits.h>

/* A legacy (application-defined) block cipher that only copies: the overflow checks of
 * EVP_EncryptUpdate's legacy path run before it is called. */
static int copy_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in,
                       size_t inl)
{
    (void)ctx;
    memmove(out, in, inl);
    return 1;
}

static int no_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv,
                   int enc)
{
    (void)ctx, (void)key, (void)iv, (void)enc;
    return 1;
}

/* CVE-2021-23840 and CVE-2016-2106: a partial block buffered, then an update of nearly
 * INT_MAX octets, whose output length would overflow an int. */
static void cipher_update(void)
{
    EVP_CIPHER *c = EVP_CIPHER_meth_new(NID_undef, 16, 16);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[16] = {0}, first[16] = {0}, *in = malloc((size_t)INT_MAX);
    unsigned char *out = malloc((size_t)INT_MAX + 64);
    int outl = -1, r1, r2 = -1;

    EVP_CIPHER_meth_set_iv_length(c, 16);
    EVP_CIPHER_meth_set_init(c, no_init);
    EVP_CIPHER_meth_set_do_cipher(c, copy_cipher);
    if (in == NULL || out == NULL) {
        note("cipher update: no 2 GiB buffers");
        check(1, "CVE-2021-23840: # skip no 2 GiB of address space");
        check(1, "CVE-2016-2106: # skip no 2 GiB of address space");
        goto end;
    }
    r1 = EVP_EncryptInit_ex(ctx, c, NULL, key, key)
         && EVP_EncryptUpdate(ctx, out, &outl, first, 5);
    note("cipher update: 5 octets buffered: %d, out %d", r1, outl);
    outl = -1;
    if (r1)
        r2 = EVP_EncryptUpdate(ctx, out, &outl, in, INT_MAX);
    note("cipher update: then %d octets: %d, out %d", INT_MAX, r2, outl);
    errors("cipher update");
    check(r1 == 1 && r2 == 0, "CVE-2021-23840: an update whose output would pass INT_MAX "
          "fails instead of overflowing the output length");
    check(r1 == 1 && r2 == 0, "CVE-2016-2106: a buffered partial block plus nearly INT_MAX "
          "octets doesn't overflow the length check");
end:
    free(in);
    free(out);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_meth_free(c);
}

/* CVE-2016-2105: EVP_EncodeUpdate of 1.6 GB, whose base64 (4/3 of it, plus newlines) passes
 * INT_MAX. */
static void encode_update(void)
{
    enum { IN = 1600 * 1000 * 1000 };
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    unsigned char *in = calloc(1, (size_t)IN), *out = malloc((size_t)INT_MAX + 4096);
    int outl = -1, r = -1;

    if (in == NULL || out == NULL) {
        check(1, "CVE-2016-2105: # skip no 3.7 GB of address space");
        goto end;
    }
    EVP_EncodeInit(ctx);
    r = EVP_EncodeUpdate(ctx, out, &outl, in, IN);
    note("encode update of %d octets: %d, out %d", (int)IN, r, outl);
    errors("encode update");
    check(r == 0 && outl == 0, "CVE-2016-2105: base64 output past INT_MAX fails, reporting no "
          "length, instead of overflowing it");
end:
    free(in);
    free(out);
    EVP_ENCODE_CTX_free(ctx);
}

/* CVE-2016-0797: BN_hex2bn and BN_dec2bn on more than INT_MAX / 4 digits. */
static void bn_digits(void)
{
    size_t n = (size_t)INT_MAX / 4 + 2;
    char *digits = malloc(n + 1);
    BIGNUM *bn = NULL;
    int hex, dec;

    if (digits == NULL) {
        check(1, "CVE-2016-0797: # skip no 512 MiB");
        return;
    }
    memset(digits, '1', n);
    digits[n] = '\0';
    hex = BN_hex2bn(&bn, digits);
    note("BN_hex2bn on %zu digits: %d, %s", n, hex, bn == NULL ? "no number" : "a number");
    BN_free(bn);
    bn = NULL;
    dec = BN_dec2bn(&bn, digits);
    note("BN_dec2bn on %zu digits: %d, %s", n, dec, bn == NULL ? "no number" : "a number");
    BN_free(bn);
    errors("BN digits");
    check(hex == 0 && dec == 0, "CVE-2016-0797: BN_hex2bn and BN_dec2bn refuse more than "
          "INT_MAX / 4 digits instead of overflowing their length");
    free(digits);
}

int main(void)
{
    cipher_update();
    encode_update();
    bn_digits();
    return finish();
}
