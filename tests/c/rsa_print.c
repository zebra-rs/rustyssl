/*
 * Conformance test for printing RSA keys (RSA_print(3), RSA_print_fp(3), EVP_PKEY_print_public(3),
 * EVP_PKEY_print_private(3) on legacy keys), in TAP format: private and public keys, small numbers
 * (decimal) and large ones (hex in columns), a negative number, missing numbers, a three-prime
 * key, offsets, an RSA-PSS key without parameter restrictions, and printing to a FILE.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* The error queue, emptied: each entry's library and reason. */
static void errors(void)
{
    unsigned long code;

    printf("  errors:");
    while ((code = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
    printf("\n");
}

static BIGNUM *num(const char *h)
{
    BIGNUM *b = NULL;

    BN_hex2bn(&b, h);
    return b;
}

/* Prints what a memory BIO holds, then empties it. */
static void dump(BIO *mem, int ret)
{
    char *text;
    long n = BIO_get_mem_data(mem, &text);

    printf("  ret %d, %ld bytes:\n%.*s", ret, n, (int)n, text);
    if (n > 0 && text[n - 1] != '\n')
        printf("\n");
    (void)BIO_reset(mem);
}

static RSA *private_key(void)
{
    RSA *r = RSA_new();

    RSA_set0_key(r,
                 num("C3A5F1E2D4B6978812345678ABCDEF0102030405060708090A0B0C0D0E0F1011"
                     "8899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF0011223344556677"),
                 num("010001"), num("7F00112233445566778899AABBCCDDEEFF0011223344556677"));
    RSA_set0_factors(r, num("E1F2A3B4C5D6E7F8091A2B3C4D5E6F71"),
                     num("DDEEFF00112233445566778899AABBCD"));
    RSA_set0_crt_params(r, num("0123456789ABCDEF"), num("80"), num("00"));
    return r;
}

int main(void)
{
    BIO *mem = BIO_new(BIO_s_mem());
    RSA *r = private_key(), *pub = RSA_new(), *empty = RSA_new(), *three = private_key();
    EVP_PKEY *pk;
    int ret;

    ret = RSA_print(mem, r, 0);
    check(ret == 1, "RSA_print: a private key");
    dump(mem, ret);
    ret = RSA_print(mem, r, 6);
    check(ret == 1, "RSA_print: indented 6");
    dump(mem, ret);
    ret = RSA_print(mem, r, 200);
    check(ret == 1, "RSA_print: indented past 128");
    dump(mem, ret);

    RSA_set0_key(pub, num("BADC0FFEE0DDF00D"), num("03"), NULL);
    ret = RSA_print(mem, pub, 2);
    check(ret == 1, "RSA_print: a public key (small numbers in decimal)");
    dump(mem, ret);
    {
        RSA *nd = RSA_new();

        RSA_set0_key(nd, num("BADC0FFEE0DDF00D1234"), num("03"), num("1234567890ABCDEF12"));
        ret = RSA_print(mem, nd, 0);
        check(ret == 1, "RSA_print: d without the factors");
        dump(mem, ret);
        RSA_free(nd);
    }
    ret = RSA_print(mem, empty, 0);
    check(ret == 1, "RSA_print: a key without numbers");
    dump(mem, ret);
    errors();

    {
        BIGNUM *ps[1], *es[1], *cs[1];

        ps[0] = num("F00DFACEF00DFACEF00DFACEF00DFACE11");
        es[0] = num("BEEF");
        cs[0] = num("FF");
        RSA_set0_multi_prime_params(three, ps, es, cs, 1);
    }
    ret = RSA_print(mem, three, 1);
    check(ret == 1, "RSA_print: a three-prime key");
    dump(mem, ret);

    {
        BIGNUM *n = num("123456789ABCDEF0123456789ABCDEF0");
        RSA *neg = RSA_new();

        BN_set_negative(n, 1);
        RSA_set0_key(neg, n, num("03"), NULL);
        ret = RSA_print(mem, neg, 0);
        check(ret == 1, "RSA_print: a negative modulus");
        dump(mem, ret);
        RSA_free(neg);
    }

    pk = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pk, r);
    ret = EVP_PKEY_print_public(mem, pk, 3, NULL);
    check(ret == 1, "EVP_PKEY_print_public: a legacy private key's public part");
    dump(mem, ret);
    ret = EVP_PKEY_print_private(mem, pk, 0, NULL);
    check(ret == 1, "EVP_PKEY_print_private: a legacy key");
    dump(mem, ret);
    ret = EVP_PKEY_print_params(mem, pk, 0, NULL);
    check(1, "EVP_PKEY_print_params: RSA has none");
    dump(mem, ret);
    errors();
    EVP_PKEY_free(pk);

    pk = EVP_PKEY_new();
    RSA_up_ref(r);
    check(EVP_PKEY_assign(pk, EVP_PKEY_RSA_PSS, r) == 1, "an RSA-PSS legacy key");
    ret = EVP_PKEY_print_private(mem, pk, 2, NULL);
    check(ret == 1, "EVP_PKEY_print_private: RSA-PSS, no restrictions");
    dump(mem, ret);
    ret = EVP_PKEY_print_public(mem, pk, 0, NULL);
    check(ret == 1, "EVP_PKEY_print_public: RSA-PSS");
    dump(mem, ret);
    EVP_PKEY_free(pk);

    {
        FILE *f = tmpfile();
        char buf[4096];
        size_t n;

        check(f != NULL && RSA_print_fp(f, pub, 4) == 1, "RSA_print_fp");
        if (f != NULL) {
            rewind(f);
            n = fread(buf, 1, sizeof(buf) - 1, f);
            buf[n] = '\0';
            printf("%s", buf);
            fclose(f);
        }
    }

    RSA_free(r);
    RSA_free(pub);
    RSA_free(empty);
    RSA_free(three);
    BIO_free(mem);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
