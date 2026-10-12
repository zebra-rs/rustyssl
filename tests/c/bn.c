/*
 * Conformance test for BIGNUM (BN_new(3), BN_add(3), BN_add_word(3), BN_bn2bin(3), BN_cmp(3),
 * BN_copy(3), BN_CTX_new(3), BN_CTX_start(3), BN_num_bytes(3), BN_rand(3), BN_set_bit(3),
 * BN_swap(3), BN_zero(3), BN_security_bits(3), ASN1_INTEGER_get_int64(3)'s BN conversions,
 * OSSL_PARAM_BLD(3)'s pushes, OSSL_PARAM_allocate_from_text(3)), in TAP format: the numbers'
 * lifecycle and flags, their conversions (octets either way round and signed, text, MPIs, ASN.1
 * integers, printing), the arithmetic and its errors, BN_CTX's frames, random numbers from a
 * generator with known output, and the big-number parameters.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/rand.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* The queue's codes, oldest first, with any data. */
static void codes(void)
{
    unsigned long code;
    const char *data;
    int flags;

    printf("  errors:");
    while ((code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        if ((flags & ERR_TXT_STRING) != 0 && data != NULL && data[0] != '\0')
            printf(" [%s]", data);
    }
    printf("\n");
}

/* A number as hex and decimal text. */
static void show(const char *label, const BIGNUM *a)
{
    char *h = BN_bn2hex(a), *d = BN_bn2dec(a);

    printf("  %s: %s (%s) bits %d\n", label, h == NULL ? "(null)" : h, d == NULL ? "(null)" : d,
           BN_num_bits(a));
    OPENSSL_free(h);
    OPENSSL_free(d);
}

static void octets(const char *label, const unsigned char *p, int n)
{
    int i;

    printf("  %s (%d):", label, n);
    for (i = 0; i < n; i++)
        printf(" %02x", p[i]);
    printf("\n");
}

/* A new number from hex text. */
static BIGNUM *hexbn(const char *s)
{
    BIGNUM *b = NULL;

    BN_hex2bn(&b, s);
    return b;
}

/* ---------------------------------------------------------------------------------------- */

static void lifecycle(void)
{
    BIGNUM *a = BN_new(), *s = BN_secure_new(), *d, *w = BN_new();
    const BIGNUM *one = BN_value_one();

    check(a != NULL && BN_is_zero(a) && !BN_is_negative(a), "BN_new is zero");
    check(BN_get_flags(a, ~0) == BN_FLG_MALLOCED, "flagged malloced");
    check(BN_get_flags(s, ~0) == (BN_FLG_MALLOCED | BN_FLG_SECURE), "BN_secure_new is secure");
    check(BN_get_flags(one, ~0) == BN_FLG_STATIC_DATA && BN_is_one(one), "BN_value_one");
    check(BN_value_one() == one, "is one number");
    BN_free(NULL);
    BN_clear_free(NULL);
    BN_clear(NULL);

    check(BN_set_word(a, 0x1234) == 1 && BN_get_word(a) == 0x1234, "set and get a word");
    check(BN_is_word(a, 0x1234) && BN_abs_is_word(a, 0x1234) && !BN_is_word(a, 1), "is word");
    BN_set_negative(a, 1);
    check(BN_is_negative(a) && !BN_is_word(a, 0x1234) && BN_abs_is_word(a, 0x1234), "negative");
    check(BN_get_word(a) == 0x1234, "get word ignores the sign");
    BN_zero(w);
    BN_set_negative(w, 1);
    check(!BN_is_negative(w) && BN_is_word(w, 0) && BN_abs_is_word(w, 0), "zero isn't negative");
    check(BN_is_odd(one) && !BN_is_odd(a) && !BN_is_odd(w), "odd");
    check(BN_num_bits(a) == 13 && BN_num_bits(w) == 0 && BN_num_bytes(a) == 2, "num bits");
    check(BN_num_bits_word(0) == 0 && BN_num_bits_word(1) == 1
              && BN_num_bits_word(~0UL) == 64 && BN_num_bits_word(0x80000000UL) == 32,
          "num bits of a word");

    d = BN_dup(a);
    check(d != NULL && BN_cmp(a, d) == 0 && BN_get_flags(d, ~0) == BN_FLG_MALLOCED, "BN_dup");
    BN_free(d);
    check(BN_dup(NULL) == NULL, "BN_dup(NULL)");
    d = BN_dup(s);
    check(BN_get_flags(d, BN_FLG_SECURE) == BN_FLG_SECURE, "a secure number's dup is secure");
    BN_free(d);
    check(BN_copy(a, a) == a, "BN_copy to itself");
    check(BN_copy(w, a) == w && BN_cmp(w, a) == 0, "BN_copy");
    BN_clear(w);
    check(BN_is_zero(w), "BN_clear");
    BN_one(w);
    check(BN_is_one(w), "BN_one");
    BN_zero_ex(w);
    check(BN_is_zero(w), "BN_zero_ex");

    /* Flags travel with the digits in BN_swap; MALLOCED stays. */
    BN_set_word(w, 5);
    BN_set_flags(s, BN_FLG_CONSTTIME);
    BN_swap(w, s);
    check(BN_is_word(s, 5) && BN_is_zero(w), "BN_swap");
    printf("  flags after swap: %x %x\n", BN_get_flags(w, ~0), BN_get_flags(s, ~0));
    BN_set_flags(w, 0x100);
    check(BN_get_flags(w, 0x100) == 0x100, "BN_set_flags adds");

    /* BN_with_flags: a static copy. */
    d = BN_new();
    BN_with_flags(d, a, BN_FLG_CONSTTIME);
    check(BN_cmp(d, a) == 0, "BN_with_flags copies");
    printf("  with flags: %x\n", BN_get_flags(d, ~0));
    BN_free(d);

    /* BN_consttime_swap: values and CONSTTIME, when told to. */
    BN_set_word(a, 7);
    BN_set_word(w, 9);
    BN_set_flags(a, BN_FLG_CONSTTIME);
    /* Both must have room for nwords words, which OpenSSL doesn't check. */
    BN_consttime_swap(0, a, w, 1);
    check(BN_is_word(a, 7) && BN_is_word(w, 9), "consttime swap (no)");
    BN_consttime_swap(1, a, w, 1);
    check(BN_is_word(a, 9) && BN_is_word(w, 7), "consttime swap (yes)");
    printf("  consttime flags: %x %x\n", BN_get_flags(a, ~0), BN_get_flags(w, ~0));

    BN_free(a);
    BN_clear_free(s);
    BN_free(w);
    codes();
}

/* ---------------------------------------------------------------------------------------- */

static void conversions(void)
{
    static const unsigned char be[] = {0x00, 0x00, 0x01, 0x02, 0x03};
    static const unsigned char neg129[] = {0xff, 0x7f};
    static const unsigned char ffs[] = {0xff, 0xff, 0xff};
    static const unsigned char top80[] = {0x80};
    static const unsigned char top0080[] = {0x00, 0x80};
    static const unsigned char mpi_bad[] = {0x00, 0x00, 0x00, 0x02, 0x01};
    static const unsigned char mpi_neg[] = {0x00, 0x00, 0x00, 0x02, 0x80, 0x81};
    unsigned char buf[32];
    BIGNUM *a, *b = BN_new(), *r;
    char *s;
    int n;
    long values[] = {0, 1, -1, 127, 128, -128, -129, 255, -255, 256, -256, 0x7fff, -0x8000, -0x8001};
    size_t i;

    a = BN_bin2bn(be, sizeof(be), NULL);
    show("bin2bn", a);
    check(BN_bin2bn(be, 0, a) == a && BN_is_zero(a), "no octets are zero");
    check(BN_bin2bn(be, -1, a) == NULL, "a negative length fails");
    BN_lebin2bn(be, sizeof(be), a);
    show("lebin2bn", a);
    BN_native2bn(be, sizeof(be), a);
    show("native2bn", a);
    BN_signed_bin2bn(neg129, sizeof(neg129), a);
    show("signed ff7f", a);
    BN_signed_bin2bn(ffs, sizeof(ffs), a);
    show("signed ffffff", a);
    BN_signed_bin2bn(top80, sizeof(top80), a);
    show("signed 80", a);
    BN_signed_bin2bn(top0080, sizeof(top0080), a);
    show("signed 0080", a);
    BN_signed_lebin2bn(neg129, sizeof(neg129), a);
    show("signed le ff7f", a);
    BN_signed_native2bn(top80, sizeof(top80), a);
    show("signed native 80", a);

    /* Each value, out every way. */
    for (i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        char label[32];

        BN_set_word(a, (BN_ULONG)labs(values[i]));
        BN_set_negative(a, values[i] < 0);
        printf("  %ld:\n", values[i]);
        n = BN_bn2bin(a, buf);
        octets("bn2bin", buf, n);
        n = BN_signed_bn2bin(a, buf, -1);
        snprintf(label, sizeof(label), "signed exact");
        printf("  signed -1: %d\n", n);
        n = BN_signed_bn2bin(a, buf, 0);
        printf("  signed 0: %d\n", n);
        n = BN_signed_bn2bin(a, buf, 1);
        octets("signed 1", buf, n < 0 ? 0 : n);
        n = BN_signed_bn2bin(a, buf, 3);
        octets(label, buf, n < 0 ? 0 : n);
        n = BN_signed_bn2lebin(a, buf, 3);
        octets("signed le 3", buf, n < 0 ? 0 : n);
        n = BN_signed_bn2native(a, buf, 2);
        octets("signed native 2", buf, n < 0 ? 0 : n);
        n = BN_bn2binpad(a, buf, 4);
        octets("binpad 4", buf, n < 0 ? 0 : n);
        n = BN_bn2lebinpad(a, buf, 3);
        octets("lebinpad 3", buf, n < 0 ? 0 : n);
        n = BN_bn2nativepad(a, buf, 2);
        octets("nativepad 2", buf, n < 0 ? 0 : n);
        n = BN_bn2mpi(a, NULL);
        check(BN_bn2mpi(a, buf) == n, "mpi length");
        octets("mpi", buf, n);
        r = BN_mpi2bn(buf, n, NULL);
        check(r != NULL && BN_cmp(r, a) == 0, "mpi round trip");
        BN_free(r);
    }
    check(BN_bn2binpad(a, buf, -1) == -1 && BN_bn2lebinpad(a, buf, -2) == -1
              && BN_bn2nativepad(a, buf, -1) == -1 && BN_signed_bn2bin(a, buf, -2) == -1
              && BN_signed_bn2lebin(a, buf, -2) == -1 && BN_signed_bn2native(a, buf, -2) == -1,
          "negative lengths fail");

    /* Text. */
    BN_free(a);
    a = hexbn("-00000123456789ABCDEFabcdef0123456789");
    show("hex2bn", a);
    s = BN_bn2hex(a);
    printf("  bn2hex: %s\n", s);
    OPENSSL_free(s);
    BN_set_word(a, 10);
    s = BN_bn2hex(a);
    printf("  bn2hex 10: %s\n", s);
    OPENSSL_free(s);
    BN_zero(a);
    s = BN_bn2hex(a);
    printf("  bn2hex 0: %s\n", s);
    OPENSSL_free(s);
    r = NULL;
    printf("  hex2bn counts: %d %d %d %d %d\n", BN_hex2bn(NULL, "12xyz"), BN_hex2bn(NULL, "-ff "),
           BN_hex2bn(NULL, ""), BN_hex2bn(NULL, "-"), BN_hex2bn(NULL, NULL));
    printf("  hex2bn -0: %d\n", BN_hex2bn(&r, "-0"));
    show("-0", r);
    printf("  dec2bn: %d\n", BN_dec2bn(&r, "-123456789012345678901234567890xyz"));
    show("dec2bn", r);
    printf("  dec2bn counts: %d %d %d\n", BN_dec2bn(NULL, "007"), BN_dec2bn(&r, "x"),
           BN_dec2bn(&r, "-"));
    show("after failed dec2bn", r);
    printf("  dec2bn leading zeros: %d\n", BN_dec2bn(&r, "0000000000000000000000000000042"));
    show("leading zeros", r);
    printf("  asc2bn: %d", BN_asc2bn(&r, "0x1F"));
    show("", r);
    printf("  asc2bn: %d", BN_asc2bn(&r, "-0X1f"));
    show("", r);
    printf("  asc2bn: %d", BN_asc2bn(&r, "-42"));
    show("", r);
    printf("  asc2bn: %d", BN_asc2bn(&r, "-0x-5"));
    show("", r);
    printf("  asc2bn: %d", BN_asc2bn(&r, "--5"));
    show("", r);
    printf("  asc2bn: %d", BN_asc2bn(&r, "0x"));
    show("", r);
    BN_set_word(r, 1);
    BN_lshift(r, r, 200);
    BN_sub_word(r, 1);
    s = BN_bn2dec(r);
    printf("  bn2dec 2^200-1: %s\n", s);
    OPENSSL_free(s);
    BN_set_negative(r, 1);
    s = BN_bn2dec(r);
    printf("  bn2dec negative: %s\n", s);
    OPENSSL_free(s);
    check(BN_hex2bn((BIGNUM **)&(const BIGNUM *){BN_value_one()}, "5") == 0, "hex2bn refuses static data");
    codes();

    /* MPIs. */
    check(BN_mpi2bn(buf, 3, NULL) == NULL, "a short MPI fails");
    codes();
    check(BN_mpi2bn(mpi_bad, sizeof(mpi_bad), NULL) == NULL, "an MPI of the wrong length fails");
    codes();
    buf[0] = 0x80;
    check(BN_mpi2bn(buf, 4, NULL) == NULL, "an MPI with the top bit set fails");
    codes();
    r = BN_mpi2bn(mpi_neg, sizeof(mpi_neg), r);
    show("mpi -0x81", r);

    /* Printing. */
    {
        BIO *out = BIO_new_fp(stdout, BIO_NOCLOSE);

        BN_set_word(b, 0x0a0b);
        BN_set_negative(b, 1);
        printf("  print: ");
        fflush(stdout);
        n = BN_print(out, b);
        (void)BIO_flush(out);
        printf("\n");
        check(n == 1, "BN_print");
        printf("  print zero: ");
        fflush(stdout);
        BN_zero(b);
        BN_print(out, b);
        (void)BIO_flush(out);
        printf("\n  print_fp: ");
        fflush(stdout);
        BN_set_word(b, 0xfedcba);
        n = BN_print_fp(stdout, b);
        fflush(stdout);
        printf("\n");
        check(n == 1, "BN_print_fp");
        BIO_free(out);
    }

    BN_free(a);
    BN_free(b);
    BN_free(r);
    codes();
}

/* ---------------------------------------------------------------------------------------- */

static void asn1(void)
{
    BIGNUM *a = hexbn("-0102030405060708090A"), *b = NULL;
    ASN1_INTEGER *ai = BN_to_ASN1_INTEGER(a, NULL);
    ASN1_ENUMERATED *ae;
    BIO *out = BIO_new_fp(stdout, BIO_NOCLOSE);
    unsigned char ign[1];

    check(ai != NULL && ai->type == V_ASN1_NEG_INTEGER && ai->length == 10, "BN_to_ASN1_INTEGER");
    b = ASN1_INTEGER_to_BN(ai, NULL);
    check(b != NULL && BN_cmp(a, b) == 0, "ASN1_INTEGER_to_BN");
    BN_zero(a);
    check(BN_to_ASN1_INTEGER(a, ai) == ai && ai->type == V_ASN1_INTEGER && ai->length == 1
              && ai->data[0] == 0,
          "zero is one octet");
    ae = BN_to_ASN1_ENUMERATED(b, NULL);
    check(ae != NULL && ae->type == V_ASN1_NEG_ENUMERATED, "BN_to_ASN1_ENUMERATED");
    check(ASN1_INTEGER_to_BN(ae, b) == NULL, "an ENUMERATED isn't an INTEGER");
    codes();
    check(ASN1_ENUMERATED_to_BN(ae, b) == b, "ASN1_ENUMERATED_to_BN");
    show("enumerated", b);
    check(BN_to_ASN1_ENUMERATED(b, ai) == ai && ai->type == V_ASN1_NEG_ENUMERATED,
          "an INTEGER's type is reset");

    printf("  ASN1_bn_print:\n");
    fflush(stdout);
    check(ASN1_bn_print(out, "zero:", a, ign, 2) == 1, "zero");
    BN_set_word(a, 0x1234);
    ASN1_bn_print(out, "small:", a, ign, 2);
    BN_set_negative(a, 1);
    ASN1_bn_print(out, "negative:", a, ign, 0);
    ASN1_bn_print(out, "large:", b, ign, 4);
    BN_set_negative(b, 0);
    BN_set_bit(b, 255);
    ASN1_bn_print(out, "top bit:", b, ign, 1);
    check(ASN1_bn_print(out, "none:", NULL, ign, 1) == 1, "NULL prints nothing");
    (void)BIO_flush(out);

    BIO_free(out);
    ASN1_INTEGER_free(ai);
    ASN1_ENUMERATED_free(ae);
    BN_free(a);
    BN_free(b);
    codes();
}

/* ---------------------------------------------------------------------------------------- */

static void arithmetic(void)
{
    static const char *const values[] = {
        "0", "1", "-1", "FFFFFFFFFFFFFFFF", "-10000000000000000", "123456789ABCDEF0123456789",
        "-FEDCBA9876543210FEDCBA98765432100123456789",
        "100000000000000000000000000000000000000000000000000000000000000000000001",
    };
    const size_t nv = sizeof(values) / sizeof(values[0]);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *r = BN_new(), *q = BN_new(), *a, *b;
    size_t i, j;
    char label[64];
    BN_ULONG w;

    for (i = 0; i < nv; i++) {
        for (j = 0; j < nv; j++) {
            a = hexbn(values[i]);
            b = hexbn(values[j]);
            printf("  %s, %s\n", values[i], values[j]);
            BN_add(r, a, b);
            show("add", r);
            BN_sub(r, a, b);
            show("sub", r);
            BN_uadd(r, a, b);
            show("uadd", r);
            if (BN_usub(r, a, b))
                show("usub", r);
            else
                codes();
            BN_mul(r, a, b, ctx);
            show("mul", r);
            if (BN_div(q, r, a, b, ctx)) {
                show("div", q);
                show("rem", r);
                BN_nnmod(r, a, b, ctx);
                show("nnmod", r);
            } else {
                codes();
            }
            BN_free(a);
            BN_free(b);
        }
        a = hexbn(values[i]);
        BN_sqr(r, a, ctx);
        show("sqr", r);
        BN_lshift(r, a, 67);
        show("lshift 67", r);
        BN_rshift(r, a, 3);
        show("rshift 3", r);
        BN_rshift(r, a, 200);
        show("rshift 200", r);
        BN_lshift1(r, a);
        show("lshift1", r);
        BN_rshift1(r, a);
        show("rshift1", r);
        BN_copy(r, a);
        BN_add_word(r, 0xffffffffffffffffUL);
        show("add_word", r);
        BN_copy(r, a);
        BN_sub_word(r, 2);
        show("sub_word", r);
        BN_copy(r, a);
        BN_mul_word(r, 0x100000001UL);
        show("mul_word", r);
        BN_copy(r, a);
        w = BN_div_word(r, 7);
        snprintf(label, sizeof(label), "div_word (rem %lu)", (unsigned long)w);
        show(label, r);
        printf("  mod_word %lu\n", (unsigned long)BN_mod_word(a, 1000000007UL));
        printf("  cmp with 1: %d ucmp %d\n", BN_cmp(a, BN_value_one()), BN_ucmp(a, BN_value_one()));
        BN_free(a);
    }

    /* In place. */
    a = hexbn("-12345");
    BN_add(a, a, a);
    show("a + a in place", a);
    BN_mul(a, a, a, ctx);
    show("a * a in place", a);
    BN_div(a, NULL, a, BN_value_one(), ctx);
    show("a / 1 in place", a);
    check(BN_div(NULL, NULL, a, a, ctx) == 1, "BN_div with nowhere to put the results");

    /* Errors. */
    BN_zero(r);
    check(BN_div(q, NULL, a, r, ctx) == 0, "division by zero");
    codes();
    check(BN_nnmod(q, a, r, ctx) == 0, "nnmod by zero");
    codes();
    check(BN_lshift(r, a, -1) == 0 && BN_rshift(r, a, -1) == 0, "negative shifts");
    codes();
    check(BN_div_word(a, 0) == (BN_ULONG)-1 && BN_mod_word(a, 0) == (BN_ULONG)-1, "word division by zero");
    show("unchanged", a);
    b = hexbn("10000000000000000");
    BN_set_word(q, 1);
    check(BN_usub(r, q, b) == 0, "usub of a longer number");
    codes();
    BN_set_word(q, 2);
    check(BN_usub(r, BN_value_one(), q) == 1, "usub of a larger number of the same length wraps");
    show("wrapped", r);

    /* Powers. */
    BN_set_word(a, 3);
    BN_set_word(b, 100);
    check(BN_exp(r, a, b, ctx) == 1, "BN_exp");
    show("3^100", r);
    BN_set_negative(a, 1);
    BN_set_word(b, 5);
    BN_exp(r, a, b, ctx);
    show("-3^5", r);
    BN_set_negative(b, 1);
    BN_exp(r, a, b, ctx);
    show("-3^-5", r);
    BN_zero(b);
    BN_exp(a, a, b, ctx);
    show("x^0 in place", a);
    BN_set_flags(b, BN_FLG_CONSTTIME);
    check(BN_exp(r, a, b, ctx) == 0, "BN_exp refuses CONSTTIME");
    codes();

    BN_free(a);
    BN_free(b);
    BN_free(q);
    BN_free(r);
    BN_CTX_free(ctx);
}

/* ---------------------------------------------------------------------------------------- */

static void bits(void)
{
    BIGNUM *a = BN_new();
    BIGNUM *b;

    check(BN_set_bit(a, 130) == 1 && BN_num_bits(a) == 131, "set bit 130");
    check(BN_is_bit_set(a, 130) && !BN_is_bit_set(a, 129) && !BN_is_bit_set(a, 1000)
              && !BN_is_bit_set(a, -1),
          "is bit set");
    check(BN_set_bit(a, -1) == 0 && BN_clear_bit(a, -1) == 0, "negative bits fail");
    check(BN_clear_bit(a, 200) == 0, "clearing past the top fails");
    check(BN_clear_bit(a, 3) == 1, "clearing a clear bit");
    check(BN_clear_bit(a, 130) == 1 && BN_is_zero(a), "clearing the top bit");
    b = hexbn("-FFFFFFFFFFFFFFFFFF");
    check(BN_mask_bits(b, 128) == 0, "masking past the top word fails");
    check(BN_mask_bits(b, 70) == 1, "mask 70");
    show("masked", b);
    check(BN_mask_bits(b, 64) == 1, "mask 64");
    show("masked", b);
    check(BN_mask_bits(b, -1) == 0, "a negative mask fails");
    check(BN_mask_bits(b, 0) == 1 && BN_is_zero(b) && !BN_is_negative(b), "mask 0");
    BN_set_word(a, 6);
    BN_set_negative(a, 1);
    check(BN_set_bit(a, 0) == 1, "set bit of a negative number");
    show("bit set", a);

    printf("  cmp: %d %d %d %d %d %d\n", BN_cmp(a, b), BN_cmp(b, a), BN_cmp(a, a), BN_cmp(NULL, a),
           BN_cmp(a, NULL), BN_cmp(NULL, NULL));
    printf("  ucmp: %d %d %d\n", BN_ucmp(a, b), BN_ucmp(b, a), BN_ucmp(a, a));
    BN_free(a);
    BN_free(b);
    codes();
}

/* ---------------------------------------------------------------------------------------- */

static void contexts(void)
{
    BN_CTX *ctx = BN_CTX_new(), *sctx = BN_CTX_secure_new(), *ectx = BN_CTX_new_ex(NULL);
    BN_CTX *sectx = BN_CTX_secure_new_ex(NULL);
    BIGNUM *a, *b, *c, *x;
    int i;

    check(ctx != NULL && sctx != NULL && ectx != NULL && sectx != NULL, "BN_CTX_new");
    BN_CTX_start(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    check(a != NULL && b != NULL && a != b && BN_is_zero(a), "BN_CTX_get");
    check(BN_get_flags(a, ~0) == 0, "a context's numbers have no flags");
    BN_set_word(a, 5);
    BN_set_flags(a, BN_FLG_CONSTTIME);
    BN_CTX_start(ctx);
    c = BN_CTX_get(ctx);
    check(c != a && c != b, "a nested frame's number is another");
    BN_CTX_end(ctx);
    BN_CTX_end(ctx);
    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx);
    check(x == a && BN_is_zero(x) && BN_get_flags(x, BN_FLG_CONSTTIME) == 0,
          "numbers come back zeroed, without CONSTTIME");
    check(BN_CTX_get(ctx) == b && BN_CTX_get(ctx) == c, "in order");
    for (i = 0; i < 40; i++)
        check(BN_CTX_get(ctx) != NULL, "many numbers");
    BN_CTX_end(ctx);

    BN_CTX_start(sctx);
    a = BN_CTX_get(sctx);
    check(BN_get_flags(a, ~0) == BN_FLG_SECURE, "a secure context's numbers are secure");
    BN_CTX_end(sctx);

    BN_CTX_free(ctx);
    BN_CTX_free(sctx);
    BN_CTX_free(ectx);
    BN_CTX_free(sectx);
    BN_CTX_free(NULL);
    codes();
}

/* ---------------------------------------------------------------------------------------- */

/* A CTR-DRBG under a TEST-RAND parent with known entropy and nonce. */
static EVP_RAND_CTX *known_drbg(unsigned char seed)
{
    EVP_RAND *rand = EVP_RAND_fetch(NULL, "TEST-RAND", NULL);
    EVP_RAND_CTX *parent = EVP_RAND_CTX_new(rand, NULL), *ctx;
    unsigned char entropy[64], nonce[32];
    unsigned int strength = 256;
    OSSL_PARAM params[4];

    EVP_RAND_free(rand);
    memset(entropy, seed, sizeof(entropy));
    memset(nonce, seed ^ 0x5a, sizeof(nonce));
    params[0] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, &strength);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY, entropy, sizeof(entropy));
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_NONCE, nonce, sizeof(nonce));
    params[3] = OSSL_PARAM_construct_end();
    EVP_RAND_instantiate(parent, 256, 0, NULL, 0, params);
    rand = EVP_RAND_fetch(NULL, "CTR-DRBG", NULL);
    ctx = EVP_RAND_CTX_new(rand, parent);
    EVP_RAND_free(rand);
    EVP_RAND_CTX_free(parent);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, "AES-256-CTR", 0);
    params[1] = OSSL_PARAM_construct_end();
    if (!EVP_RAND_instantiate(ctx, 256, 0, NULL, 0, params)) {
        EVP_RAND_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

static void random_numbers(void)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *r = BN_new(), *range = BN_new();
    int bits[] = {1, 2, 7, 8, 9, 16, 63, 64, 65, 200};
    size_t i;

    check(RAND_set0_public(NULL, known_drbg(3)) == 1 && RAND_set0_private(NULL, known_drbg(4)) == 1,
          "known generators");
    for (i = 0; i < sizeof(bits) / sizeof(bits[0]); i++) {
        printf("  %d bits:\n", bits[i]);
        check(BN_rand(r, bits[i], BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) == 1, "BN_rand");
        show("any", r);
        BN_rand(r, bits[i], BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
        show("top one, odd", r);
        if (bits[i] > 1) {
            BN_rand(r, bits[i], BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ANY);
            show("top two", r);
        }
        BN_priv_rand(r, bits[i], BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
        show("private", r);
        BN_pseudo_rand(r, bits[i], BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD);
        show("pseudo", r);
        BN_bntest_rand(r, bits[i], BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
        show("bntest", r);
        BN_rand_ex(r, bits[i], BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY, 128, ctx);
        show("ex", r);
        BN_priv_rand_ex(r, bits[i], BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, 0, ctx);
        show("private ex", r);
    }
    check(BN_rand(r, 0, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) == 1 && BN_is_zero(r), "0 bits");
    check(BN_rand(r, 0, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) == 0, "0 bits with a top bit");
    codes();
    check(BN_rand(r, 0, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD) == 0, "0 bits, odd");
    codes();
    check(BN_rand(r, 1, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ANY) == 0, "1 bit, top two");
    codes();
    check(BN_rand(r, -1, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) == 0, "negative bits");
    codes();

    /* Ranges: 100... (three times the range is a bit longer) and others. */
    {
        static const char *const ranges[] = {"1", "2", "3", "8", "9", "C", "1000000000000000000000",
                                             "1FFFFFFFFFFFFFFFFFFFFF", "1234567"};

        for (i = 0; i < sizeof(ranges) / sizeof(ranges[0]); i++) {
            BN_hex2bn(&range, ranges[i]);
            printf("  range %s:\n", ranges[i]);
            check(BN_rand_range(r, range) == 1 && BN_cmp(r, range) < 0, "BN_rand_range");
            show("in range", r);
            BN_priv_rand_range(r, range);
            show("private", r);
            BN_pseudo_rand_range(r, range);
            show("pseudo", r);
            BN_rand_range_ex(r, range, 0, ctx);
            show("ex", r);
            BN_priv_rand_range_ex(r, range, 0, ctx);
            show("private ex", r);
        }
    }
    BN_zero(range);
    check(BN_rand_range(r, range) == 0, "an empty range fails");
    codes();
    BN_set_word(range, 5);
    BN_set_negative(range, 1);
    check(BN_rand_range(r, range) == 0, "a negative range fails");
    codes();
    check(BN_rand_range(NULL, range) == 0, "no result fails");
    codes();

    RAND_set0_public(NULL, NULL);
    RAND_set0_private(NULL, NULL);
    BN_free(r);
    BN_free(range);
    BN_CTX_free(ctx);
}

/* ---------------------------------------------------------------------------------------- */

static void misc(void)
{
    int l[] = {0, 1023, 1024, 2048, 3072, 7680, 15360, 20000};
    int n[] = {-1, 0, 159, 160, 223, 224, 256, 512};
    size_t i, j;

    printf("  security bits:");
    for (i = 0; i < sizeof(l) / sizeof(l[0]); i++)
        for (j = 0; j < sizeof(n) / sizeof(n[0]); j++)
            printf(" %d", BN_security_bits(l[i], n[j]));
    printf("\n");
    printf("  options: %s\n", BN_options());
    BN_set_params(3, 40, -1, 5);
    printf("  params: %d %d %d %d %d\n", BN_get_params(0), BN_get_params(1), BN_get_params(2),
           BN_get_params(3), BN_get_params(4));
    BN_set_params(0, 0, 0, 0);
    codes();
}

/* ---------------------------------------------------------------------------------------- */

static void param_octets(const char *label, const OSSL_PARAM *p)
{
    printf("  %s: type %u size %zu return %zu", label, p->data_type, p->data_size, p->return_size);
    if (p->data != NULL) {
        size_t i;

        printf(" data");
        for (i = 0; i < p->data_size; i++)
            printf(" %02x", ((unsigned char *)p->data)[i]);
    }
    printf("\n");
}

static void params(void)
{
    unsigned char buf[16];
    long lv = -5;
    BIGNUM *a = hexbn("-0102"), *b = NULL, *big = hexbn("123456789ABCDEF0123");
    OSSL_PARAM p[2], *out;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    int found;
    char text[16] = "hello";
    double dv = 2.5;
    static const OSSL_PARAM defs[] = {
        OSSL_PARAM_int("int", NULL),
        OSSL_PARAM_uint("uint", NULL),
        OSSL_PARAM_BN("bn", NULL, 0),
        OSSL_PARAM_DEFN("sbig", OSSL_PARAM_INTEGER, NULL, 0),
        OSSL_PARAM_utf8_string("str", NULL, 0),
        OSSL_PARAM_octet_string("oct", NULL, 0),
        OSSL_PARAM_double("real", NULL),
        OSSL_PARAM_END,
    };
    static const char *const tests[][2] = {
        {"int", "-1"}, {"int", "127"}, {"int", "128"}, {"int", "-129"}, {"int", "0x7fffffff"},
        {"int", "0x80000000"}, {"int", "-2147483648"}, {"uint", "4294967295"}, {"uint", "-1"},
        {"hexint", "ff"}, {"hexuint", "-ff"}, {"bn", "0"}, {"bn", "123456789012345678901234567890"},
        {"bn", "-1"}, {"sbig", "-1"}, {"sbig", "0"}, {"sbig", "-128"}, {"sbig", "255"},
        {"str", "text"}, {"hexstr", "74"}, {"oct", "raw"}, {"hexoct", "01:02"}, {"hexoct", "0102AB"},
        {"hexoct", "zz"}, {"real", "1.5"}, {"missing", "1"}, {"bn", "x"},
    };
    size_t i;

    /* get and set */
    memset(buf, 0, sizeof(buf));
    p[0] = OSSL_PARAM_construct_BN("n", buf, sizeof(buf));
    p[1] = OSSL_PARAM_construct_end();
    check(OSSL_PARAM_set_BN(p, a) == 0, "an unsigned parameter can't take a negative number");
    codes();
    p[0].data_type = OSSL_PARAM_INTEGER;
    check(OSSL_PARAM_set_BN(p, a) == 1, "set a negative number");
    param_octets("signed -0102", p);
    check(OSSL_PARAM_get_BN(p, &b) == 1, "get it back");
    show("got", b);
    p[0].data_size = 2;
    check(OSSL_PARAM_set_BN(p, a) == 0, "too small");
    param_octets("too small", p);
    codes();
    p[0].data = NULL;
    check(OSSL_PARAM_set_BN(p, a) == 1, "the size it needs");
    param_octets("no data", p);
    p[0] = OSSL_PARAM_construct_BN("n", buf, 3);
    BN_set_word(b, 0);
    check(OSSL_PARAM_set_BN(p, b) == 1, "zero");
    param_octets("zero", p);
    BN_set_word(b, 0x8081);
    BN_set_negative(b, 1);
    p[0].data_type = OSSL_PARAM_INTEGER;
    check(OSSL_PARAM_set_BN(p, b) == 1, "-0x8081 in 3 octets");
    param_octets("-0x8081", p);
    p[0].data_type = OSSL_PARAM_UTF8_STRING;
    check(OSSL_PARAM_set_BN(p, b) == 0 && OSSL_PARAM_get_BN(p, &b) == 0, "a string isn't a number");
    codes();
    check(OSSL_PARAM_set_BN(NULL, b) == 0 && OSSL_PARAM_set_BN(p, NULL) == 0
              && OSSL_PARAM_get_BN(NULL, &b) == 0 && OSSL_PARAM_get_BN(p, NULL) == 0,
          "NULL arguments");
    codes();
    p[0] = OSSL_PARAM_construct_long("l", &lv);
    BN_free(b);
    b = NULL;
    check(OSSL_PARAM_get_BN(p, &b) == 1, "a long as a number");
    show("long", b);

    /* The builder: numbers are read when the array is made. */
    check(OSSL_PARAM_BLD_push_BN(bld, "neg", a) == 1, "push a negative number");
    check(OSSL_PARAM_BLD_push_BN(bld, "big", big) == 1, "push a number");
    check(OSSL_PARAM_BLD_push_BN(bld, "none", NULL) == 1, "push NULL");
    check(OSSL_PARAM_BLD_push_BN_pad(bld, "pad", big, 12) == 1, "push padded");
    check(OSSL_PARAM_BLD_push_BN_pad(bld, "negpad", a, 1) == 1, "push a negative number padded");
    check(OSSL_PARAM_BLD_push_BN_pad(bld, "short", big, 4) == 0, "too short a pad");
    codes();
    check(OSSL_PARAM_BLD_push_BN(NULL, "x", a) == 0 && OSSL_PARAM_BLD_push_BN(bld, NULL, a) == 0
              && OSSL_PARAM_BLD_push_BN_pad(NULL, "x", a, 4) == 0,
          "NULL builder or key");
    codes();
    BN_set_word(big, 0x77);
    out = OSSL_PARAM_BLD_to_param(bld);
    check(out != NULL, "to_param");
    for (i = 0; out != NULL && out[i].key != NULL; i++)
        param_octets(out[i].key, &out[i]);
    OSSL_PARAM_free(out);
    BN_set_negative(big, 1);
    check(OSSL_PARAM_BLD_push_BN_pad(bld, "neg", big, 8) == 1, "a negative number padded");
    BN_set_negative(big, 0);
    out = OSSL_PARAM_BLD_to_param(bld);
    param_octets("changed sign", out);
    OSSL_PARAM_free(out);
    BN_set_negative(big, 1);
    check(OSSL_PARAM_BLD_push_BN_pad(bld, "u", NULL, 4) == 1, "NULL padded");
    out = OSSL_PARAM_BLD_to_param(bld);
    param_octets("NULL padded", out);
    OSSL_PARAM_free(out);

    /* From text. */
    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        OSSL_PARAM to;
        int r;

        found = -1;
        r = OSSL_PARAM_allocate_from_text(&to, defs, tests[i][0], tests[i][1], strlen(tests[i][1]),
                                          &found);
        printf("  %s=%s: %d found %d\n", tests[i][0], tests[i][1], r, found);
        if (r) {
            param_octets(to.key, &to);
            OPENSSL_free(to.data);
        }
        codes();
    }
    {
        OSSL_PARAM sized[] = {OSSL_PARAM_DEFN("s", OSSL_PARAM_INTEGER, NULL, 2), OSSL_PARAM_END};
        OSSL_PARAM to;

        printf("  sized: %d %d", OSSL_PARAM_allocate_from_text(&to, sized, "s", "-32768", 6, NULL),
               OSSL_PARAM_allocate_from_text(&to, sized, "s", "32768", 5, NULL));
        printf("\n");
        codes();
        check(OSSL_PARAM_allocate_from_text(NULL, sized, "s", "1", 1, NULL) == 0
                  && OSSL_PARAM_allocate_from_text(&to, NULL, "s", "1", 1, NULL) == 0,
              "NULL target or definitions");
    }

    /* Printing. */
    {
        int iv = -7;
        unsigned int uv = 7;
        uint64_t bigu = 0;
        unsigned char oct[3] = {1, 2, 3};
        OSSL_PARAM all[] = {
            OSSL_PARAM_construct_int("i", &iv),
            OSSL_PARAM_construct_uint("u", &uv),
            OSSL_PARAM_construct_utf8_string("s", text, 0),
            OSSL_PARAM_construct_octet_string("o", oct, sizeof(oct)),
            OSSL_PARAM_construct_double("d", &dv),
            OSSL_PARAM_construct_uint64("u64", &bigu),
            OSSL_PARAM_construct_end(),
        };

        all[5].data_type = 99;
        printf("  print:\n");
        fflush(stdout);
        check(OSSL_PARAM_print_to_bio(all, bio, 1) == 1, "OSSL_PARAM_print_to_bio");
        (void)BIO_flush(bio);
        printf("\n");
        check(OSSL_PARAM_print_to_bio(all, bio, 0) == 1, "keys only");
        (void)BIO_flush(bio);
        check(OSSL_PARAM_print_to_bio(all + 6, bio, 1) == 0, "nothing to print");
    }

    BIO_free(bio);
    OSSL_PARAM_BLD_free(bld);
    BN_free(a);
    BN_free(b);
    BN_free(big);
    codes();
}

int main(void)
{
    lifecycle();
    conversions();
    asn1();
    arithmetic();
    bits();
    contexts();
    random_numbers();
    misc();
    params();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
