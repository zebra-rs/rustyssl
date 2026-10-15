/*
 * Conformance test for RSA's ASN.1 items (d2i_RSAPrivateKey(3), RSA_PSS_PARAMS_new(3),
 * ASN1_item_d2i(3), ASN1_item_print(3)), in TAP format: BIGNUM and CBIGNUM; RSAPublicKey and
 * RSAPrivateKey encoded from keys made from their numbers (two primes and three), decoded
 * back, decoded into an existing key (whose BIGNUMs are reused), duplicated, and through BIOs
 * and files; versions other than 0 and 1, a multi-prime version without its primes, and
 * malformed input with the errors it queues; the items inside an application's SEQUENCE
 * (plain, implicitly tagged, a SET OF), printed with each printing flag; and RSA_PSS_PARAMS
 * and RSA_OAEP_PARAMS.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* The error queue, emptied: each entry's library, reason, and text. */
static void errors(void)
{
    unsigned long code;
    const char *data;
    int flags;

    printf("  errors:");
    while ((code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        if ((flags & ERR_TXT_STRING) != 0 && *data != '\0')
            printf(" (%s)", data);
    }
    printf("\n");
}

static void hex(const char *label, const unsigned char *p, long len)
{
    long i;

    printf("  %s (%ld):", label, len);
    for (i = 0; i < len; i++)
        printf("%s%02x", i % 32 == 0 && i > 0 ? "\n    " : "", p[i]);
    printf("\n");
}

static void bn(const char *label, const BIGNUM *b)
{
    char *s;

    if (b == NULL) {
        printf("  %s: (none)\n", label);
        return;
    }
    s = BN_bn2hex(b);
    printf("  %s: %s%s\n", label, s, BN_get_flags(b, BN_FLG_CONSTTIME) ? " (consttime)" : "");
    OPENSSL_free(s);
}

static BIGNUM *num(const char *h)
{
    BIGNUM *b = NULL;

    BN_hex2bn(&b, h);
    return b;
}

/* Prints every number of a key, and its version. */
static void numbers(const RSA *r)
{
    const BIGNUM *primes[8], *exps[8], *coeffs[8];
    int i, extra;

    printf("  version %d\n", RSA_get_version((RSA *)r));
    bn("n", RSA_get0_n(r));
    bn("e", RSA_get0_e(r));
    bn("d", RSA_get0_d(r));
    bn("p", RSA_get0_p(r));
    bn("q", RSA_get0_q(r));
    bn("dmp1", RSA_get0_dmp1(r));
    bn("dmq1", RSA_get0_dmq1(r));
    bn("iqmp", RSA_get0_iqmp(r));
    extra = RSA_get_multi_prime_extra_count(r);
    printf("  extra primes %d\n", extra);
    if (extra > 0 && extra <= 8 && RSA_get0_multi_prime_factors(r, primes)
        && RSA_get0_multi_prime_crt_params(r, exps, coeffs)) {
        for (i = 0; i < extra; i++) {
            bn("r", primes[i]);
            bn("d_i", exps[i]);
            bn("t", coeffs[i]);
        }
    }
}

/* A two-prime key from made-up numbers (the encodings don't care). */
static RSA *two_prime(void)
{
    RSA *r = RSA_new();

    RSA_set0_key(r, num("C3A5F1E2D4B6978812345678ABCDEF0102030405060708090A0B0C0D0E0F1011"),
                 num("010001"), num("7F00112233445566778899AABBCCDDEEFF0011223344556677"));
    RSA_set0_factors(r, num("E1F2A3B4C5D6E7F8091A2B3C4D5E6F71"),
                     num("DDEEFF00112233445566778899AABBCD"));
    RSA_set0_crt_params(r, num("0123456789ABCDEF"), num("80"), num("00"));
    return r;
}

/* The same with a third prime. */
static RSA *three_prime(void)
{
    RSA *r = two_prime();
    BIGNUM *ps[1], *es[1], *cs[1];

    ps[0] = num("F00DFACE");
    es[0] = num("BEEF");
    cs[0] = num("FF");
    RSA_set0_multi_prime_params(r, ps, es, cs, 1);
    return r;
}

/* Encodes a key with an item's i2d, printing the DER; the encoding's length. */
static int encode(const char *label, int (*i2d)(const RSA *, unsigned char **), const RSA *r,
                  unsigned char **der)
{
    int len;

    *der = NULL;
    len = i2d(r, der);
    if (len > 0)
        hex(label, *der, len);
    else
        printf("  %s: %d\n", label, len);
    return len;
}

/* DER builder: an INTEGER from hex content (two digits an octet), appended at `p`. */
static size_t integer(unsigned char *p, const char *h)
{
    size_t n = strlen(h) / 2, i;

    p[0] = 0x02;
    p[1] = (unsigned char)n;
    for (i = 0; i < n; i++) {
        unsigned int v;

        sscanf(h + 2 * i, "%2x", &v);
        p[2 + i] = (unsigned char)v;
    }
    return n + 2;
}

/* A SEQUENCE around `len` octets at `body`, into `out`; its length. */
static size_t sequence(unsigned char *out, const unsigned char *body, size_t len)
{
    out[0] = 0x30;
    if (len < 128) {
        out[1] = (unsigned char)len;
        memcpy(out + 2, body, len);
        return len + 2;
    }
    out[1] = 0x81;
    out[2] = (unsigned char)len;
    memcpy(out + 3, body, len);
    return len + 3;
}

/* A SEQUENCE of INTEGERs (NULL ends the list), then `tail` octets. */
static size_t ints(unsigned char *out, const char **hs, const unsigned char *tail, size_t tlen)
{
    unsigned char body[512];
    size_t n = 0;

    for (; *hs != NULL; hs++)
        n += integer(body + n, *hs);
    if (tlen > 0)
        memcpy(body + n, tail, tlen);
    return sequence(out, body, n + tlen);
}

/* Decodes `len` octets as a private key, reporting what it gives or the errors. */
static RSA *decode_priv(const char *what, const unsigned char *der, long len)
{
    const unsigned char *p = der;
    RSA *r = d2i_RSAPrivateKey(NULL, &p, len);

    check(1, what);
    if (r == NULL) {
        printf("  failed\n");
        errors();
        return NULL;
    }
    printf("  consumed %ld\n", (long)(p - der));
    numbers(r);
    return r;
}

/* An application's SEQUENCE holding the items. */
typedef struct {
    RSA *key;
    RSA *tagged;
    STACK_OF(OPENSSL_BLOCK) *keys;
} HOLDER;

ASN1_SEQUENCE(HOLDER) = {
    ASN1_SIMPLE(HOLDER, key, RSAPublicKey),
    ASN1_IMP_OPT(HOLDER, tagged, RSAPrivateKey, 0),
    ASN1_IMP_SET_OF_OPT(HOLDER, keys, RSAPublicKey, 1),
} ASN1_SEQUENCE_END(HOLDER)

/* Prints a value of `it` with each flag set. */
static void print_all(const ASN1_VALUE *v, const ASN1_ITEM *it)
{
    static const unsigned long flagsets[] = {
        0,
        ASN1_PCTX_FLAGS_SHOW_SEQUENCE,
        ASN1_PCTX_FLAGS_NO_STRUCT_NAME,
        ASN1_PCTX_FLAGS_NO_FIELD_NAME,
        ASN1_PCTX_FLAGS_NO_STRUCT_NAME | ASN1_PCTX_FLAGS_NO_FIELD_NAME,
        ASN1_PCTX_FLAGS_SHOW_ABSENT | ASN1_PCTX_FLAGS_SHOW_TYPE | ASN1_PCTX_FLAGS_SHOW_SSOF,
    };
    BIO *out = BIO_new(BIO_s_mem());
    ASN1_PCTX *pctx = ASN1_PCTX_new();
    size_t i;

    for (i = 0; i < sizeof(flagsets) / sizeof(flagsets[0]); i++) {
        char *text;
        long n;
        int ret;

        ASN1_PCTX_set_flags(pctx, flagsets[i]);
        ret = ASN1_item_print(out, v, 2, it, pctx);
        n = BIO_get_mem_data(out, &text);
        printf("  flags %lx: %d\n%.*s", flagsets[i], ret, (int)n, text);
        (void)BIO_reset(out);
    }
    ASN1_PCTX_free(pctx);
    BIO_free(out);
}

static void test_bignum(void)
{
    static const unsigned char neg[] = { 0x02, 0x02, 0xff, 0x01 };
    static const unsigned char empty[] = { 0x02, 0x00 };
    static const unsigned char wrong[] = { 0x04, 0x01, 0x01 };
    BIGNUM *b = num("80"), *z = BN_new(), *m = num("-1234"), *got = NULL;
    unsigned char *der = NULL;
    const unsigned char *p;
    int len;

    len = ASN1_item_i2d((ASN1_VALUE *)b, &der, ASN1_ITEM_rptr(BIGNUM));
    check(len == 4, "BIGNUM: 0x80 takes a leading zero octet");
    hex("der", der, len);
    OPENSSL_free(der);
    der = NULL;
    len = ASN1_item_i2d((ASN1_VALUE *)z, &der, ASN1_ITEM_rptr(BIGNUM));
    check(len == 3, "BIGNUM: zero is one zero octet");
    hex("der", der, len);
    OPENSSL_free(der);
    der = NULL;
    len = ASN1_item_i2d((ASN1_VALUE *)m, &der, ASN1_ITEM_rptr(CBIGNUM));
    check(len > 0, "CBIGNUM: a negative number encodes its magnitude");
    hex("der", der, len);
    OPENSSL_free(der);

    p = neg;
    got = (BIGNUM *)ASN1_item_d2i(NULL, &p, sizeof(neg), ASN1_ITEM_rptr(BIGNUM));
    check(got != NULL, "BIGNUM: a negative INTEGER decodes as its octets, unsigned");
    bn("value", got);
    BN_free(got);
    p = neg;
    got = (BIGNUM *)ASN1_item_d2i(NULL, &p, sizeof(neg), ASN1_ITEM_rptr(CBIGNUM));
    check(got != NULL, "CBIGNUM: decoded constant-time");
    bn("value", got);
    BN_clear_free(got);
    p = empty;
    got = (BIGNUM *)ASN1_item_d2i(NULL, &p, sizeof(empty), ASN1_ITEM_rptr(BIGNUM));
    check(1, "BIGNUM: empty content");
    bn("value", got);
    errors();
    BN_free(got);
    p = wrong;
    got = (BIGNUM *)ASN1_item_d2i(NULL, &p, sizeof(wrong), ASN1_ITEM_rptr(BIGNUM));
    check(got == NULL, "BIGNUM: an OCTET STRING is refused");
    errors();

    printf("  item %s, itype %d, size %ld\n", ASN1_ITEM_rptr(BIGNUM)->sname,
           ASN1_ITEM_rptr(BIGNUM)->itype, ASN1_ITEM_rptr(BIGNUM)->size);
    printf("  item %s, itype %d, size %ld\n", ASN1_ITEM_rptr(CBIGNUM)->sname,
           ASN1_ITEM_rptr(CBIGNUM)->itype, ASN1_ITEM_rptr(CBIGNUM)->size);
    check(1, "BIGNUM: printed");
    print_all((ASN1_VALUE *)m, ASN1_ITEM_rptr(BIGNUM));
    BN_free(b);
    BN_free(z);
    BN_free(m);
}

static void test_encode(void)
{
    RSA *two = two_prime(), *three = three_prime(), *pub = RSA_new(), *empty = RSA_new();
    unsigned char *der;
    int len;

    len = encode("public", i2d_RSAPublicKey, two, &der);
    check(len > 0, "RSAPublicKey: n and e");
    OPENSSL_free(der);
    len = encode("private", i2d_RSAPrivateKey, two, &der);
    check(len > 0, "RSAPrivateKey: version 0 and the eight numbers");
    OPENSSL_free(der);
    len = encode("private", i2d_RSAPrivateKey, three, &der);
    check(len > 0, "RSAPrivateKey: version 1 and the other prime's info");
    OPENSSL_free(der);
    len = encode("public", i2d_RSAPublicKey, three, &der);
    check(len > 0, "RSAPublicKey: a three-prime key's");
    OPENSSL_free(der);

    RSA_set0_key(pub, num("BADC0FFEE0DDF00D"), num("03"), NULL);
    len = encode("private", i2d_RSAPrivateKey, pub, &der);
    check(len <= 0, "RSAPrivateKey: a public key has nothing to encode");
    errors();
    if (len > 0)
        OPENSSL_free(der);
    len = encode("public", i2d_RSAPublicKey, empty, &der);
    check(len <= 0, "RSAPublicKey: an empty key has nothing to encode");
    errors();
    if (len > 0)
        OPENSSL_free(der);

    /* The size alone, then into a caller's buffer. */
    {
        unsigned char buf[512], *q = buf;
        int n1 = i2d_RSAPrivateKey(three, NULL), n2 = i2d_RSAPrivateKey(three, &q);

        check(n1 == n2 && q == buf + n2, "RSAPrivateKey: measured, then into a buffer");
    }

    RSA_free(two);
    RSA_free(three);
    RSA_free(pub);
    RSA_free(empty);
}

static void test_decode(void)
{
    RSA *two = two_prime(), *three = three_prime(), *r, *existing;
    unsigned char *der, *pubder, buf[600];
    const unsigned char *p;
    const BIGNUM *n_before, *d_before;
    int len, publen;
    size_t blen;

    len = i2d_RSAPrivateKey(three, NULL);
    der = NULL;
    i2d_RSAPrivateKey(three, &der);
    r = decode_priv("RSAPrivateKey: a three-prime key decodes", der, len);
    {
        unsigned char *again = NULL;
        int len2 = r != NULL ? i2d_RSAPrivateKey(r, &again) : 0;

        check(len2 == len && memcmp(again, der, len) == 0, "RSAPrivateKey: and encodes the same");
        OPENSSL_free(again);
    }
    RSA_free(r);

    /* Into an existing key: its BIGNUMs are reused, the extra primes replaced. */
    existing = two_prime();
    n_before = RSA_get0_n(existing);
    d_before = RSA_get0_d(existing);
    p = der;
    r = d2i_RSAPrivateKey(&existing, &p, len);
    check(r == existing, "RSAPrivateKey: decoded into an existing key");
    check(RSA_get0_n(r) == n_before && RSA_get0_d(r) == d_before,
          "RSAPrivateKey: into the key's own BIGNUMs");
    numbers(r);
    OPENSSL_free(der);

    /* A public key decoded over a private one leaves the private numbers. */
    publen = i2d_RSAPublicKey(two, NULL);
    pubder = NULL;
    i2d_RSAPublicKey(two, &pubder);
    p = pubder;
    r = d2i_RSAPublicKey(&existing, &p, publen);
    check(r == existing && RSA_get0_n(r) == n_before, "RSAPublicKey: over a private key");
    numbers(r);

    /* A failure frees the key the caller gave, and clears the pointer. */
    RSA_up_ref(existing);
    r = existing;
    p = pubder;
    check(d2i_RSAPrivateKey(&r, &p, publen) == NULL && r == NULL,
          "RSAPrivateKey: a public key fails, the caller's key freed");
    errors();
    numbers(existing);
    RSA_free(existing);

    p = pubder;
    r = d2i_RSAPublicKey(NULL, &p, publen - 1);
    check(r == NULL, "RSAPublicKey: truncated");
    errors();
    p = pubder;
    r = d2i_RSAPublicKey(NULL, &p, publen);
    check(r != NULL && RSA_get0_d(r) == NULL, "RSAPublicKey: n and e only");
    numbers(r);
    RSA_free(r);
    OPENSSL_free(pubder);

    {
        const char *v5[] = { "05", "00C3", "03", "0D", "0B", "07", "01", "01", "02", NULL };
        const char *v1[] = { "01", "00C3", "03", "0D", "0B", "07", "01", "01", "02", NULL };
        const char *neg[] = { "00", "FF01", "FF", "0D", "0B", "07", "01", "01", "02", NULL };
        const char *empty[] = { "00", "", "03", "0D", "0B", "07", "01", "01", "02", NULL };
        const char *bigv[] = { "0100000000", "00C3", "03", "0D", "0B", "07", "01", "01", "02",
                               NULL };
        const char *pubints[] = { "00C3", "03", NULL };
        const char *infos[] = { "11", "05", "09", NULL };
        unsigned char info[32], infoseq[40], extra[8];
        size_t ilen, slen;

        blen = ints(buf, v5, NULL, 0);
        r = decode_priv("RSAPrivateKey: version 5 is kept", buf, (long)blen);
        if (r != NULL) {
            unsigned char *again = NULL;
            int n2 = i2d_RSAPrivateKey(r, &again);

            check(n2 == (int)blen && memcmp(again, buf, blen) == 0,
                  "RSAPrivateKey: and encoded again");
            OPENSSL_free(again);
            RSA_free(r);
        } else {
            check(0, "RSAPrivateKey: and encoded again");
        }
        blen = ints(buf, v1, NULL, 0);
        r = decode_priv("RSAPrivateKey: version 1 without its primes", buf, (long)blen);
        RSA_free(r);
        blen = ints(buf, neg, NULL, 0);
        r = decode_priv("RSAPrivateKey: negative numbers", buf, (long)blen);
        RSA_free(r);
        blen = ints(buf, empty, NULL, 0);
        r = decode_priv("RSAPrivateKey: an empty INTEGER", buf, (long)blen);
        RSA_free(r);
        blen = ints(buf, bigv, NULL, 0);
        r = decode_priv("RSAPrivateKey: a version too large for an int32", buf, (long)blen);
        RSA_free(r);
        blen = ints(buf, pubints, NULL, 0);
        r = decode_priv("RSAPrivateKey: two INTEGERs", buf, (long)blen);
        RSA_free(r);

        /* The other primes: version 1 with them, version 0 with them, and an empty list. */
        ilen = ints(info, infos, NULL, 0);
        slen = sequence(infoseq, info, ilen);
        blen = ints(buf, v1, infoseq, slen);
        r = decode_priv("RSAPrivateKey: version 1 with a prime's info", buf, (long)blen);
        if (r != NULL) {
            unsigned char *again = NULL;
            int n2 = i2d_RSAPrivateKey(r, &again);

            check(n2 == (int)blen && memcmp(again, buf, blen) == 0,
                  "RSAPrivateKey: and encoded again");
            OPENSSL_free(again);
            RSA_free(r);
        } else {
            check(0, "RSAPrivateKey: and encoded again");
        }
        {
            const char *v0[] = { "00", "00C3", "03", "0D", "0B", "07", "01", "01", "02", NULL };

            blen = ints(buf, v0, infoseq, slen);
            r = decode_priv("RSAPrivateKey: version 0 with a prime's info", buf, (long)blen);
            if (r != NULL) {
                unsigned char *again = NULL;
                int n2 = i2d_RSAPrivateKey(r, &again);

                check(n2 > 0, "RSAPrivateKey: and encoded again");
                hex("der", again, n2);
                OPENSSL_free(again);
                RSA_free(r);
            } else {
                check(0, "RSAPrivateKey: and encoded again");
            }
        }
        extra[0] = 0x30;
        extra[1] = 0x00;
        blen = ints(buf, v1, extra, 2);
        r = decode_priv("RSAPrivateKey: version 1 with an empty list", buf, (long)blen);
        RSA_free(r);
        {
            const char *v0[] = { "00", "00C3", "03", "0D", "0B", "07", "01", "01", "02", NULL };

            blen = ints(buf, v0, extra, 2);
            r = decode_priv("RSAPrivateKey: version 0 with an empty list", buf, (long)blen);
            if (r != NULL) {
                unsigned char *again = NULL;
                int n2 = i2d_RSAPrivateKey(r, &again);

                check(n2 > 0, "RSAPrivateKey: and encoded again");
                hex("der", again, n2);
                OPENSSL_free(again);
                RSA_free(r);
            } else {
                check(0, "RSAPrivateKey: and encoded again");
            }

            /* Two primes decoded over a three-prime key: the other prime goes. */
            existing = three_prime();
            blen = ints(buf, v0, NULL, 0);
            p = buf;
            r = d2i_RSAPrivateKey(&existing, &p, (long)blen);
            check(r == existing, "RSAPrivateKey: two primes over a three-prime key");
            numbers(existing);
            RSA_free(existing);
        }
        {
            const char *short_info[] = { "11", "05", NULL };

            ilen = ints(info, short_info, NULL, 0);
            slen = sequence(infoseq, info, ilen);
            blen = ints(buf, v1, infoseq, slen);
            r = decode_priv("RSAPrivateKey: a prime's info missing its coefficient", buf,
                            (long)blen);
            RSA_free(r);
        }
        extra[0] = 0x05;
        extra[1] = 0x00;
        blen = ints(buf, v5, extra, 2);
        r = decode_priv("RSAPrivateKey: a NULL after the numbers", buf, (long)blen);
        RSA_free(r);
    }

    RSA_free(two);
    RSA_free(three);
}

static void test_dup_io(void)
{
    RSA *three = three_prime(), *d;
    BIO *mem = BIO_new(BIO_s_mem());
    FILE *f;
    unsigned char *a = NULL, *b = NULL;
    int la, lb;

    d = RSAPrivateKey_dup(three);
    la = i2d_RSAPrivateKey(three, &a);
    lb = d != NULL ? i2d_RSAPrivateKey(d, &b) : 0;
    check(d != NULL && d != three && la == lb && memcmp(a, b, la) == 0,
          "RSAPrivateKey_dup: the same encoding");
    RSA_free(d);
    OPENSSL_free(b);
    b = NULL;
    d = RSAPublicKey_dup(three);
    check(d != NULL && RSA_get0_d(d) == NULL && BN_cmp(RSA_get0_n(d), RSA_get0_n(three)) == 0,
          "RSAPublicKey_dup: n and e only");
    RSA_free(d);
    check(RSAPublicKey_dup(NULL) == NULL, "RSAPublicKey_dup: NULL");
    errors();

    check(i2d_RSAPrivateKey_bio(mem, three) == 1, "i2d_RSAPrivateKey_bio");
    check(i2d_RSAPublicKey_bio(mem, three) == 1, "i2d_RSAPublicKey_bio");
    check(BIO_pending(mem) == la + i2d_RSAPublicKey(three, NULL), "the BIO holds both");
    d = d2i_RSAPrivateKey_bio(mem, NULL);
    lb = d != NULL ? i2d_RSAPrivateKey(d, &b) : 0;
    check(lb == la && memcmp(a, b, la) == 0, "d2i_RSAPrivateKey_bio");
    OPENSSL_free(b);
    b = NULL;
    RSA_free(d);
    d = d2i_RSAPublicKey_bio(mem, NULL);
    check(d != NULL && RSA_get0_d(d) == NULL, "d2i_RSAPublicKey_bio");
    RSA_free(d);
    check(d2i_RSAPublicKey_bio(mem, NULL) == NULL, "d2i_RSAPublicKey_bio: at the end");
    errors();

    f = tmpfile();
    check(f != NULL && i2d_RSAPrivateKey_fp(f, three) == 1 && i2d_RSAPublicKey_fp(f, three) == 1,
          "i2d_RSAPrivateKey_fp, i2d_RSAPublicKey_fp");
    if (f != NULL) {
        rewind(f);
        d = d2i_RSAPrivateKey_fp(f, NULL);
        lb = d != NULL ? i2d_RSAPrivateKey(d, &b) : 0;
        check(lb == la && memcmp(a, b, la) == 0, "d2i_RSAPrivateKey_fp");
        OPENSSL_free(b);
        RSA_free(d);
        d = d2i_RSAPublicKey_fp(f, NULL);
        check(d != NULL && BN_cmp(RSA_get0_e(d), RSA_get0_e(three)) == 0, "d2i_RSAPublicKey_fp");
        RSA_free(d);
        fclose(f);
    }
    OPENSSL_free(a);
    BIO_free(mem);
    RSA_free(three);
}

static void test_holder(void)
{
    HOLDER *h = (HOLDER *)ASN1_item_new(ASN1_ITEM_rptr(HOLDER)), *back;
    unsigned char *der = NULL;
    const unsigned char *p;
    int len;

    check(h != NULL && h->key != NULL && h->tagged == NULL,
          "HOLDER: a new one makes its required key");
    if (h == NULL)
        return;
    numbers(h->key);
    RSA_set0_key(h->key, num("C0FFEE"), num("03"), NULL);
    len = ASN1_item_i2d((ASN1_VALUE *)h, &der, ASN1_ITEM_rptr(HOLDER));
    check(len > 0, "HOLDER: the key alone");
    hex("der", der, len);
    OPENSSL_free(der);
    der = NULL;
    check(1, "HOLDER: printed");
    print_all((ASN1_VALUE *)h, ASN1_ITEM_rptr(HOLDER));

    h->tagged = three_prime();
    h->keys = sk_OPENSSL_BLOCK_new_null();
    sk_OPENSSL_BLOCK_push(h->keys, two_prime());
    sk_OPENSSL_BLOCK_push(h->keys, three_prime());
    len = ASN1_item_i2d((ASN1_VALUE *)h, &der, ASN1_ITEM_rptr(HOLDER));
    check(len > 0, "HOLDER: a tagged private key and a SET OF public keys");
    hex("der", der, len);
    p = der;
    back = (HOLDER *)ASN1_item_d2i(NULL, &p, len, ASN1_ITEM_rptr(HOLDER));
    check(back != NULL && back->tagged != NULL && sk_OPENSSL_BLOCK_num(back->keys) == 2,
          "HOLDER: decoded");
    if (back != NULL) {
        numbers(back->tagged);
        numbers(sk_OPENSSL_BLOCK_value(back->keys, 1));
    }
    check(1, "HOLDER: printed");
    print_all((ASN1_VALUE *)back, ASN1_ITEM_rptr(HOLDER));

    /* A key with a bad number inside: the field and type in the error. */
    {
        unsigned char *bad = OPENSSL_memdup(der, len);
        int i;

        /* The first INTEGER inside the [0] key: make its tag an OCTET STRING. */
        for (i = 0; i + 4 < len; i++)
            if (bad[i] == 0xa0) {
                int j = i + 2 + (bad[i + 1] & 0x80 ? (bad[i + 1] & 0x7f) : 0);

                bad[j] = 0x04;
                break;
            }
        p = bad;
        ASN1_item_free((ASN1_VALUE *)back, ASN1_ITEM_rptr(HOLDER));
        back = (HOLDER *)ASN1_item_d2i(NULL, &p, len, ASN1_ITEM_rptr(HOLDER));
        check(back == NULL, "HOLDER: a bad version in the tagged key");
        errors();
        OPENSSL_free(bad);
    }
    OPENSSL_free(der);
    ASN1_item_free((ASN1_VALUE *)back, ASN1_ITEM_rptr(HOLDER));
    ASN1_item_free((ASN1_VALUE *)h, ASN1_ITEM_rptr(HOLDER));

    check(1, "RSAPrivateKey: printed on its own");
    {
        RSA *three = three_prime();

        print_all((ASN1_VALUE *)three, ASN1_ITEM_rptr(RSAPrivateKey));
        print_all((ASN1_VALUE *)three, ASN1_ITEM_rptr(RSAPublicKey));
        RSA_free(three);
    }
}

/* An AlgorithmIdentifier filled directly (its structure is public). */
static X509_ALGOR *algor(int nid, int ptype, void *pval)
{
    X509_ALGOR *a = X509_ALGOR_new();

    a->algorithm = OBJ_nid2obj(nid);
    if (ptype != V_ASN1_UNDEF) {
        a->parameter = ASN1_TYPE_new();
        ASN1_TYPE_set(a->parameter, ptype, pval);
    }
    return a;
}

static void test_params(void)
{
    RSA_PSS_PARAMS *pss = RSA_PSS_PARAMS_new(), *pss2;
    RSA_OAEP_PARAMS *oaep = RSA_OAEP_PARAMS_new(), *oaep2;
    unsigned char *der = NULL;
    const unsigned char *p;
    int len;

    check(pss != NULL && pss->hashAlgorithm == NULL && pss->maskHash == NULL,
          "RSA_PSS_PARAMS_new: empty");
    len = i2d_RSA_PSS_PARAMS(pss, &der);
    check(len == 2, "RSA_PSS_PARAMS: the defaults are an empty SEQUENCE");
    hex("der", der, len);
    OPENSSL_free(der);
    der = NULL;

    pss->hashAlgorithm = algor(NID_sha256, V_ASN1_NULL, NULL);
    pss->maskGenAlgorithm = algor(NID_mgf1, V_ASN1_UNDEF, NULL);
    pss->saltLength = ASN1_INTEGER_new();
    ASN1_INTEGER_set(pss->saltLength, 32);
    pss->trailerField = ASN1_INTEGER_new();
    ASN1_INTEGER_set(pss->trailerField, 1);
    pss->maskHash = X509_ALGOR_new();
    len = i2d_RSA_PSS_PARAMS(pss, &der);
    check(len > 2, "RSA_PSS_PARAMS: every field, explicitly tagged");
    hex("der", der, len);
    p = der;
    pss2 = d2i_RSA_PSS_PARAMS(NULL, &p, len);
    check(pss2 != NULL && pss2->maskHash == NULL && ASN1_INTEGER_get(pss2->saltLength) == 32,
          "RSA_PSS_PARAMS: decoded (maskHash is the caller's to fill)");
    RSA_PSS_PARAMS_free(pss2);
    pss2 = RSA_PSS_PARAMS_dup(pss);
    check(pss2 != NULL && pss2 != pss && pss2->maskHash == NULL, "RSA_PSS_PARAMS_dup");
    RSA_PSS_PARAMS_free(pss2);
    check(1, "RSA_PSS_PARAMS: printed");
    print_all((ASN1_VALUE *)pss, ASN1_ITEM_rptr(RSA_PSS_PARAMS));
    der[2] = 0xa5;
    p = der;
    pss2 = d2i_RSA_PSS_PARAMS(NULL, &p, len);
    check(pss2 == NULL, "RSA_PSS_PARAMS: an unknown tag");
    errors();
    OPENSSL_free(der);
    der = NULL;
    RSA_PSS_PARAMS_free(pss);
    RSA_PSS_PARAMS_free(NULL);

    oaep->hashFunc = algor(NID_sha384, V_ASN1_NULL, NULL);
    {
        ASN1_OCTET_STRING *label = ASN1_OCTET_STRING_new();

        ASN1_OCTET_STRING_set(label, (const unsigned char *)"label", 5);
        oaep->pSourceFunc = algor(NID_pSpecified, V_ASN1_OCTET_STRING, label);
    }
    oaep->maskHash = X509_ALGOR_new();
    len = i2d_RSA_OAEP_PARAMS(oaep, &der);
    check(len > 2, "RSA_OAEP_PARAMS: hash and source");
    hex("der", der, len);
    p = der;
    oaep2 = d2i_RSA_OAEP_PARAMS(NULL, &p, len);
    check(oaep2 != NULL && oaep2->maskGenFunc == NULL && oaep2->pSourceFunc != NULL,
          "RSA_OAEP_PARAMS: decoded");
    RSA_OAEP_PARAMS_free(oaep2);
    check(1, "RSA_OAEP_PARAMS: printed");
    print_all((ASN1_VALUE *)oaep, ASN1_ITEM_rptr(RSA_OAEP_PARAMS));
    OPENSSL_free(der);
    RSA_OAEP_PARAMS_free(oaep);

    printf("  items: %s %d %ld, %s %d %ld, %s, %s\n",
           ASN1_ITEM_rptr(RSA_PSS_PARAMS)->sname, ASN1_ITEM_rptr(RSA_PSS_PARAMS)->itype,
           ASN1_ITEM_rptr(RSA_PSS_PARAMS)->tcount, ASN1_ITEM_rptr(RSA_OAEP_PARAMS)->sname,
           ASN1_ITEM_rptr(RSA_OAEP_PARAMS)->itype, ASN1_ITEM_rptr(RSA_OAEP_PARAMS)->tcount,
           ASN1_ITEM_rptr(RSAPublicKey)->sname, ASN1_ITEM_rptr(RSAPrivateKey)->sname);
}

int main(void)
{
    test_bignum();
    test_encode();
    test_decode();
    test_dup_io();
    test_holder();
    test_params();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
