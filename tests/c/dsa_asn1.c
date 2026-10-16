/*
 * Conformance test for DSA's ASN.1 and PEM (d2i_DSAPrivateKey(3), d2i_DSAparams(3),
 * d2i_DSAPublicKey(3), PEM_read_bio_DSAparams(3), DSAparams_dup(3)), in TAP format: the
 * traditional private key, the parameters, and the public key encoded and decoded (a new key
 * and into a key, which keeps what the encoding doesn't carry), hand-made encodings (other
 * versions, negative and zero numbers, missing and extra fields, truncation), the private
 * key through BIOs and FILEs, the parameters' PEM through BIOs and FILEs, and copies of the
 * parameters.
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
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static void errors(void)
{
    unsigned long e;
    const char *data;
    int flags;

    printf("  errors:");
    while ((e = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
        if ((flags & ERR_TXT_STRING) != 0 && data != NULL && *data != '\0')
            printf(" [%s]", data);
    }
    printf("\n");
}

static void octets(const char *label, const unsigned char *p, int n)
{
    unsigned char d[32];
    unsigned int dl = 0;
    int i;

    if (n <= 0) {
        printf("  %s: %d\n", label, n);
        return;
    }
    EVP_Digest(p, (size_t)n, d, &dl, EVP_sha256(), NULL);
    printf("  %s (%d):", label, n);
    for (i = 0; i < n && i < 10; i++)
        printf("%02x", p[i]);
    printf(" sha256 ");
    for (i = 0; i < 8; i++)
        printf("%02x", d[i]);
    printf("\n");
}

static void hexnum(const char *label, const BIGNUM *b)
{
    char *h = b != NULL ? BN_bn2hex(b) : NULL;

    printf(" %s %s", label, h != NULL ? h : "-");
    OPENSSL_free(h);
}

static void show(const char *label, const DSA *d)
{
    if (d == NULL) {
        printf("  %s: (none)\n", label);
        return;
    }
    printf("  %s:", label);
    hexnum("p", DSA_get0_p(d));
    hexnum("q", DSA_get0_q(d));
    hexnum("g", DSA_get0_g(d));
    hexnum("pub", DSA_get0_pub_key(d));
    hexnum("priv", DSA_get0_priv_key(d));
    printf("\n");
}

static BIGNUM *bn(const char *h)
{
    BIGNUM *b = NULL;

    BN_hex2bn(&b, h);
    return b;
}

static DSA *made_up(int with_pub, int with_priv)
{
    DSA *d = DSA_new();

    DSA_set0_pqg(d, bn("F7E75FDC469067FFDC4E847C51F452DF"), bn("7BF3AFEE234833FF"), bn("05"));
    DSA_set0_key(d, with_pub ? bn("1234567890ABCDEF") : NULL, with_priv ? bn("42") : NULL);
    return d;
}

typedef int (*i2d_fn)(const DSA *, unsigned char **);
typedef DSA *(*d2i_fn)(DSA **, const unsigned char **, long);

static void roundtrip(const char *label, DSA *d, i2d_fn i2d, d2i_fn d2i)
{
    unsigned char *der = NULL;
    const unsigned char *pp;
    int n = i2d(d, &der);
    DSA *back;

    octets(label, der, n);
    if (n > 0) {
        pp = der;
        back = d2i(NULL, &pp, n);
        printf("  consumed %ld\n", (long)(pp - der));
        show("decoded", back);
        DSA_free(back);
    }
    OPENSSL_free(der);
    errors();
}

static void test_roundtrip(void)
{
    DSA *full = made_up(1, 1), *pub = made_up(1, 0), *params = made_up(0, 0), *empty = DSA_new();

    check(full != NULL, "encodings");
    roundtrip("private", full, i2d_DSAPrivateKey, d2i_DSAPrivateKey);
    roundtrip("params", full, i2d_DSAparams, d2i_DSAparams);
    roundtrip("public", full, i2d_DSAPublicKey, d2i_DSAPublicKey);
    roundtrip("public of a public key", pub, i2d_DSAPublicKey, d2i_DSAPublicKey);
    roundtrip("params alone", params, i2d_DSAparams, d2i_DSAparams);
    printf("  private without priv %d", i2d_DSAPrivateKey(pub, NULL));
    errors();
    printf("  public without pub %d", i2d_DSAPublicKey(params, NULL));
    errors();
    printf("  empty params %d", i2d_DSAparams(empty, NULL));
    errors();
    DSA_free(full);
    DSA_free(pub);
    DSA_free(params);
    DSA_free(empty);
}

static void decode(const char *label, const char *hexder, d2i_fn d2i, i2d_fn i2d)
{
    long n = 0;
    unsigned char *der = OPENSSL_hexstr2buf(hexder, &n);
    const unsigned char *pp = der;
    unsigned char *re = NULL;
    DSA *d = d2i(NULL, &pp, n);
    int rn;

    printf("  %s: %s consumed %ld\n", label, d == NULL ? "fails" : "ok", (long)(pp - der));
    if (d != NULL) {
        show("decoded", d);
        rn = i2d(d, &re);
        printf("  re-encodes the same %d\n", rn == n && memcmp(re, der, (size_t)n) == 0);
        OPENSSL_free(re);
    }
    DSA_free(d);
    OPENSSL_free(der);
    errors();
}

static void test_decode(void)
{
    check(1, "hand-made encodings");
    decode("private v0", "3012020100020117020103020105020107020102", d2i_DSAPrivateKey,
           i2d_DSAPrivateKey);
    decode("private v5", "3012020105020117020103020105020107020102", d2i_DSAPrivateKey,
           i2d_DSAPrivateKey);
    decode("private v-1", "30120201ff020117020103020105020107020102", d2i_DSAPrivateKey,
           i2d_DSAPrivateKey);
    decode("private zero priv", "3012020100020117020103020105020107020100", d2i_DSAPrivateKey,
           i2d_DSAPrivateKey);
    decode("private missing priv", "300c020100020117020103020105020107", d2i_DSAPrivateKey,
           i2d_DSAPrivateKey);
    decode("private extra", "3015020100020117020103020105020107020102020101",
           d2i_DSAPrivateKey, i2d_DSAPrivateKey);
    decode("private negative p", "30120201000201e9020103020105020107020102", d2i_DSAPrivateKey,
           i2d_DSAPrivateKey);
    decode("private big version", "30170206010000000000020117020103020105020107020102",
           d2i_DSAPrivateKey, i2d_DSAPrivateKey);
    decode("params", "3009020117020103020105", d2i_DSAparams, i2d_DSAparams);
    decode("params two", "3006020117020103", d2i_DSAparams, i2d_DSAparams);
    decode("params truncated", "3009020117020103020", d2i_DSAparams, i2d_DSAparams);
    decode("params indefinite", "30800201170201030201050000", d2i_DSAparams, i2d_DSAparams);
    decode("public", "300c020107020117020103020105", d2i_DSAPublicKey, i2d_DSAPublicKey);
    decode("public as params", "300c020107020117020103020105", d2i_DSAparams, i2d_DSAparams);
}

static void test_reuse(void)
{
    DSA *d = made_up(1, 1), *r;
    unsigned char *der = NULL;
    const unsigned char *pp;
    const BIGNUM *p0 = DSA_get0_p(d);
    int n;
    static const unsigned char params[] = { 0x30, 0x09, 0x02, 0x01, 0x17, 0x02, 0x01, 0x03,
                                            0x02, 0x01, 0x05 };
    static const unsigned char pubk[] = { 0x30, 0x0c, 0x02, 0x01, 0x09, 0x02, 0x01, 0x17,
                                          0x02, 0x01, 0x03, 0x02, 0x01, 0x05 };

    check(d != NULL, "decoding into a key");
    pp = params;
    r = d2i_DSAparams(&d, &pp, sizeof(params));
    printf("  params into %d same p object %d\n", r == d, DSA_get0_p(d) == p0);
    show("after params", d);
    pp = pubk;
    r = d2i_DSAPublicKey(&d, &pp, sizeof(pubk));
    printf("  public into %d\n", r == d);
    show("after public", d);
    n = i2d_DSAPrivateKey(d, &der);
    octets("private now", der, n);
    OPENSSL_free(der);
    pp = params;
    r = d2i_DSAparams(&d, &pp, 3);
    printf("  truncated into %d\n", r != NULL);
    show("after a failure", d);
    errors();
    DSA_free(d);
}

static void test_io(void)
{
    DSA *d = made_up(1, 1), *back = NULL, *dup;
    BIO *b = BIO_new(BIO_s_mem());
    FILE *f;
    char *data;
    long n;

    check(d != NULL && b != NULL, "BIOs, FILEs, and PEM");
    printf("  bio write %d", i2d_DSAPrivateKey_bio(b, d));
    back = d2i_DSAPrivateKey_bio(b, NULL);
    show(" read", back);
    DSA_free(back);
    printf("  bio empty %d\n", d2i_DSAPrivateKey_bio(b, NULL) != NULL);
    errors();
    f = tmpfile();
    printf("  fp write %d", i2d_DSAPrivateKey_fp(f, d));
    rewind(f);
    back = d2i_DSAPrivateKey_fp(f, NULL);
    show(" read", back);
    DSA_free(back);
    fclose(f);
    errors();

    (void)BIO_reset(b);
    printf("  pem %d", PEM_write_bio_DSAparams(b, d));
    n = BIO_get_mem_data(b, &data);
    printf(" (%ld):\n%.*s", n, (int)n, data);
    back = PEM_read_bio_DSAparams(b, NULL, NULL, NULL);
    show("pem read", back);
    DSA_free(back);
    printf("  pem empty %d", PEM_read_bio_DSAparams(b, NULL, NULL, NULL) != NULL);
    errors();
    f = tmpfile();
    printf("  pem fp %d %d", PEM_write_DSAparams(f, d), PEM_write_DSAparams(f, d));
    rewind(f);
    back = PEM_read_DSAparams(f, NULL, NULL, NULL);
    show(" read", back);
    printf("  second into it %d\n", PEM_read_DSAparams(f, &back, NULL, NULL) == back);
    DSA_free(back);
    fclose(f);
    errors();

    dup = DSAparams_dup(d);
    show("dup", dup);
    DSA_free(dup);
    DSA_free(d);
    d = DSA_new();
    printf("  dup of empty %d", DSAparams_dup(d) != NULL);
    errors();
    DSA_free(d);
    BIO_free(b);
}

int main(void)
{
    test_roundtrip();
    test_decode();
    test_reuse();
    test_io();
    errors();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
