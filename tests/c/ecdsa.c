/*
 * Conformance test for ECDSA and ECDH (ECDSA_sign(3), ECDSA_SIG_new(3), ECDH_compute_key(3)),
 * in TAP format: signatures with fixed nonces (given as kinv and r, so they're reproducible)
 * on curves of each kind, with digests longer than the order and orders whose length isn't a
 * multiple of eight; random signatures verified, and verification of tampered, malformed, and
 * out-of-range ones; ECDSA_SIG and its DER (which accepts only what OpenSSL accepts);
 * shared secrets with and without the cofactor, cut to every length, through a KDF and
 * X9.63's; and applications' methods for both. Random values aren't printed.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
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

static void hex(const char *label, const unsigned char *p, size_t len)
{
    size_t i;

    printf("  %s (%zu):", label, len);
    for (i = 0; i < len; i++)
        printf("%s%02x", i % 40 == 0 && i > 0 ? "\n    " : "", p[i]);
    printf("\n");
}

static void bn(const char *label, const BIGNUM *b)
{
    char *s;

    if (b == NULL) {
        printf("  %s: (null)\n", label);
        return;
    }
    s = BN_bn2hex(b);
    printf("  %s: %s\n", label, s);
    OPENSSL_free(s);
}

static BIGNUM *num(const char *h)
{
    BIGNUM *b = NULL;

    BN_hex2bn(&b, h);
    return b;
}

static unsigned char *unhex(const char *h, int *len)
{
    size_t n = strlen(h) / 2, i;
    unsigned char *b = OPENSSL_malloc(n + 1);

    for (i = 0; i < n; i++) {
        unsigned int v;

        sscanf(h + 2 * i, "%2x", &v);
        b[i] = (unsigned char)v;
    }
    *len = (int)n;
    return b;
}

/* A key on `nid` with private key `priv_hex` and its public key. */
static EC_KEY *fixed_key(int nid, const char *priv_hex)
{
    EC_KEY *k = EC_KEY_new_by_curve_name(nid);
    BIGNUM *priv = num(priv_hex);
    EC_POINT *P = EC_POINT_new(EC_KEY_get0_group(k));

    EC_POINT_mul(EC_KEY_get0_group(k), P, priv, NULL, NULL, NULL);
    EC_KEY_set_private_key(k, priv);
    EC_KEY_set_public_key(k, P);
    BN_free(priv);
    EC_POINT_free(P);
    return k;
}

/* kinv and r for the nonce `k_hex` on the key's group. */
static void setup_fixed(const EC_KEY *key, const char *k_hex, BIGNUM **kinv, BIGNUM **r)
{
    const EC_GROUP *g = EC_KEY_get0_group(key);
    BIGNUM *k = num(k_hex), *x = BN_new();
    EC_POINT *R = EC_POINT_new(g);
    BN_CTX *ctx = BN_CTX_new();

    EC_POINT_mul(g, R, k, NULL, NULL, ctx);
    EC_POINT_get_affine_coordinates(g, R, x, NULL, ctx);
    *r = BN_new();
    BN_nnmod(*r, x, EC_GROUP_get0_order(g), ctx);
    *kinv = BN_mod_inverse(NULL, k, EC_GROUP_get0_order(g), ctx);
    BN_free(k);
    BN_free(x);
    EC_POINT_free(R);
    BN_CTX_free(ctx);
}

static const unsigned char digest64[64] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
    0x10, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2,
    0xe1, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
    0xee, 0xff, 0x00, 0x13, 0x57, 0x9b, 0xdf, 0x24, 0x68, 0xac, 0xe0, 0xf1, 0xe2, 0xd3, 0xc4,
    0xb5, 0xa6, 0x97, 0x88
};

/* Fixed-nonce signatures with digests of several lengths, and random ones verified. */
static void test_curve(int nid, const char *priv_hex)
{
    EC_KEY *k = fixed_key(nid, priv_hex);
    BIGNUM *kinv = NULL, *r = NULL;
    static const int lens[] = { 0, 1, 20, 32, 48, 64 };
    size_t i;
    char what[120];

    printf("# %s\n", OBJ_nid2sn(nid));
    printf("  ECDSA_size: %d\n", ECDSA_size(k));
    setup_fixed(k, "1D2C3B4A59687786950A1B2C3D4E5F", &kinv, &r);
    for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        ECDSA_SIG *s = ECDSA_do_sign_ex(digest64, lens[i], kinv, r, k);
        unsigned char sig[200];
        unsigned int siglen = 0;

        snprintf(what, sizeof(what), "fixed nonce, %d-octet digest", lens[i]);
        check(s != NULL, what);
        if (s != NULL) {
            bn("r", ECDSA_SIG_get0_r(s));
            bn("s", ECDSA_SIG_get0_s(s));
            printf("  verifies: %d\n", ECDSA_do_verify(digest64, lens[i], s, k));
            printf("  another digest: %d\n",
                   ECDSA_do_verify(digest64 + 1, lens[i] > 0 ? lens[i] - 1 : 0, s, k));
            errors();
        }
        check(ECDSA_sign_ex(0, digest64, lens[i], sig, &siglen, kinv, r, k) == 1,
              "ECDSA_sign_ex");
        hex("DER", sig, siglen);
        printf("  ECDSA_verify: %d\n", ECDSA_verify(0, digest64, lens[i], sig, (int)siglen, k));
        ECDSA_SIG_free(s);
    }
    for (i = 0; i < 3; i++) {
        unsigned char sig[200];
        unsigned int siglen = 0;
        BIGNUM *rk = NULL, *rr = NULL;

        check(ECDSA_sign(0, digest64, 32, sig, &siglen, k) == 1, "a random signature");
        printf("  verifies: %d, length <= size: %d\n",
               ECDSA_verify(0, digest64, 32, sig, (int)siglen, k), (int)siglen <= ECDSA_size(k));
        check(ECDSA_sign_setup(k, NULL, &rk, &rr) == 1, "ECDSA_sign_setup");
        siglen = 0;
        check(ECDSA_sign_ex(0, digest64, 32, sig, &siglen, rk, rr, k) == 1
              && ECDSA_verify(0, digest64, 32, sig, (int)siglen, k) == 1,
              "signing with its values");
        BN_clear_free(rk);
        BN_clear_free(rr);
    }
    {
        ECDSA_SIG *s = ECDSA_do_sign(digest64, 20, k);

        check(s != NULL && ECDSA_do_verify(digest64, 20, s, k) == 1, "ECDSA_do_sign");
        ECDSA_SIG_free(s);
    }
    {
        unsigned int siglen = 0;

        check(ECDSA_sign(0, digest64, 32, NULL, &siglen, k) == 1
              && (int)siglen == ECDSA_size(k), "ECDSA_sign with no buffer gives the size");
    }
    BN_free(kinv);
    BN_free(r);
    EC_KEY_free(k);
}

/* Verification of signatures out of range and of encodings that aren't DER. */
static void test_verify_edges(void)
{
    EC_KEY *k = fixed_key(NID_X9_62_prime256v1, "C0FFEE");
    const BIGNUM *order = EC_GROUP_get0_order(EC_KEY_get0_group(k));
    BIGNUM *kinv = NULL, *r = NULL;
    ECDSA_SIG *s, *bad = ECDSA_SIG_new();
    unsigned char der[200], *p;
    int len;
    static const struct {
        const char *what, *hex;
    } encs[] = {
        { "a long-form length", "3081440220" },
        { "trailing octets", NULL },
        { "a negative r", "3006020181020101" },
        { "a zero-padded r", "300702020001020101" },
        { "BER INTEGER length", "300702810101020101" },
        { "empty", "" },
    };
    size_t i;

    printf("# verification\n");
    setup_fixed(k, "ABCDEF", &kinv, &r);
    s = ECDSA_do_sign_ex(digest64, 32, kinv, r, k);
    p = der;
    len = i2d_ECDSA_SIG(s, &p);

    /* r and s out of range. */
    ECDSA_SIG_set0(bad, BN_new(), BN_dup(ECDSA_SIG_get0_s(s)));
    printf("  r = 0: %d\n", ECDSA_do_verify(digest64, 32, bad, k));
    errors();
    ECDSA_SIG_set0(bad, BN_dup(order), BN_dup(ECDSA_SIG_get0_s(s)));
    printf("  r = order: %d\n", ECDSA_do_verify(digest64, 32, bad, k));
    errors();
    {
        BIGNUM *neg = BN_dup(ECDSA_SIG_get0_s(s));

        BN_set_negative(neg, 1);
        ECDSA_SIG_set0(bad, BN_dup(ECDSA_SIG_get0_r(s)), neg);
        printf("  negative s: %d\n", ECDSA_do_verify(digest64, 32, bad, k));
        errors();
    }

    for (i = 0; i < sizeof(encs) / sizeof(encs[0]); i++) {
        unsigned char buf[200];
        int n;

        if (encs[i].hex == NULL) {
            memcpy(buf, der, len);
            buf[len] = 0;
            n = len + 1;
        } else if (strcmp(encs[i].what, "a long-form length") == 0) {
            /* The signature with its SEQUENCE length in long form. */
            buf[0] = 0x30;
            buf[1] = 0x81;
            memcpy(buf + 2, der + 1, len - 1);
            n = len + 1;
        } else {
            unsigned char *b = unhex(encs[i].hex, &n);

            memcpy(buf, b, n);
            OPENSSL_free(b);
        }
        printf("  %s: ECDSA_verify %d\n", encs[i].what, ECDSA_verify(0, digest64, 32, buf, n, k));
        errors();
    }
    {
        EC_KEY *nopub = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

        printf("  without a public key: %d\n", ECDSA_do_verify(digest64, 32, s, nopub));
        errors();
        printf("  a NULL signature: %d\n", ECDSA_do_verify(digest64, 32, NULL, k));
        errors();
        check(ECDSA_do_sign(digest64, 32, nopub) == NULL, "signing without a private key");
        errors();
        check(ECDSA_sign_setup(nopub, NULL, &kinv, &r) == 0, "setup without a private key");
        errors();
        EC_KEY_free(nopub);
    }
    {
        /* Values given for the setup that make s zero ask for new ones. */
        BIGNUM *m_neg = NULL, *rr = BN_new(), *one = BN_new();
        ECDSA_SIG *z;

        BN_one(one);
        /* s = kinv (m + r d): with d = C0FFEE and m = the digest, choose r = -m/d mod n. */
        {
            BN_CTX *ctx = BN_CTX_new();
            BIGNUM *m = BN_bin2bn(digest64, 32, NULL), *d = num("C0FFEE");
            BIGNUM *dinv = BN_mod_inverse(NULL, d, order, ctx);

            m_neg = BN_new();
            BN_mod_sub(m_neg, order, m, order, ctx);
            BN_mod_mul(rr, m_neg, dinv, order, ctx);
            BN_free(m);
            BN_free(d);
            BN_free(dinv);
            BN_CTX_free(ctx);
        }
        z = ECDSA_do_sign_ex(digest64, 32, one, rr, k);
        check(z == NULL, "a zero s with given kinv and r");
        errors();
        ECDSA_SIG_free(z);
        BN_free(m_neg);
        BN_free(rr);
        BN_free(one);
    }
    ECDSA_SIG_free(s);
    ECDSA_SIG_free(bad);
    BN_free(kinv);
    BN_free(r);
    EC_KEY_free(k);
}

/* ECDSA_SIG and its DER. */
static void test_sig(void)
{
    static const struct {
        const char *what, *hex;
    } cases[] = {
        { "r = 1, s = 2", "3006020101020102" },
        { "r with a sign octet", "300702020080020102" },
        { "long-form lengths", "30810702810101020102" },
        { "two-octet lengths", "3082000802820001010201 02" },
        { "a negative s", "30060201010201ff" },
        { "a needless zero octet", "300702020001020102" },
        { "zero", "3006020100020100" },
        { "an empty INTEGER", "30050200020101" },
        { "extra inside", "3009020101020102020103" },
        { "trailing outside", "300602010102010200" },
        { "cut short", "30060201010201" },
        { "not a SEQUENCE", "3106020101020102" },
        { "indefinite length", "3080020101020102 0000" },
    };
    size_t i;
    ECDSA_SIG *sig = ECDSA_SIG_new();
    const BIGNUM *pr = (const BIGNUM *)1, *ps = (const BIGNUM *)1;

    printf("# ECDSA_SIG\n");
    ECDSA_SIG_get0(sig, &pr, &ps);
    check(pr == NULL && ps == NULL && ECDSA_SIG_get0_r(sig) == NULL, "a new one is empty");
    check(ECDSA_SIG_set0(sig, NULL, BN_new()) == 0, "set0 needs both");
    check(ECDSA_SIG_set0(sig, num("123"), num("456")) == 1, "ECDSA_SIG_set0");
    {
        unsigned char *der = NULL, buf[100], *p = buf;
        int len = i2d_ECDSA_SIG(sig, NULL);

        printf("  length: %d\n", len);
        check(i2d_ECDSA_SIG(sig, &der) == len, "i2d_ECDSA_SIG, allocating");
        hex("DER", der, (size_t)len);
        check(i2d_ECDSA_SIG(sig, &p) == len && p == buf + len, "into a buffer, advancing");
        OPENSSL_free(der);
    }
    ECDSA_SIG_get0(sig, NULL, NULL);

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char h[200];
        size_t a, b = 0;
        unsigned char *der;
        const unsigned char *p;
        int len;
        ECDSA_SIG *d;

        for (a = 0; cases[i].hex[a] != '\0'; a++)
            if (cases[i].hex[a] != ' ')
                h[b++] = cases[i].hex[a];
        h[b] = '\0';
        der = unhex(h, &len);
        p = der;
        d = d2i_ECDSA_SIG(NULL, &p, len);
        printf("  %s: %s, consumed %d\n", cases[i].what, d != NULL ? "decoded" : "refused",
               (int)(p - der));
        errors();
        if (d != NULL) {
            unsigned char *again = NULL;
            int n = i2d_ECDSA_SIG(d, &again);

            bn("r", ECDSA_SIG_get0_r(d));
            bn("s", ECDSA_SIG_get0_s(d));
            hex("again", again, n > 0 ? (size_t)n : 0);
            OPENSSL_free(again);
        }
        ECDSA_SIG_free(d);

        /* Into an existing signature: what's left of it on failure. */
        p = der;
        d = d2i_ECDSA_SIG(&sig, &p, len);
        printf("    into one: %s, r ", d != NULL ? "decoded" : "refused");
        BN_print_fp(stdout, ECDSA_SIG_get0_r(sig));
        printf("\n");
        OPENSSL_free(der);
    }
    {
        const unsigned char *p = (const unsigned char *)"\x30";

        check(d2i_ECDSA_SIG(NULL, &p, -1) == NULL, "a negative length");
    }
    {
        BIGNUM *neg = num("-5");
        ECDSA_SIG *n = ECDSA_SIG_new();

        ECDSA_SIG_set0(n, neg, num("5"));
        printf("  i2d of a negative r: %d\n", i2d_ECDSA_SIG(n, NULL));
        errors();
        ECDSA_SIG_free(n);
    }
    ECDSA_SIG_free(sig);
    ECDSA_SIG_free(NULL);
}

/* A KDF that prints its input's length and copies it. */
static void *my_kdf(const void *in, size_t inlen, void *out, size_t *outlen)
{
    printf("  kdf: %zu octets in, %zu out\n", inlen, *outlen);
    memset(out, 0xab, *outlen);
    if (*outlen > inlen)
        *outlen = inlen;
    memcpy(out, in, *outlen);
    return out;
}

static void test_ecdh(void)
{
    static const struct {
        int nid;
        const char *a, *b;
    } curves[] = {
        { NID_X9_62_prime256v1, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
          "7E5A" },
        { NID_secp521r1, "1", "1F" },
        { NID_sect163r1, "3A41434AA99C2EF40C8495B2ED9739CB2155A1E0D", "1234567" },
        { NID_brainpoolP256r1, "ABCDEF0123", "13579BDF" },
    };
    size_t i;

    printf("# ECDH\n");
    for (i = 0; i < sizeof(curves) / sizeof(curves[0]); i++) {
        EC_KEY *a = fixed_key(curves[i].nid, curves[i].a);
        EC_KEY *b = fixed_key(curves[i].nid, curves[i].b);
        unsigned char s1[100], s2[100];
        int n1, n2;

        printf("  %s\n", OBJ_nid2sn(curves[i].nid));
        n1 = ECDH_compute_key(s1, sizeof(s1), EC_KEY_get0_public_key(b), a, NULL);
        n2 = ECDH_compute_key(s2, sizeof(s2), EC_KEY_get0_public_key(a), b, NULL);
        check(n1 > 0 && n1 == n2 && memcmp(s1, s2, n1) == 0, "both sides agree");
        hex("shared", s1, n1 > 0 ? (size_t)n1 : 0);
        n1 = ECDH_compute_key(s1, 5, EC_KEY_get0_public_key(b), a, NULL);
        hex("cut to 5", s1, n1 > 0 ? (size_t)n1 : 0);
        n1 = ECDH_compute_key(s1, 10, EC_KEY_get0_public_key(b), a, my_kdf);
        hex("through a KDF", s1, n1 > 0 ? (size_t)n1 : 0);
        EC_KEY_set_flags(a, EC_FLAG_COFACTOR_ECDH);
        n1 = ECDH_compute_key(s1, sizeof(s1), EC_KEY_get0_public_key(b), a, NULL);
        hex("with the cofactor", s1, n1 > 0 ? (size_t)n1 : 0);
        errors();
        EC_KEY_free(a);
        EC_KEY_free(b);
    }
    {
        EC_KEY *a = fixed_key(NID_X9_62_prime256v1, "1234");
        EC_POINT *inf = EC_POINT_new(EC_KEY_get0_group(a));
        EC_KEY *nopriv = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        unsigned char s[64];

        check(ECDH_compute_key(s, sizeof(s), inf, a, NULL) == 0, "with the point at infinity");
        errors();
        check(ECDH_compute_key(s, sizeof(s), EC_KEY_get0_public_key(a), nopriv, NULL) == 0,
              "without a private key");
        errors();
        check(ECDH_compute_key(s, (size_t)1 << 31, EC_KEY_get0_public_key(a), a, NULL) == 0,
              "an output longer than INT_MAX");
        errors();
        EC_POINT_free(inf);
        EC_KEY_free(nopriv);
        EC_KEY_free(a);
    }
    {
        static const unsigned char z[] = "shared secret Z";
        static const unsigned char info[] = "info";
        unsigned char out[70];

        check(ECDH_KDF_X9_62(out, sizeof(out), z, sizeof(z) - 1, info, sizeof(info) - 1,
                             EVP_sha256()) == 1, "ECDH_KDF_X9_62, SHA-256");
        hex("X9.63", out, sizeof(out));
        check(ECDH_KDF_X9_62(out, 20, z, sizeof(z) - 1, NULL, 0, EVP_sha1()) == 1,
              "SHA-1, no info");
        hex("X9.63", out, 20);
    }
}

/* Applications' methods: each signing and agreement function counted, then the library's. */
static int calls;
static ECDSA_SIG *(*lib_sign_sig)(const unsigned char *, int, const BIGNUM *, const BIGNUM *,
                                  EC_KEY *);
static int (*lib_verify_sig)(const unsigned char *, int, const ECDSA_SIG *, EC_KEY *);
static int (*lib_ckey)(unsigned char **, size_t *, const EC_POINT *, const EC_KEY *);

static ECDSA_SIG *my_sign_sig(const unsigned char *d, int dl, const BIGNUM *kinv,
                              const BIGNUM *r, EC_KEY *k)
{
    calls++;
    return lib_sign_sig(d, dl, kinv, r, k);
}

static int my_verify_sig(const unsigned char *d, int dl, const ECDSA_SIG *s, EC_KEY *k)
{
    calls += 10;
    return lib_verify_sig(d, dl, s, k);
}

static int my_ckey(unsigned char **ps, size_t *pl, const EC_POINT *p, const EC_KEY *k)
{
    calls += 100;
    return lib_ckey(ps, pl, p, k);
}

static void test_methods(void)
{
    EC_KEY_METHOD *m = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
    EC_KEY_METHOD *none = EC_KEY_METHOD_new(NULL);
    EC_KEY *k = fixed_key(NID_secp384r1, "ABCDEF");
    int (*sign)(int, const unsigned char *, int, unsigned char *, unsigned int *,
                const BIGNUM *, const BIGNUM *, EC_KEY *) = NULL;
    int (*setup)(EC_KEY *, BN_CTX *, BIGNUM **, BIGNUM **) = NULL;
    int (*verify)(int, const unsigned char *, int, const unsigned char *, int, EC_KEY *) = NULL;
    unsigned char sig[200], sec[64];
    unsigned int siglen = 0;
    ECDSA_SIG *s;

    printf("# methods\n");
    EC_KEY_METHOD_get_sign(EC_KEY_OpenSSL(), &sign, &setup, &lib_sign_sig);
    EC_KEY_METHOD_get_verify(EC_KEY_OpenSSL(), &verify, &lib_verify_sig);
    EC_KEY_METHOD_get_compute_key(EC_KEY_OpenSSL(), &lib_ckey);
    EC_KEY_METHOD_set_sign(m, sign, setup, my_sign_sig);
    EC_KEY_METHOD_set_verify(m, verify, my_verify_sig);
    EC_KEY_METHOD_set_compute_key(m, my_ckey);
    EC_KEY_set_method(k, m);
    s = ECDSA_do_sign(digest64, 48, k);
    check(s != NULL && ECDSA_do_verify(digest64, 48, s, k) == 1, "through the method");
    check(ECDSA_sign(0, digest64, 48, sig, &siglen, k) == 1
          && ECDSA_verify(0, digest64, 48, sig, (int)siglen, k) == 1,
          "the library's sign and verify call the method's");
    check(ECDH_compute_key(sec, sizeof(sec), EC_KEY_get0_public_key(k), k, NULL) > 0,
          "ECDH through the method");
    printf("  calls: %d\n", calls);
    ECDSA_SIG_free(s);

    EC_KEY_set_method(k, none);
    check(ECDSA_do_sign(digest64, 48, k) == NULL, "no sign_sig");
    errors();
    check(ECDSA_sign(0, digest64, 48, sig, &siglen, k) == 0, "no sign");
    errors();
    check(ECDSA_sign_setup(k, NULL, NULL, NULL) == 0, "no sign_setup");
    errors();
    printf("  no verify: %d\n", ECDSA_verify(0, digest64, 48, sig, (int)siglen, k));
    errors();
    printf("  no verify_sig: %d\n", ECDSA_do_verify(digest64, 48, NULL, k));
    errors();
    check(ECDH_compute_key(sec, sizeof(sec), EC_KEY_get0_public_key(k), k, NULL) == 0,
          "no compute_key");
    errors();
    EC_KEY_free(k);
    EC_KEY_METHOD_free(m);
    EC_KEY_METHOD_free(none);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    test_curve(NID_X9_62_prime256v1,
               "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    test_curve(NID_secp224r1, "1");
    test_curve(NID_secp521r1, "1A2B3C4D5E6F");
    test_curve(NID_secp256k1, "FEDCBA9876543210");
    test_curve(NID_sect163k1, "3A41434AA99C2EF40C8495B2ED9739CB2155A1E0D");
    test_curve(NID_brainpoolP256r1, "123456789");
    test_curve(NID_sm2, "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
    test_curve(NID_secp112r1, "AB");
    test_verify_edges();
    test_sig();
    test_ecdh();
    test_methods();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
