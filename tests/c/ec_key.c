/*
 * Conformance test for EC keys (EC_KEY_new(3), EC_KEY_METHOD_new(3), d2i_ECPrivateKey(3),
 * EC_KEY_print(3)), in TAP format: keys made by curve name and from groups, their private and
 * public keys set, generated, checked, copied, and encoded every way (octets, ECPrivateKey
 * with and without parameters and public key, ECParameters, the public key's octets, BIO and
 * FILE forms), and printed; the flags and forms; and applications' methods, whose functions
 * the key calls. Generated keys are random, so only what doesn't depend on that is printed.
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
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/objects.h>
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

/* The error queue, emptied: each entry's library and reason, and its text. */
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

/* What a memory BIO holds, printed and emptied. */
static void show(BIO *mem)
{
    char *text;
    long n = BIO_get_mem_data(mem, &text);

    printf("%.*s", (int)n, text);
    (void)BIO_reset(mem);
}

/* A key's public key, as uncompressed octets. */
static void pub(const char *label, const EC_KEY *k)
{
    unsigned char *buf = NULL;
    size_t len = EC_KEY_key2buf(k, POINT_CONVERSION_UNCOMPRESSED, &buf, NULL);

    hex(label, buf, len);
    OPENSSL_free(buf);
}

/* An encoding through i2d and back through d2i. */
#define ROUNDTRIP(what, type, key, i2d, d2i)                                          \
    do {                                                                              \
        unsigned char *der_ = NULL;                                                   \
        const unsigned char *p_;                                                      \
        int len_ = i2d(key, &der_);                                                   \
        type *back_;                                                                  \
                                                                                      \
        hex(what, der_, len_ > 0 ? (size_t)len_ : 0);                                 \
        errors();                                                                     \
        p_ = der_;                                                                    \
        back_ = len_ > 0 ? d2i(NULL, &p_, len_) : NULL;                               \
        printf("  back: %s, consumed %d\n", back_ != NULL ? "decoded" : "refused",    \
               len_ > 0 ? (int)(p_ - der_) : 0);                                      \
        errors();                                                                     \
        if (back_ != NULL)                                                            \
            describe("decoded", back_);                                               \
        EC_KEY_free(back_);                                                           \
        OPENSSL_free(der_);                                                           \
    } while (0)

/* A key's state. */
static void describe(const char *label, const EC_KEY *k)
{
    const EC_GROUP *g = EC_KEY_get0_group(k);

    printf("  %s: curve %d, flags %d, enc %u, form %d, explicit %d, can sign %d\n", label,
           g != NULL ? EC_GROUP_get_curve_name(g) : -1, EC_KEY_get_flags(k),
           EC_KEY_get_enc_flags(k), (int)EC_KEY_get_conv_form(k),
           EC_KEY_decoded_from_explicit_params(k), g != NULL ? EC_KEY_can_sign(k) : -1);
    bn("priv", EC_KEY_get0_private_key(k));
    if (EC_KEY_get0_public_key(k) != NULL && g != NULL)
        pub("pub", k);
    else
        printf("  pub: (none)\n");
}

/* Keys with fixed private keys on curves of each kind. */
static void test_fixed(int nid, const char *priv_hex)
{
    EC_KEY *k = EC_KEY_new_by_curve_name(nid);
    BIGNUM *priv = num(priv_hex);
    EC_POINT *P;
    BIO *mem = BIO_new(BIO_s_mem());
    unsigned char oct[200];
    size_t n;

    printf("# %s\n", OBJ_nid2sn(nid));
    check(k != NULL, "EC_KEY_new_by_curve_name");
    describe("new", k);
    check(EC_KEY_check_key(k) == 0, "no public key to check");
    errors();
    check(EC_KEY_set_private_key(k, priv) == 1, "EC_KEY_set_private_key");
    check(EC_KEY_get0_private_key(k) != priv, "a copy");
    P = EC_POINT_new(EC_KEY_get0_group(k));
    EC_POINT_mul(EC_KEY_get0_group(k), P, priv, NULL, NULL, NULL);
    check(EC_KEY_set_public_key(k, P) == 1, "EC_KEY_set_public_key");
    check(EC_KEY_get0_public_key(k) != P, "a copy");
    check(EC_KEY_check_key(k) == 1, "EC_KEY_check_key");
    errors();
    describe("key", k);

    n = EC_KEY_priv2oct(k, NULL, 0);
    printf("  priv2oct length: %zu\n", n);
    check(EC_KEY_priv2oct(k, oct, n - 1) == 0, "priv2oct into too little");
    errors();
    n = EC_KEY_priv2oct(k, oct, sizeof(oct));
    hex("priv2oct", oct, n);
    {
        unsigned char *buf = NULL;
        size_t len = EC_KEY_priv2buf(k, &buf);

        check(len == n && memcmp(buf, oct, n) == 0, "EC_KEY_priv2buf");
        OPENSSL_free(buf);
    }

    /* The encodings. */
    ROUNDTRIP("ECPrivateKey", EC_KEY, k, i2d_ECPrivateKey, d2i_ECPrivateKey);
    EC_KEY_set_enc_flags(k, EC_PKEY_NO_PARAMETERS);
    {
        unsigned char *der = NULL;
        int len = i2d_ECPrivateKey(k, &der);
        const unsigned char *p = der;
        EC_KEY *into = EC_KEY_new_by_curve_name(nid);

        hex("without parameters", der, len > 0 ? (size_t)len : 0);
        check(d2i_ECPrivateKey(NULL, &p, len) == NULL, "can't be decoded alone");
        errors();
        p = der;
        check(d2i_ECPrivateKey(&into, &p, len) == into, "but into a key with the group");
        describe("into", into);
        EC_KEY_free(into);
        OPENSSL_free(der);
    }
    EC_KEY_set_enc_flags(k, EC_PKEY_NO_PUBKEY);
    ROUNDTRIP("without the public key", EC_KEY, k, i2d_ECPrivateKey, d2i_ECPrivateKey);
    EC_KEY_set_enc_flags(k, 0);
    EC_KEY_set_conv_form(k, POINT_CONVERSION_COMPRESSED);
    ROUNDTRIP("compressed", EC_KEY, k, i2d_ECPrivateKey, d2i_ECPrivateKey);
    EC_KEY_set_asn1_flag(k, OPENSSL_EC_EXPLICIT_CURVE);
    ROUNDTRIP("explicit", EC_KEY, k, i2d_ECPrivateKey, d2i_ECPrivateKey);
    ROUNDTRIP("ECParameters", EC_KEY, k, i2d_ECParameters, d2i_ECParameters);
    EC_KEY_set_asn1_flag(k, OPENSSL_EC_NAMED_CURVE);
    EC_KEY_set_conv_form(k, POINT_CONVERSION_UNCOMPRESSED);

    /* The public key's octets. */
    {
        unsigned char *buf = NULL, *q;
        const unsigned char *p;
        int len = i2o_ECPublicKey(k, NULL);
        EC_KEY *other = EC_KEY_new_by_curve_name(nid);

        printf("  i2o_ECPublicKey length: %d\n", len);
        check(i2o_ECPublicKey(k, &buf) == len, "i2o_ECPublicKey, allocating");
        hex("public", buf, (size_t)len);
        q = OPENSSL_malloc(len + 4);
        {
            unsigned char *w = q;

            check(i2o_ECPublicKey(k, &w) == len && w == q + len, "into a buffer, advancing");
        }
        p = buf;
        check(o2i_ECPublicKey(&other, &p, len) == other && p == buf + len, "o2i_ECPublicKey");
        describe("other", other);
        p = buf;
        check(o2i_ECPublicKey(&other, &p, len - 1) == NULL, "cut short");
        errors();
        OPENSSL_free(q);
        OPENSSL_free(buf);
        EC_KEY_free(other);
    }

    /* Printing. */
    check(EC_KEY_print(mem, k, 2) == 1, "EC_KEY_print");
    show(mem);
    check(ECParameters_print(mem, k) == 1, "ECParameters_print");
    show(mem);
    {
        EC_KEY *pubonly = EC_KEY_new_by_curve_name(nid);

        EC_KEY_set_public_key(pubonly, EC_KEY_get0_public_key(k));
        check(EC_KEY_print(mem, pubonly, 0) == 1, "EC_KEY_print, a public key");
        show(mem);
        EC_KEY_free(pubonly);
    }

    BIO_free(mem);
    BN_free(priv);
    EC_POINT_free(P);
    EC_KEY_free(k);
}

/* Generation, checks of bad keys, setting by coordinates. */
static void test_generate(void)
{
    static const int nids[] = { NID_X9_62_prime256v1, NID_secp384r1, NID_secp256k1,
                                NID_sm2, NID_sect163k1, NID_brainpoolP256r1 };
    size_t i;

    printf("# generation\n");
    for (i = 0; i < sizeof(nids) / sizeof(nids[0]); i++) {
        EC_KEY *k = EC_KEY_new_by_curve_name(nids[i]);
        const EC_GROUP *g = EC_KEY_get0_group(k);
        EC_POINT *P = EC_POINT_new(g);
        int ok;

        ok = EC_KEY_generate_key(k);
        EC_POINT_mul(g, P, EC_KEY_get0_private_key(k), NULL, NULL, NULL);
        printf("  %s: generated %d, check %d, flags %d, priv bits <= order %d, pub = priv G %d\n",
               OBJ_nid2sn(nids[i]), ok, EC_KEY_check_key(k), EC_KEY_get_flags(k),
               BN_num_bits(EC_KEY_get0_private_key(k)) <= EC_GROUP_order_bits(g),
               EC_POINT_cmp(g, P, EC_KEY_get0_public_key(k), NULL) == 0);
        errors();
        EC_POINT_free(P);
        EC_KEY_free(k);
    }
    {
        EC_KEY *k = EC_KEY_new();

        check(EC_KEY_generate_key(k) == 0, "generating without a group");
        errors();
        check(EC_KEY_generate_key(NULL) == 0, "generating NULL");
        errors();
        EC_KEY_free(k);
    }
}

static void test_bad_keys(void)
{
    EC_KEY *k = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    const EC_GROUP *g = EC_KEY_get0_group(k);
    BIGNUM *x = BN_new(), *y = BN_new(), *one = num("1");
    EC_POINT *P = EC_POINT_new(g);
    BIGNUM *order = BN_dup(EC_GROUP_get0_order(g));

    printf("# checks\n");
    EC_POINT_set_to_infinity(g, P);
    EC_KEY_set_public_key(k, P);
    check(EC_KEY_check_key(k) == 0, "a public key at infinity");
    errors();

    EC_POINT_get_affine_coordinates(g, EC_GROUP_get0_generator(g), x, y, NULL);
    check(EC_KEY_set_public_key_affine_coordinates(k, x, y) == 1,
          "EC_KEY_set_public_key_affine_coordinates");
    errors();
    BN_add_word(y, 1);
    check(EC_KEY_set_public_key_affine_coordinates(k, x, y) == 0, "off the curve");
    errors();
    BN_sub_word(y, 1);
    BN_add(y, y, EC_GROUP_get0_field(g));
    check(EC_KEY_set_public_key_affine_coordinates(k, x, y) == 0, "y + p");
    errors();
    check(EC_KEY_set_public_key_affine_coordinates(k, NULL, y) == 0, "a NULL x");
    errors();

    EC_KEY_set_public_key(k, EC_GROUP_get0_generator(g));
    check(EC_KEY_set_private_key(k, one) == 1 && EC_KEY_check_key(k) == 1,
          "private key 1 with G");
    errors();
    BN_add_word(one, 1);
    EC_KEY_set_private_key(k, one);
    check(EC_KEY_check_key(k) == 0, "private key 2 with G");
    errors();
    EC_KEY_set_private_key(k, order);
    check(EC_KEY_check_key(k) == 0, "the order as the private key");
    errors();
    BN_zero(one);
    EC_KEY_set_private_key(k, one);
    check(EC_KEY_check_key(k) == 0, "zero as the private key");
    errors();
    check(EC_KEY_set_private_key(k, NULL) == 0 && EC_KEY_get0_private_key(k) == NULL,
          "EC_KEY_set_private_key(NULL) clears it, returning 0");
    errors();
    check(EC_KEY_check_key(k) == 1, "then only the public key is checked");
    {
        EC_KEY *empty = EC_KEY_new();

        check(EC_KEY_set_private_key(empty, one) == 0, "a private key without a group");
        errors();
        check(EC_KEY_check_key(empty) == 0, "checking a key without a group");
        errors();
        check(EC_KEY_oct2key(empty, (const unsigned char *)"\x04", 1, NULL) == 0,
              "oct2key without a group");
        errors();
        printf("  decoded from explicit: %d, key2buf %zu\n",
               EC_KEY_decoded_from_explicit_params(empty),
               EC_KEY_key2buf(empty, POINT_CONVERSION_UNCOMPRESSED, NULL, NULL));
        EC_KEY_free(empty);
    }
    {
        /* A cofactor-4 curve: the order check of the public key. */
        EC_KEY *b = EC_KEY_new_by_curve_name(NID_sect163r1);
        const EC_GROUP *bg = EC_KEY_get0_group(b);
        BIGNUM *h = NULL;

        printf("  sect163r1 cofactor: ");
        h = BN_dup(EC_GROUP_get0_cofactor(bg));
        BN_print_fp(stdout, h);
        printf("\n");
        EC_KEY_set_public_key(b, EC_GROUP_get0_generator(bg));
        check(EC_KEY_check_key(b) == 1, "a binary curve's generator");
        errors();
        BN_free(h);
        EC_KEY_free(b);
    }

    BN_free(x);
    BN_free(y);
    BN_free(one);
    BN_free(order);
    EC_POINT_free(P);
    EC_KEY_free(k);
}

/* Copies, references, flags, forms. */
static void test_object(void)
{
    EC_KEY *k = EC_KEY_new_by_curve_name(NID_secp256k1), *c, *d, *e;
    BIGNUM *priv = num("C0FFEE");
    EC_POINT *P;
    EC_GROUP *g2 = EC_GROUP_new_by_curve_name(NID_sm2);

    printf("# the object\n");
    P = EC_POINT_new(EC_KEY_get0_group(k));
    EC_POINT_mul(EC_KEY_get0_group(k), P, priv, NULL, NULL, NULL);
    EC_KEY_set_private_key(k, priv);
    EC_KEY_set_public_key(k, P);
    EC_KEY_set_flags(k, EC_FLAG_COFACTOR_ECDH | 0x4000);
    EC_KEY_set_enc_flags(k, EC_PKEY_NO_PARAMETERS);
    EC_KEY_set_conv_form(k, POINT_CONVERSION_HYBRID);
    printf("  group form after set_conv_form: %d\n",
           (int)EC_GROUP_get_point_conversion_form(EC_KEY_get0_group(k)));
    EC_KEY_clear_flags(k, 0x4000);
    describe("key", k);

    c = EC_KEY_dup(k);
    check(c != NULL, "EC_KEY_dup");
    describe("dup", c);
    check(EC_KEY_get0_group(c) != EC_KEY_get0_group(k), "with its own group");
    d = EC_KEY_new();
    check(EC_KEY_copy(d, k) == d, "EC_KEY_copy");
    describe("copy", d);
    check(EC_KEY_copy(NULL, k) == NULL, "EC_KEY_copy to NULL");
    errors();
    e = EC_KEY_new();
    check(EC_KEY_copy(k, e) == k, "copying an empty key keeps the group and keys");
    describe("after", k);

    check(EC_KEY_up_ref(c) == 1, "EC_KEY_up_ref");
    EC_KEY_free(c);
    describe("still", c);
    check(EC_KEY_get0_engine(c) == NULL, "no engine");

    check(EC_KEY_set_group(d, g2) == 1, "EC_KEY_set_group to SM2");
    describe("SM2 group", d);
    check(EC_KEY_get0_group(d) != g2, "a copy of it");
    check(EC_KEY_precompute_mult(d, NULL) == 1, "EC_KEY_precompute_mult");
    printf("  precomputed on the key's group: %d\n",
           EC_GROUP_have_precompute_mult(EC_KEY_get0_group(d)));
    {
        EC_KEY *n = EC_KEY_new();

        check(EC_KEY_precompute_mult(n, NULL) == 0, "without a group");
        EC_KEY_set_conv_form(n, POINT_CONVERSION_COMPRESSED);
        EC_KEY_set_asn1_flag(n, 0);
        describe("no group", n);
        EC_KEY_free(n);
    }
    {
        EC_KEY *x = EC_KEY_new_ex(NULL, NULL), *y = EC_KEY_new_by_curve_name_ex(NULL, NULL,
                                                                                 NID_secp224r1);

        check(x != NULL && y != NULL, "EC_KEY_new_ex, EC_KEY_new_by_curve_name_ex");
        check(EC_KEY_new_by_curve_name(NID_undef) == NULL, "an unknown curve");
        errors();
        EC_KEY_free(x);
        EC_KEY_free(y);
    }
    EC_KEY_free(NULL);

    BN_free(priv);
    EC_POINT_free(P);
    EC_GROUP_free(g2);
    EC_KEY_free(c);
    EC_KEY_free(d);
    EC_KEY_free(e);
    EC_KEY_free(k);
}

/* Octets in, and malformed private keys. */
static void test_octets(void)
{
    EC_KEY *k = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    const EC_GROUP *g = EC_KEY_get0_group(k);
    unsigned char *buf = NULL;
    size_t len = EC_POINT_point2buf(g, EC_GROUP_get0_generator(g), POINT_CONVERSION_COMPRESSED,
                                    &buf, NULL);
    static const unsigned char priv[] = { 0, 0, 1, 2, 3 };

    printf("# octets\n");
    check(EC_KEY_oct2key(k, buf, len, NULL) == 1, "EC_KEY_oct2key, compressed");
    describe("key", k);
    check(EC_KEY_oct2key(k, buf, len - 1, NULL) == 0, "cut short");
    errors();
    check(EC_KEY_oct2priv(k, priv, sizeof(priv)) == 1, "EC_KEY_oct2priv, leading zeros");
    describe("key", k);
    check(EC_KEY_oct2priv(k, priv, 0) == 1, "of nothing");
    bn("priv", EC_KEY_get0_private_key(k));
    OPENSSL_free(buf);
    EC_KEY_free(k);
}

/* Malformed ECPrivateKey encodings. */
static void test_malformed(void)
{
    static const char *cases[] = {
        /* version 1, private key 01, prime256v1 */
        "3012020101040101a00a06082a8648ce3d030107",
        /* no parameters */
        "3006020101040101",
        /* version 0 */
        "3012020100040101a00a06082a8648ce3d030107",
        /* an empty private key */
        "30110201010400a00a06082a8648ce3d030107",
        /* a public key off the curve */
        "3058020101040101a00a06082a8648ce3d030107a144034200040102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
        /* a public key cut short */
        "3019020101040101a00a06082a8648ce3d030107a1050303000401",
        /* an unknown curve */
        "3011020101040101a00906072a8648ce3d0399",
        /* a private key longer than the order */
        "30350201010424ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa00a06082a8648ce3d030107",
        /* a private key of zeros */
        "303102010104200000000000000000000000000000000000000000000000000000000000000000a00a06082a8648ce3d030107",
        /* trailing octets */
        "3012020101040101a00a06082a8648ce3d03010700",
        /* not a SEQUENCE */
        "020101",
    };
    size_t i;

    printf("# malformed ECPrivateKey\n");
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        unsigned char der[200];
        size_t n = 0;
        const char *h = cases[i];
        const unsigned char *p = der;
        EC_KEY *k;

        while (*h != '\0') {
            unsigned int v;

            if (*h == ' ') {
                h++;
                continue;
            }
            sscanf(h, "%2x", &v);
            der[n++] = (unsigned char)v;
            h += 2;
        }
        k = d2i_ECPrivateKey(NULL, &p, (long)n);
        printf("  case %zu: %s, consumed %ld\n", i, k != NULL ? "decoded" : "refused",
               (long)(p - der));
        errors();
        if (k != NULL) {
            describe("key", k);
            printf("  check %d\n", EC_KEY_check_key(k));
            errors();
        }
        EC_KEY_free(k);
    }
    check(1, "malformed encodings");
}

/* The BIO and FILE forms. */
static void test_io(void)
{
    EC_KEY *k = EC_KEY_new_by_curve_name(NID_secp384r1), *back;
    BIGNUM *priv = num("123456789");
    EC_POINT *P = EC_POINT_new(EC_KEY_get0_group(k));
    BIO *mem = BIO_new(BIO_s_mem());
    FILE *f = tmpfile();

    printf("# BIO and FILE\n");
    EC_POINT_mul(EC_KEY_get0_group(k), P, priv, NULL, NULL, NULL);
    EC_KEY_set_private_key(k, priv);
    EC_KEY_set_public_key(k, P);
    check(i2d_ECPrivateKey_bio(mem, k) == 1, "i2d_ECPrivateKey_bio");
    back = d2i_ECPrivateKey_bio(mem, NULL);
    check(back != NULL, "d2i_ECPrivateKey_bio");
    describe("back", back);
    EC_KEY_free(back);
    check(i2d_ECPrivateKey_fp(f, k) == 1, "i2d_ECPrivateKey_fp");
    rewind(f);
    back = d2i_ECPrivateKey_fp(f, NULL);
    check(back != NULL, "d2i_ECPrivateKey_fp");
    EC_KEY_free(back);
    fflush(stdout);
    check(EC_KEY_print_fp(stdout, k, 1) == 1, "EC_KEY_print_fp");
    fflush(stdout);
    check(ECParameters_print_fp(stdout, k) == 1, "ECParameters_print_fp");
    fflush(stdout);
    /* Not EC_KEY_print of NULL: OpenSSL's dereferences it. */
    fclose(f);
    BIO_free(mem);
    BN_free(priv);
    EC_POINT_free(P);
    EC_KEY_free(k);
}

/* An application's method: each function counts its calls. */
static int calls_init, calls_finish, calls_copy, calls_group, calls_priv, calls_pub, calls_keygen;
static int refuse_priv;

static int my_init(EC_KEY *k)
{
    (void)k;
    calls_init++;
    return 1;
}

static void my_finish(EC_KEY *k)
{
    (void)k;
    calls_finish++;
}

static int my_copy(EC_KEY *d, const EC_KEY *s)
{
    (void)d;
    (void)s;
    calls_copy++;
    return 1;
}

static int my_set_group(EC_KEY *k, const EC_GROUP *g)
{
    (void)k;
    (void)g;
    calls_group++;
    return 1;
}

static int my_set_private(EC_KEY *k, const BIGNUM *p)
{
    (void)k;
    (void)p;
    calls_priv++;
    return !refuse_priv;
}

static int my_set_public(EC_KEY *k, const EC_POINT *p)
{
    (void)k;
    (void)p;
    calls_pub++;
    return 1;
}

static int my_keygen(EC_KEY *k)
{
    BIGNUM *one = num("1");
    int ok = EC_KEY_set_private_key(k, one)
             && EC_KEY_set_public_key(k, EC_GROUP_get0_generator(EC_KEY_get0_group(k)));

    BN_free(one);
    calls_keygen++;
    return ok;
}

static void counts(void)
{
    printf("  calls: init %d finish %d copy %d group %d priv %d pub %d keygen %d\n", calls_init,
           calls_finish, calls_copy, calls_group, calls_priv, calls_pub, calls_keygen);
}

static void test_method(void)
{
    const EC_KEY_METHOD *def = EC_KEY_OpenSSL();
    EC_KEY_METHOD *m = EC_KEY_METHOD_new(def), *empty = EC_KEY_METHOD_new(NULL);
    int (*init)(EC_KEY *) = NULL;
    void (*finish)(EC_KEY *) = NULL;
    int (*copy)(EC_KEY *, const EC_KEY *) = NULL;
    int (*set_group)(EC_KEY *, const EC_GROUP *) = NULL;
    int (*set_private)(EC_KEY *, const BIGNUM *) = NULL;
    int (*set_public)(EC_KEY *, const EC_POINT *) = NULL;
    int (*keygen)(EC_KEY *) = NULL;
    int (*ckey)(unsigned char **, size_t *, const EC_POINT *, const EC_KEY *) = NULL;
    int (*sign)(int, const unsigned char *, int, unsigned char *, unsigned int *,
                const BIGNUM *, const BIGNUM *, EC_KEY *) = NULL;
    int (*sign_setup)(EC_KEY *, BN_CTX *, BIGNUM **, BIGNUM **) = NULL;
    ECDSA_SIG *(*sign_sig)(const unsigned char *, int, const BIGNUM *, const BIGNUM *,
                           EC_KEY *) = NULL;
    int (*verify)(int, const unsigned char *, int, const unsigned char *, int, EC_KEY *) = NULL;
    int (*verify_sig)(const unsigned char *, int, const ECDSA_SIG *, EC_KEY *) = NULL;
    EC_KEY *k, *c;

    printf("# methods\n");
    check(EC_KEY_get_default_method() == def, "the default is EC_KEY_OpenSSL");
    EC_KEY_METHOD_get_init(def, &init, &finish, &copy, &set_group, &set_private, &set_public);
    printf("  default init: %d %d %d %d %d %d\n", init != NULL, finish != NULL, copy != NULL,
           set_group != NULL, set_private != NULL, set_public != NULL);
    EC_KEY_METHOD_get_keygen(def, &keygen);
    EC_KEY_METHOD_get_compute_key(def, &ckey);
    EC_KEY_METHOD_get_sign(def, &sign, &sign_setup, &sign_sig);
    EC_KEY_METHOD_get_verify(def, &verify, &verify_sig);
    printf("  default operations: %d %d %d %d %d %d %d\n", keygen != NULL, ckey != NULL,
           sign != NULL, sign_setup != NULL, sign_sig != NULL, verify != NULL,
           verify_sig != NULL);
    EC_KEY_METHOD_get_keygen(empty, &keygen);
    printf("  an empty method's keygen: %d\n", keygen != NULL);
    EC_KEY_METHOD_get_init(m, NULL, NULL, NULL, NULL, NULL, NULL);
    EC_KEY_METHOD_get_sign(m, NULL, NULL, NULL);
    EC_KEY_METHOD_get_verify(m, NULL, NULL);
    EC_KEY_METHOD_get_keygen(m, NULL);
    EC_KEY_METHOD_get_compute_key(m, NULL);

    /* The default's signing and agreement functions, copied into an empty method. */
    EC_KEY_METHOD_set_compute_key(empty, ckey);
    EC_KEY_METHOD_set_sign(empty, sign, sign_setup, sign_sig);
    EC_KEY_METHOD_set_verify(empty, verify, verify_sig);
    {
        int (*ckey2)(unsigned char **, size_t *, const EC_POINT *, const EC_KEY *) = NULL;
        int (*sign2)(int, const unsigned char *, int, unsigned char *, unsigned int *,
                     const BIGNUM *, const BIGNUM *, EC_KEY *) = NULL;
        int (*verify2)(int, const unsigned char *, int, const unsigned char *, int,
                       EC_KEY *) = NULL;

        EC_KEY_METHOD_get_compute_key(empty, &ckey2);
        EC_KEY_METHOD_get_sign(empty, &sign2, NULL, NULL);
        EC_KEY_METHOD_get_verify(empty, &verify2, NULL);
        check(ckey2 == ckey && sign2 == sign && verify2 == verify,
              "EC_KEY_METHOD_set_compute_key, _set_sign, _set_verify");
        EC_KEY_METHOD_set_compute_key(empty, NULL);
        EC_KEY_METHOD_set_sign(empty, NULL, NULL, NULL);
        EC_KEY_METHOD_set_verify(empty, NULL, NULL);
    }
    EC_KEY_METHOD_set_init(m, my_init, my_finish, my_copy, my_set_group, my_set_private,
                           my_set_public);
    EC_KEY_METHOD_set_keygen(m, my_keygen);
    EC_KEY_METHOD_get_init(m, &init, NULL, NULL, NULL, NULL, NULL);
    check(init == my_init, "EC_KEY_METHOD_set_init");

    EC_KEY_set_default_method(m);
    check(EC_KEY_get_default_method() == m, "EC_KEY_set_default_method");
    k = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    counts();
    check(EC_KEY_get_method(k) == m, "a new key takes it");
    check(EC_KEY_generate_key(k) == 1, "its keygen");
    counts();
    describe("generated", k);
    c = EC_KEY_dup(k);
    counts();
    refuse_priv = 1;
    check(EC_KEY_set_private_key(k, EC_KEY_get0_private_key(c)) == 0, "a refused private key");
    errors();
    refuse_priv = 0;
    check(EC_KEY_set_method(k, def) == 1, "EC_KEY_set_method");
    counts();
    EC_KEY_free(k);
    EC_KEY_free(c);
    counts();
    EC_KEY_set_default_method(NULL);
    check(EC_KEY_get_default_method() == def, "the default again");
    {
        EC_KEY *n = EC_KEY_new_method(NULL);
        EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_secp224r1);

        check(n != NULL && EC_KEY_get_method(n) == def, "EC_KEY_new_method");
        EC_KEY_set_method(n, empty);
        EC_KEY_set_group(n, grp);
        check(EC_KEY_generate_key(n) == 0, "a method without keygen");
        errors();
        EC_GROUP_free(grp);
        EC_KEY_free(n);
    }
    EC_KEY_METHOD_free(m);
    EC_KEY_METHOD_free(empty);
    EC_KEY_METHOD_free((EC_KEY_METHOD *)def);
    check(1, "EC_KEY_METHOD_free of the built-in method does nothing");
}

static void ex_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
    (void)parent;
    (void)ad;
    (void)idx;
    (void)argl;
    (void)argp;
    printf("  ex_data freed: %s\n", (const char *)ptr);
}

static void test_ex_data(void)
{
    int idx = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, ex_free);
    EC_KEY *k = EC_KEY_new();

    printf("# ex_data\n");
    check(EC_KEY_set_ex_data(k, idx, "value") == 1, "EC_KEY_set_ex_data");
    check(strcmp(EC_KEY_get_ex_data(k, idx), "value") == 0, "EC_KEY_get_ex_data");
    EC_KEY_free(k);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    test_fixed(NID_X9_62_prime256v1,
               "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    test_fixed(NID_secp256k1, "1");
    test_fixed(NID_sect163k1, "3A41434AA99C2EF40C8495B2ED9739CB2155A1E0D");
    test_fixed(NID_sm2, "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
    test_fixed(NID_secp112r1, "DB7C2ABF62E35E7628DFAC6561C4");
    test_generate();
    test_bad_keys();
    test_object();
    test_octets();
    test_malformed();
    test_io();
    test_method();
    test_ex_data();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
