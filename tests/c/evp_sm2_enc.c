/*
 * Conformance test for the default provider's SM2 encryption (EVP_ASYM_CIPHER-SM2(7),
 * provider-asym_cipher(7)), in TAP format: the algorithm and its parameter lists; messages
 * encrypted and decrypted again with SM3 and another digest; ciphertexts the reference made,
 * decrypted; the size queries; changed, cut, and malformed ciphertexts; short buffers; an empty
 * message; the digest parameter; copies of a context; a public key; and a legacy EC_KEY on
 * SM2's curve.
 *
 * Encryption draws a random k, so only what decrypts again is printed; the fixed ciphertexts
 * were made by the reference with GB/T 32918's example key.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/provider.h>

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

static void names(const char *label, const OSSL_PARAM *p)
{
    printf("  %s:", label);
    if (p == NULL)
        printf(" (none)");
    for (; p != NULL && p->key != NULL; p++)
        printf(" %s/%u", p->key, p->data_type);
    printf("\n");
}

static void print_name(const char *name, void *arg)
{
    (void)arg;
    printf(" %s", name);
}

static const char PRIV[] = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";
static const char MSG[] = "encryption standard";
/* The reference's ciphertexts of MSG: with SM3, and with SHA-256. */
static const char CT_SM3[] =
    "307c02201a1ecd12a0f3b0badf3c241a9c07759a4f6b6a7c5c3cc0edab11edab4d5cf2a2022100c65cf9021869"
    "dbb1a36881f0989d036181c2ce580767041047e77ff98e15c1370420fb74f7ed1a47564f091b529cfb3378a5b8"
    "35ad2fcf512d4d24d0331fa91e93cf04135ec66f780bf2592f9864811e71ed21f8c85bcb";
static const char CT_SHA256[] =
    "307b02206401572ed8e268c7eb79b0ba738e3adf08e2e2483a7e43a2e3d21e5609829c5d02201092ab3b739838"
    "fd3777f4eaacc2611451ef5a291ef695f73d108c8c1616ed2a0420384250525994ca16c61896c6bd7ca5ce411a"
    "b867195cf13b230f04b0686baab404136971ec38dacb683f85803d13f650323f2a23b2";

static EVP_PKEY *sm2_key(const char *x, int priv)
{
    EC_GROUP *g = EC_GROUP_new_by_curve_name(NID_sm2);
    EC_POINT *q = EC_POINT_new(g);
    BIGNUM *d = NULL;
    unsigned char pub[100];
    size_t publen;
    OSSL_PARAM_BLD *b = OSSL_PARAM_BLD_new();
    OSSL_PARAM *ps;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);
    EVP_PKEY *k = NULL;

    BN_hex2bn(&d, x);
    EC_POINT_mul(g, q, d, NULL, NULL, NULL);
    publen = EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED, pub, sizeof(pub), NULL);
    OSSL_PARAM_BLD_push_utf8_string(b, OSSL_PKEY_PARAM_GROUP_NAME, "SM2", 0);
    OSSL_PARAM_BLD_push_octet_string(b, OSSL_PKEY_PARAM_PUB_KEY, pub, publen);
    if (priv)
        OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_PRIV_KEY, d);
    ps = OSSL_PARAM_BLD_to_param(b);
    if (EVP_PKEY_fromdata_init(c) != 1
        || EVP_PKEY_fromdata(c, &k, priv ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, ps) != 1)
        k = NULL;
    OSSL_PARAM_free(ps);
    OSSL_PARAM_BLD_free(b);
    EVP_PKEY_CTX_free(c);
    BN_free(d);
    EC_POINT_free(q);
    EC_GROUP_free(g);
    return k;
}

static unsigned char *octets(const char *h, size_t *len)
{
    long n = 0;
    unsigned char *p = OPENSSL_hexstr2buf(h, &n);

    *len = (size_t)n;
    return p;
}

/* A context for op on k, with the digest md (if any). */
static EVP_PKEY_CTX *ctx_for(EVP_PKEY *k, int (*init)(EVP_PKEY_CTX *), const char *md)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    int r = init(c);

    if (r == 1 && md != NULL) {
        OSSL_PARAM p[2];

        p[0] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_DIGEST, (char *)md, 0);
        p[1] = OSSL_PARAM_construct_end();
        r = EVP_PKEY_CTX_set_params(c, p);
    }
    if (r != 1) {
        printf("  context %d\n", r);
        errors();
    }
    return c;
}

/* Decrypts ct into a buffer of room octets, printing what comes out. */
static int decrypt(EVP_PKEY *k, const char *md, const unsigned char *ct, size_t ctlen,
                   size_t room)
{
    EVP_PKEY_CTX *c = ctx_for(k, EVP_PKEY_decrypt_init, md);
    unsigned char out[300];
    size_t len = room;
    int r = EVP_PKEY_decrypt(c, out, &len, ct, ctlen);

    printf("  decrypt %d", r);
    if (r == 1)
        printf(" %zu [%.*s]", len, (int)len, out);
    printf("\n");
    errors();
    EVP_PKEY_CTX_free(c);
    return r;
}

static void test_algorithm(void)
{
    EVP_ASYM_CIPHER *a = EVP_ASYM_CIPHER_fetch(NULL, "SM2", NULL);

    check(a != NULL, "SM2");
    if (a == NULL) {
        errors();
        return;
    }
    printf("  names:");
    EVP_ASYM_CIPHER_names_do_all(a, print_name, NULL);
    printf("\n  name %s, provider %s\n", EVP_ASYM_CIPHER_get0_name(a),
           OSSL_PROVIDER_get0_name(EVP_ASYM_CIPHER_get0_provider(a)));
    names("gettable", EVP_ASYM_CIPHER_gettable_ctx_params(a));
    names("settable", EVP_ASYM_CIPHER_settable_ctx_params(a));
    EVP_ASYM_CIPHER_free(a);
}

static void test_fixed(EVP_PKEY *k, EVP_PKEY *pub)
{
    size_t l1, l2;
    unsigned char *c1 = octets(CT_SM3, &l1), *c2 = octets(CT_SHA256, &l2);
    unsigned char bad[300];

    check(decrypt(k, NULL, c1, l1, 300) == 1, "the reference's ciphertext");
    check(decrypt(k, "SHA256", c2, l2, 300) == 1, "with SHA-256");
    decrypt(k, NULL, c2, l2, 300);
    decrypt(k, "SM3", c1, l1, 19);
    decrypt(k, "SM3", c1, l1, 18);
    decrypt(pub, NULL, c1, l1, 300);
    {
        EVP_PKEY_CTX *c = ctx_for(k, EVP_PKEY_decrypt_init, NULL);
        size_t len = 0;
        int r = EVP_PKEY_decrypt(c, NULL, &len, c1, l1);

        printf("  plaintext size %d %zu", r, len);
        len = 0;
        r = EVP_PKEY_decrypt(c, NULL, &len, c1, 10);
        printf(" of a cut one %d %zu\n", r, len);
        errors();
        EVP_PKEY_CTX_free(c);
    }
    memcpy(bad, c1, l1);
    bad[l1 - 1] ^= 1;
    printf("  C2 changed:");
    decrypt(k, NULL, bad, l1, 300);
    memcpy(bad, c1, l1);
    bad[80] ^= 1;
    printf("  C3 changed:");
    decrypt(k, NULL, bad, l1, 300);
    memcpy(bad, c1, l1);
    bad[10] ^= 1;
    printf("  C1 changed:");
    decrypt(k, NULL, bad, l1, 300);
    printf("  cut:");
    decrypt(k, NULL, c1, l1 - 1, 300);
    memcpy(bad, c1, l1);
    bad[l1] = 0;
    printf("  an octet more:");
    decrypt(k, NULL, bad, l1 + 1, 300);
    printf("  not DER:");
    decrypt(k, NULL, (const unsigned char *)"\x30\x03\x02\x01\x01", 5, 300);
    {
        /* C3 of 31 octets; an empty C2. */
        static const char short_c3[] =
            "3029020101020101041f"
            "00000000000000000000000000000000000000000000000000000000000000"
            "0400";
        static const char empty_c2[] =
            "302a0201010201010420"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0400";
        size_t ls, le;
        unsigned char *s = octets(short_c3, &ls), *e = octets(empty_c2, &le);

        printf("  a short C3:");
        decrypt(k, NULL, s, ls, 300);
        printf("  an empty C2:");
        decrypt(k, NULL, e, le, 300);
        OPENSSL_free(s);
        OPENSSL_free(e);
    }
    OPENSSL_free(c1);
    OPENSSL_free(c2);
}

static void test_encrypt(EVP_PKEY *k, EVP_PKEY *pub)
{
    static const char *const mds[] = { NULL, "SM3", "SHA256", "SHA3-512", "MD5" };
    unsigned char ct[400];
    size_t len, i;
    EVP_PKEY_CTX *c;
    int r;

    for (i = 0; i < sizeof(mds) / sizeof(mds[0]); i++) {
        c = ctx_for(pub, EVP_PKEY_encrypt_init, mds[i]);
        len = 0;
        r = EVP_PKEY_encrypt(c, NULL, &len, (const unsigned char *)MSG, strlen(MSG));
        printf("  %s: size %d %zu", mds[i] != NULL ? mds[i] : "default", r, len);
        len = sizeof(ct);
        r = EVP_PKEY_encrypt(c, ct, &len, (const unsigned char *)MSG, strlen(MSG));
        printf(" encrypt %d\n", r);
        errors();
        if (r == 1)
            decrypt(k, mds[i], ct, len, 300);
        EVP_PKEY_CTX_free(c);
    }
    c = ctx_for(k, EVP_PKEY_encrypt_init, NULL);
    len = 50;
    r = EVP_PKEY_encrypt(c, ct, &len, (const unsigned char *)MSG, strlen(MSG));
    printf("  a short buffer %d\n", r);
    errors();
    len = sizeof(ct);
    r = EVP_PKEY_encrypt(c, ct, &len, (const unsigned char *)"", 0);
    printf("  an empty message %d\n", r);
    errors();
    len = sizeof(ct);
    r = EVP_PKEY_encrypt(c, ct, &len, (const unsigned char *)"x", 1);
    printf("  one octet %d\n", r);
    errors();
    if (r == 1)
        decrypt(k, NULL, ct, len, 300);
    {
        char md[40] = "?";
        OSSL_PARAM g[2];
        EVP_PKEY_CTX *fresh = ctx_for(k, EVP_PKEY_encrypt_init, NULL);
        EVP_PKEY_CTX *d;

        g[0] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_DIGEST, md, sizeof(md));
        g[1] = OSSL_PARAM_construct_end();
        r = EVP_PKEY_CTX_get_params(fresh, g);
        printf("  digest before use %d [%s]", r, md);
        r = EVP_PKEY_CTX_get_params(c, g);
        printf(" after %d [%s]\n", r, md);
        names("settable", EVP_PKEY_CTX_settable_params(c));
        names("gettable", EVP_PKEY_CTX_gettable_params(c));
        d = EVP_PKEY_CTX_dup(c);
        check(d != NULL, "a copy");
        len = sizeof(ct);
        r = EVP_PKEY_encrypt(d, ct, &len, (const unsigned char *)MSG, strlen(MSG));
        printf("  the copy encrypts %d\n", r);
        if (r == 1)
            decrypt(k, NULL, ct, len, 300);
        EVP_PKEY_CTX_free(d);
        EVP_PKEY_CTX_free(fresh);
    }
    {
        OSSL_PARAM p[3];

        p[0] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_DIGEST, "nosuch", 0);
        p[1] = OSSL_PARAM_construct_end();
        printf("  digest nosuch %d\n", EVP_PKEY_CTX_set_params(c, p));
        errors();
        p[0] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_DIGEST, "SHA256", 0);
        p[1] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PROPERTIES,
                                                "provider=default", 0);
        p[2] = OSSL_PARAM_construct_end();
        printf("  SHA256 with properties %d\n", EVP_PKEY_CTX_set_params(c, p));
        errors();
        p[0] = OSSL_PARAM_construct_end();
        printf("  empty %d\n", EVP_PKEY_CTX_set_params(c, p));
    }
    EVP_PKEY_CTX_free(c);
}

/* A legacy EC_KEY on SM2's curve encrypts and decrypts through the provider. */
static void test_legacy(void)
{
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_sm2);
    EVP_PKEY *k = EVP_PKEY_new();
    BIGNUM *d = NULL;
    EC_POINT *q = EC_POINT_new(EC_KEY_get0_group(ec));
    size_t l;
    unsigned char *ct = octets(CT_SM3, &l);

    BN_hex2bn(&d, PRIV);
    EC_POINT_mul(EC_KEY_get0_group(ec), q, d, NULL, NULL, NULL);
    EC_KEY_set_private_key(ec, d);
    EC_KEY_set_public_key(ec, q);
    check(EVP_PKEY_set1_EC_KEY(k, ec) == 1, "a legacy EC_KEY on SM2's curve");
    decrypt(k, NULL, ct, l, 300);
    OPENSSL_free(ct);
    EC_POINT_free(q);
    BN_free(d);
    EC_KEY_free(ec);
    EVP_PKEY_free(k);
}

int main(void)
{
    EVP_PKEY *k = sm2_key(PRIV, 1), *pub = sm2_key(PRIV, 0);

    check(k != NULL && pub != NULL, "GB/T 32918's key");
    test_algorithm();
    test_fixed(k, pub);
    test_encrypt(k, pub);
    test_legacy();
    errors();
    EVP_PKEY_free(k);
    EVP_PKEY_free(pub);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
