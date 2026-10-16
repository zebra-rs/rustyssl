/*
 * Conformance test for the default provider's SM2 signatures (EVP_SIGNATURE-SM2(7),
 * provider-signature(7)), in TAP format: the algorithm and its parameter lists; messages signed
 * through a digest context with SM3 (the Z value over the distinguishing ID, set or not) and
 * verified; digests signed and verified as they are; signatures the reference made, verified,
 * changed, and malformed; the context's parameters (the algorithm identifier, digest, digest
 * size) and their errors; copies of a context mid-message; other digests refused; and a
 * legacy EC_KEY on SM2's curve.
 *
 * SM2's nonces are random, so the signatures made here are only verified; the fixed ones were
 * made by the reference with GB/T 32918's example key.
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

static void hex(const char *label, const unsigned char *p, size_t len)
{
    size_t i;

    printf("  %s (%zu):", label, len);
    for (i = 0; i < len; i++)
        printf("%s%02x", i % 40 == 0 && i > 0 ? "\n    " : "", p[i]);
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
static const char ID[] = "1234567812345678";
static const char MSG[] = "message digest";
/* The reference's signatures of MSG with SM3: without an ID, with ID; and of 32 octets 0x5a. */
static const char SIG_NO_ID[] =
    "3045022100dc01688490a9e4de82a29490c0ed48230976053ada6bd4f1d71e9d3a45f7d767022072fe107e9cb4"
    "cf769f3b3e1bb5d01441dd4eecb5034530478a5c4bd51976221b";
static const char SIG_ID[] =
    "3046022100fda2e30b3f09078d6fdefd9aa0eb011c6bfb424bb014c58d5d47ddcf7f256793022100fc57cef351"
    "7de1a5f5f6f003078bdfcf452af9d7bd42b1fd1345631737387598";
static const char SIG_RAW[] =
    "3044022025ac36326f0ffe1f2a27669c93fd177a9b8191f367f4169adfd5a88606e1580702201a0b728f5f61"
    "69061d7e9ab9e20142b61becf61d1eb52a964bb6b471a01eb0fb";

/* A key on SM2's curve from a private number (only its public point for !priv). */
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

/* EVP_DigestVerify of sig over msg, with the ID if id. */
static int digest_verify(EVP_PKEY *k, const char *md, int id, const unsigned char *sig,
                         size_t len, const char *msg)
{
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pc = NULL;
    int r = EVP_DigestVerifyInit_ex(m, &pc, md, NULL, NULL, k, NULL);

    if (r == 1 && id)
        r = EVP_PKEY_CTX_set1_id(pc, ID, 16);
    if (r == 1)
        r = EVP_DigestVerify(m, sig, len, (const unsigned char *)msg, strlen(msg));
    EVP_MD_CTX_free(m);
    return r;
}

static void test_algorithm(void)
{
    EVP_SIGNATURE *s = EVP_SIGNATURE_fetch(NULL, "SM2", NULL);

    check(s != NULL, "SM2");
    if (s == NULL) {
        errors();
        return;
    }
    printf("  names:");
    EVP_SIGNATURE_names_do_all(s, print_name, NULL);
    printf("\n  name %s, provider %s\n", EVP_SIGNATURE_get0_name(s),
           OSSL_PROVIDER_get0_name(EVP_SIGNATURE_get0_provider(s)));
    names("gettable", EVP_SIGNATURE_gettable_ctx_params(s));
    names("settable", EVP_SIGNATURE_settable_ctx_params(s));
    EVP_SIGNATURE_free(s);
}

static void test_fixed(EVP_PKEY *k, EVP_PKEY *pub)
{
    size_t l1, l2, l3;
    unsigned char *s1 = octets(SIG_NO_ID, &l1), *s2 = octets(SIG_ID, &l2);
    unsigned char *s3 = octets(SIG_RAW, &l3);
    unsigned char dg[32], longer[80];
    EVP_PKEY_CTX *c;

    printf("  without an ID %d, with %d\n", digest_verify(k, NULL, 0, s1, l1, MSG),
           digest_verify(k, NULL, 1, s2, l2, MSG));
    printf("  crossed: %d %d\n", digest_verify(k, NULL, 1, s1, l1, MSG),
           digest_verify(k, NULL, 0, s2, l2, MSG));
    errors();
    printf("  public key: %d %d\n", digest_verify(pub, NULL, 0, s1, l1, MSG),
           digest_verify(pub, "SM3", 1, s2, l2, MSG));
    errors();
    printf("  another message %d\n", digest_verify(k, NULL, 0, s1, l1, "message digesT"));
    errors();
    s1[l1 - 1] ^= 1;
    printf("  changed %d\n", digest_verify(k, NULL, 0, s1, l1, MSG));
    errors();
    s1[l1 - 1] ^= 1;
    memcpy(longer, s1, l1);
    longer[l1] = 0;
    printf("  trailing octet %d\n", digest_verify(k, NULL, 0, longer, l1 + 1, MSG));
    errors();
    printf("  truncated %d\n", digest_verify(k, NULL, 0, s1, l1 - 1, MSG));
    errors();
    printf("  empty %d\n", digest_verify(k, NULL, 0, s1, 0, MSG));
    errors();
    {
        /* r = 0, and r = n. */
        static const char zero_r[] = "3006020100020101";
        static const char n_r[] =
            "302602210"
            "0FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123020101";
        size_t lz, ln;
        unsigned char *z = octets(zero_r, &lz), *n = octets(n_r, &ln);

        printf("  r = 0: %d r = n: %d\n", digest_verify(k, NULL, 0, z, lz, MSG),
               digest_verify(k, NULL, 0, n, ln, MSG));
        errors();
        OPENSSL_free(z);
        OPENSSL_free(n);
    }

    memset(dg, 0x5a, sizeof(dg));
    c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    check(EVP_PKEY_verify_init(c) == 1, "verify_init");
    printf("  raw %d short %d\n", EVP_PKEY_verify(c, s3, l3, dg, 32),
           EVP_PKEY_verify(c, s3, l3, dg, 31));
    errors();
    EVP_PKEY_CTX_free(c);
    OPENSSL_free(s1);
    OPENSSL_free(s2);
    OPENSSL_free(s3);
}

static void test_sign(EVP_PKEY *k, EVP_PKEY *pub)
{
    EVP_MD_CTX *m = EVP_MD_CTX_new(), *d;
    EVP_PKEY_CTX *pc = NULL;
    unsigned char sig[100], sig2[100], dg[40];
    size_t len, len2;
    int r;

    len = 0;
    r = EVP_DigestSignInit_ex(m, &pc, NULL, NULL, NULL, k, NULL);
    r = r * 10 + EVP_DigestSign(m, NULL, &len, (const unsigned char *)MSG, strlen(MSG));
    printf("  size %d %zu\n", r, len);
    errors();
    len = sizeof(sig);
    r = EVP_DigestSign(m, sig, &len, (const unsigned char *)MSG, strlen(MSG));
    check(r == 1, "a message, no ID");
    errors();
    printf("  verify %d\n", digest_verify(k, NULL, 0, sig, len, MSG));

    r = EVP_DigestSignInit_ex(m, &pc, "SM3", NULL, NULL, k, NULL);
    r = r * 10 + EVP_PKEY_CTX_set1_id(pc, ID, 16);
    r = r * 10 + EVP_DigestSignUpdate(m, "message ", 8);
    d = EVP_MD_CTX_dup(m);
    r = r * 10 + EVP_DigestSignUpdate(m, "digest", 6);
    r = r * 10 + EVP_DigestSignUpdate(d, "digest", 6);
    len = sizeof(sig);
    len2 = sizeof(sig2);
    r = r * 10 + EVP_DigestSignFinal(m, sig, &len);
    r = r * 10 + EVP_DigestSignFinal(d, sig2, &len2);
    check(r == 1111111, "with the ID, in parts, and a copy");
    errors();
    printf("  verify %d %d, without the ID %d, with the public key %d\n",
           digest_verify(k, NULL, 1, sig, len, MSG), digest_verify(k, NULL, 1, sig2, len2, MSG),
           digest_verify(k, NULL, 0, sig, len, MSG), digest_verify(pub, NULL, 1, sig, len, MSG));
    EVP_MD_CTX_free(d);

    r = EVP_DigestSignInit_ex(m, &pc, NULL, NULL, NULL, k, NULL);
    r = r * 10 + EVP_DigestSignUpdate(m, "x", 1);
    r = r * 10 + EVP_PKEY_CTX_set1_id(pc, ID, 16);
    printf("  the ID after an update %d\n", r);
    errors();

    r = EVP_DigestSignInit_ex(m, &pc, "SHA256", NULL, NULL, k, NULL);
    printf("  SHA256 %d\n", r);
    errors();
    r = EVP_DigestSignInit_ex(m, &pc, "SHAKE256", NULL, NULL, k, NULL);
    printf("  SHAKE256 %d\n", r);
    errors();

    EVP_MD_CTX_free(m);
    m = EVP_MD_CTX_new();
    r = EVP_DigestSignInit_ex(m, &pc, NULL, NULL, NULL, pub, NULL);
    len = sizeof(sig);
    r = r * 10 + EVP_DigestSign(m, sig, &len, (const unsigned char *)MSG, strlen(MSG));
    printf("  with the public key: %d", r);
    if (r == 11)
        printf(" %zu octets, verify %d", len, digest_verify(pub, NULL, 0, sig, len, MSG));
    printf("\n");
    errors();
    EVP_MD_CTX_free(m);

    memset(dg, 0x33, sizeof(dg));
    pc = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    r = EVP_PKEY_sign_init(pc);
    len = 0;
    r = r * 10 + EVP_PKEY_sign(pc, NULL, &len, dg, 32);
    printf("  sign_init and size %d %zu\n", r, len);
    len = sizeof(sig);
    r = EVP_PKEY_sign(pc, sig, &len, dg, 32);
    check(r == 1, "32 octets as they are");
    errors();
    r = EVP_PKEY_verify_init(pc);
    printf("  verify %d %d\n", r, EVP_PKEY_verify(pc, sig, len, dg, 32));
    errors();
    r = EVP_PKEY_sign_init(pc);
    len = sizeof(sig);
    r = r * 10 + EVP_PKEY_sign(pc, sig, &len, dg, 20);
    printf("  20 octets %d\n", r);
    errors();
    len = 71;
    r = EVP_PKEY_sign(pc, sig, &len, dg, 32);
    printf("  a short buffer %d\n", r);
    errors();
    EVP_PKEY_CTX_free(pc);
}

static void test_params(EVP_PKEY *k)
{
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pc = NULL, *c;
    unsigned char aid[60];
    char mdname[40] = "?";
    size_t mdsize = 0;
    OSSL_PARAM g[4], s[3];
    int r;

    r = EVP_DigestSignInit_ex(m, &pc, NULL, NULL, NULL, k, NULL);
    g[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, aid, sizeof(aid));
    g[1] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, mdname, sizeof(mdname));
    g[2] = OSSL_PARAM_construct_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, &mdsize);
    g[3] = OSSL_PARAM_construct_end();
    r = r * 10 + EVP_PKEY_CTX_get_params(pc, g);
    printf("  get_params %d digest %s size %zu\n", r, mdname, mdsize);
    hex("algorithm-id", aid, g[0].return_size);
    errors();
    names("gettable", EVP_PKEY_CTX_gettable_params(pc));
    names("settable", EVP_PKEY_CTX_settable_params(pc));
    names("md gettable", EVP_MD_CTX_gettable_params(m));
    names("md settable", EVP_MD_CTX_settable_params(m));
    mdsize = 20;
    s[0] = OSSL_PARAM_construct_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, &mdsize);
    s[1] = OSSL_PARAM_construct_end();
    printf("  digest size 20 %d\n", EVP_PKEY_CTX_set_params(pc, s));
    mdsize = 32;
    printf("  digest size 32 %d\n", EVP_PKEY_CTX_set_params(pc, s));
    s[0] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, "SM3", 0);
    printf("  digest SM3 %d\n", EVP_PKEY_CTX_set_params(pc, s));
    s[0] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, "SHA256", 0);
    printf("  digest SHA256 %d\n", EVP_PKEY_CTX_set_params(pc, s));
    errors();
    s[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_DIST_ID, NULL, 0);
    printf("  an empty ID %d\n", EVP_PKEY_CTX_set_params(pc, s));
    errors();
    {
        size_t idlen = 99;

        printf("  get1_id_len %d", EVP_PKEY_CTX_get1_id_len(pc, &idlen));
        printf(" %zu\n", idlen);
        errors();
    }
    s[0] = OSSL_PARAM_construct_end();
    printf("  empty %d\n", EVP_PKEY_CTX_set_params(pc, s));
    EVP_MD_CTX_free(m);

    c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    EVP_PKEY_sign_init(c);
    mdname[0] = '?';
    mdsize = 0;
    g[0].return_size = OSSL_PARAM_UNMODIFIED;
    r = EVP_PKEY_CTX_get_params(c, g);
    printf("  sign_init: get_params %d aid %zu\n", r, g[0].return_size);
    errors();
    r = EVP_PKEY_CTX_get_params(c, g + 1);
    printf("  without the aid %d digest %s size %zu\n", r, mdname, mdsize);
    errors();
    EVP_PKEY_CTX_free(c);
}

/* A legacy EC_KEY on SM2's curve signs and verifies through the provider. */
static void test_legacy(void)
{
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_sm2);
    EVP_PKEY *k = EVP_PKEY_new();
    BIGNUM *d = NULL;
    EC_POINT *q = EC_POINT_new(EC_KEY_get0_group(ec));
    size_t l;
    unsigned char *s = octets(SIG_ID, &l);
    unsigned char sig[100];
    size_t len = sizeof(sig);
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pc = NULL;
    int r;

    BN_hex2bn(&d, PRIV);
    EC_POINT_mul(EC_KEY_get0_group(ec), q, d, NULL, NULL, NULL);
    EC_KEY_set_private_key(ec, d);
    EC_KEY_set_public_key(ec, q);
    check(EVP_PKEY_set1_EC_KEY(k, ec) == 1, "a legacy EC_KEY on SM2's curve");
    printf("  verify the reference's %d\n", digest_verify(k, NULL, 1, s, l, MSG));
    errors();
    r = EVP_DigestSignInit(m, &pc, NULL, NULL, k);
    r = r * 10 + EVP_PKEY_CTX_set1_id(pc, ID, 16);
    r = r * 10 + EVP_DigestSign(m, sig, &len, (const unsigned char *)MSG, strlen(MSG));
    printf("  sign %d verify %d\n", r, digest_verify(k, NULL, 1, sig, len, MSG));
    errors();
    EVP_MD_CTX_free(m);
    OPENSSL_free(s);
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
    test_sign(k, pub);
    test_params(k);
    test_legacy();
    errors();
    EVP_PKEY_free(k);
    EVP_PKEY_free(pub);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
