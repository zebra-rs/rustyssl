/*
 * Conformance test for the default provider's ECDSA signatures (EVP_SIGNATURE-ECDSA(7),
 * provider-signature(7)), in TAP format: the algorithms and their parameter lists; RFC 6979's
 * deterministic signatures (nonce-type 1) over digests and messages with each digest, on
 * P-256, P-384, and P-521; random nonces (checked by verifying); the composite algorithms
 * (ECDSA-SHA256 and the others) in their digest and message forms; the context's parameters
 * (the algorithm identifier, digest, digest size, nonce type) and their errors; copies of a
 * context mid-message; keys without a private part; and a legacy EC_KEY in a key.
 *
 * The keys are RFC 6979's (A.2.5, A.2.6, A.2.7), so deterministic signatures are printed whole;
 * signatures with random nonces are only verified.
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

/* RFC 6979's keys. */
static const char P256_X[] = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
static const char P384_X[] =
    "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8"
    "96D5724E4C70A825F872C9EA60D2EDF5";
static const char P521_X[] =
    "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C"
    "AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538";

/* A key on the named curve from a private number (with only its public point for !priv). */
static EVP_PKEY *ec_key(const char *group, const char *x, int priv)
{
    EC_GROUP *g = EC_GROUP_new_by_curve_name(OBJ_sn2nid(group));
    EC_POINT *q = EC_POINT_new(g);
    BIGNUM *d = NULL;
    unsigned char pub[200];
    size_t publen;
    OSSL_PARAM_BLD *b = OSSL_PARAM_BLD_new();
    OSSL_PARAM *ps;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY *k = NULL;

    BN_hex2bn(&d, x);
    EC_POINT_mul(g, q, d, NULL, NULL, NULL);
    publen = EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED, pub, sizeof(pub), NULL);
    OSSL_PARAM_BLD_push_utf8_string(b, OSSL_PKEY_PARAM_GROUP_NAME, group, 0);
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

/* A digest of a message, into out (its length returned). */
static unsigned int digest(const char *md, const char *msg, unsigned char *out)
{
    unsigned int n = 0;

    EVP_Digest(msg, strlen(msg), out, &n, EVP_get_digestbyname(md), NULL);
    return n;
}

/* Verifies sig over msg with md through a digest context: 1, 0, or -1 (errors printed). */
static int digest_verify(EVP_PKEY *k, const char *md, const char *msg,
                         const unsigned char *sig, size_t len)
{
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int r = EVP_DigestVerifyInit_ex(m, NULL, md, NULL, NULL, k, NULL);

    if (r == 1)
        r = EVP_DigestVerify(m, sig, len, (const unsigned char *)msg, strlen(msg));
    EVP_MD_CTX_free(m);
    return r;
}

/*
 * Signs msg with md through a digest context with the nonce type: a deterministic signature is
 * printed, a random one verified.
 */
static void digest_sign(const char *what, EVP_PKEY *k, const char *md, unsigned int nonce,
                        const char *msg)
{
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    OSSL_PARAM p[2];
    unsigned char sig[200];
    size_t len = sizeof(sig);
    int ok;

    p[0] = OSSL_PARAM_construct_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE, &nonce);
    p[1] = OSSL_PARAM_construct_end();
    ok = EVP_DigestSignInit_ex(m, NULL, md, NULL, NULL, k, p) == 1
        && EVP_DigestSign(m, sig, &len, (const unsigned char *)msg, strlen(msg)) == 1;
    check(ok, what);
    if (ok && nonce == 1)
        hex("sig", sig, len);
    errors();
    if (ok)
        printf("  verify %d\n", digest_verify(k, md, msg, sig, len));
    errors();
    EVP_MD_CTX_free(m);
}

static void test_algorithms(void)
{
    static const char *const algs[] = {
        "ECDSA", "ECDSA-SHA1", "ECDSA-SHA2-224", "ECDSA-SHA2-256", "ECDSA-SHA2-384",
        "ECDSA-SHA2-512", "ECDSA-SHA3-224", "ECDSA-SHA3-256", "ECDSA-SHA3-384",
        "ECDSA-SHA3-512", "ecdsa-with-SHA256", "1.2.840.10045.4.3.2",
        "id-ecdsa-with-sha3-512",
    };
    size_t i;

    for (i = 0; i < sizeof(algs) / sizeof(algs[0]); i++) {
        EVP_SIGNATURE *s = EVP_SIGNATURE_fetch(NULL, algs[i], NULL);

        check(s != NULL, algs[i]);
        if (s == NULL) {
            errors();
            continue;
        }
        printf("  names:");
        EVP_SIGNATURE_names_do_all(s, print_name, NULL);
        printf("\n  name %s, provider %s\n", EVP_SIGNATURE_get0_name(s),
               OSSL_PROVIDER_get0_name(EVP_SIGNATURE_get0_provider(s)));
        names("gettable", EVP_SIGNATURE_gettable_ctx_params(s));
        names("settable", EVP_SIGNATURE_settable_ctx_params(s));
        EVP_SIGNATURE_free(s);
    }
}

/* RFC 6979's deterministic signatures with each digest (A.2.5's "sample" and "test"). */
static void test_deterministic(EVP_PKEY *p256, EVP_PKEY *p384, EVP_PKEY *p521)
{
    static const char *const mds[] = {
        "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHA3-224", "SHA3-256", "SHA3-384",
        "SHA3-512", "SHA512-224", "SHA512-256", "MD5", "SM3", "RIPEMD160",
    };
    char what[100];
    size_t i;

    for (i = 0; i < sizeof(mds) / sizeof(mds[0]); i++) {
        snprintf(what, sizeof(what), "P-256 %s, deterministic, \"sample\"", mds[i]);
        digest_sign(what, p256, mds[i], 1, "sample");
    }
    digest_sign("P-256 SHA256, deterministic, \"test\"", p256, "SHA256", 1, "test");
    digest_sign("P-384 SHA256, deterministic", p384, "SHA256", 1, "sample");
    digest_sign("P-384 SHA512, deterministic", p384, "SHA512", 1, "sample");
    digest_sign("P-521 SHA1, deterministic", p521, "SHA1", 1, "sample");
    digest_sign("P-521 SHA512, deterministic", p521, "SHA512", 1, "test");
    digest_sign("P-256 SHA256, random", p256, "SHA256", 0, "sample");
    digest_sign("P-256 SHA256, nonce type 2", p256, "SHA256", 2, "sample");
    digest_sign("P-521 SHA3-512, random", p521, "SHA3-512", 0, "sample");
    digest_sign("P-256, no digest named", p256, NULL, 1, "sample");
}

/* EVP_PKEY_sign over digests (and other octets), with and without a digest set. */
static void test_sign_digest(EVP_PKEY *k, EVP_PKEY *pubonly)
{
    unsigned char dg[64], sig[200], longer[100];
    unsigned int dlen = digest("SHA256", "sample", dg);
    unsigned int nonce = 1;
    size_t len;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    OSSL_PARAM p[2];
    int r;

    p[0] = OSSL_PARAM_construct_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE, &nonce);
    p[1] = OSSL_PARAM_construct_end();

    check(EVP_PKEY_sign_init(c) == 1, "sign_init");
    len = 0;
    r = EVP_PKEY_sign(c, NULL, &len, dg, dlen);
    check(r == 1 && len == 72, "the size of a signature");
    len = sizeof(sig);
    r = EVP_PKEY_sign(c, sig, &len, dg, dlen);
    check(r == 1, "a random signature of a digest, no digest set");
    errors();
    printf("  verify %d\n", digest_verify(k, "SHA256", "sample", sig, len));
    len = sizeof(sig);
    memset(longer, 0xa5, sizeof(longer));
    r = EVP_PKEY_sign(c, sig, &len, longer, sizeof(longer));
    check(r == 1, "a random signature of 100 octets, no digest set");
    errors();
    check(EVP_PKEY_verify_init(c) == 1, "verify_init");
    printf("  verify %d\n", EVP_PKEY_verify(c, sig, len, longer, sizeof(longer)));
    printf("  verify of 99 octets %d\n", EVP_PKEY_verify(c, sig, len, longer, 99));
    errors();

    check(EVP_PKEY_sign_init_ex(c, p) == 1, "sign_init_ex with nonce type 1");
    len = sizeof(sig);
    r = EVP_PKEY_sign(c, sig, &len, dg, dlen);
    check(r <= 0, "deterministic without a digest is refused");
    errors();
    check(EVP_PKEY_CTX_set_signature_md(c, EVP_sha256()) == 1, "set_signature_md SHA256");
    len = sizeof(sig);
    r = EVP_PKEY_sign(c, sig, &len, dg, dlen);
    check(r == 1, "deterministic over a SHA-256 digest");
    hex("sig", sig, len);
    errors();
    len = sizeof(sig);
    r = EVP_PKEY_sign(c, sig, &len, dg, dlen - 1);
    check(r <= 0, "a digest of the wrong length is refused");
    errors();
    len = 71;
    r = EVP_PKEY_sign(c, sig, &len, dg, dlen);
    check(r <= 0, "a buffer too small is refused");
    errors();

    check(EVP_PKEY_verify_init(c) == 1 && EVP_PKEY_CTX_set_signature_md(c, EVP_sha256()) == 1,
          "verify_init with SHA256");
    len = sizeof(sig);
    {
        EVP_PKEY_CTX *s = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);

        EVP_PKEY_sign_init_ex(s, p);
        EVP_PKEY_CTX_set_signature_md(s, EVP_sha256());
        EVP_PKEY_sign(s, sig, &len, dg, dlen);
        EVP_PKEY_CTX_free(s);
    }
    printf("  verify %d\n", EVP_PKEY_verify(c, sig, len, dg, dlen));
    printf("  verify of a short digest %d\n", EVP_PKEY_verify(c, sig, len, dg, dlen - 1));
    errors();
    sig[len - 1] ^= 1;
    printf("  verify of a changed signature %d\n", EVP_PKEY_verify(c, sig, len, dg, dlen));
    errors();
    printf("  verify of garbage %d\n", EVP_PKEY_verify(c, longer, 30, dg, dlen));
    errors();
    EVP_PKEY_CTX_free(c);

    c = EVP_PKEY_CTX_new_from_pkey(NULL, pubonly, NULL);
    check(EVP_PKEY_sign_init(c) == 1, "sign_init with a public key");
    len = sizeof(sig);
    r = EVP_PKEY_sign(c, sig, &len, dg, dlen);
    check(r <= 0, "signing with a public key is refused");
    errors();
    EVP_PKEY_CTX_free(c);
}

/* The context's parameters: got, set, and refused. */
static void test_params(EVP_PKEY *k)
{
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pc = NULL;
    EVP_PKEY_CTX *c;
    unsigned char aid[100];
    char mdname[60];
    size_t mdsize = 0;
    unsigned int nonce = 7;
    OSSL_PARAM g[5];
    OSSL_PARAM s[3];
    static const char *const bad[] = {
        "SHAKE256", "nosuchdigest", "ThisNameIsLongerThanFiftyCharactersAndSoCannotFitAtAll",
        "SHA1",
    };
    size_t i;
    int r;

    check(EVP_DigestSignInit_ex(m, &pc, "SHA2-384", NULL, NULL, k, NULL) == 1,
          "DigestSignInit with SHA2-384");
    g[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, aid, sizeof(aid));
    g[1] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, mdname, sizeof(mdname));
    g[2] = OSSL_PARAM_construct_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, &mdsize);
    g[3] = OSSL_PARAM_construct_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE, &nonce);
    g[4] = OSSL_PARAM_construct_end();
    r = EVP_PKEY_CTX_get_params(pc, g);
    printf("  get_params %d digest %s size %zu nonce %u\n", r, mdname, mdsize, nonce);
    hex("algorithm-id", aid, g[0].return_size);
    errors();
    names("gettable", EVP_PKEY_CTX_gettable_params(pc));
    names("settable", EVP_PKEY_CTX_settable_params(pc));
    names("md gettable", EVP_MD_CTX_gettable_params(m));
    names("md settable", EVP_MD_CTX_settable_params(m));
    s[0] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, "SHA256", 0);
    s[1] = OSSL_PARAM_construct_end();
    r = EVP_PKEY_CTX_set_params(pc, s);
    check(r <= 0, "the digest can't change mid-message");
    errors();
    s[0] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, "SHA2-384", 0);
    r = EVP_PKEY_CTX_set_params(pc, s);
    check(r == 1, "but may be named again");
    errors();
    mdsize = 20;
    s[0] = OSSL_PARAM_construct_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, &mdsize);
    r = EVP_PKEY_CTX_set_params(pc, s);
    check(r <= 0, "nor can its size");
    errors();
    EVP_MD_CTX_free(m);

    c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    EVP_PKEY_sign_init(c);
    nonce = 9;
    mdsize = 99;
    aid[0] = 0;
    g[0].return_size = OSSL_PARAM_UNMODIFIED;
    r = EVP_PKEY_CTX_get_params(c, g);
    printf("  without a digest: get_params %d digest [%s] size %zu nonce %u aid %zu\n", r,
           mdname, mdsize, nonce, g[0].return_size);
    errors();
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        s[0] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, (char *)bad[i], 0);
        s[1] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, "", 0);
        s[2] = OSSL_PARAM_construct_end();
        r = EVP_PKEY_CTX_set_params(c, s);
        printf("  digest %s: %d\n", bad[i], r);
        errors();
    }
    g[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, aid, sizeof(aid));
    r = EVP_PKEY_CTX_get_params(c, g);
    printf("  after SHA1: get_params %d digest %s size %zu\n", r, mdname, mdsize);
    hex("algorithm-id", aid, g[0].return_size);
    s[0] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, "SHA512-224", 0);
    s[1] = OSSL_PARAM_construct_end();
    r = EVP_PKEY_CTX_set_params(c, s);
    g[0].return_size = OSSL_PARAM_UNMODIFIED;
    r = r * 10 + EVP_PKEY_CTX_get_params(c, g);
    printf("  SHA512-224: %d aid %zu\n", r, g[0].return_size);
    errors();
    r = EVP_PKEY_CTX_get_params(c, g + 1);
    printf("  without the aid: %d digest %s size %zu\n", r, mdname, mdsize);
    s[0] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, "MD5", 0);
    r = EVP_PKEY_CTX_set_params(c, s);
    r = r * 10 + EVP_PKEY_CTX_get_params(c, g + 1);
    printf("  MD5: %d digest %s size %zu\n", r, mdname, mdsize);
    errors();
    mdsize = 5;
    s[0] = OSSL_PARAM_construct_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, &mdsize);
    r = EVP_PKEY_CTX_set_params(c, s);
    mdsize = 0;
    r = r * 10 + EVP_PKEY_CTX_get_params(c, g + 1);
    printf("  digest size 5: %d size %zu\n", r, mdsize);
    errors();
    s[0] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_NONCE_TYPE, "1", 0);
    r = EVP_PKEY_CTX_set_params(c, s);
    printf("  nonce type as a string: %d\n", r);
    errors();
    {
        unsigned int kat = 1;

        s[0] = OSSL_PARAM_construct_uint(OSSL_SIGNATURE_PARAM_KAT, &kat);
        r = EVP_PKEY_CTX_set_params(c, s);
        printf("  kat: %d\n", r);
        errors();
    }
    s[0] = OSSL_PARAM_construct_end();
    printf("  empty: %d\n", EVP_PKEY_CTX_set_params(c, s));
    EVP_PKEY_CTX_free(c);
}

/* A message signature continued in a copy of its context. */
static void test_dup(EVP_PKEY *k)
{
    EVP_MD_CTX *m = EVP_MD_CTX_new(), *d;
    unsigned int nonce = 1;
    OSSL_PARAM p[2];
    unsigned char s1[200], s2[200];
    size_t l1 = sizeof(s1), l2 = sizeof(s2);
    int r;

    p[0] = OSSL_PARAM_construct_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE, &nonce);
    p[1] = OSSL_PARAM_construct_end();
    r = EVP_DigestSignInit_ex(m, NULL, "SHA256", NULL, NULL, k, p);
    r = r * 10 + EVP_DigestSignUpdate(m, "sam", 3);
    d = EVP_MD_CTX_dup(m);
    r = r * 10 + (d != NULL);
    r = r * 10 + EVP_DigestSignUpdate(m, "ple", 3);
    r = r * 10 + EVP_DigestSignUpdate(d, "ple", 3);
    r = r * 10 + EVP_DigestSignFinal(m, s1, &l1);
    r = r * 10 + EVP_DigestSignFinal(d, s2, &l2);
    check(r == 1111111 && l1 == l2 && memcmp(s1, s2, l1) == 0, "a copy signs the same");
    hex("sig", s1, l1);
    errors();
    EVP_MD_CTX_free(d);
    EVP_MD_CTX_free(m);
}

/* The composite algorithms, in the digest and message forms. */
static void test_sigalgs(EVP_PKEY *k)
{
    EVP_SIGNATURE *s384 = EVP_SIGNATURE_fetch(NULL, "ECDSA-SHA384", NULL);
    EVP_SIGNATURE *s3 = EVP_SIGNATURE_fetch(NULL, "ECDSA-SHA3-256", NULL);
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    unsigned int nonce = 1;
    OSSL_PARAM p[2];
    unsigned char sig[200], sig2[200], dg[64];
    unsigned int dlen = digest("SHA384", "sample", dg);
    size_t len = sizeof(sig), len2 = sizeof(sig2);
    unsigned char aid[100];
    OSSL_PARAM g[2];
    int r;

    p[0] = OSSL_PARAM_construct_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE, &nonce);
    p[1] = OSSL_PARAM_construct_end();
    r = EVP_PKEY_sign_message_init(c, s384, p);
    r = r * 10 + EVP_PKEY_sign_message_update(c, (const unsigned char *)"sam", 3);
    r = r * 10 + EVP_PKEY_sign_message_update(c, (const unsigned char *)"ple", 3);
    r = r * 10 + EVP_PKEY_sign_message_final(c, sig, &len);
    check(r == 1111, "ECDSA-SHA384 over a message, in parts");
    hex("sig", sig, len);
    errors();
    names("settable (sign message)", EVP_PKEY_CTX_settable_params(c));
    g[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, aid, sizeof(aid));
    g[1] = OSSL_PARAM_construct_end();
    r = EVP_PKEY_CTX_get_params(c, g);
    printf("  get_params %d\n", r);
    hex("algorithm-id", aid, g[0].return_size);
    printf("  verify %d\n", digest_verify(k, "SHA384", "sample", sig, len));

    r = EVP_PKEY_sign_message_init(c, s384, p);
    r = r * 10 + EVP_PKEY_sign(c, sig2, &len2, (const unsigned char *)"sample", 6);
    check(r == 11 && len2 == len && memcmp(sig, sig2, len) == 0,
          "ECDSA-SHA384 one-shot over a message signs the same");
    errors();
    r = EVP_PKEY_sign_message_init(c, s384, p);
    len2 = 0;
    r = r * 10 + EVP_PKEY_sign(c, NULL, &len2, (const unsigned char *)"sample", 6);
    printf("  size query %d %zu\n", r, len2);
    errors();

    r = EVP_PKEY_sign_init_ex2(c, s384, p);
    len2 = sizeof(sig2);
    r = r * 10 + EVP_PKEY_sign(c, sig2, &len2, dg, dlen);
    check(r == 11 && len2 == len && memcmp(sig, sig2, len) == 0,
          "ECDSA-SHA384 over a digest signs the same");
    errors();
    len2 = sizeof(sig2);
    r = EVP_PKEY_sign(c, sig2, &len2, dg, 32);
    check(r <= 0, "ECDSA-SHA384 over a digest of the wrong size is refused");
    errors();
    names("settable (sign)", EVP_PKEY_CTX_settable_params(c));

    r = EVP_PKEY_verify_message_init(c, s384, NULL);
    r = r * 10 + EVP_PKEY_CTX_set_signature(c, sig, len);
    r = r * 10 + EVP_PKEY_verify_message_update(c, (const unsigned char *)"sample", 6);
    r = r * 10 + EVP_PKEY_verify_message_final(c);
    check(r == 1111, "ECDSA-SHA384 verifies a message");
    errors();
    names("settable (verify message)", EVP_PKEY_CTX_settable_params(c));
    r = EVP_PKEY_verify_message_init(c, s384, NULL);
    r = r * 10 + EVP_PKEY_verify_message_update(c, (const unsigned char *)"sample", 6);
    r = r * 10 + EVP_PKEY_verify_message_final(c);
    printf("  verify_message without a signature %d\n", r);
    errors();
    r = EVP_PKEY_verify_message_init(c, s384, NULL);
    r = r * 10 + EVP_PKEY_CTX_set_signature(c, sig, 0);
    printf("  an empty signature %d\n", r);
    errors();
    r = EVP_PKEY_verify_message_init(c, s384, NULL);
    r = r * 10 + EVP_PKEY_verify(c, sig, len, (const unsigned char *)"sample", 6);
    r = r * 10 + EVP_PKEY_verify(c, sig, len, (const unsigned char *)"sample", 6);
    printf("  one-shot verify of a message, twice %d\n", r);
    errors();
    r = EVP_PKEY_verify_init_ex2(c, s384, NULL);
    r = r * 10 + EVP_PKEY_verify(c, sig, len, dg, dlen);
    printf("  verify of a digest %d\n", r);
    errors();
    names("settable (verify)", EVP_PKEY_CTX_settable_params(c));
    r = EVP_PKEY_CTX_set_signature(c, sig, len);
    printf("  set_signature on a digest verification %d\n", r);
    errors();

    r = EVP_PKEY_sign_message_init(c, s3, NULL);
    len = sizeof(sig);
    r = r * 10 + EVP_PKEY_sign(c, sig, &len, (const unsigned char *)"sample", 6);
    r = r * 10 + EVP_PKEY_verify_message_init(c, s3, NULL);
    r = r * 10 + EVP_PKEY_CTX_set_signature(c, sig, len);
    r = r * 10 + EVP_PKEY_verify_message_update(c, (const unsigned char *)"sample", 6);
    r = r * 10 + EVP_PKEY_verify_message_final(c);
    check(r == 111111, "ECDSA-SHA3-256 with a random nonce signs and verifies");
    errors();
    {
        EVP_MD_CTX *m = EVP_MD_CTX_new();

        r = EVP_DigestSignInit_ex(m, NULL, NULL, NULL, "?provider=default", k, NULL);
        printf("  DigestSignInit without a digest %d\n", r);
        errors();
        EVP_MD_CTX_free(m);
    }
    EVP_PKEY_CTX_free(c);
    EVP_SIGNATURE_free(s384);
    EVP_SIGNATURE_free(s3);
}

/* A legacy EC_KEY in a key signs through the provider. */
static void test_legacy(void)
{
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EVP_PKEY *k = EVP_PKEY_new();
    BIGNUM *d = NULL;
    EC_POINT *q = EC_POINT_new(EC_KEY_get0_group(ec));

    BN_hex2bn(&d, P256_X);
    EC_POINT_mul(EC_KEY_get0_group(ec), q, d, NULL, NULL, NULL);
    EC_KEY_set_private_key(ec, d);
    EC_KEY_set_public_key(ec, q);
    check(EVP_PKEY_set1_EC_KEY(k, ec) == 1, "a legacy EC key");
    digest_sign("the legacy key, SHA256, deterministic", k, "SHA256", 1, "sample");
    EC_POINT_free(q);
    BN_free(d);
    EC_KEY_free(ec);
    EVP_PKEY_free(k);
}

int main(void)
{
    EVP_PKEY *p256 = ec_key("prime256v1", P256_X, 1);
    EVP_PKEY *p384 = ec_key("secp384r1", P384_X, 1);
    EVP_PKEY *p521 = ec_key("secp521r1", P521_X, 1);
    EVP_PKEY *pub = ec_key("prime256v1", P256_X, 0);

    check(p256 != NULL && p384 != NULL && p521 != NULL && pub != NULL, "RFC 6979's keys");
    test_algorithms();
    test_deterministic(p256, p384, p521);
    test_sign_digest(p256, pub);
    test_params(p256);
    test_dup(p256);
    test_sigalgs(p256);
    test_legacy();
    errors();
    EVP_PKEY_free(p256);
    EVP_PKEY_free(p384);
    EVP_PKEY_free(p521);
    EVP_PKEY_free(pub);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
