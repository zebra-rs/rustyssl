/*
 * Conformance test for the default provider's DSA signatures (EVP_SIGNATURE-DSA(7),
 * provider-signature(7)) and the legacy DSA key method (EVP_PKEY_meth_find(3) for
 * EVP_PKEY_DSA; OpenSSL's dsa_pmeth.c), in TAP format: the algorithms and their parameter
 * lists; RFC 6979's deterministic signatures (nonce-type 1) over digests and messages with each
 * digest, on DSA-1024 and a generated 2048/256-bit key; the digest-seeded nonces (checked by
 * verifying); the composite algorithms (DSA-SHA256 and the others) in their digest and message
 * forms; the context's parameters (the algorithm identifier, digest, nonce type) and their
 * errors; copies of a context mid-message; keys without a private part; a legacy DSA in a key;
 * then a DSA with an application's DSA_METHOD, which stays a legacy key, so it signs through
 * the built-in method (the digest's checks, the ctrls and ctrl strings with their errors); and
 * parameter and key generation through an application's copy of the built-in method.
 *
 * Generation runs on a known DRBG, so generated keys and primes are printed (as a hash) and
 * must match the reference's; signatures with the digest-seeded nonce are only verified.
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
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/provider.h>
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

    printf("  %s (%zu): ", label, len);
    for (i = 0; i < len; i++)
        printf("%02x", p[i]);
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
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY, entropy,
                                                  sizeof(entropy));
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_NONCE, nonce,
                                                  sizeof(nonce));
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

static void known_rand(unsigned char seed)
{
    RAND_set0_public(NULL, known_drbg(seed));
    RAND_set0_private(NULL, known_drbg(seed + 1));
}

/* Octets as their length and the start of their SHA-256. */
static void octets(const char *label, const unsigned char *p, size_t n)
{
    unsigned char d[32];
    unsigned int dl = 0;
    size_t i;

    EVP_Digest(p, n, d, &dl, EVP_sha256(), NULL);
    printf("  %s (%zu): sha256 ", label, n);
    for (i = 0; i < 8; i++)
        printf("%02x", d[i]);
    printf("\n");
}

/* RFC 6979's DSA-1024 key (A.2.1). */
static const char P[] =
    "86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447E6533B86B18BED6E8A48B784A1"
    "4C252C5BE0DBF60B86D6385BD2F12FB763ED8873ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C"
    "77ADEDFC846C881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779";
static const char Q[] = "996F967F6C8E388D9E28D01E205FBA957A5698B1";
static const char G[] =
    "07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D89BBCD97E904E09114D9A7DEFD"
    "EADFC9078EA544D2E401AEECC40BB9FBBF78FD87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB7"
    "7175464ADCA417BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD";
static const char X[] = "411602CB19A6CCC34494D79D98EF1E7ED5AF25F7";
static const char Y[] =
    "5DF5E01DED31D0297E274E1691C192FE5868FEF9E19A84776454B100CF16F65392195A38B90523E2542EE61871"
    "C0440CB87C322FC4B4D2EC5E1E7EC766E1BE8D4CE935437DC11C3C8FD426338933EBFE739CB3465F4D3668C5E4"
    "73508253B1E682F65CBDC4FAE93C2EA212390E54905A86E2223170B44EAA7DA5DD9FFCFB7F3B";

static BIGNUM *hexbn(const char *h)
{
    BIGNUM *b = NULL;

    BN_hex2bn(&b, h);
    return b;
}

/* RFC 6979's DSA-1024 key, made by the key manager (without x for !priv). */
static EVP_PKEY *rfc_key(int priv)
{
    OSSL_PARAM_BLD *b = OSSL_PARAM_BLD_new();
    BIGNUM *p = hexbn(P), *q = hexbn(Q), *g = hexbn(G), *x = hexbn(X), *y = hexbn(Y);
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL);
    EVP_PKEY *k = NULL;
    OSSL_PARAM *ps;

    OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_FFC_P, p);
    OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_FFC_Q, q);
    OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_FFC_G, g);
    OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_PUB_KEY, y);
    if (priv)
        OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_PRIV_KEY, x);
    ps = OSSL_PARAM_BLD_to_param(b);
    if (EVP_PKEY_fromdata_init(c) != 1
        || EVP_PKEY_fromdata(c, &k, priv ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, ps) != 1)
        k = NULL;
    OSSL_PARAM_free(ps);
    OSSL_PARAM_BLD_free(b);
    EVP_PKEY_CTX_free(c);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(x);
    BN_free(y);
    return k;
}

/* RFC 6979's DSA-1024 key as a legacy DSA (with `meth`, if any). */
static DSA *rfc_dsa(const DSA_METHOD *meth)
{
    DSA *d = DSA_new();

    if (meth != NULL)
        DSA_set_method(d, meth);
    DSA_set0_pqg(d, hexbn(P), hexbn(Q), hexbn(G));
    DSA_set0_key(d, hexbn(Y), hexbn(X));
    return d;
}

/* A 2048-bit key with a 256-bit q, generated on a known DRBG. */
static EVP_PKEY *gen_2048(void)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL), *kc = NULL;
    EVP_PKEY *params = NULL, *k = NULL;

    known_rand(17);
    if (EVP_PKEY_paramgen_init(c) == 1 && EVP_PKEY_CTX_set_dsa_paramgen_bits(c, 2048) == 1
        && EVP_PKEY_CTX_set_dsa_paramgen_q_bits(c, 256) == 1
        && EVP_PKEY_paramgen(c, &params) == 1) {
        kc = EVP_PKEY_CTX_new_from_pkey(NULL, params, NULL);
        if (EVP_PKEY_keygen_init(kc) != 1 || EVP_PKEY_keygen(kc, &k) != 1)
            k = NULL;
    }
    EVP_PKEY_CTX_free(kc);
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(params);
    return k;
}

/* A digest of a message, into out (its length returned). */
static unsigned int digest(const char *md, const char *msg, unsigned char *out)
{
    unsigned int n = 0;

    EVP_Digest(msg, strlen(msg), out, &n, EVP_get_digestbyname(md), NULL);
    return n;
}

/* Verifies sig over msg with md through a digest context: 1, 0, or -1. */
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
 * Signs msg with md through a digest context with the nonce type (expected to work or not): a
 * deterministic signature is printed, another verified.
 */
static void digest_sign(const char *what, EVP_PKEY *k, const char *md, unsigned int nonce,
                        const char *msg, int expected)
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
    check(ok == expected, what);
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
        "DSA", "DSA-SHA1", "DSA-SHA2-224", "DSA-SHA2-256", "DSA-SHA2-384", "DSA-SHA2-512",
        "DSA-SHA3-224", "DSA-SHA3-256", "DSA-SHA3-384", "DSA-SHA3-512", "dsaWithSHA1",
        "dsa_with_SHA256", "2.16.840.1.101.3.4.3.2", "id-dsa-with-sha3-512", "dsaEncryption",
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

/* RFC 6979's deterministic signatures with each digest (A.2.1's "sample" and "test"). */
static void test_deterministic(EVP_PKEY *k, EVP_PKEY *k2048)
{
    static const char *const mds[] = {
        "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHA3-224", "SHA3-256", "SHA3-384",
        "SHA3-512", "SHA512-224", "SHA512-256", "MD5", "SM3", "SHAKE256",
    };
    char what[100];
    size_t i;

    for (i = 0; i < sizeof(mds) / sizeof(mds[0]); i++) {
        snprintf(what, sizeof(what), "DSA-1024 %s, deterministic, \"sample\"", mds[i]);
        digest_sign(what, k, mds[i], 1, "sample", i < 11);
    }
    digest_sign("DSA-1024 SHA256, deterministic, \"test\"", k, "SHA256", 1, "test", 1);
    digest_sign("DSA-2048 SHA256, deterministic", k2048, "SHA256", 1, "sample", 1);
    digest_sign("DSA-2048 SHA512, deterministic", k2048, "SHA512", 1, "test", 1);
    digest_sign("DSA-2048 SHA1, deterministic", k2048, "SHA1", 1, "sample", 1);
    digest_sign("DSA-1024 SHA256, digest-seeded", k, "SHA256", 0, "sample", 1);
    digest_sign("DSA-1024 SHA256, nonce type 2", k, "SHA256", 2, "sample", 1);
    digest_sign("DSA-2048 SHA3-512, digest-seeded", k2048, "SHA3-512", 0, "sample", 1);
    digest_sign("DSA-1024, no digest named", k, NULL, 1, "sample", 1);
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
    check(r == 1 && len == 48, "the size of a signature");
    len = sizeof(sig);
    r = EVP_PKEY_sign(c, sig, &len, dg, dlen);
    check(r == 1, "a signature of a digest, no digest set");
    errors();
    printf("  verify %d\n", digest_verify(k, "SHA256", "sample", sig, len));
    len = sizeof(sig);
    memset(longer, 0xa5, sizeof(longer));
    r = EVP_PKEY_sign(c, sig, &len, longer, sizeof(longer));
    check(r == 1, "a signature of 100 octets, no digest set");
    errors();
    check(EVP_PKEY_verify_init(c) == 1, "verify_init");
    printf("  verify %d\n", EVP_PKEY_verify(c, sig, len, longer, sizeof(longer)));
    printf("  verify of 99 octets %d\n", EVP_PKEY_verify(c, sig, len, longer, 99));
    printf("  verify of 20 octets %d\n", EVP_PKEY_verify(c, sig, len, longer, 20));
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
    len = 47;
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
    check(EVP_PKEY_verify_init(c) == 1, "verify_init with a public key");
    {
        EVP_PKEY_CTX *s = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);

        len = sizeof(sig);
        EVP_PKEY_sign_init(s);
        EVP_PKEY_sign(s, sig, &len, dg, dlen);
        EVP_PKEY_CTX_free(s);
    }
    printf("  verify with the public key %d\n", EVP_PKEY_verify(c, sig, len, dg, dlen));
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
    unsigned int nonce = 7;
    OSSL_PARAM g[4];
    OSSL_PARAM s[3];
    static const char *const bad[] = {
        "SHAKE256", "nosuchdigest", "ThisNameIsLongerThanFiftyCharactersAndSoCannotFitAtAll",
        "MD5", "SHA512-224", "sha256", "SHA1",
    };
    size_t i;
    int r;

    check(EVP_DigestSignInit_ex(m, &pc, "SHA2-384", NULL, NULL, k, NULL) == 1,
          "DigestSignInit with SHA2-384");
    g[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, aid, sizeof(aid));
    g[1] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, mdname, sizeof(mdname));
    g[2] = OSSL_PARAM_construct_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE, &nonce);
    g[3] = OSSL_PARAM_construct_end();
    r = EVP_PKEY_CTX_get_params(pc, g);
    printf("  get_params %d digest %s nonce %u\n", r, mdname, nonce);
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
    printf("  named again %d\n", r);
    errors();
    {
        size_t mdsize = 20;

        s[0] = OSSL_PARAM_construct_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, &mdsize);
        r = EVP_PKEY_CTX_set_params(pc, s);
        printf("  digest size %d\n", r);
        errors();
    }
    EVP_MD_CTX_free(m);

    c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    EVP_PKEY_sign_init(c);
    nonce = 9;
    aid[0] = 0;
    mdname[0] = 'x';
    mdname[1] = 0;
    g[0].return_size = OSSL_PARAM_UNMODIFIED;
    r = EVP_PKEY_CTX_get_params(c, g);
    printf("  without a digest: get_params %d digest [%s] nonce %u aid %zu\n", r, mdname, nonce,
           g[0].return_size);
    errors();
    r = EVP_PKEY_CTX_get_params(c, g + 1);
    printf("  without the aid: %d digest [%s] nonce %u\n", r, mdname, nonce);
    errors();
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        s[0] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, (char *)bad[i], 0);
        s[1] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, "", 0);
        s[2] = OSSL_PARAM_construct_end();
        r = EVP_PKEY_CTX_set_params(c, s);
        g[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, aid,
                                                 sizeof(aid));
        g[0].return_size = OSSL_PARAM_UNMODIFIED;
        r = r * 10 + EVP_PKEY_CTX_get_params(c, g);
        printf("  digest %s: %d digest %s aid %zu\n", bad[i], r, mdname, g[0].return_size);
        errors();
    }
    hex("algorithm-id", aid, g[0].return_size);
    s[0] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_NONCE_TYPE, "1", 0);
    s[1] = OSSL_PARAM_construct_end();
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
    names("settable (sign)", EVP_PKEY_CTX_settable_params(c));
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
    EVP_SIGNATURE *s384 = EVP_SIGNATURE_fetch(NULL, "DSA-SHA384", NULL);
    EVP_SIGNATURE *s3 = EVP_SIGNATURE_fetch(NULL, "DSA-SHA3-256", NULL);
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    unsigned int nonce = 1;
    OSSL_PARAM p[2];
    unsigned char sig[200], sig2[200], dg[64];
    unsigned int dlen = digest("SHA384", "sample", dg);
    size_t len = sizeof(sig), len2 = sizeof(sig2);
    unsigned char aid[100];
    char mdname[60];
    OSSL_PARAM g[3];
    int r;

    p[0] = OSSL_PARAM_construct_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE, &nonce);
    p[1] = OSSL_PARAM_construct_end();
    r = EVP_PKEY_sign_message_init(c, s384, p);
    r = r * 10 + EVP_PKEY_sign_message_update(c, (const unsigned char *)"sam", 3);
    r = r * 10 + EVP_PKEY_sign_message_update(c, (const unsigned char *)"ple", 3);
    r = r * 10 + EVP_PKEY_sign_message_final(c, sig, &len);
    check(r == 1111, "DSA-SHA384 over a message, in parts");
    hex("sig", sig, len);
    errors();
    names("settable (sign message)", EVP_PKEY_CTX_settable_params(c));
    g[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, aid, sizeof(aid));
    g[1] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, mdname, sizeof(mdname));
    g[2] = OSSL_PARAM_construct_end();
    r = EVP_PKEY_CTX_get_params(c, g);
    printf("  get_params %d digest %s\n", r, mdname);
    hex("algorithm-id", aid, g[0].return_size);
    printf("  verify %d\n", digest_verify(k, "SHA384", "sample", sig, len));

    r = EVP_PKEY_sign_message_init(c, s384, p);
    r = r * 10 + EVP_PKEY_sign(c, sig2, &len2, (const unsigned char *)"sample", 6);
    check(r == 11 && len2 == len && memcmp(sig, sig2, len) == 0,
          "DSA-SHA384 one-shot over a message signs the same");
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
          "DSA-SHA384 over a digest signs the same");
    errors();
    len2 = sizeof(sig2);
    r = EVP_PKEY_sign(c, sig2, &len2, dg, 32);
    check(r <= 0, "DSA-SHA384 over a digest of the wrong size is refused");
    errors();
    names("settable (sign)", EVP_PKEY_CTX_settable_params(c));

    r = EVP_PKEY_verify_message_init(c, s384, NULL);
    r = r * 10 + EVP_PKEY_CTX_set_signature(c, sig, len);
    r = r * 10 + EVP_PKEY_verify_message_update(c, (const unsigned char *)"sample", 6);
    r = r * 10 + EVP_PKEY_verify_message_final(c);
    check(r == 1111, "DSA-SHA384 verifies a message");
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
    check(r == 111111, "DSA-SHA3-256 with the digest-seeded nonce signs and verifies");
    errors();
    {
        EVP_MD_CTX *m = EVP_MD_CTX_new();

        r = EVP_DigestSignInit_ex(m, NULL, NULL, NULL, "?provider=default", k, NULL);
        printf("  DigestSignInit without a digest %d\n", r);
        errors();
        r = EVP_DigestSignUpdate(m, "x", 1);
        printf("  update %d\n", r);
        errors();
        EVP_MD_CTX_free(m);
    }
    EVP_PKEY_CTX_free(c);
    EVP_SIGNATURE_free(s384);
    EVP_SIGNATURE_free(s3);
}

/* A legacy DSA in a key signs through the provider (deterministically, too). */
static void test_legacy_in_key(void)
{
    DSA *d = rfc_dsa(NULL);
    EVP_PKEY *k = EVP_PKEY_new();
    unsigned char dg[64], sig[100];
    unsigned int dlen = digest("SHA1", "sample", dg), slen = 0;

    check(EVP_PKEY_set1_DSA(k, d) == 1, "a legacy DSA");
    digest_sign("the legacy key, SHA1, deterministic", k, "SHA1", 1, "sample", 1);
    digest_sign("the legacy key, SHA256, digest-seeded", k, "SHA256", 0, "sample", 1);
    printf("  DSA_sign %d", DSA_sign(0, dg, (int)dlen, sig, &slen, d));
    printf(" verify %d\n", digest_verify(k, "SHA1", "sample", sig, slen));
    errors();
    EVP_PKEY_free(k);
    DSA_free(d);
}

static int signed_by_method = 0;
static DSA_SIG *(*orig_sign)(const unsigned char *, int, DSA *);

static DSA_SIG *count_sign(const unsigned char *dgst, int dlen, DSA *dsa)
{
    signed_by_method++;
    return orig_sign(dgst, dlen, dsa);
}

/* Signs a digest with a legacy context's method: the result, and a verification. */
static void legacy_sign(const char *what, EVP_PKEY_CTX *c, EVP_PKEY_CTX *v,
                        const unsigned char *dg, size_t dlen)
{
    unsigned char sig[200];
    size_t len = 0;
    int r = EVP_PKEY_sign(c, NULL, &len, dg, dlen);

    printf("  %s: size %d %zu", what, r, len);
    len = sizeof(sig);
    r = EVP_PKEY_sign(c, sig, &len, dg, dlen);
    printf(" sign %d", r);
    if (r == 1)
        printf(" verify %d", EVP_PKEY_verify(v, sig, len, dg, dlen));
    printf("\n");
    errors();
}

/* A DSA with an application's method stays a legacy key and signs through the method. */
static void test_foreign(void)
{
    DSA_METHOD *meth = DSA_meth_dup(DSA_OpenSSL());
    DSA *d;
    EVP_PKEY *k = EVP_PKEY_new();
    EVP_PKEY_CTX *c, *v;
    unsigned char dg[64], dg1[64];
    unsigned int dlen = digest("SHA256", "sample", dg);
    unsigned int dlen1 = digest("SHA1", "sample", dg1);
    const EVP_MD *md = NULL;

    orig_sign = DSA_meth_get_sign(meth);
    DSA_meth_set_sign(meth, count_sign);
    d = rfc_dsa(meth);
    check(EVP_PKEY_set1_DSA(k, d) == 1, "a DSA with an application's method");
    c = EVP_PKEY_CTX_new(k, NULL);
    v = EVP_PKEY_CTX_new(k, NULL);
    printf("  sign_init %d verify_init %d\n", EVP_PKEY_sign_init(c), EVP_PKEY_verify_init(v));
    errors();
    legacy_sign("no digest", c, v, dg, dlen);
    legacy_sign("no digest, 100 octets", c, v, (const unsigned char *)
                "0123456789012345678901234567890123456789012345678901234567890123456789"
                "012345678901234567890123456789", 100);
    printf("  set md %d %d", EVP_PKEY_CTX_set_signature_md(c, EVP_sha256()),
           EVP_PKEY_CTX_set_signature_md(v, EVP_sha256()));
    printf(" get %d", EVP_PKEY_CTX_get_signature_md(c, &md));
    printf(" %s\n", md != NULL ? EVP_MD_get0_name(md) : "(none)");
    errors();
    legacy_sign("SHA256", c, v, dg, dlen);
    legacy_sign("SHA256, a SHA-1 digest", c, v, dg1, dlen1);
    printf("  set md5 %d", EVP_PKEY_CTX_set_signature_md(c, EVP_md5()));
    printf(" sha512-224 %d", EVP_PKEY_CTX_set_signature_md(c, EVP_sha512_224()));
    printf(" sha3-512 %d", EVP_PKEY_CTX_set_signature_md(c, EVP_sha3_512()));
    printf(" sha1 %d\n", EVP_PKEY_CTX_set_signature_md(c, EVP_sha1()));
    errors();
    legacy_sign("SHA1", c, v, dg1, dlen1);
#define CTRL(cmd, p1, p2) EVP_PKEY_CTX_ctrl(c, -1, -1, cmd, p1, p2)
    printf("  ctrls: digestinit %d pkcs7 %d cms %d peer %d nonsense %d\n",
           CTRL(EVP_PKEY_CTRL_DIGESTINIT, 0, NULL), CTRL(EVP_PKEY_CTRL_PKCS7_SIGN, 0, NULL),
           CTRL(EVP_PKEY_CTRL_CMS_SIGN, 0, NULL), CTRL(EVP_PKEY_CTRL_PEER_KEY, 0, NULL),
           CTRL(EVP_PKEY_ALG_CTRL + 100, 0, NULL));
    errors();
#undef CTRL
    printf("  ctrl str nonsense %d\n", EVP_PKEY_CTX_ctrl_str(c, "nonsense", "1"));
    errors();
    {
        EVP_PKEY_CTX *dup = EVP_PKEY_CTX_dup(c);

        md = NULL;
        printf("  dup %d", dup != NULL);
        if (dup != NULL)
            printf(" md %d %s", EVP_PKEY_CTX_get_signature_md(dup, &md),
                   md != NULL ? EVP_MD_get0_name(md) : "(none)");
        printf("\n");
        errors();
        EVP_PKEY_CTX_free(dup);
    }
    {
        EVP_MD_CTX *m = EVP_MD_CTX_new();
        unsigned char sig[100];
        size_t len = sizeof(sig);
        int r = EVP_DigestSignInit(m, NULL, EVP_sha256(), NULL, k);

        r = r * 10 + EVP_DigestSign(m, sig, &len, (const unsigned char *)"sample", 6);
        printf("  DigestSign %d verify %d\n", r, digest_verify(k, "SHA256", "sample", sig, len));
        errors();
        EVP_MD_CTX_free(m);
    }
    printf("  signed by the method: %d\n", signed_by_method > 0);
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_CTX_free(v);
    EVP_PKEY_free(k);
    DSA_free(d);
    DSA_meth_free(meth);
}

static void gen_with(const char *label, int (*set)(EVP_PKEY_CTX *))
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL), *kc;
    EVP_PKEY *p = NULL, *k = NULL;
    int r1, r2, r3;

    r1 = EVP_PKEY_paramgen_init(c);
    r2 = set != NULL ? set(c) : -9;
    r3 = EVP_PKEY_paramgen(c, &p);
    printf("  %s: %d %d %d", label, r1, r2, r3);
    if (p != NULL) {
        const DSA *d = EVP_PKEY_get0_DSA(p);
        unsigned char buf[1100];
        int n = BN_bn2bin(DSA_get0_p(d), buf);

        printf(" id %d bits %d q %d\n", EVP_PKEY_get_id(p), EVP_PKEY_get_bits(p),
               BN_num_bits(DSA_get0_q(d)));
        octets("p", buf, (size_t)n);
        n = BN_bn2bin(DSA_get0_g(d), buf);
        octets("g", buf, (size_t)n);
        kc = EVP_PKEY_CTX_new(p, NULL);
        printf("  keygen %d", EVP_PKEY_keygen_init(kc));
        printf(" %d", EVP_PKEY_keygen(kc, &k));
        if (k != NULL) {
            n = BN_bn2bin(DSA_get0_pub_key(EVP_PKEY_get0_DSA(k)), buf);
            printf(" id %d\n", EVP_PKEY_get_id(k));
            octets("y", buf, (size_t)n);
        } else {
            printf("\n");
        }
        EVP_PKEY_CTX_free(kc);
    } else {
        printf("\n");
    }
    errors();
    EVP_PKEY_free(k);
    EVP_PKEY_free(p);
    EVP_PKEY_CTX_free(c);
}

#define GCTRL(cmd, p1, p2) EVP_PKEY_CTX_ctrl(c, -1, EVP_PKEY_OP_PARAMGEN, cmd, p1, p2)

static int set_1024(EVP_PKEY_CTX *c)
{
    return GCTRL(EVP_PKEY_CTRL_DSA_PARAMGEN_BITS, 1024, NULL) * 10
           + GCTRL(EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS, 160, NULL);
}

static int set_1024_sha256(EVP_PKEY_CTX *c)
{
    return set_1024(c) * 100 + GCTRL(EVP_PKEY_CTRL_DSA_PARAMGEN_MD, 0, (void *)EVP_sha256()) * 10
           + EVP_PKEY_CTX_set_signature_md(c, EVP_sha256());
}

static int set_bad(EVP_PKEY_CTX *c)
{
    return GCTRL(EVP_PKEY_CTRL_DSA_PARAMGEN_BITS, 255, NULL) * 1000
           + GCTRL(EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS, 200, NULL) * 100
           + GCTRL(EVP_PKEY_CTRL_DSA_PARAMGEN_MD, 0, (void *)EVP_sha384()) * 10
           + set_1024(c);
}

static int set_q0(EVP_PKEY_CTX *c)
{
    return GCTRL(EVP_PKEY_CTRL_DSA_PARAMGEN_BITS, 1024, NULL) * 10
           + GCTRL(EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS, 0, NULL);
}

static int set_mismatch(EVP_PKEY_CTX *c)
{
    return GCTRL(EVP_PKEY_CTRL_DSA_PARAMGEN_BITS, 1024, NULL);
}

static int set_strs(EVP_PKEY_CTX *c)
{
    return EVP_PKEY_CTX_ctrl_str(c, "dsa_paramgen_bits", "1024") * 100
           + EVP_PKEY_CTX_ctrl_str(c, "dsa_paramgen_q_bits", "160") * 10
           + EVP_PKEY_CTX_ctrl_str(c, "dsa_paramgen_md", "SHA1");
}

static int set_bad_strs(EVP_PKEY_CTX *c)
{
    return EVP_PKEY_CTX_ctrl_str(c, "dsa_paramgen_md", "nope") * 1000
           + EVP_PKEY_CTX_ctrl_str(c, "dsa_paramgen_md", "SHA512") * 100
           + EVP_PKEY_CTX_ctrl_str(c, "dsa_paramgen_bits", "x") * 10 + set_1024(c);
}

static int set_typed(EVP_PKEY_CTX *c)
{
    return EVP_PKEY_CTX_set_dsa_paramgen_bits(c, 1024) * 100
           + EVP_PKEY_CTX_set_dsa_paramgen_q_bits(c, 160) * 10
           + EVP_PKEY_CTX_set_dsa_paramgen_md(c, EVP_sha1());
}

static void test_gen(void)
{
    EVP_PKEY_METHOD *m = EVP_PKEY_meth_new(EVP_PKEY_DSA, 0);
    EVP_PKEY_CTX *c;
    EVP_PKEY *k = NULL;

    EVP_PKEY_meth_copy(m, EVP_PKEY_meth_find(EVP_PKEY_DSA));
    check(EVP_PKEY_meth_add0(m) == 1, "an application's copy of the DSA method");
    known_rand(41);
    gen_with("1024/160", set_1024);
    gen_with("1024/160 with SHA-256", set_1024_sha256);
    gen_with("bad", set_bad);
    gen_with("q 0", set_q0);
    gen_with("1024/224", set_mismatch);
    gen_with("strings", set_strs);
    gen_with("bad strings", set_bad_strs);
    gen_with("typed setters", set_typed);

    c = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL);
    printf("  keygen without parameters %d", EVP_PKEY_keygen_init(c));
    printf(" %d\n", EVP_PKEY_keygen(c, &k));
    errors();
    {
        EVP_PKEY_CTX *dup = EVP_PKEY_CTX_dup(c);

        printf("  dup %d\n", dup != NULL);
        errors();
        EVP_PKEY_CTX_free(dup);
    }
    EVP_PKEY_free(k);
    EVP_PKEY_CTX_free(c);
}

int main(void)
{
    EVP_PKEY *k = rfc_key(1);
    EVP_PKEY *pub = rfc_key(0);
    EVP_PKEY *k2048 = gen_2048();

    check(k != NULL && pub != NULL, "RFC 6979's key");
    check(k2048 != NULL, "a generated 2048-bit key");
    errors();
    test_algorithms();
    test_deterministic(k, k2048);
    test_sign_digest(k, pub);
    test_params(k);
    test_dup(k);
    test_sigalgs(k);
    test_legacy_in_key();
    test_foreign();
    test_gen();
    errors();
    EVP_PKEY_free(k);
    EVP_PKEY_free(pub);
    EVP_PKEY_free(k2048);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
