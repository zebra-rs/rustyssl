/*
 * Conformance test for the default provider's DSA key manager (EVP_PKEY-DSA(7),
 * provider-keymgmt(7)) and DSA keys in EVP_PKEY (EVP_PKEY_set1_DSA(3), DSA_print(3)), in TAP
 * format: its names and parameter lists; keys made from data (RFC 6979's DSA-1024 key, each
 * part alone, the FFC fields, and the errors), every gettable parameter, exports of each
 * selection; generated parameters and keys (FIPS 186-4, 186-2, and by size, with seeds,
 * indexes, and templates, and the refusals); comparison and validation; the moves between a DSA
 * in a key and the key manager's data; and the legacy method's printing.
 *
 * Generation runs on a known DRBG, so its keys and primes are printed (as their bits and a
 * hash) and must match the reference's.
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

/* Octets as their length, first octets, and the start of their SHA-256. */
static void octets(const char *label, const unsigned char *p, size_t n)
{
    unsigned char d[32];
    unsigned int dl = 0;
    size_t i;

    EVP_Digest(p, n, d, &dl, EVP_sha256(), NULL);
    printf("  %s (%zu):", label, n);
    for (i = 0; i < n && i < 8; i++)
        printf("%02x", p[i]);
    printf(" sha256 ");
    for (i = 0; i < 8; i++)
        printf("%02x", d[i]);
    printf("\n");
}

/* A number as its bits and its octets' hash. */
static void num(const char *label, const BIGNUM *b)
{
    unsigned char buf[1100];
    int n;

    if (b == NULL) {
        printf("  %s: (null)\n", label);
        return;
    }
    n = BN_bn2bin(b, buf);
    printf("  %s: %d bits", label, BN_num_bits(b));
    if (BN_num_bits(b) <= 64) {
        char *h = BN_bn2hex(b);

        printf(" %s\n", h);
        OPENSSL_free(h);
        return;
    }
    printf("\n");
    octets("  octets", buf, n);
}

/*
 * Every parameter of an array: its name and its value (with `got`, those a get left alone are
 * skipped).
 */
static void dump(const OSSL_PARAM *p, int got)
{
    for (; p != NULL && p->key != NULL; p++) {
        size_t n = got ? p->return_size : p->data_size;

        if (got && p->return_size == OSSL_PARAM_UNMODIFIED)
            continue;
        switch (p->data_type) {
        case OSSL_PARAM_INTEGER: {
            long v = 0;

            if (OSSL_PARAM_get_long(p, &v))
                printf("  %s: int %ld (%zu)\n", p->key, v, n);
            else
                printf("  %s: int ?\n", p->key);
            break;
        }
        case OSSL_PARAM_UNSIGNED_INTEGER: {
            BIGNUM *b = NULL;

            if (OSSL_PARAM_get_BN(p, &b))
                num(p->key, b);
            else
                printf("  %s: bn ?\n", p->key);
            BN_free(b);
            break;
        }
        case OSSL_PARAM_UTF8_STRING:
            printf("  %s: utf8 %.*s\n", p->key, (int)n, (const char *)p->data);
            break;
        case OSSL_PARAM_OCTET_STRING:
            octets(p->key, p->data, n);
            break;
        default:
            printf("  %s: type %u\n", p->key, p->data_type);
        }
    }
}

static void names(const char *label, const OSSL_PARAM *p)
{
    printf("  %s:", label);
    for (; p != NULL && p->key != NULL; p++)
        printf(" %s/%u", p->key, p->data_type);
    printf("\n");
}

/* Asks for every gettable parameter at once. */
static void get_all(EVP_PKEY *k)
{
    const OSSL_PARAM *g = EVP_PKEY_gettable_params(k);
    static long long bufs[64][160];
    OSSL_PARAM ps[64];
    size_t n;

    for (n = 0; g != NULL && g[n].key != NULL && n < 63; n++) {
        ps[n] = g[n];
        ps[n].data = bufs[n];
        ps[n].data_size = ps[n].data_type == OSSL_PARAM_INTEGER ? sizeof(int) : sizeof(bufs[n]);
        ps[n].return_size = OSSL_PARAM_UNMODIFIED;
    }
    ps[n] = OSSL_PARAM_construct_end();
    printf("  get_params: %d\n", EVP_PKEY_get_params(k, ps));
    errors();
    dump(ps, 1);
}

static void todata(EVP_PKEY *k, int selection, const char *label)
{
    OSSL_PARAM *out = NULL;

    printf("  todata %s: %d\n", label, EVP_PKEY_todata(k, selection, &out));
    errors();
    dump(out, 0);
    OSSL_PARAM_free(out);
}

static EVP_PKEY *fromdata(const char *type, int selection, const OSSL_PARAM *params)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
    EVP_PKEY *k = NULL;
    int r;

    r = EVP_PKEY_fromdata_init(c);
    printf("  fromdata %s: %d", type, r);
    r = EVP_PKEY_fromdata(c, &k, selection, (OSSL_PARAM *)params);
    printf(" %d\n", r);
    errors();
    EVP_PKEY_CTX_free(c);
    return k;
}

static void print_names(const char *name, void *arg)
{
    (void)arg;
    printf(" %s", name);
}

static void has(EVP_PKEY *k)
{
    const DSA *d;

    if (k == NULL) {
        printf("  (no key)\n");
        return;
    }
    printf("  id %d bits %d security %d size %d", EVP_PKEY_get_id(k), EVP_PKEY_get_bits(k),
           EVP_PKEY_get_security_bits(k), EVP_PKEY_get_size(k));
    printf(" type %s\n", EVP_PKEY_get0_type_name(k));
    d = EVP_PKEY_get0_DSA(k);
    if (d != NULL) {
        printf("  DSA flags %#x\n", DSA_test_flags(d, ~0));
        num("p", DSA_get0_p(d));
        num("q", DSA_get0_q(d));
        num("g", DSA_get0_g(d));
        num("pub", DSA_get0_pub_key(d));
        num("priv", DSA_get0_priv_key(d));
    }
    errors();
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

/* The key's parameters with what's asked for: q (or not), the keys, an int field. */
static OSSL_PARAM *key_params(int with_q, const char *pub, const char *priv,
                              const char *more_key, int more)
{
    OSSL_PARAM_BLD *b = OSSL_PARAM_BLD_new();
    BIGNUM *p = hexbn(P), *q = hexbn(Q), *g = hexbn(G), *x = NULL, *y = NULL;
    OSSL_PARAM *ps;

    OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_FFC_P, p);
    if (with_q)
        OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_FFC_Q, q);
    OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_FFC_G, g);
    if (pub != NULL) {
        y = hexbn(pub);
        OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_PUB_KEY, y);
    }
    if (priv != NULL) {
        x = hexbn(priv);
        OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_PRIV_KEY, x);
    }
    if (more_key != NULL)
        OSSL_PARAM_BLD_push_int(b, more_key, more);
    ps = OSSL_PARAM_BLD_to_param(b);
    OSSL_PARAM_BLD_free(b);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(x);
    BN_free(y);
    return ps;
}

static void test_keymgmt(void)
{
    EVP_KEYMGMT *km = EVP_KEYMGMT_fetch(NULL, "DSA", NULL);
    static const int sels[] = { 0, 1, 2, 3, 4, 0x80, 0x84, 0x86, 0x87 };
    size_t i;

    check(km != NULL, "the DSA key manager");
    printf("  names:");
    EVP_KEYMGMT_names_do_all(km, print_names, NULL);
    printf("\n  description: %s\n", EVP_KEYMGMT_get0_description(km));
    names("gettable", EVP_KEYMGMT_gettable_params(km));
    names("settable", EVP_KEYMGMT_settable_params(km));
    names("gen settable", EVP_KEYMGMT_gen_settable_params(km));
    for (i = 0; i < sizeof(sels) / sizeof(sels[0]); i++) {
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL);

        EVP_PKEY_fromdata_init(c);
        printf("  selection %#x", sels[i]);
        names("", EVP_PKEY_fromdata_settable(c, sels[i]));
        EVP_PKEY_CTX_free(c);
    }
    EVP_KEYMGMT_free(km);
    errors();
}

static void test_fromdata(void)
{
    EVP_PKEY *k;
    OSSL_PARAM *ps;
    OSSL_PARAM bad[3];
    int len = 7;

    check(1, "keys from data");
    ps = key_params(1, Y, X, NULL, 0);
    k = fromdata("DSA", EVP_PKEY_KEYPAIR, ps);
    has(k);
    get_all(k);
    todata(k, EVP_PKEY_KEYPAIR, "key pair");
    todata(k, EVP_PKEY_PUBLIC_KEY, "public key");
    todata(k, EVP_PKEY_KEY_PARAMETERS, "parameters");
    EVP_PKEY_free(k);
    k = fromdata("DSA", EVP_PKEY_PUBLIC_KEY, ps);
    has(k);
    EVP_PKEY_free(k);
    k = fromdata("DSA", EVP_PKEY_KEY_PARAMETERS, ps);
    has(k);
    get_all(k);
    EVP_PKEY_free(k);
    OSSL_PARAM_free(ps);

    printf(" without q, with an index:\n");
    ps = key_params(0, Y, NULL, OSSL_PKEY_PARAM_FFC_GINDEX, 5);
    k = fromdata("DSA", EVP_PKEY_KEYPAIR, ps);
    has(k);
    todata(k, EVP_PKEY_KEY_PARAMETERS, "parameters");
    EVP_PKEY_free(k);
    OSSL_PARAM_free(ps);

    printf(" a group name:\n");
    bad[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "ffdhe2048", 0);
    bad[1] = OSSL_PARAM_construct_end();
    k = fromdata("DSA", EVP_PKEY_KEY_PARAMETERS, bad);
    has(k);
    todata(k, EVP_PKEY_KEY_PARAMETERS, "parameters");
    EVP_PKEY_free(k);

    printf(" wrong types:\n");
    bad[0] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_FFC_P, &len);
    bad[1] = OSSL_PARAM_construct_end();
    k = fromdata("DSA", EVP_PKEY_KEY_PARAMETERS, bad);
    has(k);
    bad[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_PUB_KEY, "x", 0);
    k = fromdata("DSA", EVP_PKEY_KEYPAIR, bad);
    has(k);
    EVP_PKEY_free(k);
    bad[0] = OSSL_PARAM_construct_end();
    k = fromdata("DSA", 0, bad);
    has(k);
}

static EVP_PKEY *gen(int params_only, const OSSL_PARAM *ps, EVP_PKEY *templ)
{
    EVP_PKEY_CTX *c = templ != NULL ? EVP_PKEY_CTX_new_from_pkey(NULL, templ, NULL)
                                    : EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL);
    EVP_PKEY *k = NULL;
    int r1, r2, r3;

    r1 = params_only ? EVP_PKEY_paramgen_init(c) : EVP_PKEY_keygen_init(c);
    r2 = ps != NULL ? EVP_PKEY_CTX_set_params(c, ps) : 1;
    /* A refused parameter would leave a 2048-bit generation: stop there. */
    r3 = r2 <= 0 ? -9 : params_only ? EVP_PKEY_paramgen(c, &k) : EVP_PKEY_keygen(c, &k);
    printf("  %s: %d %d %d\n", params_only ? "paramgen" : "keygen", r1, r2, r3);
    errors();
    EVP_PKEY_CTX_free(c);
    return k;
}

static void test_generate(void)
{
    EVP_PKEY *k, *p;
    OSSL_PARAM ps[8];
    size_t pbits = 1024, qbits = 160;
    int gindex = 1, h = 3;
    unsigned char seed[20];

    known_rand(91);
    check(1, "generation");
    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE, "fips186_4", 0);
    ps[1] = OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_FFC_PBITS, &pbits);
    ps[2] = OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_FFC_QBITS, &qbits);
    ps[3] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_FFC_GINDEX, &gindex);
    ps[4] = OSSL_PARAM_construct_end();
    p = gen(1, ps, NULL);
    has(p);
    todata(p, EVP_PKEY_KEY_PARAMETERS, "parameters");
    k = gen(0, NULL, p);
    has(k);
    EVP_PKEY_free(k);
    EVP_PKEY_free(p);

    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE, "FIPS186_2", 0);
    ps[3] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_FFC_H, &h);
    p = gen(1, ps, NULL);
    has(p);
    todata(p, EVP_PKEY_KEY_PARAMETERS, "parameters");
    EVP_PKEY_free(p);

    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE, "default", 0);
    ps[3] = OSSL_PARAM_construct_end();
    p = gen(1, ps, NULL);
    has(p);
    todata(p, EVP_PKEY_KEY_PARAMETERS, "parameters");
    EVP_PKEY_free(p);
    printf(" a key pair at once:\n");
    k = gen(0, ps, NULL);
    has(k);
    EVP_PKEY_free(k);

    printf(" with a seed:\n");
    memset(seed, 0x3c, sizeof(seed));
    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE, "fips186_4", 0);
    ps[3] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_FFC_SEED, seed, sizeof(seed));
    ps[4] = OSSL_PARAM_construct_end();
    p = gen(1, ps, NULL);
    has(p);
    EVP_PKEY_free(p);

    printf(" refused:\n");
    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE, "generator", 0);
    ps[1] = OSSL_PARAM_construct_end();
    p = gen(1, ps, NULL);
    has(p);
    ps[0] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_FFC_TYPE, &h);
    p = gen(1, ps, NULL);
    has(p);
    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_FFC_SEED, "x", 0);
    p = gen(1, ps, NULL);
    has(p);
    printf(" a key without parameters:\n");
    k = gen(0, NULL, NULL);
    has(k);
    {
        EVP_KEYMGMT *km = EVP_KEYMGMT_fetch(NULL, "DSA", NULL);

        names("gen gettable", EVP_KEYMGMT_gen_gettable_params(km));
        EVP_KEYMGMT_free(km);
    }
}

static void validate(EVP_PKEY *k, const char *label)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);

    printf("  %s: check %d", label, EVP_PKEY_check(c));
    printf(" public %d", EVP_PKEY_public_check(c));
    printf(" quick %d", EVP_PKEY_public_check_quick(c));
    printf(" param %d", EVP_PKEY_param_check(c));
    printf(" quick %d", EVP_PKEY_param_check_quick(c));
    printf(" private %d", EVP_PKEY_private_check(c));
    printf(" pairwise %d\n", EVP_PKEY_pairwise_check(c));
    errors();
    EVP_PKEY_CTX_free(c);
}

static void test_compare_validate(void)
{
    EVP_PKEY *a, *b, *c, *e;
    OSSL_PARAM *ps;

    ps = key_params(1, Y, X, NULL, 0);
    a = fromdata("DSA", EVP_PKEY_KEYPAIR, ps);
    OSSL_PARAM_free(ps);
    check(a != NULL, "comparison and validation");
    ps = key_params(1, Y, NULL, NULL, 0);
    b = fromdata("DSA", EVP_PKEY_PUBLIC_KEY, ps);
    OSSL_PARAM_free(ps);
    ps = key_params(1, NULL, NULL, NULL, 0);
    c = fromdata("DSA", EVP_PKEY_KEY_PARAMETERS, ps);
    OSSL_PARAM_free(ps);
    ps = key_params(1, Y, "1234", NULL, 0);
    e = fromdata("DSA", EVP_PKEY_KEYPAIR, ps);
    OSSL_PARAM_free(ps);
    printf("  eq a b %d a c %d a e %d\n", EVP_PKEY_eq(a, b), EVP_PKEY_eq(a, c), EVP_PKEY_eq(a, e));
    printf("  parameters_eq a b %d a c %d\n", EVP_PKEY_parameters_eq(a, b),
           EVP_PKEY_parameters_eq(a, c));
    errors();
    validate(a, "key pair");
    validate(b, "public key");
    validate(c, "parameters");
    validate(e, "a bad key pair");
    {
        EVP_PKEY *f = EVP_PKEY_dup(a);

        printf("  dup eq %d\n", EVP_PKEY_eq(a, f));
        EVP_PKEY_free(f);
    }
    {
        /* q no shorter than p. */
        OSSL_PARAM_BLD *bl = OSSL_PARAM_BLD_new();
        BIGNUM *q = hexbn(Q), *g = hexbn("05");
        EVP_PKEY *h;

        OSSL_PARAM_BLD_push_BN(bl, OSSL_PKEY_PARAM_FFC_P, q);
        OSSL_PARAM_BLD_push_BN(bl, OSSL_PKEY_PARAM_FFC_Q, q);
        OSSL_PARAM_BLD_push_BN(bl, OSSL_PKEY_PARAM_FFC_G, g);
        ps = OSSL_PARAM_BLD_to_param(bl);
        h = fromdata("DSA", EVP_PKEY_KEY_PARAMETERS, ps);
        validate(h, "q as long as p");
        EVP_PKEY_free(h);
        OSSL_PARAM_free(ps);
        OSSL_PARAM_BLD_free(bl);
        BN_free(q);
        BN_free(g);
    }
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);
    EVP_PKEY_free(c);
    EVP_PKEY_free(e);
}

static void print_bio(const char *label, int (*f)(BIO *, const EVP_PKEY *, int, ASN1_PCTX *),
                      EVP_PKEY *k, int indent)
{
    BIO *b = BIO_new(BIO_s_mem());
    char *data;
    long n;
    int r = f(b, k, indent, NULL);

    n = BIO_get_mem_data(b, &data);
    printf("  %s %d (%ld):\n%.*s", label, r, n, (int)n, data);
    BIO_free(b);
    errors();
}

static void test_legacy(void)
{
    EVP_PKEY *k = EVP_PKEY_new(), *k2, *prov;
    DSA *d = DSA_new(), *got;
    OSSL_PARAM *ps;
    BIO *b;
    char *data;
    long n;

    DSA_set0_pqg(d, hexbn(P), hexbn(Q), hexbn(G));
    DSA_set0_key(d, hexbn(Y), hexbn(X));
    check(k != NULL && d != NULL, "DSA in EVP_PKEY");
    printf("  set1 %d", EVP_PKEY_set1_DSA(k, d));
    has(k);
    print_bio("params", EVP_PKEY_print_params, k, 2);
    print_bio("public", EVP_PKEY_print_public, k, 0);
    print_bio("private", EVP_PKEY_print_private, k, 4);
    b = BIO_new(BIO_s_mem());
    printf("  DSA_print %d", DSA_print(b, d, 3));
    printf(" DSAparams_print %d", DSAparams_print(b, d));
    n = BIO_get_mem_data(b, &data);
    printf(" (%ld):\n%.*s", n, (int)n, data);
    BIO_free(b);
    errors();
    {
        FILE *f = tmpfile();
        char line[200];

        printf("  print_fp %d %d\n", DSA_print_fp(f, d, 0), DSAparams_print_fp(f, d));
        rewind(f);
        while (fgets(line, sizeof(line), f) != NULL)
            printf("  | %s", line);
        fclose(f);
    }
    get_all(k);
    todata(k, EVP_PKEY_KEYPAIR, "key pair");
    printf("  missing %d", EVP_PKEY_missing_parameters(k));
    k2 = EVP_PKEY_new();
    EVP_PKEY_set_type(k2, EVP_PKEY_DSA);
    printf(" empty %d", EVP_PKEY_missing_parameters(k2));
    printf(" copy %d", EVP_PKEY_copy_parameters(k2, k));
    printf(" cmp %d", EVP_PKEY_parameters_eq(k, k2));
    printf(" eq %d\n", EVP_PKEY_eq(k, k2));
    has(k2);
    EVP_PKEY_free(k2);
    k2 = EVP_PKEY_dup(k);
    printf("  dup eq %d\n", EVP_PKEY_eq(k, k2));
    EVP_PKEY_free(k2);
    {
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
        EVP_PKEY *kk = NULL;

        printf("  keygen from the legacy key %d", EVP_PKEY_keygen_init(c));
        printf(" %d\n", EVP_PKEY_keygen(c, &kk));
        has(kk);
        printf("  same params %d\n", EVP_PKEY_parameters_eq(k, kk));
        EVP_PKEY_free(kk);
        EVP_PKEY_CTX_free(c);
    }
    {
        int nid = 0;

        printf("  default digest %d", EVP_PKEY_get_default_digest_nid(k, &nid));
        printf(" %d\n", nid);
    }

    ps = key_params(1, Y, X, NULL, 0);
    prov = fromdata("DSA", EVP_PKEY_KEYPAIR, ps);
    OSSL_PARAM_free(ps);
    got = EVP_PKEY_get1_DSA(prov);
    printf("  provided get1 same as get0 %d same numbers %d\n", got == EVP_PKEY_get0_DSA(prov),
           BN_cmp(DSA_get0_priv_key(got), DSA_get0_priv_key(d)) == 0);
    DSA_free(got);
    {
        int nid = 0;

        printf("  provided default digest %d", EVP_PKEY_get_default_digest_nid(prov, &nid));
        printf(" %d\n", nid);
    }
    EVP_PKEY_free(prov);
    k2 = EVP_PKEY_new();
    printf("  get0 of empty %d", EVP_PKEY_get0_DSA(k2) != NULL);
    errors();
    EVP_PKEY_free(k2);
    EVP_PKEY_free(k);
    DSA_free(d);
}

int main(void)
{
    test_keymgmt();
    test_fromdata();
    test_generate();
    test_compare_validate();
    test_legacy();
    errors();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
