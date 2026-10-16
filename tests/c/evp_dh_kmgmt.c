/*
 * Conformance test for the default provider's DH and DHX key managers (EVP_PKEY-DH(7),
 * provider-keymgmt(7)) and DH keys in EVP_PKEY (EVP_PKEY_set1_DH(3)), in TAP format: their
 * names and parameter lists; keys made from data (a named group, explicit p and g, X9.42
 * parameters with q, j, the seed and counters, the private key length, each part alone, and
 * the errors), every gettable parameter, exports of each selection, the encoded public key
 * set on a key; generated parameters and keys (by group name, by size, safe primes with a
 * generator, FIPS 186-4 and 186-2 parameters, from a template, and with each parameter the
 * other key type refuses); comparison and validation; and the moves between a DH in a key
 * and the key managers' data (EVP_PKEY_set1_DH, EVP_PKEY_get0_DH, EVP_PKEY_get1_DH, copies,
 * parameters copied and compared).
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
#include <openssl/dh.h>
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
    const DH *dh;

    if (k == NULL) {
        printf("  (no key)\n");
        return;
    }
    printf("  id %d bits %d security %d size %d", EVP_PKEY_get_id(k), EVP_PKEY_get_bits(k),
           EVP_PKEY_get_security_bits(k), EVP_PKEY_get_size(k));
    printf(" type %s\n", EVP_PKEY_get0_type_name(k));
    dh = EVP_PKEY_get0_DH(k);
    if (dh != NULL) {
        printf("  DH flags %#x length %ld nid %d\n", DH_test_flags(dh, ~0), DH_get_length(dh),
               DH_get_nid(dh));
        num("p", DH_get0_p(dh));
        num("q", DH_get0_q(dh));
        num("g", DH_get0_g(dh));
        num("pub", DH_get0_pub_key(dh));
        num("priv", DH_get0_priv_key(dh));
    }
    errors();
}

static void test_keymgmt(void)
{
    static const char *types[] = { "DH", "DHX" };
    static const int sels[] = { 0, 1, 2, 3, 4, 0x80, 0x84, 0x86, 0x87 };
    size_t t, i;

    for (t = 0; t < 2; t++) {
        EVP_KEYMGMT *km = EVP_KEYMGMT_fetch(NULL, types[t], NULL);

        check(km != NULL, types[t]);
        printf("  names:");
        EVP_KEYMGMT_names_do_all(km, print_names, NULL);
        printf("\n  description: %s\n", EVP_KEYMGMT_get0_description(km));
        names("gettable", EVP_KEYMGMT_gettable_params(km));
        names("settable", EVP_KEYMGMT_settable_params(km));
        names("gen settable", EVP_KEYMGMT_gen_settable_params(km));
        for (i = 0; i < sizeof(sels) / sizeof(sels[0]); i++) {
            EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, types[t], NULL);

            EVP_PKEY_fromdata_init(c);
            printf("  selection %#x", sels[i]);
            names("", EVP_PKEY_fromdata_settable(c, sels[i]));
            EVP_PKEY_CTX_free(c);
        }
        EVP_KEYMGMT_free(km);
    }
    check(EVP_PKEY_type(EVP_PKEY_DHX) == EVP_PKEY_DHX, "the types");
    printf("  is_a dhKeyAgreement %d dhpublicnumber %d X9.42 DH %d\n",
           EVP_KEYMGMT_is_a(EVP_KEYMGMT_fetch(NULL, "DH", NULL), "dhKeyAgreement"),
           EVP_KEYMGMT_is_a(EVP_KEYMGMT_fetch(NULL, "DHX", NULL), "dhpublicnumber"),
           EVP_KEYMGMT_is_a(EVP_KEYMGMT_fetch(NULL, "X9.42 DH", NULL), "DHX"));
    errors();
}

/* The parameters of a named group's DH (its p, q, and g as numbers). */
static OSSL_PARAM *group_params(int nid, int with_q, const char *more_key, long more,
                                const char *pub, const char *priv)
{
    DH *dh = DH_new_by_nid(nid);
    OSSL_PARAM_BLD *b = OSSL_PARAM_BLD_new();
    OSSL_PARAM *ps;
    BIGNUM *x = NULL, *y = NULL;

    OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_FFC_P, DH_get0_p(dh));
    OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_FFC_G, DH_get0_g(dh));
    if (with_q)
        OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_FFC_Q, DH_get0_q(dh));
    if (more_key != NULL)
        OSSL_PARAM_BLD_push_long(b, more_key, more);
    if (pub != NULL) {
        BN_hex2bn(&y, pub);
        OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_PUB_KEY, y);
    }
    if (priv != NULL) {
        BN_hex2bn(&x, priv);
        OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_PRIV_KEY, x);
    }
    ps = OSSL_PARAM_BLD_to_param(b);
    OSSL_PARAM_BLD_free(b);
    BN_free(x);
    BN_free(y);
    DH_free(dh);
    return ps;
}

static EVP_PKEY *named(const char *type, int selection, const char *group)
{
    OSSL_PARAM ps[2];

    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)group, 0);
    ps[1] = OSSL_PARAM_construct_end();
    return fromdata(type, selection, ps);
}

/* A key pair of ffdhe2048: x and g^x mod p. */
static void keypair(char **pub, char **priv)
{
    DH *dh = DH_new_by_nid(NID_ffdhe2048);
    BIGNUM *x = NULL;

    BN_hex2bn(&x, "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
                  "0123456789");
    DH_set0_key(dh, NULL, x);
    DH_generate_key(dh);
    *pub = BN_bn2hex(DH_get0_pub_key(dh));
    *priv = BN_bn2hex(DH_get0_priv_key(dh));
    DH_free(dh);
}

static void test_fromdata(void)
{
    EVP_PKEY *k;
    OSSL_PARAM *ps;
    OSSL_PARAM bad[3];
    char *pub, *priv;
    int len = 7;

    keypair(&pub, &priv);
    check(pub != NULL && priv != NULL, "keys from data");

    printf(" named group, domain parameters:\n");
    k = named("DH", EVP_PKEY_KEY_PARAMETERS, "ffdhe2048");
    has(k);
    get_all(k);
    todata(k, EVP_PKEY_KEY_PARAMETERS, "parameters");
    todata(k, EVP_PKEY_KEYPAIR, "key pair");
    EVP_PKEY_free(k);

    printf(" named group with DHX:\n");
    k = named("DHX", EVP_PKEY_KEY_PARAMETERS, "modp_2048");
    has(k);
    EVP_PKEY_free(k);

    printf(" an unknown group:\n");
    k = named("DH", EVP_PKEY_KEY_PARAMETERS, "ffdhe1024");
    has(k);
    EVP_PKEY_free(k);

    printf(" explicit p and g (a named group's), with a key pair:\n");
    ps = group_params(NID_ffdhe2048, 0, NULL, 0, pub, priv);
    k = fromdata("DH", EVP_PKEY_KEYPAIR, ps);
    has(k);
    get_all(k);
    todata(k, EVP_PKEY_KEYPAIR, "key pair");
    todata(k, EVP_PKEY_PUBLIC_KEY, "public key");
    todata(k, EVP_PKEY_KEY_PARAMETERS, "parameters");
    EVP_PKEY_free(k);
    k = fromdata("DH", EVP_PKEY_PUBLIC_KEY, ps);
    has(k);
    EVP_PKEY_free(k);
    k = fromdata("DH", OSSL_KEYMGMT_SELECT_PRIVATE_KEY, ps);
    has(k);
    EVP_PKEY_free(k);
    OSSL_PARAM_free(ps);

    printf(" RFC 5114's 2048_256 with q and a private key length:\n");
    {
        DH *r = DH_get_2048_256();
        OSSL_PARAM_BLD *b = OSSL_PARAM_BLD_new();
        BIGNUM *j = BN_new();
        unsigned char seed[20];

        memset(seed, 0xa5, sizeof(seed));
        BN_set_word(j, 12345);
        OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_FFC_P, DH_get0_p(r));
        OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_FFC_Q, DH_get0_q(r));
        OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_FFC_G, DH_get0_g(r));
        OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_FFC_COFACTOR, j);
        OSSL_PARAM_BLD_push_int(b, OSSL_PKEY_PARAM_FFC_GINDEX, 3);
        OSSL_PARAM_BLD_push_int(b, OSSL_PKEY_PARAM_FFC_PCOUNTER, 77);
        OSSL_PARAM_BLD_push_int(b, OSSL_PKEY_PARAM_FFC_H, 2);
        OSSL_PARAM_BLD_push_octet_string(b, OSSL_PKEY_PARAM_FFC_SEED, seed, sizeof(seed));
        OSSL_PARAM_BLD_push_int(b, OSSL_PKEY_PARAM_DH_PRIV_LEN, 224);
        OSSL_PARAM_BLD_push_int(b, OSSL_PKEY_PARAM_FFC_VALIDATE_PQ, 1);
        OSSL_PARAM_BLD_push_utf8_string(b, OSSL_PKEY_PARAM_FFC_DIGEST, "SHA256", 0);
        ps = OSSL_PARAM_BLD_to_param(b);
        k = fromdata("DHX", EVP_PKEY_KEY_PARAMETERS, ps);
        has(k);
        get_all(k);
        todata(k, EVP_PKEY_KEY_PARAMETERS, "parameters");
        EVP_PKEY_free(k);
        k = fromdata("DH", EVP_PKEY_KEY_PARAMETERS, ps);
        has(k);
        EVP_PKEY_free(k);
        OSSL_PARAM_free(ps);
        OSSL_PARAM_BLD_free(b);
        BN_free(j);
        DH_free(r);
    }

    printf(" nothing selected, and no parameters:\n");
    ps = group_params(NID_ffdhe2048, 0, NULL, 0, pub, NULL);
    k = fromdata("DH", 0, ps);
    has(k);
    EVP_PKEY_free(k);
    OSSL_PARAM_free(ps);
    bad[0] = OSSL_PARAM_construct_end();
    k = fromdata("DH", EVP_PKEY_KEYPAIR, bad);
    has(k);
    EVP_PKEY_free(k);

    printf(" wrong types:\n");
    bad[0] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_GROUP_NAME, &len);
    bad[1] = OSSL_PARAM_construct_end();
    k = fromdata("DH", EVP_PKEY_KEY_PARAMETERS, bad);
    has(k);
    EVP_PKEY_free(k);
    bad[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "ffdhe2048", 0);
    bad[1] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_FFC_SEED, "seed", 0);
    bad[2] = OSSL_PARAM_construct_end();
    k = fromdata("DH", EVP_PKEY_KEY_PARAMETERS, bad);
    has(k);
    EVP_PKEY_free(k);
    bad[1] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_DH_PRIV_LEN, "x", 0);
    k = fromdata("DH", EVP_PKEY_KEY_PARAMETERS, bad);
    has(k);
    EVP_PKEY_free(k);
    bad[1] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_FFC_DIGEST, &len);
    k = fromdata("DH", EVP_PKEY_KEY_PARAMETERS, bad);
    has(k);
    EVP_PKEY_free(k);

    OPENSSL_free(pub);
    OPENSSL_free(priv);
}

static void encoded(EVP_PKEY *k, const unsigned char *p, size_t n, const char *label)
{
    int r = EVP_PKEY_set1_encoded_public_key(k, p, n);

    printf("  set encoded %s: %d\n", label, r);
    errors();
}

static void test_encoded(void)
{
    EVP_PKEY *k = named("DH", EVP_PKEY_KEY_PARAMETERS, "ffdhe2048"), *k2;
    unsigned char *enc = NULL, buf[300];
    size_t n;
    char *pub, *priv;
    BIGNUM *y = NULL;
    OSSL_PARAM ps[2];

    check(k != NULL, "the encoded public key");
    n = EVP_PKEY_get1_encoded_public_key(k, &enc);
    printf("  get without a key: %zu\n", n);
    errors();
    keypair(&pub, &priv);
    BN_hex2bn(&y, pub);
    BN_bn2binpad(y, buf, 256);
    encoded(k, buf, 256, "the public key");
    n = EVP_PKEY_get1_encoded_public_key(k, &enc);
    octets("encoded", enc, n);
    OPENSSL_free(enc);
    enc = NULL;
    /* Shorter (the leading zeros dropped) and padded. */
    encoded(k, buf + 1, 255, "255 octets");
    memset(buf, 0, sizeof(buf));
    buf[255] = 1;
    encoded(k, buf, 256, "1");
    buf[255] = 2;
    encoded(k, buf, 256, "2");
    encoded(k, buf, 0, "nothing");
    memset(buf, 0xff, 256);
    encoded(k, buf, 256, "all ones");
    get_all(k);

    /* The parameter, with the buffer too small, and asked for its size. */
    ps[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, buf, 10);
    ps[1] = OSSL_PARAM_construct_end();
    printf("  get into 10: %d", EVP_PKEY_get_params(k, ps));
    errors();
    ps[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0);
    printf("  get the size: %d %zu\n", EVP_PKEY_get_params(k, ps), ps[0].return_size);
    errors();
    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, (char *)buf,
                                             sizeof(buf));
    printf("  get as UTF-8: %d", EVP_PKEY_get_params(k, ps));
    errors();
    printf("  set as UTF-8: %d", EVP_PKEY_set_params(k, ps));
    errors();

    /* No parameters. */
    k2 = EVP_PKEY_new();
    {
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
        OSSL_PARAM none[1] = { OSSL_PARAM_END };

        EVP_PKEY_fromdata_init(c);
        EVP_PKEY_free(k2);
        k2 = NULL;
        printf("  empty key: %d\n", EVP_PKEY_fromdata(c, &k2, EVP_PKEY_KEY_PARAMETERS, none));
        EVP_PKEY_CTX_free(c);
    }
    errors();
    buf[0] = 5;
    encoded(k2, buf, 1, "without parameters");
    EVP_PKEY_free(k2);
    EVP_PKEY_free(k);
    BN_free(y);
    OPENSSL_free(pub);
    OPENSSL_free(priv);
}

static EVP_PKEY *gen(const char *type, int params_only, const OSSL_PARAM *ps, EVP_PKEY *templ)
{
    EVP_PKEY_CTX *c = templ != NULL ? EVP_PKEY_CTX_new_from_pkey(NULL, templ, NULL)
                                    : EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
    EVP_PKEY *k = NULL;
    int r1, r2, r3;

    r1 = params_only ? EVP_PKEY_paramgen_init(c) : EVP_PKEY_keygen_init(c);
    r2 = ps != NULL ? EVP_PKEY_CTX_set_params(c, ps) : 1;
    /* A refused parameter would leave a 2048-bit safe prime to generate: stop there. */
    r3 = r2 <= 0 ? -9 : params_only ? EVP_PKEY_paramgen(c, &k) : EVP_PKEY_keygen(c, &k);
    printf("  %s %s: %d %d %d\n", type, params_only ? "paramgen" : "keygen", r1, r2, r3);
    errors();
    EVP_PKEY_CTX_free(c);
    return k;
}

static void test_generate(void)
{
    EVP_PKEY *k, *p;
    OSSL_PARAM ps[8];
    size_t pbits = 3072, qbits = 160;
    int gen2 = 2, gindex = 1, plen = 300;
    unsigned char seed[20];

    known_rand(11);
    check(1, "generation");
    printf(" by group name:\n");
    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "ffdhe2048", 0);
    ps[1] = OSSL_PARAM_construct_end();
    k = gen("DH", 0, ps, NULL);
    has(k);
    EVP_PKEY_free(k);
    p = gen("DH", 1, ps, NULL);
    has(p);
    printf(" from those parameters:\n");
    k = gen("DH", 0, NULL, p);
    has(k);
    EVP_PKEY_free(k);
    EVP_PKEY_free(p);

    printf(" by size, of type group:\n");
    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE, "group", 0);
    ps[1] = OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_FFC_PBITS, &pbits);
    ps[2] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_DH_PRIV_LEN, &plen);
    ps[3] = OSSL_PARAM_construct_end();
    p = gen("DH", 1, ps, NULL);
    has(p);
    EVP_PKEY_free(p);
    pbits = 1000;
    p = gen("DH", 1, ps, NULL);
    has(p);
    EVP_PKEY_free(p);
    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE, "generator", 0);
    p = gen("DHX", 1, ps, NULL);
    has(p);
    EVP_PKEY_free(p);

    printf(" a safe prime with a generator:\n");
    pbits = 512;
    ps[0] = OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_FFC_PBITS, &pbits);
    ps[1] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_DH_GENERATOR, &gen2);
    ps[2] = OSSL_PARAM_construct_end();
    p = gen("DH", 1, ps, NULL);
    has(p);
    k = gen("DH", 0, NULL, p);
    has(k);
    printf("  check %d\n", EVP_PKEY_param_check(EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL)));
    EVP_PKEY_free(k);
    EVP_PKEY_free(p);
    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE, "default", 0);
    ps[1] = OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_FFC_PBITS, &pbits);
    ps[2] = OSSL_PARAM_construct_end();
    p = gen("DH", 1, ps, NULL);
    has(p);
    EVP_PKEY_free(p);

    printf(" FIPS 186-4 and 186-2 parameters:\n");
    pbits = 1024;
    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE, "fips186_4", 0);
    ps[1] = OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_FFC_PBITS, &pbits);
    ps[2] = OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_FFC_QBITS, &qbits);
    ps[3] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_FFC_GINDEX, &gindex);
    /*
     * Not a digest: OpenSSL's generated key keeps a pointer to the generation context's copy of
     * its name, which is freed (docs/DEVIATIONS.md).
     */
    ps[4] = OSSL_PARAM_construct_end();
    p = gen("DHX", 1, ps, NULL);
    has(p);
    todata(p, EVP_PKEY_KEY_PARAMETERS, "parameters");
    k = gen("DHX", 0, NULL, p);
    has(k);
    EVP_PKEY_free(k);
    EVP_PKEY_free(p);
    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE, "fips186_2", 0);
    ps[3] = OSSL_PARAM_construct_end();
    p = gen("DHX", 1, ps, NULL);
    has(p);
    todata(p, EVP_PKEY_KEY_PARAMETERS, "parameters");
    EVP_PKEY_free(p);
    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE, "default", 0);
    p = gen("DHX", 1, ps, NULL);
    has(p);
    EVP_PKEY_free(p);
    printf(" with a seed:\n");
    memset(seed, 0x3c, sizeof(seed));
    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE, "fips186_4", 0);
    ps[3] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_FFC_SEED, seed, sizeof(seed));
    ps[4] = OSSL_PARAM_construct_end();
    p = gen("DHX", 1, ps, NULL);
    has(p);
    EVP_PKEY_free(p);

    printf(" refused:\n");
    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE, "fips186_4", 0);
    ps[1] = OSSL_PARAM_construct_end();
    p = gen("DH", 1, ps, NULL);
    has(p);
    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE, "nonsense", 0);
    p = gen("DHX", 1, ps, NULL);
    has(p);
    ps[0] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_FFC_GINDEX, &gindex);
    p = gen("DH", 1, ps, NULL);
    has(p);
    ps[0] = OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_FFC_QBITS, &qbits);
    p = gen("DH", 1, ps, NULL);
    has(p);
    ps[0] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_DH_GENERATOR, &gen2);
    p = gen("DHX", 1, ps, NULL);
    has(p);
    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "nope", 0);
    p = gen("DH", 1, ps, NULL);
    has(p);
    ps[0] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_GROUP_NAME, &gen2);
    p = gen("DH", 1, ps, NULL);
    has(p);
    printf(" a key with no parameters:\n");
    k = gen("DH", 0, NULL, NULL);
    has(k);

    printf(" the setters:\n");
    {
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "DHX", NULL);

        printf("  init %d", EVP_PKEY_paramgen_init(c));
        printf(" prime %d", EVP_PKEY_CTX_set_dh_paramgen_prime_len(c, 1024));
        printf(" subprime %d", EVP_PKEY_CTX_set_dh_paramgen_subprime_len(c, 160));
        printf(" gindex %d", EVP_PKEY_CTX_set_dh_paramgen_gindex(c, 2));
        printf(" nid %d\n", EVP_PKEY_CTX_set_dh_nid(c, NID_ffdhe2048));
        errors();
        p = NULL;
        printf("  paramgen %d\n", EVP_PKEY_paramgen(c, &p));
        has(p);
        EVP_PKEY_free(p);
        EVP_PKEY_CTX_free(c);
        c = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
        printf("  init %d", EVP_PKEY_paramgen_init(c));
        printf(" prime %d", EVP_PKEY_CTX_set_dh_paramgen_prime_len(c, 512));
        printf(" generator %d", EVP_PKEY_CTX_set_dh_paramgen_generator(c, 5));
        printf(" rfc5114 %d\n", EVP_PKEY_CTX_set_dh_rfc5114(c, 2));
        errors();
        p = NULL;
        printf("  paramgen %d\n", EVP_PKEY_paramgen(c, &p));
        has(p);
        EVP_PKEY_free(p);
        EVP_PKEY_CTX_free(c);
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
    EVP_PKEY *a, *b, *c, *d, *e;
    OSSL_PARAM *ps;
    char *pub, *priv;

    keypair(&pub, &priv);
    ps = group_params(NID_ffdhe2048, 0, NULL, 0, pub, priv);
    a = fromdata("DH", EVP_PKEY_KEYPAIR, ps);
    OSSL_PARAM_free(ps);
    check(a != NULL, "comparison and validation");
    ps = group_params(NID_ffdhe2048, 1, NULL, 0, pub, NULL);
    b = fromdata("DH", EVP_PKEY_PUBLIC_KEY, ps);
    OSSL_PARAM_free(ps);
    c = named("DH", EVP_PKEY_KEY_PARAMETERS, "ffdhe3072");
    d = named("DH", EVP_PKEY_KEY_PARAMETERS, "ffdhe2048");
    ps = group_params(NID_ffdhe2048, 0, NULL, 0, "02", "1234");
    e = fromdata("DH", EVP_PKEY_KEYPAIR, ps);
    OSSL_PARAM_free(ps);
    printf("  eq a b %d a c %d a d %d b d %d a e %d\n", EVP_PKEY_eq(a, b), EVP_PKEY_eq(a, c),
           EVP_PKEY_eq(a, d), EVP_PKEY_eq(b, d), EVP_PKEY_eq(a, e));
    printf("  parameters_eq a b %d a c %d a d %d\n", EVP_PKEY_parameters_eq(a, b),
           EVP_PKEY_parameters_eq(a, c), EVP_PKEY_parameters_eq(a, d));
    errors();
    validate(a, "key pair");
    validate(b, "public key");
    validate(c, "parameters");
    validate(e, "a bad key pair");
    {
        EVP_PKEY *f = gen("DH", 0, NULL, c), *g;

        validate(f, "generated");
        g = EVP_PKEY_dup(f);
        printf("  dup eq %d\n", EVP_PKEY_eq(f, g));
        has(g);
        EVP_PKEY_free(g);
        EVP_PKEY_free(f);
    }
    {
        /* Explicit parameters that aren't a safe prime group: 2048_224's p with g 2. */
        DH *r = DH_get_2048_224();
        OSSL_PARAM_BLD *bl = OSSL_PARAM_BLD_new();
        BIGNUM *two = BN_new();
        EVP_PKEY *h;

        BN_set_word(two, 2);
        OSSL_PARAM_BLD_push_BN(bl, OSSL_PKEY_PARAM_FFC_P, DH_get0_p(r));
        OSSL_PARAM_BLD_push_BN(bl, OSSL_PKEY_PARAM_FFC_G, two);
        ps = OSSL_PARAM_BLD_to_param(bl);
        h = fromdata("DH", EVP_PKEY_KEY_PARAMETERS, ps);
        validate(h, "not a safe prime");
        EVP_PKEY_free(h);
        OSSL_PARAM_free(ps);
        OSSL_PARAM_BLD_free(bl);
        BN_free(two);
        h = EVP_PKEY_new();
        EVP_PKEY_set1_DH(h, r);
        validate(h, "2048_224");
        EVP_PKEY_free(h);
        DH_free(r);
    }
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);
    EVP_PKEY_free(c);
    EVP_PKEY_free(d);
    EVP_PKEY_free(e);
    OPENSSL_free(pub);
    OPENSSL_free(priv);
}

static void test_legacy(void)
{
    EVP_PKEY *k = EVP_PKEY_new(), *k2, *prov;
    DH *dh = DH_new_by_nid(NID_ffdhe2048), *r = DH_get_2048_256(), *got, *plain = DH_new();
    BIGNUM *p = NULL, *g = NULL;
    OSSL_PARAM ps[2];
    int bits = 0;

    check(k != NULL && dh != NULL, "DH in EVP_PKEY");
    printf("  set1 named %d", EVP_PKEY_set1_DH(k, dh));
    has(k);
    get_all(k);
    printf("  set1 2048_256 %d", EVP_PKEY_set1_DH(k, r));
    has(k);
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&g, "05");
    DH_set0_pqg(plain, p, NULL, g);
    printf("  set1 made up %d", EVP_PKEY_set1_DH(k, plain));
    has(k);
    k2 = EVP_PKEY_new();
    printf("  get0 of empty %d", EVP_PKEY_get0_DH(k2) != NULL);
    errors();
    EVP_PKEY_free(k2);

    /* A provided key's DH, made once and kept. */
    prov = named("DHX", EVP_PKEY_KEY_PARAMETERS, "ffdhe2048");
    got = EVP_PKEY_get1_DH(prov);
    printf("  provided get1 same as get0 %d\n", got == EVP_PKEY_get0_DH(prov));
    has(prov);
    DH_free(got);
    k2 = gen("DH", 0, NULL, prov);
    has(k2);
    got = EVP_PKEY_get1_DH(k2);
    printf("  generated, its DH's keys %d %d\n", DH_get0_pub_key(got) != NULL,
           DH_get0_priv_key(got) != NULL);
    DH_free(got);
    EVP_PKEY_free(k2);
    EVP_PKEY_free(prov);

    /* A key with a legacy DH used as a provided one. */
    EVP_PKEY_set1_DH(k, dh);
    get_all(k);
    todata(k, EVP_PKEY_KEY_PARAMETERS, "parameters");
    k2 = gen("DH", 0, NULL, k);
    has(k2);
    printf("  generated eq params %d\n", EVP_PKEY_parameters_eq(k, k2));
    EVP_PKEY_free(k2);
    ps[0] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_BITS, &bits);
    ps[1] = OSSL_PARAM_construct_end();
    printf("  get bits %d %d\n", EVP_PKEY_get_params(k, ps), bits);
    printf("  missing %d", EVP_PKEY_missing_parameters(k));
    k2 = EVP_PKEY_new();
    EVP_PKEY_set_type(k2, EVP_PKEY_DH);
    printf(" empty %d", EVP_PKEY_missing_parameters(k2));
    printf(" copy %d", EVP_PKEY_copy_parameters(k2, k));
    printf(" cmp %d", EVP_PKEY_parameters_eq(k, k2));
    printf(" eq %d\n", EVP_PKEY_eq(k, k2));
    has(k2);
    EVP_PKEY_free(k2);
    k2 = EVP_PKEY_new();
    EVP_PKEY_set1_DH(k2, r);
    printf("  cmp DHX %d", EVP_PKEY_parameters_eq(k, k2));
    printf(" copy across %d\n", EVP_PKEY_copy_parameters(k2, k));
    errors();
    EVP_PKEY_free(k2);
    k2 = EVP_PKEY_dup(k);
    has(k2);
    {
        /* With a key pair, and a public key set from octets. */
        EVP_PKEY *kp = EVP_PKEY_new();
        DH *d2 = DH_new_by_nid(NID_ffdhe2048);
        unsigned char *enc = NULL;
        size_t n;

        DH_generate_key(d2);
        EVP_PKEY_set1_DH(kp, d2);
        n = EVP_PKEY_get1_encoded_public_key(kp, &enc);
        printf("  encoded %zu\n", n);
        printf("  set encoded on the legacy key %d\n",
               EVP_PKEY_set1_encoded_public_key(k2, enc, n));
        errors();
        printf("  eq %d\n", EVP_PKEY_eq(kp, k2));
        validate(kp, "legacy");
        OPENSSL_free(enc);
        EVP_PKEY_free(kp);
        DH_free(d2);
    }
    EVP_PKEY_free(k2);
    EVP_PKEY_free(k);
    DH_free(dh);
    DH_free(r);
    DH_free(plain);
}

int main(void)
{
    test_keymgmt();
    test_fromdata();
    test_encoded();
    test_generate();
    test_compare_validate();
    test_legacy();
    errors();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
