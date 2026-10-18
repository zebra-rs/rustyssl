/*
 * Conformance test for the DH object (DH_new(3), DH_get0_pqg(3), DH_set_method(3),
 * DH_meth_new(3), DH_new_by_nid(3), DH_get_1024_160(3), DH_generate_key(3), DH_size(3)), in
 * TAP format: empty objects; parameters set from numbers (a named group recognized, its q
 * filled in, by p and g with q or without), and given back (the same BIGNUMs); every named
 * group by NID, and RFC 5114's by their functions; the private key length; keys set and given
 * back; flags, application data, and references; key generation (from known generators, so
 * every key is the reference's) for named groups, RFC 5114's, and parameters without q, with
 * length limits and moduli too small; shared secrets, padded and not, and bad peers; and
 * methods: copies, names, flags, application data, every function's getter and setter, an
 * application's method that counts its calls and hands them to OpenSSL's, its init and
 * finish, and the default method.
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
#include <openssl/obj_mac.h>
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

/* The first 8 octets of the SHA-256 of a number's big-endian octets, with its bits. */
static void num(const char *label, const BIGNUM *b)
{
    unsigned char buf[1100], d[32];
    unsigned int dl = 0;
    int n, i;

    if (b == NULL) {
        printf("  %s: (null)\n", label);
        return;
    }
    n = BN_bn2bin(b, buf);
    EVP_Digest(buf, n, d, &dl, EVP_sha256(), NULL);
    printf("  %s: %d bits ", label, BN_num_bits(b));
    for (i = 0; i < 8; i++)
        printf("%02x", d[i]);
    printf("\n");
}

static void digest(const char *label, const unsigned char *p, int n)
{
    unsigned char d[32];
    unsigned int dl = 0;
    int i;

    if (n < 0) {
        printf("  %s: %d\n", label, n);
        return;
    }
    EVP_Digest(p, n, d, &dl, EVP_sha256(), NULL);
    printf("  %s (%d): ", label, n);
    for (i = 0; i < 8; i++)
        printf("%02x", d[i]);
    printf("\n");
}

static void sizes(const char *label, const DH *dh)
{
    printf("  %s: bits %d size %d security %d length %ld nid %d\n", label, DH_bits(dh),
           DH_size(dh), DH_security_bits(dh), DH_get_length(dh), DH_get_nid(dh));
}

static void pqg(const char *label, const DH *dh)
{
    const BIGNUM *p, *q, *g;

    DH_get0_pqg(dh, &p, &q, &g);
    printf("  %s:\n", label);
    num("p", p);
    num("q", q);
    num("g", g);
}

static void test_empty(void)
{
    DH *dh = DH_new();
    const BIGNUM *p = (const BIGNUM *)1, *q = (const BIGNUM *)1, *g = (const BIGNUM *)1;
    const BIGNUM *pub = (const BIGNUM *)1, *priv = (const BIGNUM *)1;

    check(dh != NULL, "an empty DH");
    sizes("empty", dh);
    DH_get0_pqg(dh, &p, &q, &g);
    DH_get0_key(dh, &pub, &priv);
    printf("  null %d %d %d %d %d, getters %d %d %d %d %d, engine %d\n", p == NULL, q == NULL,
           g == NULL, pub == NULL, priv == NULL, DH_get0_p(dh) == NULL, DH_get0_q(dh) == NULL,
           DH_get0_g(dh) == NULL, DH_get0_pub_key(dh) == NULL, DH_get0_priv_key(dh) == NULL,
           DH_get0_engine(dh) == NULL);
    DH_get0_pqg(dh, NULL, NULL, NULL);
    DH_get0_key(dh, NULL, NULL);
    printf("  set0_pqg without p %d, without g %d\n", DH_set0_pqg(dh, NULL, NULL, BN_new()),
           0);
    printf("  flags %d test %d\n", DH_test_flags(dh, ~0), DH_test_flags(dh, DH_FLAG_CACHE_MONT_P));
    DH_set_flags(dh, 0x1000);
    printf("  set %d", DH_test_flags(dh, ~0));
    DH_clear_flags(dh, 0x1001);
    printf(" cleared %d\n", DH_test_flags(dh, ~0));
    printf("  set_length %d", DH_set_length(dh, 300));
    printf(" length %ld\n", DH_get_length(dh));
    printf("  up_ref %d\n", DH_up_ref(dh));
    DH_free(dh);
    DH_free(dh);
    DH_free(NULL);
    errors();
}

static void test_pqg(void)
{
    DH *ff = DH_new_by_nid(NID_ffdhe2048), *dh = DH_new();
    BIGNUM *p, *g, *q, *p2;
    const BIGNUM *gp, *gq, *gg;

    check(ff != NULL && dh != NULL, "parameters from numbers");
    p = BN_dup(DH_get0_p(ff));
    g = BN_dup(DH_get0_g(ff));
    printf("  set0_pqg without g %d\n", DH_set0_pqg(dh, p, NULL, NULL));
    printf("  set0_pqg p g %d\n", DH_set0_pqg(dh, p, NULL, g));
    DH_get0_pqg(dh, &gp, &gq, &gg);
    printf("  same p %d g %d, q filled %d\n", gp == p, gg == g, gq != NULL);
    sizes("ffdhe2048 by numbers", dh);
    pqg("numbers", dh);
    /* Another q for the same p and g: no longer the named group. */
    q = BN_new();
    BN_set_word(q, 12345);
    printf("  set0_pqg q %d\n", DH_set0_pqg(dh, NULL, q, NULL));
    sizes("with another q", dh);
    /* Set p again, and back to the group's. */
    p2 = BN_dup(p);
    BN_add_word(p2, 2);
    printf("  set0_pqg p %d", DH_set0_pqg(dh, p2, NULL, NULL));
    printf(" p is the new %d\n", DH_get0_p(dh) == p2);
    sizes("another p", dh);
    DH_free(dh);
    DH_free(ff);
    errors();
}

static void test_groups(void)
{
    static const int nids[] = { NID_ffdhe2048, NID_ffdhe3072, NID_ffdhe4096, NID_ffdhe6144,
                                NID_ffdhe8192, NID_modp_1536, NID_modp_2048, NID_modp_3072,
                                NID_modp_4096, NID_modp_6144, NID_modp_8192, 1, 2, 3,
                                NID_undef, NID_sha256 };
    DH *dh;
    size_t i;

    check(1, "named groups");
    for (i = 0; i < sizeof(nids) / sizeof(nids[0]); i++) {
        dh = DH_new_by_nid(nids[i]);
        printf("  nid %d: %s", nids[i], dh == NULL ? "none\n" : "\n");
        if (dh != NULL) {
            sizes(OBJ_nid2sn(nids[i]), dh);
            pqg("numbers", dh);
        }
        DH_free(dh);
        errors();
    }
    dh = DH_get_1024_160();
    sizes("DH_get_1024_160", dh);
    pqg("numbers", dh);
    DH_free(dh);
    dh = DH_get_2048_224();
    sizes("DH_get_2048_224", dh);
    DH_free(dh);
    dh = DH_get_2048_256();
    sizes("DH_get_2048_256", dh);
    pqg("numbers", dh);
    DH_free(dh);
    errors();
}

static void test_keys(void)
{
    DH *dh = DH_new_by_nid(NID_ffdhe2048), *d;
    BIGNUM *pub = BN_new(), *priv = BN_new(), *pub2 = BN_new();
    const BIGNUM *gp, *gq;

    check(dh != NULL, "keys");
    BN_set_word(pub, 5);
    BN_set_word(priv, 7);
    printf("  set0_key %d", DH_set0_key(dh, pub, priv));
    DH_get0_key(dh, &gp, &gq);
    printf(" same %d %d\n", gp == pub, gq == priv);
    BN_set_word(pub2, 9);
    printf("  set0_key pub only %d", DH_set0_key(dh, pub2, NULL));
    DH_get0_key(dh, &gp, &gq);
    printf(" same %d %d\n", gp == pub2, gq == priv);
    printf("  set0_key none %d\n", DH_set0_key(dh, NULL, NULL));
    d = DHparams_dup(dh);
    sizes("dup", d);
    DH_get0_key(d, &gp, &gq);
    printf("  dup keys %d %d, p equal %d\n", gp == NULL, gq == NULL,
           BN_cmp(DH_get0_p(d), DH_get0_p(dh)) == 0);
    DH_free(d);
    DH_free(dh);
    errors();
}

static int free_calls = 0;

static void ex_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
    (void)parent;
    (void)ad;
    (void)idx;
    (void)argp;
    free_calls++;
    printf("  ex free %s %ld\n", (const char *)ptr, argl);
}

static void test_ex_data(void)
{
    int idx = DH_get_ex_new_index(7, NULL, NULL, NULL, ex_free);
    DH *dh = DH_new();

    check(idx >= 0, "application data");
    printf("  get unset %d\n", DH_get_ex_data(dh, idx) == NULL);
    printf("  set %d", DH_set_ex_data(dh, idx, "hello"));
    printf(" get %s\n", (const char *)DH_get_ex_data(dh, idx));
    DH_free(dh);
    printf("  free calls %d\n", free_calls);
    errors();
}

/* Two keys of the same parameters and their shared secrets. */
static void exchange(const char *label, DH *a, DH *b)
{
    unsigned char s1[1100], s2[1100], s3[1100];
    int n1, n2, n3;

    n1 = DH_compute_key(s1, DH_get0_pub_key(b), a);
    n2 = DH_compute_key(s2, DH_get0_pub_key(a), b);
    n3 = DH_compute_key_padded(s3, DH_get0_pub_key(b), a);
    printf("  %s: %d %d %d same %d\n", label, n1, n2, n3, n1 == n2 && memcmp(s1, s2, n1) == 0);
    digest("secret", s1, n1);
    digest("padded", s3, n3);
}

static void test_generate(void)
{
    DH *a = DH_new_by_nid(NID_ffdhe2048), *b = DH_new_by_nid(NID_ffdhe2048), *c, *d;
    BIGNUM *one = BN_new(), *pm1, *p, *g;
    unsigned char s[1100];

    check(RAND_set0_public(NULL, known_drbg(41)) == 1
          && RAND_set0_private(NULL, known_drbg(42)) == 1, "key generation");
    printf("  generate %d %d\n", DH_generate_key(a), DH_generate_key(b));
    num("pub", DH_get0_pub_key(a));
    num("priv", DH_get0_priv_key(a));
    num("pub b", DH_get0_pub_key(b));
    exchange("ffdhe2048", a, b);
    /* Again with the keys there: the private key kept, the public one recomputed. */
    printf("  again %d\n", DH_generate_key(a));
    num("pub", DH_get0_pub_key(a));
    errors();

    /* Bad peers. */
    BN_one(one);
    printf("  peer 1: %d", DH_compute_key(s, one, a));
    errors();
    pm1 = BN_dup(DH_get0_p(a));
    BN_sub_word(pm1, 1);
    printf("  peer p-1: %d", DH_compute_key(s, pm1, a));
    errors();
    BN_free(pm1);
    BN_free(one);

    /* A private key length. */
    c = DH_new_by_nid(NID_modp_3072);
    DH_set_length(c, 256);
    printf("  modp_3072 length 256: %d", DH_generate_key(c));
    printf(" priv bits %d\n", BN_num_bits(DH_get0_priv_key(c)));
    DH_free(c);
    c = DH_new_by_nid(NID_ffdhe2048);
    DH_set_length(c, 4000);
    printf("  ffdhe2048 length 4000: %d", DH_generate_key(c));
    errors();
    DH_free(c);

    /* RFC 5114's and parameters without q (a legacy private key of the length asked). */
    c = DH_get_2048_256();
    d = DH_get_2048_256();
    printf("  2048_256: %d %d\n", DH_generate_key(c), DH_generate_key(d));
    num("pub", DH_get0_pub_key(c));
    exchange("2048_256", c, d);
    DH_free(c);
    DH_free(d);
    c = DH_get_1024_160();
    printf("  1024_160: %d", DH_generate_key(c));
    num("pub", DH_get0_pub_key(c));
    errors();
    DH_free(c);
    c = DH_new();
    p = BN_dup(DH_get0_p(a));
    BN_sub_word(p, 0); /* the same prime */
    g = BN_new();
    BN_set_word(g, 5);
    DH_set0_pqg(c, p, NULL, g);
    sizes("p with g 5", c);
    printf("  generate %d", DH_generate_key(c));
    num("priv", DH_get0_priv_key(c));
    DH_set_length(c, 100);
    DH_set0_key(c, NULL, NULL);
    errors();
    DH_free(c);
    c = DH_new();
    p = BN_dup(DH_get0_p(a));
    g = BN_new();
    BN_set_word(g, 3);
    DH_set0_pqg(c, p, NULL, g);
    DH_set_length(c, 160);
    printf("  g 3 length 160: %d", DH_generate_key(c));
    num("priv", DH_get0_priv_key(c));
    errors();
    DH_free(c);
    /* A 3072-bit modulus with a 256-bit q that isn't a named group. */
    c = DH_new();
    p = BN_dup(DH_get0_p(a));
    g = BN_new();
    BN_set_word(g, 2);
    DH_set0_pqg(c, p, BN_dup(DH_get0_q(a)), g);
    BN_add_word((BIGNUM *)DH_get0_q(c), 2);
    DH_set0_pqg(c, NULL, NULL, NULL);
    sizes("p with another q", c);
    printf("  generate %d", DH_generate_key(c));
    errors();
    DH_free(c);
    /* A modulus too small. */
    c = DH_new();
    p = BN_new();
    BN_set_word(p, 23);
    g = BN_new();
    BN_set_word(g, 5);
    DH_set0_pqg(c, p, NULL, g);
    printf("  p = 23: %d", DH_generate_key(c));
    errors();
    printf("  compute without a private key: %d", DH_compute_key(s, DH_get0_pub_key(a), c));
    errors();
    DH_free(c);
    c = DH_new_by_nid(NID_ffdhe2048);
    printf("  compute without a private key: %d", DH_compute_key(s, DH_get0_pub_key(a), c));
    errors();
    DH_free(c);
    DH_free(a);
    DH_free(b);
    RAND_set0_public(NULL, NULL);
    RAND_set0_private(NULL, NULL);
}

static int calls[8];

static int my_generate_key(DH *dh)
{
    calls[0]++;
    return DH_meth_get_generate_key(DH_OpenSSL())(dh);
}

static int my_compute_key(unsigned char *key, const BIGNUM *pub, DH *dh)
{
    calls[1]++;
    return DH_meth_get_compute_key(DH_OpenSSL())(key, pub, dh);
}

static int my_bn_mod_exp(const DH *dh, BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                         const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *mctx)
{
    calls[2]++;
    return DH_meth_get_bn_mod_exp(DH_OpenSSL())(dh, r, a, p, m, ctx, mctx);
}

static int my_init(DH *dh)
{
    (void)dh;
    calls[3]++;
    return 1;
}

static int my_finish(DH *dh)
{
    (void)dh;
    calls[4]++;
    return 1;
}

static int my_generate_params(DH *dh, int prime_len, int generator, BN_GENCB *cb)
{
    (void)dh;
    (void)cb;
    calls[5]++;
    printf("  generate_params %d %d\n", prime_len, generator);
    return 0;
}

static void test_methods(void)
{
    const DH_METHOD *ossl = DH_OpenSSL();
    DH_METHOD *m = DH_meth_new("counting", 0x40), *dup;
    DH *a, *b;
    unsigned char s[300];
    int n;

    check(ossl != NULL && m != NULL, "methods");
    printf("  OpenSSL's: %s flags %d default %d\n", DH_meth_get0_name(ossl),
           DH_meth_get_flags(ossl), DH_get_default_method() == ossl);
    printf("  OpenSSL's functions: %d %d %d %d %d %d\n",
           DH_meth_get_generate_key(ossl) != NULL, DH_meth_get_compute_key(ossl) != NULL,
           DH_meth_get_bn_mod_exp(ossl) != NULL, DH_meth_get_init(ossl) != NULL,
           DH_meth_get_finish(ossl) != NULL, DH_meth_get_generate_params(ossl) != NULL);
    printf("  new: %s flags %d app %d functions %d %d %d %d %d %d\n", DH_meth_get0_name(m),
           DH_meth_get_flags(m), DH_meth_get0_app_data(m) == NULL,
           DH_meth_get_generate_key(m) == NULL, DH_meth_get_compute_key(m) == NULL,
           DH_meth_get_bn_mod_exp(m) == NULL, DH_meth_get_init(m) == NULL,
           DH_meth_get_finish(m) == NULL, DH_meth_get_generate_params(m) == NULL);
    printf("  set %d %d %d %d %d %d %d %d %d\n", DH_meth_set1_name(m, "counting DH"),
           DH_meth_set_flags(m, 0x41), DH_meth_set0_app_data(m, (void *)"app"),
           DH_meth_set_generate_key(m, my_generate_key),
           DH_meth_set_compute_key(m, my_compute_key), DH_meth_set_bn_mod_exp(m, my_bn_mod_exp),
           DH_meth_set_init(m, my_init), DH_meth_set_finish(m, my_finish),
           DH_meth_set_generate_params(m, my_generate_params));
    printf("  got: %s flags %d app %s same %d %d %d %d %d %d\n", DH_meth_get0_name(m),
           DH_meth_get_flags(m), (const char *)DH_meth_get0_app_data(m),
           DH_meth_get_generate_key(m) == my_generate_key,
           DH_meth_get_compute_key(m) == my_compute_key,
           DH_meth_get_bn_mod_exp(m) == my_bn_mod_exp, DH_meth_get_init(m) == my_init,
           DH_meth_get_finish(m) == my_finish,
           DH_meth_get_generate_params(m) == my_generate_params);
    dup = DH_meth_dup(m);
    printf("  dup: %s flags %d same %d\n", DH_meth_get0_name(dup), DH_meth_get_flags(dup),
           DH_meth_get_compute_key(dup) == my_compute_key);
    DH_meth_free(dup);
    DH_meth_free(NULL);

    a = DH_new_by_nid(NID_ffdhe2048);
    printf("  set_method %d, init calls %d, flags %d\n", DH_set_method(a, m), calls[3],
           DH_test_flags(a, ~0));
    b = DH_new_by_nid(NID_ffdhe2048);
    printf("  generate %d %d", DH_generate_key(a), DH_generate_key(b));
    /* Random keys: the unpadded secret is shorter when it has leading zero octets. */
    n = DH_compute_key(s, DH_get0_pub_key(b), a);
    printf(" compute %d\n", n > 0 && n <= DH_size(a));
    printf("  calls %d %d %d\n", calls[0], calls[1], calls[2]);
    DH_set_default_method(m);
    DH_free(b);
    b = DH_new();
    printf("  default is ours %d, init calls %d\n", DH_get_default_method() == m, calls[3]);
    DH_free(b);
    b = DH_new_method(NULL);
    printf("  new_method init calls %d\n", calls[3]);
    DH_free(b);
    DH_set_default_method(NULL);
    printf("  default reset %d\n", DH_get_default_method() == ossl);
    DH_free(a);
    printf("  finish calls %d\n", calls[4]);
    DH_meth_free(m);
    errors();
}

int main(void)
{
    test_empty();
    test_pqg();
    test_groups();
    test_keys();
    test_ex_data();
    test_generate();
    test_methods();
    errors();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
