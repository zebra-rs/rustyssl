/*
 * Conformance test for DH parameter generation and checks (DH_generate_parameters(3),
 * DH_check(3), DH_KDF_X9_42(3)), in TAP format: safe-prime parameters for generators 2, 5,
 * and others, from known generators (so every prime is the reference's) with the progress
 * callback's events, moduli too small and too large, bad generators, and an application's
 * method's parameter generation; the parameter, full, and public key checks with their
 * flags and errors (named groups, RFC 5114's, generated, broken p, q, g, and j, and public
 * keys at and around the bounds); and the X9.42 KDF.
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
#include <openssl/objects.h>
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

static void num(const char *label, const BIGNUM *b)
{
    unsigned char buf[1300], d[32];
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

/* The progress callback's events, counted by kind. */
static int events[4];

static int progress(int a, int b, BN_GENCB *cb)
{
    (void)b;
    (void)cb;
    if (a >= 0 && a < 4)
        events[a]++;
    return 1;
}

static int stop_after = -1;

static int stopper(int a, int b, BN_GENCB *cb)
{
    (void)a;
    (void)b;
    (void)cb;
    return stop_after-- != 0;
}

static void old_progress(int a, int b, void *arg)
{
    (void)b;
    (void)arg;
    if (a >= 0 && a < 4)
        events[a]++;
}

static void show(const char *label, DH *dh)
{
    const BIGNUM *p, *q, *g;

    DH_get0_pqg(dh, &p, &q, &g);
    printf("  %s: length %ld nid %d\n", label, DH_get_length(dh), DH_get_nid(dh));
    num("p", p);
    num("q", q);
    num("g", g);
}

static void test_generate(void)
{
    BN_GENCB *cb = BN_GENCB_new();
    DH *dh;
    int r;

    check(RAND_set0_public(NULL, known_drbg(51)) == 1
          && RAND_set0_private(NULL, known_drbg(52)) == 1, "parameter generation");
    BN_GENCB_set(cb, progress, NULL);
    dh = DH_new();
    r = DH_generate_parameters_ex(dh, 512, DH_GENERATOR_2, cb);
    printf("  512, 2: %d events %d %d %d %d\n", r, events[0], events[1], events[2], events[3]);
    show("generated", dh);
    DH_free(dh);
    memset(events, 0, sizeof(events));
    dh = DH_new();
    r = DH_generate_parameters_ex(dh, 512, DH_GENERATOR_5, NULL);
    printf("  512, 5: %d\n", r);
    show("generated", dh);
    DH_free(dh);
    dh = DH_new();
    r = DH_generate_parameters_ex(dh, 576, 7, NULL);
    printf("  576, 7: %d\n", r);
    show("generated", dh);
    DH_free(dh);
    errors();
    dh = DH_new();
    printf("  511: %d", DH_generate_parameters_ex(dh, 511, 2, NULL));
    errors();
    printf("  10001: %d", DH_generate_parameters_ex(dh, 10001, 2, NULL));
    errors();
    printf("  generator 1: %d", DH_generate_parameters_ex(dh, 512, 1, NULL));
    errors();
    show("after a bad generator", dh);
    DH_free(dh);
    /* A callback that stops the generation. */
    BN_GENCB_set(cb, stopper, NULL);
    stop_after = 3;
    dh = DH_new();
    printf("  stopped: %d", DH_generate_parameters_ex(dh, 512, 2, cb));
    errors();
    DH_free(dh);
    /* The deprecated function with an old-style callback. */
    memset(events, 0, sizeof(events));
    dh = DH_generate_parameters(512, 2, old_progress, NULL);
    printf("  old: %d events %d %d %d %d\n", dh != NULL, events[0], events[1], events[2],
           events[3]);
    show("old", dh);
    DH_free(dh);
    BN_GENCB_free(cb);
    errors();
}

static int my_generate_params(DH *dh, int prime_len, int generator, BN_GENCB *cb)
{
    (void)dh;
    (void)cb;
    printf("  method's generate_params %d %d\n", prime_len, generator);
    return 7;
}

static void test_method(void)
{
    DH_METHOD *m = DH_meth_dup(DH_OpenSSL());
    DH *dh = DH_new();

    check(m != NULL && dh != NULL, "a method's parameter generation");
    DH_meth_set_generate_params(m, my_generate_params);
    DH_set_method(dh, m);
    printf("  result %d\n", DH_generate_parameters_ex(dh, 1024, 3, NULL));
    DH_free(dh);
    DH_meth_free(m);
    errors();
}

/* DH_check, DH_check_params, and their _ex forms, with the flags and errors. */
static void checks(const char *label, DH *dh)
{
    int ret = -1, r;

    r = DH_check(dh, &ret);
    printf("  %s: check %d flags %#x", label, r, ret);
    ret = -1;
    r = DH_check_params(dh, &ret);
    printf(" params %d flags %#x\n", r, ret);
    errors();
    printf("  check_ex %d", DH_check_ex(dh));
    errors();
    printf("  check_params_ex %d", DH_check_params_ex(dh));
    errors();
}

static DH *from(const BIGNUM *p, const BIGNUM *q, const BIGNUM *g)
{
    DH *dh = DH_new();

    DH_set0_pqg(dh, p == NULL ? NULL : BN_dup(p), q == NULL ? NULL : BN_dup(q),
                g == NULL ? NULL : BN_dup(g));
    return dh;
}

static void test_check(void)
{
    DH *ff = DH_new_by_nid(NID_ffdhe2048), *r1 = DH_get_2048_256(), *dh, *gen;
    const BIGNUM *p, *q, *g;
    BIGNUM *x = BN_new(), *y;

    check(ff != NULL && r1 != NULL, "checks");
    checks("empty", (dh = DH_new()));
    DH_free(dh);
    checks("ffdhe2048", ff);
    checks("2048_256", r1);
    DH_get0_pqg(r1, &p, &q, &g);
    /* p, q, g of RFC 5114 broken one at a time. */
    y = BN_dup(q);
    BN_add_word(y, 2);
    checks("q + 2", (dh = from(p, y, g)));
    DH_free(dh);
    BN_free(y);
    y = BN_dup(p);
    BN_add_word(y, 2);
    checks("p + 2", (dh = from(y, q, g)));
    DH_free(dh);
    y = BN_dup(g);
    BN_add_word(y, 1);
    checks("g + 1", (dh = from(p, q, y)));
    DH_free(dh);
    BN_free(y);
    y = BN_dup(p);
    checks("q > p", (dh = from(q, y, g)));
    DH_free(dh);
    BN_free(y);
    BN_set_word(x, 1);
    checks("g = 1", (dh = from(p, q, x)));
    DH_free(dh);
    checks("g = p", (dh = from(p, q, p)));
    DH_free(dh);
    y = BN_dup(p);
    BN_sub_word(y, 1);
    checks("p even", (dh = from(y, NULL, g)));
    DH_free(dh);
    BN_free(y);
    BN_set_word(x, 23);
    y = BN_new();
    BN_set_word(y, 5);
    checks("p = 23", (dh = from(x, NULL, y)));
    DH_free(dh);
    BN_free(y);
    /* A safe prime without q (ffdhe2048's numbers, unnamed after a changed g). */
    DH_get0_pqg(ff, &p, &q, &g);
    y = BN_new();
    BN_set_word(y, 3);
    checks("ffdhe2048 p, g 3", (dh = from(p, NULL, y)));
    DH_free(dh);
    BN_free(y);
    /* A prime that isn't safe. */
    DH_get0_pqg(r1, &p, &q, &g);
    checks("2048_256 p without q", (dh = from(p, NULL, g)));
    DH_free(dh);
    /* Generated parameters. */
    RAND_set0_private(NULL, known_drbg(61));
    gen = DH_new();
    DH_generate_parameters_ex(gen, 512, 2, NULL);
    checks("generated", gen);
    DH_free(gen);
    BN_free(x);
    DH_free(ff);
    DH_free(r1);
}

static void pubcheck(const char *label, DH *dh, const BIGNUM *pub)
{
    int ret = -1, r;

    r = DH_check_pub_key(dh, pub, &ret);
    printf("  %s: %d flags %#x", label, r, ret);
    errors();
    printf("  ex %d", DH_check_pub_key_ex(dh, pub));
    errors();
}

static void test_pub_key(void)
{
    DH *ff = DH_new_by_nid(NID_ffdhe2048), *r1 = DH_get_2048_256(), *dh, *t;
    BIGNUM *x = BN_new();
    const BIGNUM *p, *q;

    check(ff != NULL, "public key checks");
    DH_get0_pqg(ff, &p, &q, NULL);
    BN_set_word(x, 1);
    pubcheck("1", ff, x);
    BN_set_word(x, 2);
    pubcheck("2", ff, x);
    BN_copy(x, p);
    BN_sub_word(x, 1);
    pubcheck("p - 1", ff, x);
    BN_sub_word(x, 1);
    pubcheck("p - 2", ff, x);
    BN_copy(x, p);
    pubcheck("p", ff, x);
    BN_set_word(x, 4);
    pubcheck("4 (in the subgroup)", ff, x);
    BN_set_word(x, 3);
    pubcheck("3", ff, x);
    DH_get0_pqg(r1, &p, &q, NULL);
    BN_set_word(x, 2);
    pubcheck("2048_256 2", r1, x);
    pubcheck("2048_256 g", r1, DH_get0_g(r1));
    pubcheck("empty", (dh = DH_new()), x);
    DH_free(dh);
    t = from(p, NULL, DH_get0_g(r1));
    pubcheck("no q, 2", t, x);
    DH_free(t);
    t = from(q, p, DH_get0_g(r1));
    pubcheck("q > p", t, x);
    DH_free(t);
    BN_free(x);
    DH_free(ff);
    DH_free(r1);
}

static void test_kdf(void)
{
    unsigned char z[32], ukm[8], out[48];
    ASN1_OBJECT *oid = OBJ_nid2obj(NID_id_aes128_wrap);
    int r, i;

    check(oid != NULL, "the X9.42 KDF");
    memset(z, 0x11, sizeof(z));
    memset(ukm, 0x22, sizeof(ukm));
    r = DH_KDF_X9_42(out, sizeof(out), z, sizeof(z), oid, ukm, sizeof(ukm), EVP_sha256());
    printf("  ukm %d:", r);
    for (i = 0; i < (int)sizeof(out); i++)
        printf("%02x", out[i]);
    printf("\n");
    r = DH_KDF_X9_42(out, 16, z, sizeof(z), oid, NULL, 0, EVP_sha1());
    printf("  no ukm %d:", r);
    for (i = 0; i < 16; i++)
        printf("%02x", out[i]);
    printf("\n");
    r = DH_KDF_X9_42(out, 16, z, sizeof(z), OBJ_nid2obj(NID_sha256), NULL, 0, EVP_sha1());
    printf("  another oid %d\n", r);
    errors();
}

int main(void)
{
    test_generate();
    test_method();
    test_check();
    test_pub_key();
    test_kdf();
    RAND_set0_public(NULL, NULL);
    RAND_set0_private(NULL, NULL);
    errors();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
