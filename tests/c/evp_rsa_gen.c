/*
 * Conformance test for RSA key generation and validation (EVP_PKEY-RSA(7), EVP_PKEY_keygen(3),
 * EVP_PKEY_check(3)), in TAP format, with generators of known output so every key is the
 * reference's: FIPS 186-4 keys (2048 and 3072 bits), the older generator's (small keys, small
 * public exponents, three and five primes), RSA-PSS keys with restrictions, the progress
 * callback's events and a callback that stops generation, the parameters' errors; and the
 * checks of good keys, public keys, and keys broken one number at a time (each problem
 * raised in OpenSSL's order, arithmetic failures included).
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

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

/* Progress events, counted by kind, with a running checksum of their arguments. */
static long events[4];
static unsigned long checksum;
static int stop_after = -1;

static int progress(EVP_PKEY_CTX *ctx)
{
    int p = EVP_PKEY_CTX_get_keygen_info(ctx, 0), n = EVP_PKEY_CTX_get_keygen_info(ctx, 1);

    if (p >= 0 && p < 4)
        events[p]++;
    checksum = checksum * 31 + (unsigned long)(p * 1000 + n);
    return stop_after < 0 || events[1] < stop_after;
}

/* A key's numbers: the first and last octets of each, and its size. */
static void numbers(EVP_PKEY *k)
{
    const char *names[] = {
        "n", "e", "d", "rsa-factor1", "rsa-factor2", "rsa-factor3", "rsa-factor5",
        "rsa-exponent1", "rsa-exponent2", "rsa-exponent3", "rsa-coefficient1",
        "rsa-coefficient2", NULL
    };
    int i;

    for (i = 0; names[i] != NULL; i++) {
        BIGNUM *b = NULL;

        if (EVP_PKEY_get_bn_param(k, names[i], &b)) {
            char *h = BN_bn2hex(b);
            size_t len = strlen(h);

            printf("  %s=%.32s..%s (%d bits)\n", names[i], h, len > 40 ? h + len - 8 : "",
                   BN_num_bits(b));
            OPENSSL_free(h);
        }
        BN_free(b);
    }
    ERR_clear_error();
}

/* A key of `type` from the generator; 0 leaves a setting at its default. */
static EVP_PKEY *generate(const char *type, int bits, int primes, unsigned long e, int pss,
                          int ok, const char *what)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
    EVP_PKEY *k = NULL;
    int r = EVP_PKEY_keygen_init(c) == 1;

    memset(events, 0, sizeof(events));
    checksum = 0;
    printf("# %s: %s, %d bits, %d primes, e %lu\n", what, type, bits, primes, e);
    if (bits != 0)
        r = r && EVP_PKEY_CTX_set_rsa_keygen_bits(c, bits) == 1;
    if (primes != 0)
        r = r && EVP_PKEY_CTX_set_rsa_keygen_primes(c, primes) == 1;
    if (e != 0) {
        BIGNUM *b = BN_new();

        BN_set_word(b, e);
        r = r && EVP_PKEY_CTX_set1_rsa_keygen_pubexp(c, b) == 1;
        BN_free(b);
    }
    if (pss)
        r = r && EVP_PKEY_CTX_set_rsa_pss_keygen_md(c, EVP_sha256()) == 1
            && EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(c, 20) == 1;
    EVP_PKEY_CTX_set_cb(c, progress);
    r = r && EVP_PKEY_keygen(c, &k) == 1;
    check(r == ok, what);
    printf("  events %ld %ld %ld %ld, checksum %lu\n", events[0], events[1], events[2], events[3],
           checksum);
    errors();
    if (k != NULL)
        numbers(k);
    EVP_PKEY_CTX_free(c);
    return k;
}

/* The checks of `k`: whole, public, private, pairwise, and parameters. */
static void checks(EVP_PKEY *k, const char *what, int all, int pub, int priv)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new(k, NULL);

    printf("# checks: %s\n", what);
    check(EVP_PKEY_check(c) == all, "EVP_PKEY_check");
    errors();
    check(EVP_PKEY_public_check(c) == pub, "EVP_PKEY_public_check");
    errors();
    check(EVP_PKEY_private_check(c) == priv, "EVP_PKEY_private_check");
    errors();
    check(EVP_PKEY_pairwise_check(c) == all, "EVP_PKEY_pairwise_check");
    errors();
    check(EVP_PKEY_param_check(c) == 1, "EVP_PKEY_param_check (nothing to check)");
    errors();
    EVP_PKEY_CTX_free(c);
}

/* A key from its numbers in hex (NULL for none). */
static EVP_PKEY *make(const char *n, const char *e, const char *d, const char *p, const char *q,
                      const char *dp, const char *dq, const char *qi)
{
    const char *values[8] = { n, e, d, p, q, dp, dq, qi };
    const char *names[8] = {
        "n", "e", "d", "rsa-factor1", "rsa-factor2", "rsa-exponent1", "rsa-exponent2",
        "rsa-coefficient1"
    };
    BIGNUM *nums[8] = { NULL };
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    EVP_PKEY *k = NULL;
    int i;

    for (i = 0; i < 8; i++) {
        if (values[i] != NULL) {
            BN_hex2bn(&nums[i], values[i]);
            OSSL_PARAM_BLD_push_BN(bld, names[i], nums[i]);
        }
    }
    params = OSSL_PARAM_BLD_to_param(bld);
    EVP_PKEY_fromdata_init(c);
    EVP_PKEY_fromdata(c, &k, d != NULL ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, params);
    EVP_PKEY_CTX_free(c);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    for (i = 0; i < 8; i++)
        BN_free(nums[i]);
    return k;
}

static char *hex_of(EVP_PKEY *k, const char *name)
{
    BIGNUM *b = NULL;
    char *h;

    EVP_PKEY_get_bn_param(k, name, &b);
    h = BN_bn2hex(b);
    BN_free(b);
    return h;
}

static void test_generation(void)
{
    EVP_PKEY *k;

    k = generate("RSA", 0, 0, 0, 0, 1, "the default key (FIPS 186-4)");
    checks(k, "a 2048-bit key", 1, 1, 1);
    EVP_PKEY_free(k);
    k = generate("RSA", 1024, 0, 0, 0, 1, "a 1024-bit key");
    EVP_PKEY_free(k);
    k = generate("RSA", 1024, 3, 0, 0, 1, "three primes");
    checks(k, "a three-prime key", 1, 1, 1);
    EVP_PKEY_free(k);
    EVP_PKEY_free(generate("RSA", 2048, 0, 3, 0, 1, "a small public exponent"));
    k = generate("RSA", 512, 0, 0, 0, 1, "the smallest size");
    checks(k, "a 512-bit key", 1, 1, 1);
    EVP_PKEY_free(k);
    k = generate("RSA-PSS", 2048, 0, 0, 1, 1, "RSA-PSS with restrictions");
    checks(k, "an RSA-PSS key", 1, 1, 1);
    EVP_PKEY_free(k);
    EVP_PKEY_free(generate("RSA", 3072, 0, 65539, 0, 1, "3072 bits, e = 65539"));
    EVP_PKEY_free(generate("RSA", 2048, 3, 0, 0, 1, "three primes of 2048 bits"));
    EVP_PKEY_free(generate("RSA", 4096, 5, 0, 0, 0, "five primes need 8192 bits"));
    EVP_PKEY_free(generate("RSA", 8192, 5, 0, 0, 1, "five primes"));
    EVP_PKEY_free(generate("RSA", 256, 0, 0, 0, 0, "too small"));
    EVP_PKEY_free(generate("RSA", 1024, 4, 0, 0, 0, "too many primes for the size"));
    EVP_PKEY_free(generate("RSA", 1024, 0, 4, 0, 0, "an even public exponent"));
    EVP_PKEY_free(generate("RSA", 1024, 0, 1, 0, 0, "a public exponent of 1"));
    stop_after = 3;
    EVP_PKEY_free(generate("RSA", 1024, 0, 0, 0, 0, "the callback stops the older generator"));
    EVP_PKEY_free(generate("RSA", 2048, 0, 0, 0, 0, "the callback stops FIPS 186-4's"));
    stop_after = -1;
}

static void test_validation(void)
{
    EVP_PKEY *k = generate("RSA", 1024, 0, 0, 0, 1, "a key to break");
    char *n = hex_of(k, "n"), *e = hex_of(k, "e"), *d = hex_of(k, "d");
    char *p = hex_of(k, "rsa-factor1"), *q = hex_of(k, "rsa-factor2");
    char *dp = hex_of(k, "rsa-exponent1"), *dq = hex_of(k, "rsa-exponent2");
    char *qi = hex_of(k, "rsa-coefficient1"), *sq, *p3;
    BIGNUM *pb = NULL, *t = BN_new();
    BN_CTX *bc = BN_CTX_new();
    EVP_PKEY *b;

#define BROKEN(what, all, pub, priv, ...)                                                       \
    do {                                                                                     \
        b = make(__VA_ARGS__);                                                               \
        check(b != NULL, "imported: " what);                                                 \
        errors();                                                                            \
        if (b != NULL)                                                                       \
            checks(b, what, all, pub, priv);                                                 \
        EVP_PKEY_free(b);                                                                    \
    } while (0)

    BROKEN("public only", 0, 1, 0, n, e, NULL, NULL, NULL, NULL, NULL, NULL);
    BROKEN("no factors", 0, 1, 1, n, e, d, NULL, NULL, NULL, NULL, NULL);
    BROKEN("an even e", 0, 0, 1, n, "10000", d, p, q, dp, dq, qi);
    BROKEN("e is 1", 0, 0, 1, n, "1", d, p, q, dp, dq, qi);
    BROKEN("p and q swapped", 0, 1, 1, n, e, d, q, p, dp, dq, qi);
    BROKEN("a wrong d", 0, 1, 1, n, e, "5", p, q, dp, dq, qi);
    BROKEN("the exponents swapped", 0, 1, 1, n, e, d, p, q, dq, dp, qi);
    BROKEN("a wrong coefficient", 0, 1, 1, n, e, d, p, q, dp, dq, "3");
    BROKEN("p not prime", 0, 1, 1, n, e, d, "9", q, dp, dq, qi);
    BROKEN("p is 1", 0, 1, 1, n, e, d, "1", q, dp, dq, qi);
    BROKEN("p is 0", 0, 1, 1, n, e, d, "0", q, dp, dq, qi);
    BROKEN("p twice", 0, 1, 1, n, e, d, p, p, dp, dq, qi);
    BROKEN("an even n", 0, 0, 0, "ABCD", e, NULL, NULL, NULL, NULL, NULL, NULL);
    BROKEN("a prime n", 0, 0, 0, p, e, NULL, NULL, NULL, NULL, NULL, NULL);
    BROKEN("e is 3", 0, 1, 0, n, "3", NULL, NULL, NULL, NULL, NULL, NULL);
    /* Below 512 bits, a prime's power passes; two primes do. */
    BROKEN("a small prime's square", 0, 1, 0, "8BE79", e, NULL, NULL, NULL, NULL, NULL, NULL);
    BROKEN("two small primes", 0, 1, 0, "8CA4D", e, NULL, NULL, NULL, NULL, NULL, NULL);
    BROKEN("a small factor", 0, 0, 0, "F1", e, NULL, NULL, NULL, NULL, NULL, NULL);
    BN_hex2bn(&pb, p);
    BN_mul(t, pb, pb, bc);
    sq = BN_bn2hex(t);
    BROKEN("n a prime's square", 0, 0, 1, sq, e, d, p, p, dp, dq, qi);
    BN_mul_word(pb, 3);
    p3 = BN_bn2hex(pb);
    BROKEN("n with a factor 3", 0, 0, 0, p3, e, NULL, NULL, NULL, NULL, NULL, NULL);

    b = make("ABCD", e, d, p, q, dp, dq, qi);
    check(b == NULL, "numbers longer than n aren't imported");
    errors();
    OPENSSL_free(n), OPENSSL_free(e), OPENSSL_free(d), OPENSSL_free(p), OPENSSL_free(q);
    OPENSSL_free(dp), OPENSSL_free(dq), OPENSSL_free(qi), OPENSSL_free(sq), OPENSSL_free(p3);
    BN_free(pb);
    BN_free(t);
    BN_CTX_free(bc);
    EVP_PKEY_free(k);
}

static void test_settables(void)
{
    const char *types[] = { "RSA", "RSA-PSS" };
    int i;

    for (i = 0; i < 2; i++) {
        EVP_KEYMGMT *m = EVP_KEYMGMT_fetch(NULL, types[i], NULL);
        const OSSL_PARAM *p = EVP_KEYMGMT_gen_settable_params(m);

        check(p != NULL, types[i]);
        printf("  gen settable:");
        for (; p != NULL && p->key != NULL; p++)
            printf(" %s/%u/%zu", p->key, p->data_type, p->data_size);
        printf("\n");
        EVP_KEYMGMT_free(m);
    }
}

int main(void)
{
    check(RAND_set0_public(NULL, known_drbg(21)) == 1
          && RAND_set0_private(NULL, known_drbg(22)) == 1, "known generators");
    test_generation();
    test_validation();
    test_settables();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
