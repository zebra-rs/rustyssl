/*
 * Conformance test for primes and binary fields (BN_generate_prime(3), BN_check_prime,
 * BN_GENCB_new(3), BN_X931_derive_prime_ex, BN_GF2m_add(3)), in TAP format: primality of
 * primes, composites, Carmichael numbers, and strong pseudoprimes; primes generated from a
 * generator with known output (plain, safe, with add and rem, by the deprecated functions),
 * with the callbacks' progress counted; the X9.31 functions; and GF(2^m) arithmetic over
 * trinomials and pentanomials, by number and by array, with their sign rules and errors.
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
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
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

static void codes(void)
{
    unsigned long code;

    printf("  errors:");
    while ((code = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
    printf("\n");
}

static void show(const char *label, const BIGNUM *a)
{
    char *h = a == NULL ? NULL : BN_bn2hex(a);

    printf("  %s: %s\n", label, h == NULL ? "(null)" : h);
    OPENSSL_free(h);
}

static BIGNUM *hexbn(const char *s)
{
    BIGNUM *b = NULL;

    BN_hex2bn(&b, s);
    return b;
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
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY, entropy, sizeof(entropy));
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_NONCE, nonce, sizeof(nonce));
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

/* Progress events, counted by kind (0 found a candidate, 1 a round passed, 2 a safe prime's
 * round, 3 X9.31 done), with a running checksum of their arguments. */
static long events[4];
static unsigned long checksum;
static int stop_after = -1;

static void reset_events(void)
{
    memset(events, 0, sizeof(events));
    checksum = 0;
}

static void print_events(const char *label)
{
    printf("  %s events: %ld %ld %ld %ld sum %lu\n", label, events[0], events[1], events[2], events[3],
           checksum);
}

static int new_cb(int a, int b, BN_GENCB *cb)
{
    if (a >= 0 && a < 4)
        events[a]++;
    checksum = checksum * 31 + (unsigned long)(a * 1000 + b);
    if (BN_GENCB_get_arg(cb) != &events)
        return 0;
    if (stop_after >= 0 && events[1] >= stop_after)
        return 0;
    return 1;
}

static void old_cb(int a, int b, void *arg)
{
    if (a >= 0 && a < 4)
        events[a]++;
    checksum = checksum * 31 + (unsigned long)(a * 1000 + b);
    (void)arg;
}

/* ---------------------------------------------------------------------------------------- */

static void callbacks(void)
{
    BN_GENCB *cb = BN_GENCB_new();
    int x = 0;

    check(cb != NULL, "BN_GENCB_new");
    check(BN_GENCB_call(NULL, 0, 0) == 1, "no callback continues");
    BN_GENCB_set(cb, new_cb, &events);
    check(BN_GENCB_get_arg(cb) == &events, "get_arg");
    reset_events();
    check(BN_GENCB_call(cb, 1, 7) == 1 && events[1] == 1, "a new-style call");
    BN_GENCB_set(cb, new_cb, &x);
    check(BN_GENCB_call(cb, 0, 0) == 0, "a callback that stops");
    BN_GENCB_set_old(cb, old_cb, &x);
    check(BN_GENCB_get_arg(cb) == &x, "get_arg (old)");
    check(BN_GENCB_call(cb, 2, 3) == 1 && events[2] == 1, "an old-style call");
    BN_GENCB_set_old(cb, NULL, NULL);
    check(BN_GENCB_call(cb, 2, 3) == 1, "an old-style NULL callback continues");
    BN_GENCB_free(cb);
    BN_GENCB_free(NULL);
}

/* ---------------------------------------------------------------------------------------- */

static void primality(void)
{
    static const char *const nums[] = {
        "-7", "0", "1", "2", "3", "4", "5", "9", "B", "19", "61", "D3", "3F5",
        /* Carmichael numbers */
        "229", "451", "6C1",
        /* strong pseudoprimes to bases 2, 3, 5, 7 */
        "BFA17067", "C5D29CEB0F",
        /* 2^61 - 1, 2^89 - 1, 2^127 - 1 and their neighbours */
        "1FFFFFFFFFFFFFFF", "1FFFFFFFFFFFFFFFFFFFFFF", "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD",
        /* a 256-bit prime and that times 3 */
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
        "2FFFFFFFD00000003000000000000000000000002FFFFFFFFFFFFFFFFFFFFFFFD",
        /* the square of a 40-bit prime */
        "FFFFFFFFB1000000F59",
    };
    BN_CTX *ctx = BN_CTX_new();
    BN_GENCB *cb = BN_GENCB_new();
    size_t i;

    BN_GENCB_set(cb, new_cb, &events);
    for (i = 0; i < sizeof(nums) / sizeof(nums[0]); i++) {
        BIGNUM *n = hexbn(nums[i]);

        reset_events();
        printf("  %s: check %d", nums[i], BN_check_prime(n, ctx, cb));
        printf(" ex %d", BN_is_prime_ex(n, 3, ctx, NULL));
        printf(" fasttest %d %d", BN_is_prime_fasttest_ex(n, 70, ctx, 1, NULL),
               BN_is_prime_fasttest_ex(n, 0, ctx, 0, NULL));
        printf(" old %d %d\n", BN_is_prime(n, 1, old_cb, ctx, NULL),
               BN_is_prime_fasttest(n, 1, NULL, ctx, NULL, 1));
        print_events("check");
        BN_free(n);
    }
    {
        BIGNUM *n = hexbn("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");

        stop_after = 5;
        check(BN_check_prime(n, ctx, cb) == -1, "a callback can stop the test");
        stop_after = -1;
        check(BN_check_prime(n, NULL, NULL) == 1, "without a context");
        BN_free(n);
    }
    codes();
    BN_GENCB_free(cb);
    BN_CTX_free(ctx);
}

/* ---------------------------------------------------------------------------------------- */

static void generation(void)
{
    BN_CTX *ctx = BN_CTX_new();
    BN_GENCB *cb = BN_GENCB_new();
    BIGNUM *p = BN_new(), *q;
    int bits[] = {2, 3, 4, 5, 6, 7, 8, 16, 31, 32, 33, 64, 128, 256};
    size_t i;

    BN_GENCB_set(cb, new_cb, &events);
    for (i = 0; i < sizeof(bits) / sizeof(bits[0]); i++) {
        reset_events();
        printf("  %d bits: %d", bits[i], BN_generate_prime_ex2(p, bits[i], 0, NULL, NULL, cb, ctx));
        show("", p);
        print_events("prime");
        reset_events();
        printf("  safe: %d", BN_generate_prime_ex(p, bits[i], 1, NULL, NULL, cb));
        show("", p);
        print_events("safe");
        codes();
    }
    {
        BIGNUM *add = hexbn("C"), *rem = hexbn("7"), *rem11 = hexbn("B");

        printf("  add 12 rem 7: %d", BN_generate_prime_ex(p, 40, 0, add, rem, NULL));
        show("", p);
        printf("  add 12: %d", BN_generate_prime_ex(p, 40, 0, add, NULL, NULL));
        show("", p);
        printf("  safe add 12 rem 11: %d", BN_generate_prime_ex(p, 40, 1, add, rem11, NULL));
        show("", p);
        BN_free(add);
        BN_free(rem);
        BN_free(rem11);
    }
    check(BN_generate_prime_ex(p, 1, 0, NULL, NULL, NULL) == 0, "one bit");
    check(BN_generate_prime_ex(p, 5, 1, NULL, NULL, NULL) == 0, "a five-bit safe prime");
    codes();
    stop_after = 0;
    check(BN_generate_prime_ex(p, 64, 0, NULL, NULL, cb) == 0, "a callback can stop generation");
    stop_after = -1;
    reset_events();
    q = BN_generate_prime(NULL, 48, 0, NULL, NULL, old_cb, NULL);
    check(q != NULL, "BN_generate_prime");
    show("deprecated", q);
    print_events("deprecated");
    check(BN_generate_prime(q, 48, 1, NULL, NULL, NULL, NULL) == q, "into a number");
    show("deprecated safe", q);
    check(BN_generate_prime(NULL, 1, 0, NULL, NULL, NULL, NULL) == NULL, "deprecated, one bit");
    codes();
    BN_free(q);
    BN_free(p);
    BN_GENCB_free(cb);
    BN_CTX_free(ctx);
}

/* ---------------------------------------------------------------------------------------- */

static void x931(void)
{
    BN_CTX *ctx = BN_CTX_new();
    BN_GENCB *cb = BN_GENCB_new();
    BIGNUM *xp = BN_new(), *xq = BN_new(), *p = BN_new(), *p1 = BN_new(), *p2 = BN_new();
    BIGNUM *xp1 = BN_new(), *xp2 = BN_new(), *e = hexbn("10001"), *even = hexbn("10000");

    BN_GENCB_set(cb, new_cb, &events);
    check(BN_X931_generate_Xpq(xp, xq, 1000, ctx) == 0, "not a multiple of 256");
    check(BN_X931_generate_Xpq(xp, xq, 768, ctx) == 0, "fewer than 1024 bits");
    check(BN_X931_generate_Xpq(xp, xq, 1024, ctx) == 1, "Xp and Xq");
    show("Xp", xp);
    show("Xq", xq);
    reset_events();
    check(BN_X931_generate_prime_ex(p, p1, p2, xp1, xp2, xp, e, ctx, cb) == 1, "generate");
    show("p", p);
    show("p1", p1);
    show("p2", p2);
    show("Xp1", xp1);
    show("Xp2", xp2);
    print_events("x931");
    check(BN_X931_derive_prime_ex(p, NULL, NULL, xp, xp1, xp2, e, ctx, NULL) == 1, "derive again");
    show("p", p);
    check(BN_X931_derive_prime_ex(p, p1, p2, xp, xp1, xp2, even, ctx, NULL) == 0, "an even e");
    check(BN_X931_generate_prime_ex(p, NULL, NULL, NULL, NULL, xq, e, ctx, NULL) == 1,
          "generate with temporaries");
    show("q", p);
    codes();
    BN_free(xp);
    BN_free(xq);
    BN_free(p);
    BN_free(p1);
    BN_free(p2);
    BN_free(xp1);
    BN_free(xp2);
    BN_free(e);
    BN_free(even);
    BN_GENCB_free(cb);
    BN_CTX_free(ctx);
}

/* ---------------------------------------------------------------------------------------- */

static void gf2m(void)
{
    /* x^163 + x^7 + x^6 + x^3 + 1 (sect163), x^233 + x^74 + 1 (sect233), x^4 + x + 1, and
     * x^10 + x^3 + 1 (even degree, for the quadratic solver's random branch). */
    static const int p163[] = {163, 7, 6, 3, 0, -1};
    static const int p233[] = {233, 74, 0, -1};
    static const int p4[] = {4, 1, 0, -1};
    static const int p10[] = {10, 3, 0, -1};
    static const int one[] = {0, -1};
    static const int *const arrays[] = {p163, p233, p4, p10, one};
    static const char *const values[] = {
        "0", "1", "2", "3", "-5", "123456789ABCDEF0123456789ABCDEF0123456789",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    };
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *r = BN_new(), *f = BN_new(), *b = hexbn("1F"), *e = hexbn("-100");
    int arr[16];
    size_t i, k;

    for (k = 0; k < sizeof(arrays) / sizeof(arrays[0]); k++) {
        const int *p = arrays[k];

        check(BN_GF2m_arr2poly(p, f) == 1, "arr2poly");
        show("field", f);
        printf("  poly2arr %d:", BN_GF2m_poly2arr(f, arr, 16));
        for (i = 0; i < 6 && arr[i] != -1; i++)
            printf(" %d", arr[i]);
        printf("\n");
        for (i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
            BIGNUM *a = hexbn(values[i]);

            printf("  %s:", values[i]);
            printf(" mod %d", BN_GF2m_mod(r, a, f));
            show("", r);
            printf("   mod_arr %d", BN_GF2m_mod_arr(r, a, p));
            show("", r);
            printf("   add %d", BN_GF2m_add(r, a, b));
            show("", r);
            printf("   mul %d", BN_GF2m_mod_mul(r, a, b, f, ctx));
            show("", r);
            printf("   mul_arr %d", BN_GF2m_mod_mul_arr(r, a, a, p, ctx));
            show("", r);
            printf("   sqr %d", BN_GF2m_mod_sqr(r, a, f, ctx));
            show("", r);
            printf("   sqr_arr %d", BN_GF2m_mod_sqr_arr(r, a, p, ctx));
            show("", r);
            printf("   inv %d", BN_GF2m_mod_inv(r, a, f, ctx));
            show("", r);
            printf("   inv_arr %d", BN_GF2m_mod_inv_arr(r, a, p, ctx));
            show("", r);
            printf("   div %d", BN_GF2m_mod_div(r, b, a, f, ctx));
            show("", r);
            printf("   div_arr %d", BN_GF2m_mod_div_arr(r, b, a, p, ctx));
            show("", r);
            printf("   exp %d", BN_GF2m_mod_exp(r, a, e, f, ctx));
            show("", r);
            printf("   exp_arr %d", BN_GF2m_mod_exp_arr(r, a, b, p, ctx));
            show("", r);
            printf("   sqrt %d", BN_GF2m_mod_sqrt(r, a, f, ctx));
            show("", r);
            printf("   sqrt_arr %d", BN_GF2m_mod_sqrt_arr(r, a, p, ctx));
            show("", r);
            printf("   solve %d", BN_GF2m_mod_solve_quad(r, a, f, ctx));
            show("", r);
            printf("   solve_arr %d", BN_GF2m_mod_solve_quad_arr(r, a, p, ctx));
            show("", r);
            codes();
            BN_free(a);
        }
    }

    /* Signs: a reduction into a negative number keeps its sign. */
    {
        BIGNUM *a = hexbn("1234");

        BN_GF2m_arr2poly(p4, f);
        BN_set_word(r, 1);
        BN_set_negative(r, 1);
        printf("  into a negative: mod %d", BN_GF2m_mod(r, a, f));
        show("", r);
        printf("  add %d", BN_GF2m_add(r, a, b));
        show("", r);
        printf("  mul %d", BN_GF2m_mod_mul(r, a, b, f, ctx));
        show("", r);
        printf("  exp by one %d", BN_GF2m_mod_exp(r, e, BN_value_one(), f, ctx));
        show("", r);
        BN_free(a);
    }

    /* Errors. */
    {
        BIGNUM *even = hexbn("12"), *six = hexbn("100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001");
        BIGNUM *many = hexbn("10000000000000000000000000000000000000000BF"), *a = hexbn("5");

        check(BN_GF2m_mod(r, a, even) == 0, "an even polynomial");
        codes();
        check(BN_GF2m_mod_mul(r, a, a, six, ctx) == 0, "a field past 661 bits");
        codes();
        check(BN_GF2m_mod(r, a, many) == 0, "BN_GF2m_mod with seven terms");
        codes();
        check(BN_GF2m_mod_mul(r, a, a, many, ctx) == 1, "BN_GF2m_mod_mul takes seven terms");
        show("seven terms", r);
        BN_set_word(r, 99);
        check(BN_GF2m_mod_inv(r, a, many, ctx) == 0, "the inverse doesn't");
        show("left", r);
        codes();
        check(BN_GF2m_poly2arr(even, arr, 16) == 0 && BN_GF2m_poly2arr(six, arr, 16) == 0, "poly2arr refuses");
        {
            int n = BN_GF2m_poly2arr(many, arr, 2);

            printf("  poly2arr short: %d %d %d\n", n, arr[0], arr[1]);
        }
        {
            static const int bad[] = {5, -3, 0, -1};

            check(BN_GF2m_arr2poly(bad, r) == 0, "a negative exponent");
            show("partial", r);
        }
        BN_free(even);
        BN_free(six);
        BN_free(many);
        BN_free(a);
    }
    BN_free(r);
    BN_free(f);
    BN_free(b);
    BN_free(e);
    BN_CTX_free(ctx);
}

int main(void)
{
    check(RAND_set0_public(NULL, known_drbg(11)) == 1 && RAND_set0_private(NULL, known_drbg(12)) == 1,
          "known generators");
    callbacks();
    primality();
    generation();
    x931();
    gf2m();
    RAND_set0_public(NULL, NULL);
    RAND_set0_private(NULL, NULL);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
