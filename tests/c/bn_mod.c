/*
 * Conformance test for BIGNUM's modular arithmetic (BN_add(3)'s BN_mod_* functions,
 * BN_mod_exp_mont(3), BN_mod_inverse(3), BN_mod_mul_montgomery(3), BN_mod_mul_reciprocal(3),
 * BN_BLINDING_new(3), BN_generate_dsa_nonce(3), BN_get_rfc3526_prime_8192(3), BN_kronecker,
 * BN_mod_sqrt, BN_gcd, the NIST primes), in TAP format: each operation over pairs of signed
 * values and moduli (with aliasing and every error), the exponentiations by each method, the
 * Montgomery and reciprocal contexts with operands reduced or not, inverses and gcds, square
 * roots and Kronecker symbols, the NIST and RFC primes, and blinding and DSA nonces from a
 * generator with known output.
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

/* ---------------------------------------------------------------------------------------- */

static const char *const values[] = {
    "0", "1", "-1", "5", "-7", "FFFFFFFFFFFFFFFF", "-10000000000000001",
    "123456789ABCDEF0123456789ABCDEF0123", "-FEDCBA9876543210FEDCBA987654321",
};
static const char *const moduli[] = {
    "1", "-1", "2", "7", "-9", "10", "FFFFFFFFFFFFFFC5", "-10000000000000000",
    "E3A5C1F7B9D3E5A7C9B1D3F5E7A9C1B3D5E7F9A1B3C5D7E9F1A3B5C7D9E1F3A5",
};
#define NV (sizeof(values) / sizeof(values[0]))
#define NM (sizeof(moduli) / sizeof(moduli[0]))

static void simple_ops(void)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *r = BN_new();
    size_t i, j, k;

    for (k = 0; k < NM; k++) {
        BIGNUM *m = hexbn(moduli[k]);

        printf("  mod %s:\n", moduli[k]);
        for (i = 0; i < NV; i++) {
            BIGNUM *a = hexbn(values[i]);

            for (j = 0; j < NV; j += 3) {
                BIGNUM *b = hexbn(values[j]);

                printf("  %s, %s:", values[i], values[j]);
                printf(" add %d", BN_mod_add(r, a, b, m, ctx));
                show("", r);
                printf("   sub %d", BN_mod_sub(r, a, b, m, ctx));
                show("", r);
                printf("   mul %d", BN_mod_mul(r, a, b, m, ctx));
                show("", r);
                BN_free(b);
            }
            printf("   sqr %d", BN_mod_sqr(r, a, m, ctx));
            show("", r);
            printf("   lshift1 %d", BN_mod_lshift1(r, a, m, ctx));
            show("", r);
            printf("   lshift 70 %d", BN_mod_lshift(r, a, 70, m, ctx));
            show("", r);
            printf("   lshift -3 %d", BN_mod_lshift(r, a, -3, m, ctx));
            show("", r);
            BN_free(a);
        }
        BN_free(m);
    }
    codes();

    /* Aliasing: a result that is the modulus. */
    {
        BIGNUM *a = hexbn("1234"), *m = hexbn("FF");

        check(BN_mod_add(m, a, a, m, ctx) == 0, "BN_mod_add into the modulus");
        show("modulus after", m);
        codes();
        BN_set_word(m, 255);
        check(BN_mod_mul(m, a, a, m, ctx) == 0, "BN_mod_mul into the modulus");
        show("modulus after", m);
        codes();
        BN_set_word(m, 255);
        check(BN_mod_sqr(m, a, m, ctx) == 1, "BN_mod_sqr into the modulus");
        show("modulus after", m);
        BN_zero(m);
        check(BN_mod_add(r, a, a, m, ctx) == 0, "a zero modulus");
        codes();
        BN_free(a);
        BN_free(m);
    }

    /* The quick forms, reduced operands and not. */
    {
        static const char *const qs[][3] = {
            {"5", "4", "7"}, {"1", "2", "7"}, {"6", "6", "7"}, {"0", "0", "7"},
            {"FFFFFFFFFFFFFFFE", "FFFFFFFFFFFFFFFE", "FFFFFFFFFFFFFFFF"},
            {"123456789", "1", "100"}, {"FFFFFFFFFFFFFFFFFF", "1", "FFFFFFFFFFFFFFFF"},
            {"-5", "3", "7"}, {"5", "3", "-7"},
        };

        for (i = 0; i < sizeof(qs) / sizeof(qs[0]); i++) {
            BIGNUM *a = hexbn(qs[i][0]), *b = hexbn(qs[i][1]), *m = hexbn(qs[i][2]);

            printf("  quick %s %s %s:", qs[i][0], qs[i][1], qs[i][2]);
            printf(" add %d", BN_mod_add_quick(r, a, b, m));
            show("", r);
            printf("   sub %d", BN_mod_sub_quick(r, a, b, m));
            show("", r);
            printf("   lshift1 %d", BN_mod_lshift1_quick(r, a, m));
            show("", r);
            printf("   lshift 5 %d", BN_mod_lshift_quick(r, a, 5, m));
            show("", r);
            codes();
            BN_free(a);
            BN_free(b);
            BN_free(m);
        }
        {
            BIGNUM *a = hexbn("5"), *m = hexbn("7");

            check(BN_mod_sub_quick(m, a, a, m) == 0, "BN_mod_sub_quick into the modulus");
            codes();
            check(BN_mod_lshift_quick(a, a, 0, m) == 1, "a zero quick shift");
            BN_free(a);
            BN_free(m);
        }
    }
    BN_free(r);
    BN_CTX_free(ctx);
}

/* ---------------------------------------------------------------------------------------- */

static void exponentiation(void)
{
    static const char *const bases[] = {"0", "1", "2", "-3", "FFFFFFFFFFFFFFFF", "123456789ABCDEF0123456789"};
    static const char *const exps[] = {"0", "1", "2", "-5", "10001", "FEDCBA9876543210123"};
    static const char *const mods[] = {"1", "-1", "3", "-7", "F", "10", "0",
                                       "E3A5C1F7B9D3E5A7C9B1D3F5E7A9C1B3D5E7F9A1B3C5D7E9F1A3B5C7D9E1F3A5"};
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *r = BN_new();
    size_t i, j, k;

    for (k = 0; k < sizeof(mods) / sizeof(mods[0]); k++) {
        BIGNUM *m = hexbn(mods[k]);

        for (i = 0; i < sizeof(bases) / sizeof(bases[0]); i++) {
            BIGNUM *a = hexbn(bases[i]);

            for (j = 0; j < sizeof(exps) / sizeof(exps[0]); j++) {
                BIGNUM *p = hexbn(exps[j]);

                printf("  %s^%s mod %s:", bases[i], exps[j], mods[k]);
                printf(" exp %d", BN_mod_exp(r, a, p, m, ctx));
                show("", r);
                printf("   mont %d", BN_mod_exp_mont(r, a, p, m, ctx, NULL));
                show("", r);
                printf("   consttime %d", BN_mod_exp_mont_consttime(r, a, p, m, ctx, NULL));
                show("", r);
                printf("   recp %d", BN_mod_exp_recp(r, a, p, m, ctx));
                show("", r);
                printf("   simple %d", BN_mod_exp_simple(r, a, p, m, ctx));
                show("", r);
                if (!BN_is_negative(a) && BN_num_bits(a) <= 64) {
                    printf("   word %d", BN_mod_exp_mont_word(r, BN_get_word(a), p, m, ctx, NULL));
                    show("", r);
                }
                codes();
                BN_free(p);
            }
            BN_free(a);
        }
        BN_free(m);
    }

    /* Two at once. */
    {
        static const char *const pairs[][4] = {
            {"2", "3", "5", "7"}, {"-2", "3", "5", "7"}, {"-2", "3", "-5", "7"}, {"0", "0", "5", "7"},
            {"2", "0", "0", "0"}, {"7", "1", "5", "1"}, {"123456", "FFFF", "-654321", "10001"},
            {"-2", "4", "3", "0"},
        };
        BIGNUM *m = hexbn("E3A5C1F7B9D3E5A7C9B1D3F5E7A9C1B3D5E7F9A1B3C5D7E9F1A3B5C7D9E1F3A5");
        BIGNUM *one = hexbn("1"), *even = hexbn("10");

        for (i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
            BIGNUM *a1 = hexbn(pairs[i][0]), *p1 = hexbn(pairs[i][1]);
            BIGNUM *a2 = hexbn(pairs[i][2]), *p2 = hexbn(pairs[i][3]);

            printf("  exp2 %s^%s * %s^%s: %d", pairs[i][0], pairs[i][1], pairs[i][2], pairs[i][3],
                   BN_mod_exp2_mont(r, a1, p1, a2, p2, m, ctx, NULL));
            show("", r);
            printf("   mod 1: %d", BN_mod_exp2_mont(r, a1, p1, a2, p2, one, ctx, NULL));
            show("", r);
            BN_free(a1);
            BN_free(p1);
            BN_free(a2);
            BN_free(p2);
        }
        check(BN_mod_exp2_mont(r, one, one, one, one, even, ctx, NULL) == 0, "exp2 with an even modulus");
        codes();
        {
            BN_MONT_CTX *unset = BN_MONT_CTX_new();
            BIGNUM *z = hexbn("0"), *t = hexbn("3"), *mm = hexbn("7");

            printf("  exp2 unset, zero base %d", BN_mod_exp2_mont(r, z, t, t, t, mm, ctx, unset));
            show("", r);
            printf("  exp2 unset %d, mont unset %d, mont unset p 0 %d", BN_mod_exp2_mont(r, t, t, t, t, mm, ctx, unset),
                   BN_mod_exp_mont(r, t, t, mm, ctx, unset), BN_mod_exp_mont(r, t, z, mm, ctx, unset));
            show("", r);
            codes();
            BN_MONT_CTX_free(unset);
            BN_free(z);
            BN_free(t);
            BN_free(mm);
        }
        BN_free(m);
        BN_free(one);
        BN_free(even);
    }

    /* Flags, aliasing, and a given Montgomery context. */
    {
        BIGNUM *a = hexbn("3"), *p = hexbn("65"), *m = hexbn("F1"), *e = hexbn("10");
        BN_MONT_CTX *mont = BN_MONT_CTX_new();
        BIGNUM *r2 = BN_new();

        BN_set_flags(p, BN_FLG_CONSTTIME);
        check(BN_mod_exp_recp(r, a, p, m, ctx) == 0, "recp refuses CONSTTIME");
        check(BN_mod_exp_simple(r, a, p, m, ctx) == 0, "simple refuses CONSTTIME");
        check(BN_mod_exp_mont_word(r, 3, p, m, ctx, NULL) == 0, "word refuses CONSTTIME");
        codes();
        check(BN_mod_exp_mont(r, a, p, m, ctx, NULL) == 1, "mont takes CONSTTIME");
        show("3^0x65 mod 0xF1", r);
        check(BN_mod_exp(r, a, p, e, ctx) == 0, "an even modulus with CONSTTIME");
        codes();
        check(BN_mod_exp_simple(m, a, a, m, ctx) == 0, "simple into the modulus");
        codes();
        check(BN_mod_exp(a, a, a, m, ctx) == 1, "exp in place");
        show("3^3 mod 0xF1", a);
        check(BN_MONT_CTX_set(mont, m, ctx) == 1, "BN_MONT_CTX_set");
        BN_set_word(a, 5);
        check(BN_mod_exp_mont(r, a, a, m, ctx, mont) == 1, "with a context");
        show("5^5 mod 0xF1", r);
        check(BN_mod_exp_mont_consttime(r, a, a, m, ctx, mont) == 1, "consttime with a context");
        show("5^5 mod 0xF1", r);
        check(BN_mod_exp_mont_word(r, 5, a, m, ctx, mont) == 1, "word with a context");
        show("5^5 mod 0xF1", r);
        BN_set_word(e, 7);
        check(BN_mod_exp_mont_consttime_x2(r, a, a, m, mont, r2, e, e, m, NULL, ctx) == 1, "x2");
        show("first", r);
        show("second", r2);
        BN_free(a);
        BN_free(p);
        BN_free(m);
        BN_free(e);
        BN_free(r2);
        BN_MONT_CTX_free(mont);
    }
    BN_free(r);
    BN_CTX_free(ctx);
}

/* ---------------------------------------------------------------------------------------- */

static void contexts(void)
{
    BN_CTX *ctx = BN_CTX_new();
    BN_MONT_CTX *mont = BN_MONT_CTX_new(), *copy = BN_MONT_CTX_new(), *locked = NULL;
    BN_RECP_CTX *recp = BN_RECP_CTX_new();
    CRYPTO_RWLOCK *lock = CRYPTO_THREAD_lock_new();
    BIGNUM *m = hexbn("E3A5C1F7B9D3E5A7C9B1D3F5E7A9C1B3D5E7F9A1B3C5D7E9F1A3B5C7D9E1F3A5");
    BIGNUM *a = hexbn("123456789ABCDEF"), *b = hexbn("-FEDCBA987654321"), *r = BN_new(), *q = BN_new();
    BIGNUM *big = hexbn("1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001");
    BIGNUM *even = hexbn("100"), *zero = BN_new();
    static const char *const recps[] = {"7", "-7", "FFFFFFFFFFFFFFFF", "123456789ABCDEF0123456789"};
    size_t i;

    check(BN_MONT_CTX_set(mont, m, ctx) == 1, "set");
    check(BN_MONT_CTX_set(copy, even, ctx) == 0, "an even modulus");
    codes();
    check(BN_MONT_CTX_set(copy, zero, ctx) == 0, "a zero modulus");
    codes();
    check(BN_MONT_CTX_copy(copy, mont) == copy && BN_MONT_CTX_copy(copy, copy) == copy, "copy");
    check(BN_to_montgomery(r, a, copy, ctx) == 1, "to");
    show("a R", r);
    check(BN_from_montgomery(r, r, mont, ctx) == 1, "from");
    show("back", r);
    check(BN_to_montgomery(q, b, mont, ctx) == 1, "a negative number to");
    show("b R", q);
    BN_to_montgomery(r, a, mont, ctx);
    check(BN_mod_mul_montgomery(r, r, q, mont, ctx) == 1, "a product");
    BN_from_montgomery(r, r, mont, ctx);
    show("a b mod m", r);
    BN_mod_mul(q, a, b, m, ctx);
    show("BN_mod_mul's", q);
    /* Operands that aren't reduced. */
    check(BN_mod_mul_montgomery(r, big, a, mont, ctx) == 0, "an operand longer than twice the modulus");
    BN_rshift(q, big, 230);
    check(BN_mod_mul_montgomery(r, q, a, mont, ctx) == 1, "an unreduced operand");
    show("unreduced", r);
    check(BN_mod_mul_montgomery(r, big, big, mont, ctx) == 0, "operands too long");
    check(BN_to_montgomery(r, big, mont, ctx) == 0, "too long to convert");
    check(BN_from_montgomery(r, big, mont, ctx) == 1, "from cuts to twice the length");
    show("big / R", r);
    BN_set_word(r, 9);
    check(BN_mod_mul_montgomery(r, m, m, mont, ctx) == 1, "m m / R");
    show("m m / R", r);
    {
        BN_MONT_CTX *unset = BN_MONT_CTX_new();

        check(BN_mod_mul_montgomery(r, a, a, unset, ctx) == 0, "an unset context");
        check(BN_from_montgomery(r, a, unset, ctx) == 1 && BN_is_zero(r), "from an unset context");
        BN_MONT_CTX_free(unset);
    }
    check(BN_MONT_CTX_set_locked(&locked, lock, m, ctx) == locked && locked != NULL, "set_locked");
    check(BN_MONT_CTX_set_locked(&locked, lock, even, ctx) == locked, "set_locked again");
    codes();

    /* Reciprocals. */
    check(BN_RECP_CTX_set(recp, zero, ctx) == 0, "a zero divisor");
    for (i = 0; i < sizeof(recps) / sizeof(recps[0]); i++) {
        BIGNUM *d = hexbn(recps[i]);

        printf("  divisor %s:\n", recps[i]);
        check(BN_RECP_CTX_set(recp, d, ctx) == 1, "set");
        printf("  div %d", BN_div_recp(q, r, b, recp, ctx));
        show("q", q);
        show("rem", r);
        printf("  div %d", BN_div_recp(NULL, r, a, recp, ctx));
        show("rem", r);
        printf("  div small %d", BN_div_recp(q, r, zero, recp, ctx));
        show("q", q);
        printf("  mul %d", BN_mod_mul_reciprocal(r, a, b, recp, ctx));
        show("", r);
        printf("  sqr %d", BN_mod_mul_reciprocal(r, b, b, recp, ctx));
        show("", r);
        printf("  just mod %d", BN_mod_mul_reciprocal(r, big, NULL, recp, ctx));
        show("", r);
        printf("  reciprocal %d", BN_reciprocal(r, d, 200, ctx));
        show("", r);
        BN_free(d);
    }
    {
        BN_RECP_CTX *unset = BN_RECP_CTX_new();

        check(BN_div_recp(q, r, a, unset, ctx) == 0, "an unset divisor");
        codes();
        check(BN_div_recp(q, r, zero, unset, ctx) == 0, "zero by an unset divisor");
        show("q", q);
        show("rem", r);
        codes();
        BN_RECP_CTX_free(unset);
    }
    check(BN_reciprocal(r, a, -1, ctx) == -1, "a negative length");
    check(BN_reciprocal(r, zero, 10, ctx) == -1, "a zero reciprocal");
    codes();

    BN_MONT_CTX_free(mont);
    BN_MONT_CTX_free(copy);
    BN_MONT_CTX_free(locked);
    BN_MONT_CTX_free(NULL);
    BN_RECP_CTX_free(recp);
    BN_RECP_CTX_free(NULL);
    CRYPTO_THREAD_lock_free(lock);
    BN_free(m);
    BN_free(a);
    BN_free(b);
    BN_free(r);
    BN_free(q);
    BN_free(big);
    BN_free(even);
    BN_free(zero);
    BN_CTX_free(ctx);
}

/* ---------------------------------------------------------------------------------------- */

static void number_theory(void)
{
    static const char *const pairs[][2] = {
        {"3", "7"}, {"-3", "7"}, {"6", "9"}, {"0", "7"}, {"7", "0"}, {"1", "1"}, {"5", "-1"},
        {"10001", "D8E2B2C3A1F4B9C8E7D6A5B4C3D2E1F00123456789ABCDEF0123456789ABCDE0"},
        {"FFFFFFFFFFFFFFFF", "10000000000000000"}, {"-5", "12"}, {"4", "12"}, {"11", "-10"},
        {"123456789ABCDEF", "FEDCBA9876543210FEDCBA987654321"},
    };
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *r = BN_new(), *inv;
    size_t i;

    for (i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
        BIGNUM *a = hexbn(pairs[i][0]), *b = hexbn(pairs[i][1]);

        printf("  %s, %s:", pairs[i][0], pairs[i][1]);
        printf(" gcd %d", BN_gcd(r, a, b, ctx));
        show("", r);
        inv = BN_mod_inverse(NULL, a, b, ctx);
        show("   inverse", inv);
        codes();
        BN_free(inv);
        printf("   kronecker %d\n", BN_kronecker(a, b, ctx));
        printf("   coprime %d flags %x\n", BN_are_coprime(a, b, ctx), BN_get_flags(a, ~0));
        /* The result's constant-time flag travels with OpenSSL's swaps. */
        BN_set_flags(r, BN_FLG_CONSTTIME);
        BN_gcd(r, a, b, ctx);
        printf("   gcd into a flagged number: flags %x\n", BN_get_flags(r, BN_FLG_CONSTTIME));
        codes();
        BN_set_flags(b, BN_FLG_CONSTTIME);
        inv = BN_mod_inverse(r, a, b, ctx);
        printf("   consttime inverse %s", inv == r ? "into r" : "none");
        show("", r);
        codes();
        BN_free(a);
        BN_free(b);
    }

    /* Into the modulus: OpenSSL fails where its steps leave a value it has to reduce. */
    {
        static const char *const pairs[][2] = {
            {"5193817943", "3259122431"}, {"3", "7"}, {"7", "3"}, {"2", "B"}, {"-5", "11"},
            {"123456789ABCDEF", "FEDCBA987654321F"}, {"10", "21"}, {"1234567", "10000"},
            {"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE", "10001"},
        };
        size_t i;
        int flagged;

        for (flagged = 0; flagged < 2; flagged++)
            for (i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
                BIGNUM *a = NULL, *b = NULL, *inv;

                if (i == 0) {
                    BN_dec2bn(&a, pairs[i][0]);
                    BN_dec2bn(&b, pairs[i][1]);
                } else {
                    BN_hex2bn(&a, pairs[i][0]);
                    BN_hex2bn(&b, pairs[i][1]);
                }
                if (flagged)
                    BN_set_flags(a, BN_FLG_CONSTTIME);
                inv = BN_mod_inverse(b, a, b, ctx);
                printf("   inverse of %s into the modulus%s: %s", pairs[i][0], flagged ? " (consttime)" : "",
                       inv == b ? "into it" : "none");
                show("", b);
                codes();
                BN_free(a);
                BN_free(b);
            }
    }

    /* Square roots: p = 3 (mod 4), 5 (mod 8), 1 (mod 8), 2, and composites. */
    {
        static const char *const primes[] = {"7", "D", "11", "61", "2", "-61", "9", "F", "1", "4",
                                             "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED"};
        size_t j;

        for (i = 0; i < sizeof(primes) / sizeof(primes[0]); i++) {
            BIGNUM *p = hexbn(primes[i]);

            printf("  p = %s:\n", primes[i]);
            for (j = 0; j < 12; j++) {
                BIGNUM *a = BN_new(), *s;

                BN_set_word(a, j);
                if (j == 11)
                    BN_set_negative(BN_set_word(a, 3) ? a : a, 1);
                s = BN_mod_sqrt(NULL, a, p, ctx);
                printf("  %s%zu:", j == 11 ? "-" : "", j == 11 ? (size_t)3 : j);
                show("", s);
                codes();
                BN_free(s);
                BN_free(a);
            }
            BN_free(p);
        }
        {
            BIGNUM *p = hexbn("7"), *a = hexbn("3"), *in = hexbn("99");

            check(BN_mod_sqrt(in, a, p, ctx) == NULL, "a non-residue");
            show("in after", in);
            codes();
            BN_set_word(a, 2);
            check(BN_mod_sqrt(in, a, p, ctx) == in, "into in");
            show("root", in);
            BN_free(p);
            BN_free(a);
            BN_free(in);
        }
    }
    BN_free(r);
    BN_CTX_free(ctx);
}

/* ---------------------------------------------------------------------------------------- */

static void primes(void)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *r = BN_new(), *b, *sq;
    const BIGNUM *p[5];
    int (*funcs[5])(BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *) = {
        BN_nist_mod_192, BN_nist_mod_224, BN_nist_mod_256, BN_nist_mod_384, BN_nist_mod_521
    };
    BIGNUM *(*rfc[8])(BIGNUM *) = {
        BN_get_rfc2409_prime_768, BN_get_rfc2409_prime_1024, BN_get_rfc3526_prime_1536,
        BN_get_rfc3526_prime_2048, BN_get_rfc3526_prime_3072, BN_get_rfc3526_prime_4096,
        BN_get_rfc3526_prime_6144, BN_get_rfc3526_prime_8192
    };
    int i;

    p[0] = BN_get0_nist_prime_192();
    p[1] = BN_get0_nist_prime_224();
    p[2] = BN_get0_nist_prime_256();
    p[3] = BN_get0_nist_prime_384();
    p[4] = BN_get0_nist_prime_521();
    for (i = 0; i < 5; i++) {
        BIGNUM *a = hexbn("-123456789ABCDEF0123456789ABCDEF");

        show("nist", p[i]);
        check(BN_get_flags(p[i], ~0) == BN_FLG_STATIC_DATA, "static");
        check(BN_nist_mod_func(p[i]) == funcs[i], "BN_nist_mod_func");
        printf("  reduce -a %d", funcs[i](r, a, NULL, ctx));
        show("", r);
        BN_set_negative(a, 0);
        BN_lshift(a, a, BN_num_bits(p[i]) - 10);
        printf("  reduce a %d", funcs[i](r, a, p[i], ctx));
        show("", r);
        printf("  reduce in place %d", funcs[i](a, a, NULL, ctx));
        show("", a);
        /* The fast reduction leaves the result's sign as it was. */
        BN_set_word(r, 1);
        BN_set_negative(r, 1);
        BN_lshift(a, p[i], 3);
        BN_add_word(a, 5);
        printf("  reduce into a negative %d", funcs[i](r, a, NULL, ctx));
        show("", r);
        printf("  reduce p %d", funcs[i](r, p[i], NULL, ctx));
        show("", r);
        sq = BN_new();
        BN_sqr(sq, p[i], ctx);
        BN_sub_word(sq, 1);
        printf("  reduce p^2-1 %d", funcs[i](r, sq, NULL, ctx));
        show("", r);
        BN_add_word(sq, 2);
        printf("  reduce p^2+1 %d", funcs[i](r, sq, NULL, ctx));
        show("", r);
        BN_free(sq);
        BN_free(a);
    }
    check(BN_nist_mod_func(BN_value_one()) == NULL, "not a NIST prime");

    for (i = 0; i < 8; i++) {
        b = rfc[i](NULL);
        show("rfc", b);
        check(rfc[i](r) == r && BN_cmp(r, b) == 0, "into a number");
        BN_free(b);
    }
    BN_free(r);
    BN_CTX_free(ctx);
}

/* ---------------------------------------------------------------------------------------- */

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

static int exp_calls = 0;

/* An application's exponentiation, through BN_mod_exp_mont. */
static int my_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
                  BN_MONT_CTX *mont)
{
    exp_calls++;
    return BN_mod_exp_mont(r, a, p, m, ctx, mont);
}

static void blinding(void)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *m = hexbn("E3A5C1F7B9D3E5A7C9B1D3F5E7A9C1B3D5E7F9A1B3C5D7E9F1A3B5C7D9E1F3A5");
    BIGNUM *e = hexbn("10001"), *n = hexbn("123456789"), *r = BN_new(), *a = hexbn("5"), *ai;
    BN_MONT_CTX *mont = BN_MONT_CTX_new();
    BN_BLINDING *b;
    int i;

    check(RAND_set0_public(NULL, known_drbg(5)) == 1 && RAND_set0_private(NULL, known_drbg(6)) == 1,
          "known generators");
    BN_MONT_CTX_set(mont, m, ctx);

    /* Given A and Ai. */
    ai = BN_mod_inverse(NULL, a, m, ctx);
    b = BN_BLINDING_new(a, ai, m);
    check(b != NULL && BN_BLINDING_is_current_thread(b) == 1, "new");
    check(BN_BLINDING_get_flags(b) == 0, "no flags");
    check(BN_BLINDING_convert_ex(n, r, b, ctx) == 1, "convert");
    show("blinded", n);
    show("r", r);
    check(BN_BLINDING_invert_ex(n, r, b, ctx) == 1, "invert");
    show("unblinded", n);
    check(BN_BLINDING_convert(n, b, ctx) == 1 && BN_BLINDING_invert(n, b, ctx) == 1, "again");
    show("unblinded", n);
    check(BN_BLINDING_update(b, ctx) == 1, "update");
    BN_BLINDING_set_flags(b, BN_BLINDING_NO_UPDATE);
    check(BN_BLINDING_get_flags(b) == BN_BLINDING_NO_UPDATE, "flags");
    check(BN_BLINDING_update(b, ctx) == 1, "update without updating");
    check(BN_BLINDING_lock(b) == 1 && BN_BLINDING_unlock(b) == 1, "lock");
    BN_BLINDING_set_current_thread(b);
    /* Created over it, with an exponent. */
    check(BN_BLINDING_create_param(b, e, NULL, ctx, NULL, NULL) == b, "create_param");
    BN_BLINDING_set_flags(b, 0);
    /* Without the private operation between, each round trip leaves n times r^(e-1). */
    for (i = 0; i < 40; i++) {
        BN_set_word(n, 1000 + i);
        if (!BN_BLINDING_convert(n, b, ctx) || !BN_BLINDING_invert(n, b, ctx))
            break;
        if (i % 13 == 0)
            show("round trip", n);
    }
    check(i == 40, "forty conversions (one recreation)");
    BN_BLINDING_free(b);

    /* New, with an application's exponentiation and a Montgomery context. */
    b = BN_BLINDING_create_param(NULL, e, m, ctx, my_exp, mont);
    check(b != NULL && exp_calls == 1, "create_param with a function");
    BN_set_word(n, 777);
    check(BN_BLINDING_convert_ex(n, r, b, ctx) == 1, "convert in Montgomery form");
    show("blinded", n);
    check(BN_BLINDING_invert_ex(n, r, b, ctx) == 1, "invert in Montgomery form");
    show("unblinded", n);
    BN_lshift(n, m, 64);
    check(BN_BLINDING_invert(n, b, ctx) == 0, "a number longer than the modulus");
    BN_BLINDING_free(b);

    /* Without A and Ai. */
    b = BN_BLINDING_new(NULL, NULL, m);
    check(BN_BLINDING_convert(n, b, ctx) == 0 && BN_BLINDING_update(b, ctx) == 0
              && BN_BLINDING_invert(n, b, ctx) == 0,
          "not initialized");
    codes();
    check(BN_BLINDING_create_param(b, NULL, NULL, ctx, NULL, NULL) == b, "no exponent returns b");
    BN_BLINDING_free(b);
    check(BN_BLINDING_create_param(NULL, e, NULL, ctx, NULL, NULL) == NULL, "no modulus");
    BN_BLINDING_free(NULL);
    {
        BIGNUM *one = hexbn("1");

        check(BN_BLINDING_create_param(NULL, e, one, ctx, NULL, NULL) == NULL, "a modulus of one");
        codes();
        BN_free(one);
    }

    /* DSA nonces. */
    {
        BIGNUM *k = BN_new(), *range = hexbn("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
        BIGNUM *priv = hexbn("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
        static const unsigned char msg[] = "sample";

        check(BN_generate_dsa_nonce(k, range, priv, msg, sizeof(msg) - 1, ctx) == 1, "a nonce");
        show("k", k);
        check(BN_get_flags(k, BN_FLG_CONSTTIME) == BN_FLG_CONSTTIME, "flagged constant-time");
        BN_set_word(range, 1);
        check(BN_generate_dsa_nonce(k, range, priv, msg, 0, ctx) == 1 && BN_is_zero(k), "below one");
        BN_lshift(priv, priv, 600);
        check(BN_generate_dsa_nonce(k, range, priv, msg, 0, ctx) == 0, "a private key too long");
        codes();
        BN_zero(range);
        check(BN_generate_dsa_nonce(k, range, range, NULL, 0, ctx) == 0, "an empty range");
        codes();
        BN_free(k);
        BN_free(range);
        BN_free(priv);
    }

    RAND_set0_public(NULL, NULL);
    RAND_set0_private(NULL, NULL);
    BN_MONT_CTX_free(mont);
    BN_free(m);
    BN_free(e);
    BN_free(n);
    BN_free(r);
    BN_free(a);
    BN_free(ai);
    BN_CTX_free(ctx);
}

int main(void)
{
    simple_ops();
    exponentiation();
    contexts();
    number_theory();
    primes();
    blinding();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
