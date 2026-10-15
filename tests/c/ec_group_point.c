/*
 * Conformance test for EC groups and points (EC_GROUP_new(3), EC_POINT_new(3), EC_POINT_add(3),
 * EC_GFp_simple_method(3)), in TAP format: the built-in curves and their names; named groups
 * (every method of the default build: mont, nistp224, nistz256, the binary curves) and their
 * accessors, copies, comparisons, and checks; explicit groups over GF(p) and GF(2^m) and each
 * method's checks on its curve; generators and their errors; and points: coordinates (affine
 * and Jacobian), arithmetic, multiplication, every encoding (compressed, uncompressed, hybrid,
 * BIGNUM, hex) and what they refuse. What depends on random numbers (the Jacobian coordinates
 * of a blinded multiplication) isn't printed; everything else is.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/objects.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* The error queue, emptied: each entry's library and reason. */
static void errors(void)
{
    unsigned long code;

    printf("  errors:");
    while ((code = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
    printf("\n");
}

static void bn(const char *label, const BIGNUM *b)
{
    char *s;

    if (b == NULL) {
        printf("  %s: (null)\n", label);
        return;
    }
    s = BN_bn2hex(b);
    printf("  %s: %s\n", label, s);
    OPENSSL_free(s);
}

static void hex(const char *label, const unsigned char *p, size_t len)
{
    size_t i;

    printf("  %s (%zu):", label, len);
    for (i = 0; i < len; i++)
        printf("%s%02x", i % 40 == 0 && i > 0 ? "\n    " : "", p[i]);
    printf("\n");
}

static BIGNUM *num(const char *h)
{
    BIGNUM *b = NULL;

    BN_hex2bn(&b, h);
    return b;
}

/* A point's affine coordinates. */
static void affine(const char *label, const EC_GROUP *g, const EC_POINT *p)
{
    BIGNUM *x = BN_new(), *y = BN_new();

    if (EC_POINT_is_at_infinity(g, p)) {
        printf("  %s: infinity\n", label);
    } else if (EC_POINT_get_affine_coordinates(g, p, x, y, NULL)) {
        char *xs = BN_bn2hex(x), *ys = BN_bn2hex(y);

        printf("  %s: (%s, %s)\n", label, xs, ys);
        OPENSSL_free(xs);
        OPENSSL_free(ys);
    } else {
        printf("  %s: no affine coordinates\n", label);
        errors();
    }
    BN_free(x);
    BN_free(y);
}

/* A point's Jacobian coordinates (prime fields). */
static void jacobian(const char *label, const EC_GROUP *g, const EC_POINT *p)
{
    BIGNUM *x = BN_new(), *y = BN_new(), *z = BN_new();

    if (EC_POINT_get_Jprojective_coordinates_GFp(g, p, x, y, z, NULL)) {
        char *xs = BN_bn2hex(x), *ys = BN_bn2hex(y), *zs = BN_bn2hex(z);

        printf("  %s: [%s : %s : %s]\n", label, xs, ys, zs);
        OPENSSL_free(xs);
        OPENSSL_free(ys);
        OPENSSL_free(zs);
    } else {
        printf("  %s: no Jacobian coordinates\n", label);
        errors();
    }
    BN_free(x);
    BN_free(y);
    BN_free(z);
}

static void test_builtin(void)
{
    size_t n = EC_get_builtin_curves(NULL, 0), i;
    EC_builtin_curve *curves = OPENSSL_malloc(n * sizeof(*curves));

    check(n > 70, "EC_get_builtin_curves: the count");
    printf("  %zu curves\n", n);
    check(EC_get_builtin_curves(curves, 3) == n, "EC_get_builtin_curves: three of them");
    check(EC_get_builtin_curves(curves, n) == n, "EC_get_builtin_curves: all");
    for (i = 0; i < n; i++) {
        const char *nist = EC_curve_nid2nist(curves[i].nid);
        const char *name = OSSL_EC_curve_nid2name(curves[i].nid);

        printf("  %d %s %s%s%s \"%s\"\n", curves[i].nid, OBJ_nid2sn(curves[i].nid),
               name != NULL ? name : "-", nist != NULL ? " " : "", nist != NULL ? nist : "",
               curves[i].comment);
    }
    OPENSSL_free(curves);
    check(EC_curve_nist2nid("P-256") == NID_X9_62_prime256v1, "EC_curve_nist2nid");
    check(EC_curve_nist2nid("p-256") == NID_undef, "EC_curve_nist2nid: exact");
    check(EC_curve_nid2nist(NID_secp256k1) == NULL, "EC_curve_nid2nist: not NIST");
    check(OSSL_EC_curve_nid2name(0) == NULL && OSSL_EC_curve_nid2name(-1) == NULL,
          "OSSL_EC_curve_nid2name: none");
}

/* Every curve's group: its accessors and a generator check. */
static void test_named(void)
{
    size_t n = EC_get_builtin_curves(NULL, 0), i;
    EC_builtin_curve *curves = OPENSSL_malloc(n * sizeof(*curves));
    BN_CTX *ctx = BN_CTX_new();

    EC_get_builtin_curves(curves, n);
    for (i = 0; i < n; i++) {
        EC_GROUP *g = EC_GROUP_new_by_curve_name(curves[i].nid);
        BIGNUM *p = BN_new(), *a = BN_new(), *b = BN_new(), *order = BN_new(), *co = BN_new();
        const EC_METHOD *m;

        if (g == NULL) {
            check(0, "EC_GROUP_new_by_curve_name");
            errors();
            continue;
        }
        m = EC_GROUP_method_of(g);
        EC_GROUP_get_curve(g, p, a, b, ctx);
        EC_GROUP_get_order(g, order, ctx);
        EC_GROUP_get_cofactor(g, co, ctx);
        printf("  %s: field %d, degree %d, order bits %d, flag %d, form %d, seed %zu, "
               "check %d, discriminant %d\n",
               OBJ_nid2sn(curves[i].nid), EC_METHOD_get_field_type(m),
               EC_GROUP_get_degree(g), EC_GROUP_order_bits(g), EC_GROUP_get_asn1_flag(g),
               (int)EC_GROUP_get_point_conversion_form(g), EC_GROUP_get_seed_len(g),
               EC_GROUP_check(g, ctx), EC_GROUP_check_discriminant(g, ctx));
        bn("p", p);
        bn("a", a);
        bn("b", b);
        bn("order", order);
        bn("cofactor", co);
        affine("G", g, EC_GROUP_get0_generator(g));
        check(EC_GROUP_get_curve_name(g) == curves[i].nid, "the curve's name");
        ERR_clear_error();
        BN_free(p);
        BN_free(a);
        BN_free(b);
        BN_free(order);
        BN_free(co);
        EC_GROUP_free(g);
    }
    OPENSSL_free(curves);
    BN_CTX_free(ctx);
    check(EC_GROUP_new_by_curve_name(NID_sha256) == NULL, "EC_GROUP_new_by_curve_name: no curve");
    errors();
}

static void test_methods(void)
{
    static const struct {
        const char *name;
        const EC_METHOD *(*meth)(void);
    } methods[] = {
        { "simple", EC_GFp_simple_method },
        { "mont", EC_GFp_mont_method },
        { "nist", EC_GFp_nist_method },
        { "nistp224", EC_GFp_nistp224_method },
        { "nistp256", EC_GFp_nistp256_method },
        { "nistp521", EC_GFp_nistp521_method },
        { "gf2m", EC_GF2m_simple_method },
    };
    EC_GROUP *p256 = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_GROUP *k256 = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BIGNUM *p = BN_new(), *a = BN_new(), *b = BN_new();
    size_t i, j;

    for (i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
        const EC_METHOD *m = methods[i].meth();

        printf("  %s: field type %d\n", methods[i].name, EC_METHOD_get_field_type(m));
        for (j = 0; j < 2; j++) {
            EC_GROUP *g = EC_GROUP_new(m);
            int ret;

            EC_GROUP_get_curve(j == 0 ? p256 : k256, p, a, b, NULL);
            ret = EC_GROUP_set_curve(g, p, a, b, NULL);
            check(1, "EC_GROUP_set_curve with a method");
            printf("  %s, %s: %d\n", methods[i].name, j == 0 ? "P-256" : "secp256k1", ret);
            errors();
            EC_GROUP_free(g);
        }
    }
    check(EC_GROUP_new(NULL) == NULL, "EC_GROUP_new(NULL)");
    errors();
    {
        EC_GROUP *g = EC_GROUP_new(EC_GFp_mont_method());

        BN_set_word(p, 100);
        check(EC_GROUP_set_curve(g, p, a, b, NULL) == 0, "mont: an even field");
        errors();
        BN_set_word(p, 3);
        check(EC_GROUP_set_curve(g, p, a, b, NULL) == 0, "mont: a 2-bit field");
        errors();
        BN_zero(p);
        check(EC_GROUP_set_curve(g, p, a, b, NULL) == 0, "mont: zero");
        errors();
        EC_GROUP_free(g);
        g = EC_GROUP_new(EC_GF2m_simple_method());
        BN_set_word(p, 0x13); /* x^4 + x + 1, a trinomial */
        BN_set_word(a, 1);
        BN_set_word(b, 1);
        check(EC_GROUP_set_curve(g, p, a, b, NULL) == 1, "GF2m: a trinomial");
        BN_set_word(p, 0x1b); /* x^4 + x^3 + x + 1: four terms */
        check(EC_GROUP_set_curve(g, p, a, b, NULL) == 0, "GF2m: four terms");
        errors();
        BN_set_word(p, 0x12);
        check(EC_GROUP_set_curve(g, p, a, b, NULL) == 0, "GF2m: an even polynomial");
        errors();
        EC_GROUP_free(g);
    }
    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_GROUP_free(p256);
    EC_GROUP_free(k256);
}

/* A small curve over GF(p): y^2 = x^3 + 2x + 3 mod 97, with the point (3, 6) of order 5. */
static void test_explicit_gfp(void)
{
    BIGNUM *p = num("61"), *a = num("2"), *b = num("3");
    EC_GROUP *g = EC_GROUP_new_curve_GFp(p, a, b, NULL), *d;
    EC_POINT *P, *Q, *R;
    BIGNUM *x = BN_new(), *y = BN_new(), *order = num("5"), *co = num("0"), *bad;

    check(g != NULL, "EC_GROUP_new_curve_GFp: mod 97");
    printf("  method field type %d, degree %d, name %d, flag %d, a = -3? %s\n",
           EC_METHOD_get_field_type(EC_GROUP_method_of(g)), EC_GROUP_get_degree(g),
           EC_GROUP_get_curve_name(g), EC_GROUP_get_asn1_flag(g),
           "n/a");
    check(EC_GROUP_get0_generator(g) == NULL && EC_GROUP_get0_order(g) != NULL
          && BN_is_zero(EC_GROUP_get0_order(g)), "no generator yet, order zero");
    P = EC_POINT_new(g);
    Q = EC_POINT_new(g);
    R = EC_POINT_new(g);
    check(EC_POINT_is_at_infinity(g, P), "a new point is at infinity");
    jacobian("new", g, P);
    BN_set_word(x, 3);
    BN_set_word(y, 6);
    check(EC_POINT_set_affine_coordinates(g, P, x, y, NULL) == 1, "set (3, 6)");
    jacobian("P", g, P);
    BN_set_word(y, 7);
    check(EC_POINT_set_affine_coordinates(g, Q, x, y, NULL) == 0, "set (3, 7): not on the curve");
    errors();
    jacobian("Q after", g, Q);
    check(EC_POINT_is_on_curve(g, Q, NULL) == 0, "EC_POINT_is_on_curve: no");

    check(EC_POINT_dbl(g, R, P, NULL) == 1, "2P");
    jacobian("2P", g, R);
    affine("2P", g, R);
    check(EC_POINT_add(g, Q, R, P, NULL) == 1, "2P + P");
    jacobian("3P", g, Q);
    affine("3P", g, Q);
    check(EC_POINT_add(g, Q, Q, Q, NULL) == 1, "3P + 3P (one object)");
    jacobian("6P", g, Q);
    check(EC_POINT_invert(g, R, NULL) == 1, "-2P");
    jacobian("-2P", g, R);
    check(EC_POINT_add(g, Q, R, R, NULL) == 1 && EC_POINT_add(g, R, R, Q, NULL) == 1,
          "-2P + -2P, then + that");
    jacobian("-6P", g, R);
    check(EC_POINT_make_affine(g, R, NULL) == 1, "make it affine");
    jacobian("-6P affine", g, R);
    {
        EC_POINT *I = EC_POINT_new(g), *pts[3];

        EC_POINT_copy(I, P);
        EC_POINT_invert(g, I, NULL);
        check(EC_POINT_add(g, Q, P, I, NULL) == 1 && EC_POINT_is_at_infinity(g, Q),
              "P + -P is infinity");
        jacobian("infinity", g, Q);
        EC_POINT_dbl(g, I, P, NULL);
        EC_POINT_dbl(g, Q, I, NULL);
        pts[0] = I;
        pts[1] = Q;
        pts[2] = R;
        EC_POINT_set_to_infinity(g, R);
        check(EC_POINTs_make_affine(g, 3, pts, NULL) == 1, "EC_POINTs_make_affine");
        jacobian("2P", g, I);
        jacobian("4P", g, Q);
        jacobian("infinity", g, R);
        EC_POINT_free(I);
    }

    BN_set_word(x, 0x10);
    BN_set_word(y, 0x20);
    {
        BIGNUM *z = num("05");

        check(EC_POINT_set_Jprojective_coordinates_GFp(g, Q, x, y, z, NULL) == 1,
              "set Jacobian coordinates");
        jacobian("Q", g, Q);
        printf("  on curve: %d\n", EC_POINT_is_on_curve(g, Q, NULL));
        BN_set_word(z, 0x62);
        EC_POINT_set_Jprojective_coordinates_GFp(g, Q, NULL, NULL, z, NULL);
        jacobian("Q, Z reduced", g, Q);
        BN_free(z);
    }

    check(EC_GROUP_set_generator(g, NULL, order, co) == 0, "set_generator: no generator");
    errors();
    check(EC_GROUP_set_generator(g, P, NULL, co) == 0, "set_generator: no order");
    errors();
    bad = num("1FF");
    check(EC_GROUP_set_generator(g, P, bad, co) == 0, "set_generator: an order too long");
    errors();
    BN_set_negative(bad, 1);
    check(EC_GROUP_set_generator(g, P, order, bad) == 0, "set_generator: a negative cofactor");
    errors();
    BN_free(bad);
    check(EC_GROUP_set_generator(g, P, order, NULL) == 1, "set_generator: guessing the cofactor");
    bn("cofactor", EC_GROUP_get0_cofactor(g));
    check(EC_GROUP_set_generator(g, P, order, co) == 1, "set_generator: cofactor 0 (guess)");
    bn("cofactor", EC_GROUP_get0_cofactor(g));
    {
        BIGNUM *five = num("5");

        check(EC_POINT_mul(g, Q, five, NULL, NULL, NULL) == 1
              && EC_POINT_is_at_infinity(g, Q), "5G is infinity");
        BN_set_word(five, 3);
        check(EC_POINT_mul(g, Q, five, NULL, NULL, NULL) == 1, "3G");
        affine("3G", g, Q);
        check(EC_POINT_mul(g, Q, NULL, P, five, NULL) == 1, "3P");
        affine("3P", g, Q);
        check(EC_POINT_mul(g, Q, five, P, five, NULL) == 1, "3G + 3P");
        affine("6G", g, Q);
        BN_set_negative(five, 1);
        check(EC_POINT_mul(g, Q, five, NULL, NULL, NULL) == 1, "-3G");
        affine("-3G", g, Q);
        check(EC_POINT_mul(g, Q, NULL, NULL, NULL, NULL) == 1
              && EC_POINT_is_at_infinity(g, Q), "no scalars: infinity");
        BN_free(five);
    }
    printf("  check: %d, discriminant: %d\n", EC_GROUP_check(g, NULL),
           EC_GROUP_check_discriminant(g, NULL));
    errors();

    d = EC_GROUP_dup(g);
    check(d != NULL && EC_GROUP_cmp(g, d, NULL) == 0, "EC_GROUP_dup, the same");
    EC_GROUP_set_asn1_flag(d, OPENSSL_EC_EXPLICIT_CURVE);
    EC_GROUP_set_point_conversion_form(d, POINT_CONVERSION_COMPRESSED);
    printf("  dup: flag %d, form %d; cmp %d\n", EC_GROUP_get_asn1_flag(d),
           (int)EC_GROUP_get_point_conversion_form(d), EC_GROUP_cmp(g, d, NULL));
    {
        static const unsigned char seed[] = { 1, 2, 3, 4, 5 };

        check(EC_GROUP_set_seed(d, seed, sizeof(seed)) == sizeof(seed), "EC_GROUP_set_seed");
        hex("seed", EC_GROUP_get0_seed(d), EC_GROUP_get_seed_len(d));
        check(EC_GROUP_set_seed(d, NULL, 0) == 1 && EC_GROUP_get0_seed(d) == NULL,
              "EC_GROUP_set_seed: none");
    }
    BN_set_word(order, 7);
    EC_GROUP_set_generator(d, P, order, NULL);
    printf("  another order: cmp %d\n", EC_GROUP_cmp(g, d, NULL));
    EC_GROUP_set_curve_name(d, NID_secp112r1);
    printf("  a name: cmp %d, name %d\n", EC_GROUP_cmp(g, d, NULL), EC_GROUP_get_curve_name(d));
    check(EC_GROUP_copy(d, g) == 1 && EC_GROUP_cmp(g, d, NULL) == 0, "EC_GROUP_copy");
    EC_GROUP_free(d);

    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(y);
    BN_free(order);
    BN_free(co);
    EC_GROUP_free(g);
}

/* Encodings on a named curve. */
static void test_encodings(int nid)
{
    EC_GROUP *g = EC_GROUP_new_by_curve_name(nid);
    EC_POINT *P = EC_POINT_new(g), *Q = EC_POINT_new(g);
    BIGNUM *k = num("123456789ABCDEF"), *b;
    unsigned char buf[200], *alloc = NULL;
    size_t len;
    char *h;
    static const point_conversion_form_t forms[] = {
        POINT_CONVERSION_COMPRESSED, POINT_CONVERSION_UNCOMPRESSED, POINT_CONVERSION_HYBRID
    };
    size_t i;

    printf("# %s\n", OBJ_nid2sn(nid));
    check(EC_POINT_mul(g, P, k, NULL, NULL, NULL) == 1, "kG");
    affine("kG", g, P);
    for (i = 0; i < 3; i++) {
        len = EC_POINT_point2oct(g, P, forms[i], NULL, 0, NULL);
        check(len > 0 && EC_POINT_point2oct(g, P, forms[i], buf, len, NULL) == len,
              "EC_POINT_point2oct");
        hex("encoding", buf, len);
        check(EC_POINT_oct2point(g, Q, buf, len, NULL) == 1 && EC_POINT_cmp(g, P, Q, NULL) == 0,
              "EC_POINT_oct2point");
        check(EC_POINT_point2oct(g, P, forms[i], buf, len - 1, NULL) == 0,
              "EC_POINT_point2oct: a short buffer");
        errors();
        if (forms[i] != POINT_CONVERSION_UNCOMPRESSED) {
            unsigned char save = buf[0];

            buf[0] ^= 1;
            printf("  the other y bit: %d\n", EC_POINT_oct2point(g, Q, buf, len, NULL));
            errors();
            affine("Q", g, Q);
            buf[0] = save;
        }
        b = EC_POINT_point2bn(g, P, forms[i], NULL, NULL);
        bn("point2bn", b);
        check(EC_POINT_bn2point(g, b, Q, NULL) == Q, "EC_POINT_bn2point");
        BN_free(b);
        h = EC_POINT_point2hex(g, P, forms[i], NULL);
        printf("  point2hex: %s\n", h);
        check(EC_POINT_hex2point(g, h, Q, NULL) == Q && EC_POINT_cmp(g, P, Q, NULL) == 0,
              "EC_POINT_hex2point");
        OPENSSL_free(h);
    }
    len = EC_POINT_point2buf(g, P, POINT_CONVERSION_COMPRESSED, &alloc, NULL);
    check(len > 0 && alloc != NULL, "EC_POINT_point2buf");
    hex("point2buf", alloc, len);
    OPENSSL_free(alloc);
    check(EC_POINT_point2oct(g, P, 5, buf, sizeof(buf), NULL) == 0, "form 5");
    errors();

    EC_POINT_set_to_infinity(g, Q);
    len = EC_POINT_point2oct(g, Q, POINT_CONVERSION_UNCOMPRESSED, buf, sizeof(buf), NULL);
    hex("infinity", buf, len);
    check(EC_POINT_oct2point(g, P, buf, 1, NULL) == 1 && EC_POINT_is_at_infinity(g, P),
          "decoded infinity");
    alloc = NULL;
    len = EC_POINT_point2buf(g, Q, POINT_CONVERSION_UNCOMPRESSED, &alloc, NULL);
    check(1, "point2buf: infinity");
    hex("point2buf", alloc, len);
    errors();
    OPENSSL_free(alloc);
    h = EC_POINT_point2hex(g, Q, POINT_CONVERSION_UNCOMPRESSED, NULL);
    printf("  point2hex of infinity: %s\n", h != NULL ? h : "(null)");
    errors();
    OPENSSL_free(h);

    /* Malformed encodings. */
    {
        static const unsigned char bad[][3] = {
            { 0x00, 0x00, 0x00 }, { 0x01, 0, 0 }, { 0x05, 0, 0 }, { 0x08, 0, 0 }, { 0x02, 0, 0 }
        };
        int lens[] = { 2, 1, 1, 1, 3 };

        for (i = 0; i < 5; i++) {
            printf("  %02x len %d: %d", bad[i][0], lens[i],
                   EC_POINT_oct2point(g, Q, bad[i], lens[i], NULL));
            errors();
        }
        printf("  empty: %d", EC_POINT_oct2point(g, Q, bad[0], 0, NULL));
        errors();
        len = EC_POINT_point2oct(g, EC_GROUP_get0_generator(g), POINT_CONVERSION_UNCOMPRESSED,
                                 buf, sizeof(buf), NULL);
        buf[len - 1] ^= 1;
        printf("  off the curve: %d", EC_POINT_oct2point(g, Q, buf, len, NULL));
        errors();
        memset(buf + 1, 0xff, len - 1);
        printf("  x too large: %d", EC_POINT_oct2point(g, Q, buf, len, NULL));
        errors();
    }

    /* Compressed coordinates. */
    {
        BIGNUM *x = BN_new();
        int found = 0;

        for (BN_set_word(x, 1); found < 2 && BN_get_word(x) < 40; BN_add_word(x, 1)) {
            int r0 = EC_POINT_set_compressed_coordinates(g, Q, x, 0, NULL);

            printf("  x=%lu y_bit 0: %d", (unsigned long)BN_get_word(x), r0);
            if (r0 == 1) {
                affine("", g, Q);
                found++;
            } else {
                errors();
            }
        }
        BN_free(x);
    }
    BN_free(k);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_GROUP_free(g);
}

static void test_points_misc(void)
{
    EC_GROUP *g = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_GROUP *h = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT *P = EC_POINT_new(g), *Q, *H = EC_POINT_new(h);
    const EC_POINT *G = EC_GROUP_get0_generator(g);
    BIGNUM *k = num("FF"), *k2 = num("10001");
    const EC_POINT *pts[2];
    const BIGNUM *ks[2];

    check(EC_POINT_new(NULL) == NULL, "EC_POINT_new(NULL)");
    errors();
    EC_POINT_free(NULL);
    EC_POINT_clear_free(NULL);
    Q = EC_POINT_dup(G, g);
    check(Q != NULL && EC_POINT_cmp(g, Q, G, NULL) == 0, "EC_POINT_dup");
    check(EC_POINT_copy(H, G) == 0, "EC_POINT_copy across groups");
    errors();
    check(EC_POINT_cmp(g, H, G, NULL) == -1, "EC_POINT_cmp across groups");
    errors();
    check(EC_POINT_add(g, P, G, H, NULL) == 0, "EC_POINT_add across groups");
    errors();
    check(EC_POINT_mul(g, P, k, H, k, NULL) == 0, "EC_POINT_mul across groups");
    errors();

    pts[0] = G;
    pts[1] = Q;
    ks[0] = k;
    ks[1] = k2;
    check(EC_POINTs_mul(g, P, k2, 2, pts, ks, NULL) == 1, "EC_POINTs_mul: three terms");
    affine("(1+0x10001)*... ", g, P);
    check(EC_POINTs_mul(g, P, NULL, 0, NULL, NULL, NULL) == 1 && EC_POINT_is_at_infinity(g, P),
          "EC_POINTs_mul: nothing");
    printf("  method_of: %s\n",
           EC_POINT_method_of(P) == EC_GROUP_method_of(g) ? "the group's" : "another");
    check(EC_GROUP_have_precompute_mult(g) == 0, "no precomputation");
    check(EC_GROUP_precompute_mult(g, NULL) == 1 && EC_GROUP_have_precompute_mult(g) == 1,
          "EC_GROUP_precompute_mult");
    check(EC_POINT_mul(g, P, k2, NULL, NULL, NULL) == 1, "kG after precomputing");
    affine("0x10001 G", g, P);
    check(EC_POINTs_mul(g, P, k2, 2, pts, ks, NULL) == 1, "EC_POINTs_mul with the table");
    affine("the same three terms", g, P);
    check(EC_POINT_mul(g, P, k2, Q, k, NULL) == 1, "kG + k'Q with the table");
    affine("kG + k'Q", g, P);
    {
        static const int nids[] = { NID_X9_62_prime256v1, NID_sect163k1, NID_secp224r1 };
        size_t i;

        for (i = 0; i < 3; i++) {
            EC_GROUP *o = EC_GROUP_new_by_curve_name(nids[i]);
            int before = EC_GROUP_have_precompute_mult(o);
            int ret = EC_GROUP_precompute_mult(o, NULL);

            check(1, "precompute_mult on another method");
            printf("  %s: have %d, precompute %d, have %d\n", OBJ_nid2sn(nids[i]), before, ret,
                   EC_GROUP_have_precompute_mult(o));
            EC_GROUP_free(o);
        }
    }

    BN_free(k);
    BN_free(k2);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(H);
    EC_GROUP_free(g);
    EC_GROUP_free(h);
}

/* The field-specific and older names: the curve and coordinates by field type, the binary
 * fields' bases, the named-curve check, the Montgomery data, and clear_free. */
static void test_field_specific(void)
{
    EC_GROUP *gp = EC_GROUP_new_by_curve_name_ex(NULL, NULL, NID_secp384r1);
    EC_GROUP *g2 = EC_GROUP_new_by_curve_name(NID_sect163k1);
    EC_GROUP *g3 = EC_GROUP_new_by_curve_name(NID_sect113r1);
    EC_GROUP *e = NULL, *e2 = NULL;
    BIGNUM *p = BN_new(), *a = BN_new(), *b = BN_new(), *x = BN_new(), *y = BN_new();
    EC_POINT *P = NULL, *Q = NULL;
    unsigned int k = 0, k1 = 0, k2 = 0, k3 = 0;
    int nids[] = { NID_X9_62_prime256v1, NID_secp224r1, NID_secp384r1, NID_secp521r1,
                   NID_secp256k1, NID_brainpoolP256r1, NID_sm2, NID_sect163k1 };
    size_t i;

    printf("# field-specific functions\n");
    check(gp != NULL && g2 != NULL && g3 != NULL, "named groups (one by _ex)");
    printf("  field types: %d %d\n", EC_GROUP_get_field_type(gp), EC_GROUP_get_field_type(g2));
    bn("P-384 field", EC_GROUP_get0_field(gp));
    bn("sect163k1 field", EC_GROUP_get0_field(g2));

    check(EC_GROUP_get_curve_GFp(gp, p, a, b, NULL) == 1, "EC_GROUP_get_curve_GFp");
    bn("a", a);
    e = EC_GROUP_new_curve_GFp(p, a, b, NULL);
    check(e != NULL, "an explicit copy of P-384's curve");
    BN_add_word(b, 1);
    check(EC_GROUP_set_curve_GFp(e, p, a, b, NULL) == 1, "EC_GROUP_set_curve_GFp");
    check(EC_GROUP_get_curve_GFp(e, NULL, NULL, x, NULL) == 1, "its b, alone");
    bn("b", x);
    EC_GROUP_free(e);
    e = NULL;

    check(EC_GROUP_get_curve_GF2m(g2, p, a, b, NULL) == 1, "EC_GROUP_get_curve_GF2m");
    bn("polynomial", p);
    bn("b", b);
    e2 = EC_GROUP_new_curve_GF2m(p, a, b, NULL);
    check(e2 != NULL, "EC_GROUP_new_curve_GF2m");
    check(EC_GROUP_set_curve_GF2m(e2, p, a, b, NULL) == 1, "EC_GROUP_set_curve_GF2m");
    printf("  basis types: %d %d %d\n", EC_GROUP_get_basis_type(gp),
           EC_GROUP_get_basis_type(g2), EC_GROUP_get_basis_type(g3));
    printf("  sect163k1 pentanomial: %d (%u %u %u)\n",
           EC_GROUP_get_pentanomial_basis(g2, &k1, &k2, &k3), k1, k2, k3);
    errors();
    printf("  sect163k1 trinomial: %d\n", EC_GROUP_get_trinomial_basis(g2, &k));
    errors();
    printf("  sect113r1 trinomial: %d (%u)\n", EC_GROUP_get_trinomial_basis(g3, &k), k);
    errors();
    printf("  sect113r1 pentanomial: %d\n", EC_GROUP_get_pentanomial_basis(g3, &k1, &k2, &k3));
    errors();
    printf("  prime trinomial: %d, pentanomial %d\n", EC_GROUP_get_trinomial_basis(gp, &k),
           EC_GROUP_get_pentanomial_basis(gp, &k1, &k2, &k3));
    errors();

    /* Coordinates by field type. */
    P = EC_POINT_new(gp);
    check(EC_POINT_get_affine_coordinates_GFp(gp, EC_GROUP_get0_generator(gp), x, y, NULL) == 1,
          "EC_POINT_get_affine_coordinates_GFp");
    check(EC_POINT_set_affine_coordinates_GFp(gp, P, x, y, NULL) == 1,
          "EC_POINT_set_affine_coordinates_GFp");
    check(EC_POINT_cmp(gp, P, EC_GROUP_get0_generator(gp), NULL) == 0, "the generator again");
    check(EC_POINT_set_compressed_coordinates_GFp(gp, P, x, !BN_is_odd(y), NULL) == 1,
          "EC_POINT_set_compressed_coordinates_GFp, the other y");
    affine("negated generator", gp, P);
    BN_add_word(y, 1);
    check(EC_POINT_set_affine_coordinates_GFp(gp, P, x, y, NULL) == 0, "off the curve");
    errors();
    EC_POINT_free(P);

    Q = EC_POINT_new(g2);
    check(EC_POINT_get_affine_coordinates_GF2m(g2, EC_GROUP_get0_generator(g2), x, y, NULL) == 1,
          "EC_POINT_get_affine_coordinates_GF2m");
    check(EC_POINT_set_affine_coordinates_GF2m(g2, Q, x, y, NULL) == 1,
          "EC_POINT_set_affine_coordinates_GF2m");
    check(EC_POINT_cmp(g2, Q, EC_GROUP_get0_generator(g2), NULL) == 0, "the generator again");
    check(EC_POINT_set_compressed_coordinates_GF2m(g2, Q, x, 0, NULL) == 1,
          "EC_POINT_set_compressed_coordinates_GF2m");
    affine("y bit 0", g2, Q);
    check(EC_POINT_set_compressed_coordinates_GF2m(g2, Q, x, 1, NULL) == 1, "y bit 1");
    affine("y bit 1", g2, Q);
    EC_POINT_free(Q);

    /* The named-curve check, of named groups and of explicit copies. */
    for (i = 0; i < sizeof(nids) / sizeof(nids[0]); i++) {
        EC_GROUP *n = EC_GROUP_new_by_curve_name(nids[i]);
        EC_GROUP *c = NULL;
        BIGNUM *o = BN_new(), *h = BN_new();
        int prime = EC_GROUP_get_field_type(n) == NID_X9_62_prime_field;

        EC_GROUP_get_curve(n, p, a, b, NULL);
        c = prime ? EC_GROUP_new_curve_GFp(p, a, b, NULL) : EC_GROUP_new_curve_GF2m(p, a, b, NULL);
        EC_GROUP_get_order(n, o, NULL);
        EC_GROUP_get_cofactor(n, h, NULL);
        /* The named group's generator, which a group of another method refuses (and is
         * left with a generator at infinity). */
        EC_GROUP_set_generator(c, EC_GROUP_get0_generator(n), o, h);
        printf("  %s: named %d %d, explicit %d %d, mont data %s\n", OBJ_nid2sn(nids[i]),
               EC_GROUP_check_named_curve(n, 0, NULL), EC_GROUP_check_named_curve(n, 1, NULL),
               EC_GROUP_check_named_curve(c, 0, NULL), EC_GROUP_check_named_curve(c, 1, NULL),
               EC_GROUP_get_mont_data(n) == NULL ? "none" : "some");
        errors();
        /* The generator by its coordinates. */
        {
            EC_POINT *G = EC_POINT_new(c);

            EC_POINT_get_affine_coordinates(n, EC_GROUP_get0_generator(n), x, y, NULL);
            EC_POINT_set_affine_coordinates(c, G, x, y, NULL);
            printf("    copied: %d, named %d %d\n", EC_GROUP_set_generator(c, G, o, h),
                   EC_GROUP_check_named_curve(c, 0, NULL), EC_GROUP_check_named_curve(c, 1, NULL));
            errors();
            EC_POINT_free(G);
        }
        BN_free(o);
        BN_free(h);
        EC_GROUP_free(c);
        EC_GROUP_clear_free(n);
    }
    EC_GROUP_clear_free(NULL);
    check(1, "EC_GROUP_clear_free, of NULL too");

    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(y);
    EC_GROUP_free(e2);
    EC_GROUP_free(gp);
    EC_GROUP_free(g2);
    EC_GROUP_free(g3);
}

int main(void)
{
    test_builtin();
    test_named();
    test_methods();
    test_explicit_gfp();
    test_encodings(NID_X9_62_prime256v1);
    test_encodings(NID_secp224r1);
    test_encodings(NID_brainpoolP256r1);
    test_encodings(NID_sect163k1);
    test_encodings(NID_X9_62_c2pnb176v1);
    test_points_misc();
    test_field_specific();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
