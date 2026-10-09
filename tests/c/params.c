/*
 * Conformance test for parameters (OSSL_PARAM(3), OSSL_PARAM_int(3), OSSL_PARAM_dup(3),
 * OSSL_PARAM_BLD(3)), in TAP format: every typed setter into integer, unsigned, and real
 * parameters of many sizes (and NULL data, for the size query), every getter from data of
 * those types and sizes, the string and pointer forms, the modified flags, locating, and
 * duplicating, merging, and building arrays (with data in the secure heap). Each result, the
 * return_size, the stored octets, and the errors are printed, so the libraries are compared
 * byte for byte.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 *
 * Cases where OpenSSL reads or writes out of bounds (getting from an empty signed integer,
 * setting a uint64_t into a real with NULL data, ...) are left out; docs/DEVIATIONS.md lists
 * them.
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <openssl/params.h>

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

    printf(" errors:");
    while ((code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        if ((flags & ERR_TXT_STRING) != 0 && data[0] != '\0')
            printf("[%s]", data);
    }
    printf("\n");
}

static void hex(const void *p, size_t n)
{
    const unsigned char *c = p;
    size_t i;

    for (i = 0; i < n; i++)
        printf("%02x", c[i]);
}

static void show_size(size_t n)
{
    if (n == OSSL_PARAM_UNMODIFIED)
        printf("unmodified");
    else
        printf("%zu", n);
}

/* Prints a parameter: key, type, sizes, and the data (the pointer's target for the _ptr types). */
static void show(const OSSL_PARAM *p)
{
    printf("#   %s type %u size %zu return ", p->key == NULL ? "(end)" : p->key, p->data_type, p->data_size);
    show_size(p->return_size);
    if (p->data == NULL) {
        printf(" data NULL\n");
        return;
    }
    printf(" data ");
    if (p->data_type == OSSL_PARAM_UTF8_PTR || p->data_type == OSSL_PARAM_OCTET_PTR) {
        const void *q = *(const void **)p->data;

        printf("-> ");
        if (q == NULL)
            printf("NULL");
        else
            hex(q, p->data_size);
    } else {
        hex(p->data, p->data_size);
    }
    printf("\n");
}

static const unsigned int types[] = { OSSL_PARAM_INTEGER, OSSL_PARAM_UNSIGNED_INTEGER, OSSL_PARAM_REAL,
                                      OSSL_PARAM_OCTET_STRING };
static const size_t sizes[] = { 1, 2, 3, 4, 5, 8, 9, 16 };
#define N(a) (sizeof(a) / sizeof((a)[0]))

/* The parameter each setter writes to, its data filled with 0xaa first. */
static unsigned char buf[32];
static OSSL_PARAM target(unsigned int type, size_t size, int null)
{
    OSSL_PARAM p = { "t", 0, NULL, 0, 0 };

    memset(buf, 0xaa, sizeof(buf));
    p.data_type = type;
    p.data = null ? NULL : buf;
    p.data_size = size;
    p.return_size = 12345;
    return p;
}

static void outcome(const char *call, unsigned int type, size_t size, int null, int r, const OSSL_PARAM *p)
{
    printf("# %s type %u size %zu%s: %d return ", call, type, size, null ? " NULL" : "", r);
    show_size(p->return_size);
    if (!null) {
        printf(" data ");
        hex(buf, size);
    }
    errors();
}

/* Runs one setter call over every target type and size, and with NULL data. */
#define SET_ALL(fn, value, label)                                                         \
    do {                                                                                  \
        size_t t, s;                                                                      \
        OSSL_PARAM p;                                                                     \
        int r;                                                                            \
        for (t = 0; t < N(types); t++) {                                                  \
            for (s = 0; s < N(sizes); s++) {                                              \
                p = target(types[t], sizes[s], 0);                                        \
                r = fn(&p, value);                                                        \
                outcome(#fn "(" label ")", types[t], sizes[s], 0, r, &p);                 \
            }                                                                             \
            p = target(types[t], 8, 1);                                                   \
            r = fn(&p, value);                                                            \
            outcome(#fn "(" label ")", types[t], 8, 1, r, &p);                            \
            p = target(types[t], 4, 1);                                                   \
            r = fn(&p, value);                                                            \
            outcome(#fn "(" label ")", types[t], 4, 1, r, &p);                            \
        }                                                                                 \
    } while (0)

static void setters(void)
{
    static const int32_t i32[] = { 0, 1, -1, 127, 128, -128, -129, 255, 256, 32767, 32768, -32768, -32769,
                                   INT32_MAX, INT32_MIN };
    static const uint32_t u32[] = { 0, 1, 255, 256, 65535, 65536, 0x7fffffff, 0x80000000u, UINT32_MAX };
    static const int64_t i64[] = { 0, -1, 1, INT32_MAX, (int64_t)INT32_MAX + 1, INT32_MIN, (int64_t)INT32_MIN - 1,
                                   UINT32_MAX, (int64_t)UINT32_MAX + 1, (int64_t)1 << 53, ((int64_t)1 << 53) + 1,
                                   -((int64_t)1 << 53), -((int64_t)1 << 53) - 1, INT64_MAX, INT64_MIN };
    static const uint64_t u64[] = { 0, 1, UINT32_MAX, (uint64_t)UINT32_MAX + 1, ((uint64_t)1 << 53) - 1,
                                    (uint64_t)1 << 53, INT64_MAX, (uint64_t)1 << 63, UINT64_MAX };
    static const double d[] = { 0.0, -0.0, 1.0, -1.0, 0.5, -0.5, 2147483647.0, 2147483648.0, -2147483648.0,
                                -2147483649.0, 4294967295.0, 4294967296.0, 9007199254740992.0,
                                4611686018427387904.0, -4611686018427387904.0, 1e300, -1e300 };
    char label[64];
    size_t i;
    OSSL_PARAM p;
    int r;

    for (i = 0; i < N(i32); i++) {
        snprintf(label, sizeof(label), "%d", (int)i32[i]);
        SET_ALL(OSSL_PARAM_set_int32, i32[i], "");
        SET_ALL(OSSL_PARAM_set_int, (int)i32[i], "");
        printf("# (values above: %s)\n", label);
    }
    for (i = 0; i < N(u32); i++) {
        SET_ALL(OSSL_PARAM_set_uint32, u32[i], "");
        SET_ALL(OSSL_PARAM_set_uint, (unsigned int)u32[i], "");
        printf("# (values above: %u)\n", (unsigned int)u32[i]);
    }
    for (i = 0; i < N(i64); i++) {
        SET_ALL(OSSL_PARAM_set_int64, i64[i], "");
        SET_ALL(OSSL_PARAM_set_long, (long)i64[i], "");
        SET_ALL(OSSL_PARAM_set_time_t, (time_t)i64[i], "");
        printf("# (values above: %lld)\n", (long long)i64[i]);
    }
    for (i = 0; i < N(u64); i++) {
        size_t t, s;

        /* Not into a real with NULL data, where OpenSSL writes through the NULL. */
        for (t = 0; t < N(types); t++) {
            for (s = 0; s < N(sizes); s++) {
                p = target(types[t], sizes[s], 0);
                r = OSSL_PARAM_set_uint64(&p, u64[i]);
                outcome("OSSL_PARAM_set_uint64", types[t], sizes[s], 0, r, &p);
                p = target(types[t], sizes[s], 0);
                r = OSSL_PARAM_set_ulong(&p, (unsigned long)u64[i]);
                outcome("OSSL_PARAM_set_ulong", types[t], sizes[s], 0, r, &p);
                p = target(types[t], sizes[s], 0);
                r = OSSL_PARAM_set_size_t(&p, (size_t)u64[i]);
                outcome("OSSL_PARAM_set_size_t", types[t], sizes[s], 0, r, &p);
            }
            if (types[t] == OSSL_PARAM_REAL)
                continue;
            p = target(types[t], 8, 1);
            r = OSSL_PARAM_set_uint64(&p, u64[i]);
            outcome("OSSL_PARAM_set_uint64", types[t], 8, 1, r, &p);
        }
        p = target(OSSL_PARAM_REAL, 4, 1);
        r = OSSL_PARAM_set_uint64(&p, u64[i]);
        outcome("OSSL_PARAM_set_uint64", OSSL_PARAM_REAL, 4, 1, r, &p);
        printf("# (values above: %llu)\n", (unsigned long long)u64[i]);
    }
    for (i = 0; i < N(d); i++) {
        SET_ALL(OSSL_PARAM_set_double, d[i], "");
        printf("# (values above: %g)\n", d[i]);
    }
    SET_ALL(OSSL_PARAM_set_double, NAN, "nan");
    SET_ALL(OSSL_PARAM_set_double, INFINITY, "inf");

    check(OSSL_PARAM_set_int(NULL, 1) == 0 && OSSL_PARAM_set_uint64(NULL, 1) == 0
              && OSSL_PARAM_set_double(NULL, 1) == 0,
          "setters fail for a NULL parameter");
    errors();
}

/* Writes `v` as a native integer of `size` octets, sign-extended or truncated. */
static void native(unsigned char *out, size_t size, int64_t v)
{
    const uint16_t one = 1;
    int little = *(const unsigned char *)&one == 1;
    size_t i;

    for (i = 0; i < size; i++) {
        unsigned char b = i < 8 ? (unsigned char)((uint64_t)v >> (8 * i)) : (v < 0 ? 0xff : 0);

        out[little ? i : size - 1 - i] = b;
    }
}

static void getters(void)
{
    static const int64_t values[] = { 0, 1, -1, 127, 128, -128, 255, 32767, -32769, INT32_MAX,
                                      (int64_t)INT32_MAX + 1, INT32_MIN, UINT32_MAX, (int64_t)1 << 53,
                                      ((int64_t)1 << 53) + 1, INT64_MAX, INT64_MIN };
    static const double reals[] = { 0.0, 1.0, -1.0, 0.5, 2147483647.0, 2147483648.0, -2147483648.0,
                                    -2147483649.0, 4294967295.0, 4294967296.0, 9007199254740993.0,
                                    9223372036854775808.0, -9223372036854775808.0,
                                    18446744073709551616.0, 1e300 };
    unsigned char data[16];
    size_t t, s, i;

    for (t = 0; t < N(types); t++) {
        for (s = 0; s < N(sizes); s++) {
            for (i = 0; i < N(values); i++) {
                OSSL_PARAM p = { "g", 0, data, 0, 0 };
                int32_t a;
                uint32_t b;
                int64_t c;
                uint64_t e;
                double f;
                int ia;
                unsigned int ib;
                long lc;
                unsigned long le;
                size_t z;
                time_t tt;
                int r;

                if (types[t] == OSSL_PARAM_REAL && sizes[s] == 8)
                    continue;
                p.data_type = types[t];
                p.data_size = sizes[s];
                native(data, sizes[s], values[i]);
                printf("# get type %u size %zu from %lld:\n", types[t], sizes[s], (long long)values[i]);
                r = OSSL_PARAM_get_int32(&p, &a);
                printf("#  int32 %d %d", r, r ? a : 0);
                errors();
                r = OSSL_PARAM_get_uint32(&p, &b);
                printf("#  uint32 %d %u", r, r ? b : 0);
                errors();
                r = OSSL_PARAM_get_int64(&p, &c);
                printf("#  int64 %d %lld", r, r ? (long long)c : 0);
                errors();
                r = OSSL_PARAM_get_uint64(&p, &e);
                printf("#  uint64 %d %llu", r, r ? (unsigned long long)e : 0);
                errors();
                r = OSSL_PARAM_get_double(&p, &f);
                printf("#  double %d %.17g", r, r ? f : 0);
                errors();
                r = OSSL_PARAM_get_int(&p, &ia) + 2 * OSSL_PARAM_get_uint(&p, &ib) + 4 * OSSL_PARAM_get_long(&p, &lc)
                    + 8 * OSSL_PARAM_get_ulong(&p, &le) + 16 * OSSL_PARAM_get_size_t(&p, &z)
                    + 32 * OSSL_PARAM_get_time_t(&p, &tt);
                printf("#  others %d", r);
                errors();
            }
        }
    }
    for (i = 0; i < N(reals); i++) {
        OSSL_PARAM p = OSSL_PARAM_construct_double("real", (double *)&reals[i]);
        int32_t a;
        uint32_t b;
        int64_t c;
        uint64_t e;
        double f;
        int r;

        printf("# get real %.17g:\n", reals[i]);
        r = OSSL_PARAM_get_int32(&p, &a);
        printf("#  int32 %d %d", r, r ? a : 0);
        errors();
        r = OSSL_PARAM_get_uint32(&p, &b);
        printf("#  uint32 %d %u", r, r ? b : 0);
        errors();
        r = OSSL_PARAM_get_int64(&p, &c);
        printf("#  int64 %d %lld", r, r ? (long long)c : 0);
        errors();
        r = OSSL_PARAM_get_uint64(&p, &e);
        printf("#  uint64 %d %llu", r, r ? (unsigned long long)e : 0);
        errors();
        r = OSSL_PARAM_get_double(&p, &f);
        printf("#  double %d %.17g", r, r ? f : 0);
        errors();
    }
    {
        OSSL_PARAM p = { "n", OSSL_PARAM_INTEGER, NULL, 4, 0 };
        int32_t a;
        double f;

        check(OSSL_PARAM_get_int32(&p, &a) == 0 && OSSL_PARAM_get_double(&p, &f) == 0
                  && OSSL_PARAM_get_int32(NULL, &a) == 0 && OSSL_PARAM_get_int32(&p, NULL) == 0,
              "getters fail for NULL data, parameter, or result");
        errors();
    }
}

static void constructs(void)
{
    int i = 0;
    unsigned int u = 0;
    long l = 0;
    unsigned long ul = 0;
    int32_t i32 = 0;
    uint32_t u32 = 0;
    int64_t i64 = 0;
    uint64_t u64 = 0;
    size_t z = 0;
    time_t t = 0;
    double d = 0;
    unsigned char bn[5] = { 0 };
    char str[] = "hello";
    unsigned char oct[3] = { 1, 2, 3 };
    char *sp = str;
    void *op = oct;
    OSSL_PARAM params[20];
    OSSL_PARAM *p;
    size_t n = 0, k;

    params[n++] = OSSL_PARAM_construct_int("int", &i);
    params[n++] = OSSL_PARAM_construct_uint("uint", &u);
    params[n++] = OSSL_PARAM_construct_long("long", &l);
    params[n++] = OSSL_PARAM_construct_ulong("ulong", &ul);
    params[n++] = OSSL_PARAM_construct_int32("int32", &i32);
    params[n++] = OSSL_PARAM_construct_uint32("uint32", &u32);
    params[n++] = OSSL_PARAM_construct_int64("int64", &i64);
    params[n++] = OSSL_PARAM_construct_uint64("uint64", &u64);
    params[n++] = OSSL_PARAM_construct_size_t("size_t", &z);
    params[n++] = OSSL_PARAM_construct_time_t("time_t", &t);
    params[n++] = OSSL_PARAM_construct_double("double", &d);
    params[n++] = OSSL_PARAM_construct_BN("bn", bn, sizeof(bn));
    params[n++] = OSSL_PARAM_construct_utf8_string("utf8", str, 0);
    params[n++] = OSSL_PARAM_construct_utf8_string("utf8sized", str, 3);
    params[n++] = OSSL_PARAM_construct_utf8_string("utf8null", NULL, 0);
    params[n++] = OSSL_PARAM_construct_octet_string("octet", oct, sizeof(oct));
    params[n++] = OSSL_PARAM_construct_utf8_ptr("utf8ptr", &sp, 5);
    params[n++] = OSSL_PARAM_construct_octet_ptr("octetptr", &op, sizeof(oct));
    params[n++] = OSSL_PARAM_construct_end();
    for (k = 0; k < n; k++)
        show(&params[k]);
    check(params[n - 1].key == NULL && params[n - 1].data == NULL && params[n - 1].return_size == 0,
          "the end parameter is all zero");
    check(params[0].data == &i && params[12].data == str && params[16].data == &sp, "data pointers are kept");

    check(OSSL_PARAM_modified(&params[0]) == 0 && OSSL_PARAM_modified(NULL) == 0, "constructed unmodified");
    OSSL_PARAM_set_int(&params[0], 7);
    OSSL_PARAM_set_uint64(&params[7], 7);
    check(OSSL_PARAM_modified(&params[0]) == 1 && OSSL_PARAM_modified(&params[7]) == 1 && i == 7 && u64 == 7,
          "a set marks it modified");
    OSSL_PARAM_set_all_unmodified(params);
    OSSL_PARAM_set_all_unmodified(NULL);
    check(OSSL_PARAM_modified(&params[0]) == 0 && OSSL_PARAM_modified(&params[7]) == 0
              && params[n - 1].return_size == 0,
          "set_all_unmodified stops at the end");

    p = OSSL_PARAM_locate(params, "double");
    check(p == &params[10], "locate finds a key");
    check(OSSL_PARAM_locate(params, "Double") == NULL && OSSL_PARAM_locate(params, "nope") == NULL
              && OSSL_PARAM_locate(NULL, "int") == NULL && OSSL_PARAM_locate(params, NULL) == NULL,
          "locate matches exactly, and NULL finds nothing");
    check(OSSL_PARAM_locate_const(params, "octetptr") == &params[17], "locate_const");
    errors();
}

static void strings(void)
{
    char text[] = "hello world";
    char small[6];
    char *got = NULL;
    void *ogot = NULL;
    const char *cp = NULL;
    const void *vp = NULL;
    size_t used = 0;
    unsigned char octets[4] = { 0, 1, 0, 2 };
    char nulled[] = "ab\0cd";
    OSSL_PARAM u = OSSL_PARAM_construct_utf8_string("u", text, 0);
    OSSL_PARAM o = OSSL_PARAM_construct_octet_string("o", octets, sizeof(octets));
    OSSL_PARAM e = OSSL_PARAM_construct_octet_string("e", octets, 0);
    OSSL_PARAM n = OSSL_PARAM_construct_utf8_string("n", nulled, 5);
    OSSL_PARAM w;
    char out[8];
    unsigned char oout[8];
    int r;

    r = OSSL_PARAM_get_utf8_string(&u, &got, 0);
    check(r == 1 && got != NULL && strcmp(got, "hello world") == 0, "get_utf8_string allocates");
    OPENSSL_free(got);
    got = small;
    r = OSSL_PARAM_get_utf8_string(&u, &got, sizeof(small));
    printf("# into 6: %d", r);
    errors();
    got = out;
    memset(out, 'x', sizeof(out));
    u.data_size = 5;
    r = OSSL_PARAM_get_utf8_string(&u, &got, 5);
    printf("# 5 into 5: %d ", r);
    hex(out, sizeof(out));
    errors();
    u.data_size = 11;
    memset(out, 'x', sizeof(out));
    r = OSSL_PARAM_get_utf8_string(&n, &got, 5);
    printf("# embedded NUL, 5 into 5: %d ", r);
    hex(out, sizeof(out));
    errors();
    r = OSSL_PARAM_get_utf8_string(&o, &got, sizeof(out));
    printf("# octets as utf8: %d", r);
    errors();
    r = OSSL_PARAM_get_utf8_string(&u, NULL, 0);
    printf("# NULL val: %d", r);
    errors();

    r = OSSL_PARAM_get_octet_string(&o, &ogot, 0, &used);
    check(r == 1 && used == 4 && memcmp(ogot, octets, 4) == 0, "get_octet_string allocates");
    OPENSSL_free(ogot);
    ogot = NULL;
    r = OSSL_PARAM_get_octet_string(&e, &ogot, 0, &used);
    check(r == 1 && used == 0 && ogot != NULL, "an empty octet string allocates one octet");
    OPENSSL_free(ogot);
    used = 99;
    r = OSSL_PARAM_get_octet_string(&o, NULL, 0, &used);
    check(r == 1 && used == 4, "a NULL val reports the length");
    ogot = oout;
    r = OSSL_PARAM_get_octet_string(&o, &ogot, 3, &used);
    printf("# 4 into 3: %d used %zu", r, used);
    errors();
    r = OSSL_PARAM_get_octet_string(&o, NULL, 0, NULL);
    printf("# NULL val and used_len: %d", r);
    errors();
    w = o;
    w.data = NULL;
    used = 99;
    r = OSSL_PARAM_get_octet_string(&w, &ogot, 8, &used);
    printf("# NULL data: %d used %zu", r, used);
    errors();

    w = OSSL_PARAM_construct_utf8_string("w", out, sizeof(out));
    memset(out, 'x', sizeof(out));
    r = OSSL_PARAM_set_utf8_string(&w, "abc");
    printf("# set_utf8_string abc: %d return %zu ", r, w.return_size);
    hex(out, sizeof(out));
    errors();
    memset(out, 'x', sizeof(out));
    r = OSSL_PARAM_set_utf8_string(&w, "abcdefgh");
    printf("# set_utf8_string 8 into 8: %d return %zu ", r, w.return_size);
    hex(out, sizeof(out));
    errors();
    r = OSSL_PARAM_set_utf8_string(&w, "abcdefghi");
    printf("# set_utf8_string 9 into 8: %d return %zu", r, w.return_size);
    errors();
    w.data = NULL;
    r = OSSL_PARAM_set_utf8_string(&w, "sized");
    printf("# set_utf8_string NULL data: %d return %zu", r, w.return_size);
    errors();
    r = OSSL_PARAM_set_octet_string(&w, "x", 1);
    printf("# set_octet_string into utf8: %d return %zu", r, w.return_size);
    errors();
    r = OSSL_PARAM_set_utf8_string(&w, NULL) + OSSL_PARAM_set_utf8_string(NULL, "x");
    printf("# set_utf8_string NULLs: %d", r);
    errors();
    w = OSSL_PARAM_construct_octet_string("w", oout, sizeof(oout));
    memset(oout, 'x', sizeof(oout));
    r = OSSL_PARAM_set_octet_string(&w, octets, 4);
    printf("# set_octet_string: %d return %zu ", r, w.return_size);
    hex(oout, sizeof(oout));
    errors();
    r = OSSL_PARAM_set_octet_string(&w, NULL, 0);
    printf("# set_octet_string NULL: %d return %zu", r, w.return_size);
    errors();

    {
        char *sp = NULL;
        void *op = NULL;
        OSSL_PARAM up = OSSL_PARAM_construct_utf8_ptr("up", &sp, 0);
        OSSL_PARAM opp = OSSL_PARAM_construct_octet_ptr("op", &op, 0);

        r = OSSL_PARAM_set_utf8_ptr(&up, text);
        check(r == 1 && sp == text && up.return_size == 11, "set_utf8_ptr");
        r = OSSL_PARAM_set_utf8_ptr(&up, NULL);
        check(r == 1 && sp == NULL && up.return_size == 0, "set_utf8_ptr NULL");
        OSSL_PARAM_set_utf8_ptr(&up, text);
        r = OSSL_PARAM_get_utf8_ptr(&up, &cp);
        check(r == 1 && cp == text, "get_utf8_ptr");
        r = OSSL_PARAM_set_octet_ptr(&opp, octets, 3);
        check(r == 1 && op == octets && opp.return_size == 3, "set_octet_ptr");
        opp.data_size = 3;
        r = OSSL_PARAM_get_octet_ptr(&opp, &vp, &used);
        check(r == 1 && vp == octets && used == 3, "get_octet_ptr");
        r = OSSL_PARAM_get_utf8_ptr(&opp, &cp) + OSSL_PARAM_get_octet_ptr(&up, &vp, NULL)
            + OSSL_PARAM_set_utf8_ptr(&opp, "x") + OSSL_PARAM_set_octet_ptr(&up, "x", 1);
        printf("# mismatched pointer types: %d", r);
        errors();
        r = OSSL_PARAM_get_utf8_ptr(NULL, &cp) + OSSL_PARAM_get_utf8_ptr(&up, NULL)
            + OSSL_PARAM_set_utf8_ptr(NULL, "x") + OSSL_PARAM_set_octet_ptr(NULL, "x", 1);
        printf("# NULL pointer arguments: %d", r);
        errors();
        up.data = NULL;
        r = OSSL_PARAM_set_utf8_ptr(&up, text);
        printf("# set_utf8_ptr NULL data: %d return %zu", r, up.return_size);
        errors();

        up = OSSL_PARAM_construct_utf8_ptr("up", &sp, 0);
        r = OSSL_PARAM_get_utf8_string_ptr(&up, &cp);
        check(r == 1 && cp == text, "get_utf8_string_ptr from a pointer");
        r = OSSL_PARAM_get_utf8_string_ptr(&u, &cp);
        check(r == 1 && cp == text, "get_utf8_string_ptr from a string");
        r = OSSL_PARAM_get_utf8_string_ptr(&o, &cp);
        printf("# get_utf8_string_ptr from octets: %d", r);
        errors();
        opp = OSSL_PARAM_construct_octet_ptr("op", &op, 3);
        r = OSSL_PARAM_get_octet_string_ptr(&opp, &vp, &used);
        check(r == 1 && vp == octets && used == 3, "get_octet_string_ptr from a pointer");
        r = OSSL_PARAM_get_octet_string_ptr(&o, &vp, &used);
        check(r == 1 && vp == octets && used == 4, "get_octet_string_ptr from a string");
        r = OSSL_PARAM_get_octet_string_ptr(&u, &vp, &used) + OSSL_PARAM_get_octet_string_ptr(NULL, &vp, NULL)
            + OSSL_PARAM_get_utf8_string_ptr(&u, NULL);
        printf("# get_octet_string_ptr failures: %d", r);
        errors();
    }
}

static void show_array(const char *what, const OSSL_PARAM *p)
{
    printf("# %s:\n", what);
    for (; p->key != NULL; p++)
        show(p);
    printf("#   end type %u size %zu return %zu data %s\n", p->data_type, p->data_size, p->return_size,
           p->data == NULL ? "NULL" : "set");
}

static void dup_merge(void)
{
    int i = -5;
    double d = 2.5;
    char str[] = "text";
    unsigned char oct[5] = { 9, 8, 7, 6, 5 };
    char *sp = str;
    OSSL_PARAM src[8], *dup, *a, *b, *m;
    OSSL_PARAM one[] = { OSSL_PARAM_int("Beta", &i), OSSL_PARAM_double("alpha", &d),
                         OSSL_PARAM_utf8_string("Delta", str, 4), OSSL_PARAM_END };
    OSSL_PARAM two[] = { OSSL_PARAM_octet_string("gamma", oct, 5), OSSL_PARAM_int("beta", &i),
                         OSSL_PARAM_utf8_string("epsilon", str, 2), OSSL_PARAM_END };
    OSSL_PARAM empty[] = { OSSL_PARAM_END };

    src[0] = OSSL_PARAM_construct_int("i", &i);
    src[1] = OSSL_PARAM_construct_double("d", &d);
    src[2] = OSSL_PARAM_construct_utf8_string("s", str, 0);
    src[3] = OSSL_PARAM_construct_octet_string("o", oct, sizeof(oct));
    src[4] = OSSL_PARAM_construct_utf8_ptr("p", &sp, 4);
    src[5] = OSSL_PARAM_construct_octet_string("z", oct, 0);
    src[6] = OSSL_PARAM_construct_end();
    OSSL_PARAM_set_int(&src[0], -5);
    dup = OSSL_PARAM_dup(src);
    show_array("dup", dup);
    check(dup[0].key == src[0].key && dup[0].data != src[0].data && dup[2].data != str
              && ((char *)dup[2].data)[4] == '\0' && *(char **)dup[4].data == str,
          "dup copies data but not keys, and NUL-terminates strings");
    check(dup[0].return_size == src[0].return_size, "dup keeps return_size");
    check((char *)dup[1].data - (char *)dup[0].data == 8 && (char *)dup[2].data - (char *)dup[1].data == 8
              && (char *)dup[3].data - (char *)dup[2].data == 8 && (char *)dup[4].data - (char *)dup[3].data == 8
              && (char *)dup[5].data - (char *)dup[4].data == 8 && (char *)dup[0].data - (char *)dup == 7 * 40,
          "dup lays the data out after the array in 8-octet units");
    OSSL_PARAM_free(dup);
    check(OSSL_PARAM_dup(NULL) == NULL, "dup of NULL");
    errors();
    dup = OSSL_PARAM_dup(empty);
    show_array("dup of empty", dup);
    OSSL_PARAM_free(dup);
    OSSL_PARAM_free(NULL);

    m = OSSL_PARAM_merge(one, two);
    show_array("merge", m);
    check(m[1].data == two[1].data, "a key in both takes the second's");
    OSSL_PARAM_free(m);
    m = OSSL_PARAM_merge(one, NULL);
    show_array("merge with NULL", m);
    OSSL_PARAM_free(m);
    m = OSSL_PARAM_merge(NULL, two);
    show_array("merge NULL with", m);
    OSSL_PARAM_free(m);
    a = OSSL_PARAM_merge(NULL, NULL);
    b = OSSL_PARAM_merge(empty, empty);
    printf("# merge of nothing: %s %s", a == NULL ? "NULL" : "set", b == NULL ? "NULL" : "set");
    errors();
}

static void secure(void)
{
    int ok = CRYPTO_secure_malloc_init(4096, 32);
    unsigned char *s = OPENSSL_secure_malloc(16);
    unsigned char plain[3] = { 1, 2, 3 };
    OSSL_PARAM src[3], *dup, *built;
    OSSL_PARAM_BLD *bld;
    size_t used;

    printf("# secure heap: %d\n", ok != 0);
    memcpy(s, "secret-octets!!", 16);
    src[0] = OSSL_PARAM_construct_octet_string("s", s, 16);
    src[1] = OSSL_PARAM_construct_octet_string("p", plain, 3);
    src[2] = OSSL_PARAM_construct_end();
    dup = OSSL_PARAM_dup(src);
    check(CRYPTO_secure_allocated(dup[0].data) && !CRYPTO_secure_allocated(dup[1].data)
              && memcmp(dup[0].data, s, 16) == 0,
          "dup copies secure data into the secure heap");
    printf("# dup end: type %u size %zu secure %d\n", dup[2].data_type, dup[2].data_size,
           CRYPTO_secure_allocated(dup[2].data));
    used = CRYPTO_secure_used();
    OSSL_PARAM_free(dup);
    check(CRYPTO_secure_used() < used, "free releases the secure block");

    bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_octet_string(bld, "s", s, 16);
    OSSL_PARAM_BLD_push_utf8_string(bld, "u", (char *)s, 5);
    OSSL_PARAM_BLD_push_octet_string(bld, "p", plain, 3);
    built = OSSL_PARAM_BLD_to_param(bld);
    check(CRYPTO_secure_allocated(built[0].data) && CRYPTO_secure_allocated(built[1].data)
              && !CRYPTO_secure_allocated(built[2].data) && memcmp(built[1].data, "secre\0", 6) == 0,
          "the builder copies secure data into the secure heap");
    printf("# built end: type %u size %zu secure %d\n", built[3].data_type, built[3].data_size,
           CRYPTO_secure_allocated(built[3].data));
    OSSL_PARAM_free(built);
    OSSL_PARAM_BLD_free(bld);
    OPENSSL_secure_free(s);
    CRYPTO_secure_malloc_done();
    errors();
}

static void builder(void)
{
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *p, *q;
    char str[] = "a string";
    unsigned char oct[3] = { 0xde, 0xad, 0xbf };
    int r;

    r = OSSL_PARAM_BLD_push_int(bld, "int", -2) + OSSL_PARAM_BLD_push_uint(bld, "uint", 3)
        + OSSL_PARAM_BLD_push_long(bld, "long", -4) + OSSL_PARAM_BLD_push_ulong(bld, "ulong", 5)
        + OSSL_PARAM_BLD_push_int32(bld, "int32", -6) + OSSL_PARAM_BLD_push_uint32(bld, "uint32", 7)
        + OSSL_PARAM_BLD_push_int64(bld, "int64", -8) + OSSL_PARAM_BLD_push_uint64(bld, "uint64", 9)
        + OSSL_PARAM_BLD_push_size_t(bld, "size_t", 10) + OSSL_PARAM_BLD_push_time_t(bld, "time_t", 11)
        + OSSL_PARAM_BLD_push_double(bld, "double", 1.5)
        + OSSL_PARAM_BLD_push_utf8_string(bld, "utf8", str, 0)
        + OSSL_PARAM_BLD_push_utf8_string(bld, "utf8_3", str, 3)
        + OSSL_PARAM_BLD_push_utf8_ptr(bld, "utf8ptr", str, 0)
        + OSSL_PARAM_BLD_push_octet_string(bld, "octet", oct, 3)
        + OSSL_PARAM_BLD_push_octet_string(bld, "empty", NULL, 0)
        + OSSL_PARAM_BLD_push_octet_ptr(bld, "octetptr", oct, 2)
        + OSSL_PARAM_BLD_push_octet_ptr(bld, "nullptr", NULL, 0)
        + OSSL_PARAM_BLD_push_int(bld, "int", 99);
    check(r == 19, "every push succeeds");
    p = OSSL_PARAM_BLD_to_param(bld);
    show_array("built", p);
    check(*(char **)OSSL_PARAM_locate(p, "utf8ptr")->data == str && OSSL_PARAM_locate(p, "utf8")->data != str,
          "pointers are kept, strings copied");
    check((char *)p[0].data - (char *)p == 20 * 40 && (char *)p[1].data - (char *)p[0].data == 8
              && (char *)p[12].data - (char *)p[11].data == 16,
          "the array is laid out as dup lays it out");
    q = OSSL_PARAM_BLD_to_param(bld);
    show_array("reused", q);
    OSSL_PARAM_free(q);
    OSSL_PARAM_BLD_push_int(bld, "again", 1);
    q = OSSL_PARAM_BLD_to_param(bld);
    show_array("reused with one", q);
    OSSL_PARAM_free(q);
    OSSL_PARAM_free(p);

    r = OSSL_PARAM_BLD_push_int(NULL, "x", 1) + OSSL_PARAM_BLD_push_int(bld, NULL, 1)
        + OSSL_PARAM_BLD_push_utf8_string(bld, "x", NULL, 0) + OSSL_PARAM_BLD_push_utf8_ptr(bld, "x", NULL, 0)
        + OSSL_PARAM_BLD_push_octet_string(bld, "x", NULL, 1) + OSSL_PARAM_BLD_push_octet_ptr(bld, "x", NULL, 1)
        + OSSL_PARAM_BLD_push_double(NULL, "x", 1);
    printf("# NULL pushes: %d", r);
    errors();
    check(OSSL_PARAM_BLD_to_param(NULL) == NULL, "to_param of NULL");
    errors();
    OSSL_PARAM_BLD_free(bld);
    OSSL_PARAM_BLD_free(NULL);
}

int main(void)
{
    setters();
    getters();
    constructs();
    strings();
    dup_merge();
    secure();
    builder();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
