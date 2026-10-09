/*
 * Conformance test for times: ASN1_TIME_set(3), ASN1_TIME_set_string(3) and _X509,
 * ASN1_TIME_to_tm, ASN1_TIME_diff, ASN1_TIME_compare, ASN1_TIME_cmp_time_t,
 * ASN1_TIME_normalize, ASN1_TIME_print_ex, ASN1_TIME_to_generalizedtime, the UTCTIME and
 * GENERALIZEDTIME functions, and OPENSSL_gmtime, OPENSSL_gmtime_adj, and OPENSSL_gmtime_diff,
 * in TAP format. Parsed fields, normalized forms, printouts, and arithmetic are printed, so they
 * are compared too; nothing depends on the clock but relations to it.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static void show(const ASN1_TIME *t)
{
    printf("type=%d len=%d \"%.*s\" flags=%lx", t->type, t->length, t->length > 0 ? t->length : 0,
           t->data ? (const char *)t->data : "", t->flags);
}

static void print_both(const ASN1_TIME *t)
{
    BIO *mem = BIO_new(BIO_s_mem());
    char *out;
    long len;
    int a = ASN1_TIME_print(mem, t), b;

    BIO_puts(mem, " | ");
    b = ASN1_TIME_print_ex(mem, t, ASN1_DTFLGS_ISO8601);
    len = BIO_get_mem_data(mem, &out);
    printf(" print=%d/%d \"%.*s\"", a, b, (int)len, out);
    BIO_free(mem);
}

static void parse(const char *text)
{
    ASN1_TIME *t = ASN1_STRING_new(), *n;
    struct tm tm;
    int r = ASN1_TIME_set_string(t, text);

    printf("# \"%s\": set=%d check=%d utc=%d gen=%d", text, r, ASN1_TIME_check(t), ASN1_UTCTIME_check(t),
           ASN1_GENERALIZEDTIME_check(t));
    if (r) {
        memset(&tm, 0x55, sizeof(tm));
        printf(" to_tm=%d", ASN1_TIME_to_tm(t, &tm));
        printf(" %d-%d-%d %d:%d:%d wday=%d yday=%d dst=%d", tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min,
               tm.tm_sec, tm.tm_wday, tm.tm_yday, tm.tm_isdst);
        print_both(t);
        n = ASN1_STRING_dup(t);
        printf(" normalize=%d ", ASN1_TIME_normalize(n));
        show(n);
        ASN1_STRING_free(n);
    }
    printf("\n");
    ERR_clear_error();
    ASN1_STRING_free(t);
}

static void parsing(void)
{
    static const char *const texts[] = {
        "240229123456Z", "230229123456Z", "491231235959Z", "500101000000Z", "2402291234Z", "2402291234+0130",
        "240229123456-1200", "240229123456+1300", "240229123456+0060", "000101000000Z", "991231235959Z",
        "20240229123456Z", "20240229123456.5Z", "20240229123456.123456789Z", "20240229123456.Z",
        "202402291234+0000", "202402291234Z", "20240229123456+0500", "19491231235959Z", "20500101000000Z",
        "99991231235959Z", "99991231235959-0100", "00000101000000Z", "00000101000000+0100", "16000229000000Z",
        "17000229000000Z", "24022912345Z", "2402291234567Z", "240229123456z", "240229123456 Z", "24022912345aZ",
        "240231000000Z", "241301000000Z", "240229240000Z", "240229236000Z", "240229235960Z", "",
        "20240229123456ZZ",
    };
    size_t i;

    for (i = 0; i < sizeof(texts) / sizeof(texts[0]); i++)
        parse(texts[i]);
    check(1, "parsing");
}

static void typed_strings(void)
{
    ASN1_UTCTIME *u = ASN1_UTCTIME_new();
    ASN1_GENERALIZEDTIME *g = ASN1_GENERALIZEDTIME_new();

    check(ASN1_UTCTIME_set_string(u, "240229123456Z") == 1 && u->type == V_ASN1_UTCTIME
              && ASN1_UTCTIME_set_string(u, "20240229123456Z") == 0 && ASN1_UTCTIME_set_string(NULL, "240229123456Z") == 1
              && ASN1_GENERALIZEDTIME_set_string(g, "20240229123456.5Z") == 1 && g->type == V_ASN1_GENERALIZEDTIME
              && ASN1_GENERALIZEDTIME_set_string(g, "240229123456Z") == 0
              && ASN1_GENERALIZEDTIME_set_string(NULL, "20240229123456Z") == 1,
          "the typed set_string functions take only their own form");
    printf("# typed set_string: ");
    show(u);
    printf(" | ");
    show(g);
    printf("\n");
    ASN1_STRING_free(u);
    ASN1_STRING_free(g);
}

static void x509(void)
{
    static const char *const texts[] = {
        "240229123456Z", "20240229123456Z", "20500101000000Z", "19491231235959Z", "2402291234+0130",
        "20240229123456.5Z", "240229123456+0000",
    };
    size_t i;

    for (i = 0; i < sizeof(texts) / sizeof(texts[0]); i++) {
        ASN1_TIME *t = ASN1_STRING_new();
        int r = ASN1_TIME_set_string_X509(t, texts[i]);

        printf("# X509 \"%s\": %d %d ", texts[i], r, ASN1_TIME_set_string_X509(NULL, texts[i]));
        if (r)
            show(t);
        printf("\n");
        ASN1_STRING_free(t);
    }
    check(1, "ASN1_TIME_set_string_X509");
}

static void setting(void)
{
    static const time_t times[] = { 0, 1, 946684799, 1709210096, 2147483647, 2524607999, 2524608000,
                                    -631152001, -631152000, 253402300799LL, 253402300800LL, 67767976233532799LL };
    size_t i;

    for (i = 0; i < sizeof(times) / sizeof(times[0]); i++) {
        ASN1_TIME *a = ASN1_TIME_set(NULL, times[i]);
        ASN1_UTCTIME *u = ASN1_UTCTIME_set(NULL, times[i]);
        ASN1_GENERALIZEDTIME *g = ASN1_GENERALIZEDTIME_set(NULL, times[i]);
        ASN1_TIME *adj = ASN1_TIME_adj(NULL, times[i], 1, -3601);

        printf("# %lld: ", (long long)times[i]);
        if (a)
            show(a);
        printf(" | utc %s", u ? (const char *)u->data : "NULL");
        printf(" | gen %s", g ? (g->length >= 0 ? (const char *)g->data : "length -1") : "NULL");
        printf(" | adj %s", adj ? (const char *)adj->data : "NULL");
        if (a)
            printf(" | cmp %d %d %d", ASN1_TIME_cmp_time_t(a, times[i]), ASN1_TIME_cmp_time_t(a, times[i] + 1),
                   ASN1_TIME_cmp_time_t(a, times[i] - 1));
        if (u)
            printf(" | utc cmp %d %d", ASN1_UTCTIME_cmp_time_t(u, times[i]), ASN1_UTCTIME_cmp_time_t(u, times[i] - 60));
        printf("\n");
        ERR_clear_error();
        ASN1_STRING_free(a);
        ASN1_STRING_free(u);
        ASN1_STRING_free(g);
        ASN1_STRING_free(adj);
    }
    {
        ASN1_TIME *t = ASN1_STRING_new();

        check(ASN1_TIME_set(t, 0) == t && ASN1_UTCTIME_adj(t, 0, 365 * 100, 0) == NULL
                  && ASN1_GENERALIZEDTIME_adj(t, 0, 365 * 100, 0) == t,
              "setting into an existing string; a UTCTIME can't be 2069");
        show(t);
        printf("\n");
        ASN1_STRING_free(t);
    }
}

static void arithmetic(void)
{
    ASN1_TIME *a = ASN1_STRING_new(), *b = ASN1_STRING_new(), *g = NULL, *u = ASN1_UTCTIME_new();
    ASN1_GENERALIZEDTIME *out = NULL;
    int day = 7, sec = 7;
    struct tm t1, t2;
    time_t when = 1709210096;

    ASN1_TIME_set_string(a, "240229123456Z");
    ASN1_TIME_set_string(b, "20250101000000Z");
    check(ASN1_TIME_diff(&day, &sec, a, b) == 1, "ASN1_TIME_diff");
    printf("# diff a->b %d %d", day, sec);
    ASN1_TIME_diff(&day, &sec, b, a);
    printf(" b->a %d %d compare %d %d %d\n", day, sec, ASN1_TIME_compare(a, b), ASN1_TIME_compare(b, a),
           ASN1_TIME_compare(a, a));
    check(ASN1_TIME_diff(NULL, NULL, a, b) == 1 && ASN1_TIME_compare(a, NULL) == -1 && ASN1_TIME_compare(NULL, a) == 1
              && ASN1_TIME_cmp_time_t(NULL, 0) == 1,
          "NULL is now");
    ASN1_STRING_set(u, "garbage", 7);
    check(ASN1_TIME_compare(a, u) == -2 && ASN1_TIME_diff(&day, &sec, u, a) == 0
              && ASN1_TIME_cmp_time_t(u, 0) == -2 && ASN1_UTCTIME_cmp_time_t(b, 0) == -2,
          "invalid times");
    g = ASN1_TIME_to_generalizedtime(a, NULL);
    printf("# to_generalizedtime: ");
    show(g);
    printf("\n");
    out = ASN1_GENERALIZEDTIME_new();
    check(ASN1_TIME_to_generalizedtime(b, &out) == out, "into an existing string");
    printf("# into: ");
    show(out);
    printf("\n");
    check(ASN1_TIME_to_generalizedtime(u, NULL) == NULL, "not from an invalid time");

    memset(&t1, 0, sizeof(t1));
    check(OPENSSL_gmtime(&when, &t1) == &t1, "OPENSSL_gmtime");
    printf("# gmtime %d-%d-%d %d:%d:%d wday=%d yday=%d\n", t1.tm_year, t1.tm_mon, t1.tm_mday, t1.tm_hour, t1.tm_min,
           t1.tm_sec, t1.tm_wday, t1.tm_yday);
    t2 = t1;
    check(OPENSSL_gmtime_adj(&t2, 400, -90000) == 1, "OPENSSL_gmtime_adj");
    printf("# adj %d-%d-%d %d:%d:%d wday=%d yday=%d\n", t2.tm_year, t2.tm_mon, t2.tm_mday, t2.tm_hour, t2.tm_min,
           t2.tm_sec, t2.tm_wday, t2.tm_yday);
    check(OPENSSL_gmtime_diff(&day, &sec, &t1, &t2) == 1, "OPENSSL_gmtime_diff");
    printf("# gmtime_diff %d %d", day, sec);
    OPENSSL_gmtime_diff(&day, &sec, &t2, &t1);
    printf(" %d %d\n", day, sec);
    t2.tm_year = 8099;
    t2.tm_mon = 11;
    t2.tm_mday = 31;
    check(OPENSSL_gmtime_adj(&t2, 1, 0) == 0 && t2.tm_year == 8099, "past 9999 fails, leaving the time");
    t2.tm_year = -7000;
    check(OPENSSL_gmtime_diff(&day, &sec, &t1, &t2) == 0, "before Julian day 0 fails");

    printf("# printing:");
    print_both(u);
    printf(" utc=%d gen=%d", ASN1_UTCTIME_print(NULL, b), ASN1_GENERALIZEDTIME_print(NULL, a));
    printf("\n");
    {
        BIO *mem = BIO_new(BIO_s_mem());
        char *text;
        long len;

        check(ASN1_UTCTIME_print(mem, a) == 1 && ASN1_GENERALIZEDTIME_print(mem, b) == 1, "the typed printers");
        len = BIO_get_mem_data(mem, &text);
        printf("# typed: \"%.*s\"\n", (int)len, text);
        BIO_free(mem);
    }
    ERR_clear_error();
    ASN1_STRING_free(a);
    ASN1_STRING_free(b);
    ASN1_STRING_free(g);
    ASN1_STRING_free(u);
    ASN1_STRING_free(out);
}

int main(void)
{
    parsing();
    typed_strings();
    x509();
    setting();
    arithmetic();
    ERR_clear_error();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
