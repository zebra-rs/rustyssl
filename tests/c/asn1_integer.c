/*
 * Conformance test for INTEGER and ENUMERATED (ASN1_INTEGER_get_int64(3), ASN1_INTEGER_set(3),
 * ASN1_INTEGER_cmp, ASN1_ENUMERATED_get, i2a_ASN1_INTEGER, a2i_ASN1_INTEGER(3),
 * d2i_ASN1_UINTEGER), in TAP format. Values, stored octets, texts, and errors are printed as
 * comments, so they're compared too.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

static void errors(void)
{
    unsigned long code;

    printf(" errors:");
    while ((code = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
    printf("\n");
}

static void octets(const ASN1_STRING *s)
{
    int i;

    printf(" type=%d len=%d [", s->type, s->length);
    for (i = 0; i < s->length; i++)
        printf("%02x", s->data[i]);
    printf("]");
}

static void setting(void)
{
    static const int64_t values[] = { 0, 1, -1, 127, 128, -128, -129, 255, 256, 0x7fffffffLL, -0x80000000LL,
                                      INT64_MAX, INT64_MIN, INT64_MIN + 1 };
    ASN1_INTEGER *a = ASN1_INTEGER_new();
    ASN1_ENUMERATED *e = ASN1_ENUMERATED_new();
    size_t i;
    int ok = 1;

    for (i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        int64_t back = 0;

        ok = ok && ASN1_INTEGER_set_int64(a, values[i]) == 1 && ASN1_INTEGER_get_int64(&back, a) == 1
             && back == values[i];
        printf("# %lld:", (long long)values[i]);
        octets(a);
        printf(" get=%ld", ASN1_INTEGER_get(a));
        ok = ok && ASN1_ENUMERATED_set_int64(e, values[i]) == 1 && ASN1_ENUMERATED_get_int64(&back, e) == 1
             && back == values[i];
        printf(" enum get=%ld", ASN1_ENUMERATED_get(e));
        errors();
    }
    check(ok, "int64 values round-trip through INTEGER and ENUMERATED");
    check(ASN1_INTEGER_set_uint64(a, UINT64_MAX) == 1, "ASN1_INTEGER_set_uint64");
    {
        uint64_t u = 0;
        int64_t s = 0;

        printf("# uint64 max:");
        octets(a);
        printf(" uint64 %d %llu, int64 %d", ASN1_INTEGER_get_uint64(&u, a), (unsigned long long)u,
               ASN1_INTEGER_get_int64(&s, a));
        errors();
        ASN1_INTEGER_set(a, -5);
        printf("# -5 as uint64: %d", ASN1_INTEGER_get_uint64(&u, a));
        errors();
    }
    check(ASN1_INTEGER_set(a, LONG_MIN) == 1 && ASN1_INTEGER_get(a) == LONG_MIN && ASN1_ENUMERATED_set(e, 42) == 1
              && ASN1_ENUMERATED_get(e) == 42,
          "the long setters and getters");
    ASN1_INTEGER_free(a);
    ASN1_ENUMERATED_free(e);
}

static void raw(const char *what, int type, const char *bytes, int len)
{
    ASN1_STRING *s = ASN1_STRING_type_new(type);
    int64_t v = -7;
    uint64_t u = 7;
    int r;

    ASN1_STRING_set(s, bytes, len);
    s->type = type;
    r = type == V_ASN1_ENUMERATED || type == V_ASN1_NEG_ENUMERATED ? ASN1_ENUMERATED_get_int64(&v, s)
                                                                  : ASN1_INTEGER_get_int64(&v, s);
    printf("# %s: int64 %d %lld", what, r, (long long)v);
    errors();
    printf("#   uint64 %d %llu get %ld enum %ld", ASN1_INTEGER_get_uint64(&u, s), (unsigned long long)u,
           ASN1_INTEGER_get(s), ASN1_ENUMERATED_get(s));
    errors();
    ASN1_STRING_free(s);
}

static void getting(void)
{
    ASN1_STRING *s;
    int64_t v;

    raw("leading zeros", V_ASN1_INTEGER, "\x00\x00\x01\x02", 4);
    raw("eight octets", V_ASN1_INTEGER, "\x7f\xff\xff\xff\xff\xff\xff\xff", 8);
    raw("nine octets", V_ASN1_INTEGER, "\x00\x00\x00\x00\x00\x00\x00\x00\x01", 9);
    raw("top bit", V_ASN1_INTEGER, "\x80\x00\x00\x00\x00\x00\x00\x00", 8);
    raw("negative 2^63", V_ASN1_NEG_INTEGER, "\x80\x00\x00\x00\x00\x00\x00\x00", 8);
    raw("negative 2^63 + 1", V_ASN1_NEG_INTEGER, "\x80\x00\x00\x00\x00\x00\x00\x01", 8);
    raw("negative 2^32", V_ASN1_NEG_INTEGER, "\x01\x00\x00\x00\x00", 5);
    /* The unsigned getter refuses a negative value before looking at its size. */
    raw("negative nine octets", V_ASN1_NEG_INTEGER, "\x01\x00\x00\x00\x00\x00\x00\x00\x00", 9);
    raw("empty", V_ASN1_INTEGER, "", 0);
    raw("an OCTET STRING", V_ASN1_OCTET_STRING, "\x01", 1);
    raw("ENUMERATED", V_ASN1_ENUMERATED, "\x05", 1);
    raw("nine-octet ENUMERATED", V_ASN1_ENUMERATED, "\x00\x00\x00\x00\x00\x00\x00\x00\x01", 9);
    raw("negative ENUMERATED", V_ASN1_NEG_ENUMERATED, "\x05", 1);
    s = ASN1_INTEGER_new();
    printf("# no data: %d get %ld", ASN1_INTEGER_get_int64(&v, s), ASN1_INTEGER_get(s));
    errors();
    ASN1_INTEGER_free(s);
    check(ASN1_INTEGER_get(NULL) == 0 && ASN1_ENUMERATED_get(NULL) == 0, "NULL gets 0");
    check(ASN1_INTEGER_get_int64(&v, NULL) == 0, "and int64 from NULL fails");
    errors();
}

static void comparing(void)
{
    static const long values[] = { -300, -2, -1, 0, 1, 2, 255, 256 };
    ASN1_INTEGER *a = ASN1_INTEGER_new(), *b = ASN1_INTEGER_new(), *c;
    size_t i, j;
    int ok = 1;

    for (i = 0; i < 8; i++)
        for (j = 0; j < 8; j++) {
            int r;

            ASN1_INTEGER_set(a, values[i]);
            ASN1_INTEGER_set(b, values[j]);
            r = ASN1_INTEGER_cmp(a, b);
            ok = ok && (r < 0) == (values[i] < values[j]) && (r == 0) == (i == j);
        }
    check(ok, "ASN1_INTEGER_cmp orders values");
    ASN1_INTEGER_set(a, -5);
    c = ASN1_INTEGER_dup(a);
    check(c != NULL && ASN1_INTEGER_cmp(a, c) == 0 && ASN1_INTEGER_get(c) == -5, "ASN1_INTEGER_dup");
    ASN1_INTEGER_free(a);
    ASN1_INTEGER_free(b);
    ASN1_INTEGER_free(c);
}

static void printing(void)
{
    BIO *mem = BIO_new(BIO_s_mem());
    ASN1_INTEGER *a = ASN1_INTEGER_new();
    unsigned char big[80];
    char *text;
    long len;
    int i;

    for (i = 0; i < 80; i++)
        big[i] = (unsigned char)(i * 7);
    printf("# i2a: %d", i2a_ASN1_INTEGER(mem, a));
    ASN1_INTEGER_set(a, -0x1234);
    printf(" %d", i2a_ASN1_INTEGER(mem, a));
    ASN1_STRING_set(a, big, 80);
    printf(" %d", i2a_ASN1_INTEGER(mem, a));
    ASN1_ENUMERATED_free(a);
    a = ASN1_ENUMERATED_new();
    ASN1_ENUMERATED_set(a, 10);
    printf(" %d %d\n", i2a_ASN1_ENUMERATED(mem, a), i2a_ASN1_INTEGER(mem, NULL));
    len = BIO_get_mem_data(mem, &text);
    printf("# text: ");
    fwrite(text, 1, (size_t)len, stdout);
    printf("|\n");
    ASN1_INTEGER_free(a);
    BIO_free(mem);
    check(1, "i2a_ASN1_INTEGER");
}

static void parse(const char *what, const char *input, int size, int enumerated)
{
    BIO *in = BIO_new(BIO_s_mem());
    ASN1_INTEGER *a = enumerated ? ASN1_ENUMERATED_new() : ASN1_INTEGER_new();
    char buf[256];
    int r;

    BIO_puts(in, input);
    memset(buf, 'x', sizeof(buf));
    r = enumerated ? a2i_ASN1_ENUMERATED(in, a, buf, size) : a2i_ASN1_INTEGER(in, a, buf, size);
    printf("# a2i %s: %d", what, r);
    octets(a);
    printf(" buf=%.12s", buf);
    errors();
    ASN1_INTEGER_free(a);
    BIO_free(in);
}

static void parsing(void)
{
    parse("simple", "0102ff\n", 256, 0);
    parse("leading 00", "00FF\n", 256, 0);
    parse("00 alone", "00\n", 256, 0);
    parse("CRLF", "abcd\r\n", 256, 0);
    parse("trailing junk", "1234 then more\n", 256, 0);
    parse("odd", "123\n", 256, 0);
    parse("one char", "1\n", 256, 0);
    parse("empty line", "\n", 256, 0);
    parse("nothing", "", 256, 0);
    parse("continued", "0102\\\n0304\n", 256, 0);
    parse("continued odd", "01023\\\n0304\n", 256, 0);
    /* "00" then a backslash leaves -1 characters, which is odd. */
    parse("00 continued", "00\\\n01\n", 256, 0);
    parse("no newline", "beef", 256, 0);
    parse("short buffer", "0102030405060708\n", 6, 0);
    parse("enumerated", "0a\n", 256, 1);
    check(1, "a2i_ASN1_INTEGER");
}

static void uinteger(const char *what, const unsigned char *in, long len)
{
    const unsigned char *p = in;
    ASN1_INTEGER *a = d2i_ASN1_UINTEGER(NULL, &p, len);

    printf("# d2i_ASN1_UINTEGER %s: %s used=%d", what, a == NULL ? "NULL" : "ok", (int)(p - in));
    if (a != NULL)
        octets(a);
    errors();
    ASN1_INTEGER_free(a);
}

static void uintegers(void)
{
    ASN1_INTEGER *reuse = ASN1_INTEGER_new();
    const unsigned char *p;

    uinteger("plain", (const unsigned char *)"\x02\x02\x01\x02", 4);
    uinteger("leading zero", (const unsigned char *)"\x02\x03\x00\x80\x01", 5);
    uinteger("two zeros", (const unsigned char *)"\x02\x03\x00\x00\x01", 5);
    uinteger("just zero", (const unsigned char *)"\x02\x01\x00", 3);
    uinteger("empty", (const unsigned char *)"\x02\x00", 2);
    uinteger("negative-looking", (const unsigned char *)"\x02\x01\xff", 3);
    uinteger("context tag", (const unsigned char *)"\x82\x01\x05", 3);
    uinteger("wrong tag", (const unsigned char *)"\x04\x01\x05", 3);
    uinteger("overrun", (const unsigned char *)"\x02\x05\x01", 3);
    uinteger("indefinite", (const unsigned char *)"\x22\x80\x00\x00", 4);
    p = (const unsigned char *)"\x02\x01\x07";
    check(d2i_ASN1_UINTEGER(&reuse, &p, 3) == reuse && ASN1_INTEGER_get(reuse) == 7, "into an existing INTEGER");
    ASN1_INTEGER_free(reuse);
}

int main(void)
{
    setting();
    getting();
    comparing();
    printing();
    parsing();
    uintegers();
    ERR_clear_error();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
