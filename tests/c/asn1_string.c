/*
 * Conformance test for ASN1_STRING (ASN1_STRING_new(3), ASN1_STRING_set(3),
 * ASN1_STRING_length(3), ASN1_STRING_dup, ASN1_STRING_cmp, the flags that change ownership)
 * and each string type's new and free, in TAP format.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
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

static int sign(int x)
{
    return x < 0 ? -1 : x > 0;
}

static void basics(void)
{
    ASN1_STRING *s = ASN1_STRING_new(), *t;
    const unsigned char *kept;

    check(s != NULL && ASN1_STRING_type(s) == V_ASN1_OCTET_STRING && ASN1_STRING_length(s) == 0
              && ASN1_STRING_get0_data(s) == NULL && s->flags == 0,
          "ASN1_STRING_new is an empty OCTET STRING");
    check(ASN1_STRING_set(s, "hello", 5) == 1 && ASN1_STRING_length(s) == 5
              && memcmp(ASN1_STRING_get0_data(s), "hello", 6) == 0,
          "ASN1_STRING_set copies and adds a NUL");
    kept = ASN1_STRING_get0_data(s);
    check(ASN1_STRING_set(s, "hey", -1) == 1 && ASN1_STRING_length(s) == 3 && ASN1_STRING_get0_data(s) == kept
              && strcmp((const char *)kept, "hey") == 0,
          "a shorter value reuses the buffer; -1 measures a C string");
    check(ASN1_STRING_set(s, "hey", 3) == 1 && strcmp((const char *)ASN1_STRING_get0_data(s), "hey") == 0,
          "an equal length is reallocated (its pointer may move)");
    check(ASN1_STRING_set(s, NULL, 10) == 1 && ASN1_STRING_length(s) == 10, "NULL data only sizes it");
    check(ASN1_STRING_set(s, NULL, -1) == 0 && ASN1_STRING_length(s) == 10, "NULL with -1 does nothing");
    check(ASN1_STRING_set(s, "x", INT_MAX) == 0 && ERR_GET_REASON(ERR_get_error()) == ASN1_R_TOO_LARGE,
          "INT_MAX octets are too many");
    check(ASN1_STRING_set(s, "", 0) == 1 && ASN1_STRING_length(s) == 0 && ASN1_STRING_get0_data(s)[0] == '\0',
          "an empty value keeps a NUL");
    ASN1_STRING_length_set(s, 0);
    check(ASN1_STRING_data(s) == ASN1_STRING_get0_data(s), "ASN1_STRING_data");

    ASN1_STRING_set(s, "abc", 3);
    s->flags = 0x1234;
    s->type = V_ASN1_IA5STRING;
    t = ASN1_STRING_dup(s);
    check(t != NULL && t != s && ASN1_STRING_type(t) == V_ASN1_IA5STRING && t->flags == 0x1234
              && ASN1_STRING_cmp(s, t) == 0 && ASN1_STRING_get0_data(t) != ASN1_STRING_get0_data(s),
          "ASN1_STRING_dup copies the type, data, and flags");
    t->flags = ASN1_STRING_FLAG_EMBED | 1;
    check(ASN1_STRING_copy(t, s) == 1 && t->flags == (0x1234 | ASN1_STRING_FLAG_EMBED),
          "ASN1_STRING_copy keeps the destination's EMBED flag");
    t->flags = 0;
    check(ASN1_STRING_copy(t, NULL) == 0 && ASN1_STRING_dup(NULL) == NULL, "NULL sources");
    ASN1_STRING_free(t);
    ASN1_STRING_free(s);
    ASN1_STRING_free(NULL);
    ASN1_STRING_clear_free(NULL);
}

static void comparing(void)
{
    ASN1_STRING *a = ASN1_STRING_type_new(V_ASN1_UTF8STRING), *b = ASN1_STRING_type_new(V_ASN1_IA5STRING);

    ASN1_STRING_set(a, "abc", 3);
    ASN1_STRING_set(b, "abd", 3);
    printf("# cmp: %d %d", sign(ASN1_STRING_cmp(a, b)), sign(ASN1_STRING_cmp(b, a)));
    ASN1_STRING_set(b, "abc", 3);
    printf(" %d %d", ASN1_STRING_cmp(a, b), ASN1_STRING_cmp(b, a));
    ASN1_STRING_set(b, "abcd", 4);
    printf(" %d", ASN1_STRING_cmp(a, b));
    ASN1_STRING_set(a, "", 0);
    ASN1_STRING_set(b, "", 0);
    printf(" %d\n", ASN1_STRING_cmp(a, b));
    check(ASN1_OCTET_STRING_cmp(a, a) == 0, "ASN1_OCTET_STRING_cmp");
    ASN1_STRING_free(a);
    ASN1_STRING_free(b);
}

static void ownership(void)
{
    ASN1_STRING *s = ASN1_STRING_new(), embedded, *o;
    unsigned char *data = OPENSSL_malloc(4), local[] = "ndef";

    memcpy(data, "own", 4);
    ASN1_STRING_set(s, "old", 3);
    ASN1_STRING_set0(s, data, 3);
    check(ASN1_STRING_get0_data(s) == data && ASN1_STRING_length(s) == 3, "ASN1_STRING_set0 takes the data");
    ASN1_STRING_clear_free(s);

    s = ASN1_STRING_new();
    s->data = local;
    s->length = 4;
    s->flags = ASN1_STRING_FLAG_NDEF;
    ASN1_STRING_clear_free(s);
    check(memcmp(local, "ndef", 4) == 0, "an NDEF string's data is neither cleared nor freed");

    memset(&embedded, 0, sizeof(embedded));
    embedded.flags = ASN1_STRING_FLAG_EMBED;
    ASN1_STRING_set(&embedded, "inside", 6);
    ASN1_STRING_free(&embedded);
    check(1, "an EMBED string's struct isn't freed");

    o = ASN1_OCTET_STRING_new();
    check(ASN1_OCTET_STRING_set(o, (const unsigned char *)"\x01\x02", 2) == 1, "ASN1_OCTET_STRING_set");
    s = ASN1_OCTET_STRING_dup(o);
    check(s != NULL && ASN1_OCTET_STRING_cmp(s, o) == 0, "ASN1_OCTET_STRING_dup");
    ASN1_OCTET_STRING_free(s);
    ASN1_OCTET_STRING_free(o);
}

static void types(void)
{
    ASN1_STRING *s;
    int ok = 1;

    printf("# types:");
    s = (ASN1_STRING *)ASN1_OCTET_STRING_new();
    printf(" ASN1_OCTET_STRING=%d", s == NULL ? -1 : ASN1_STRING_type(s));
    ok = ok && s != NULL && ASN1_STRING_length(s) == 0 && ASN1_STRING_get0_data(s) == NULL;
    ASN1_OCTET_STRING_free((ASN1_OCTET_STRING *)s);
    s = (ASN1_STRING *)ASN1_INTEGER_new();
    printf(" ASN1_INTEGER=%d", s == NULL ? -1 : ASN1_STRING_type(s));
    ok = ok && s != NULL && ASN1_STRING_length(s) == 0 && ASN1_STRING_get0_data(s) == NULL;
    ASN1_INTEGER_free((ASN1_INTEGER *)s);
    s = (ASN1_STRING *)ASN1_ENUMERATED_new();
    printf(" ASN1_ENUMERATED=%d", s == NULL ? -1 : ASN1_STRING_type(s));
    ok = ok && s != NULL && ASN1_STRING_length(s) == 0 && ASN1_STRING_get0_data(s) == NULL;
    ASN1_ENUMERATED_free((ASN1_ENUMERATED *)s);
    s = (ASN1_STRING *)ASN1_BIT_STRING_new();
    printf(" ASN1_BIT_STRING=%d", s == NULL ? -1 : ASN1_STRING_type(s));
    ok = ok && s != NULL && ASN1_STRING_length(s) == 0 && ASN1_STRING_get0_data(s) == NULL;
    ASN1_BIT_STRING_free((ASN1_BIT_STRING *)s);
    s = (ASN1_STRING *)ASN1_UTF8STRING_new();
    printf(" ASN1_UTF8STRING=%d", s == NULL ? -1 : ASN1_STRING_type(s));
    ok = ok && s != NULL && ASN1_STRING_length(s) == 0 && ASN1_STRING_get0_data(s) == NULL;
    ASN1_UTF8STRING_free((ASN1_UTF8STRING *)s);
    s = (ASN1_STRING *)ASN1_PRINTABLESTRING_new();
    printf(" ASN1_PRINTABLESTRING=%d", s == NULL ? -1 : ASN1_STRING_type(s));
    ok = ok && s != NULL && ASN1_STRING_length(s) == 0 && ASN1_STRING_get0_data(s) == NULL;
    ASN1_PRINTABLESTRING_free((ASN1_PRINTABLESTRING *)s);
    s = (ASN1_STRING *)ASN1_T61STRING_new();
    printf(" ASN1_T61STRING=%d", s == NULL ? -1 : ASN1_STRING_type(s));
    ok = ok && s != NULL && ASN1_STRING_length(s) == 0 && ASN1_STRING_get0_data(s) == NULL;
    ASN1_T61STRING_free((ASN1_T61STRING *)s);
    s = (ASN1_STRING *)ASN1_IA5STRING_new();
    printf(" ASN1_IA5STRING=%d", s == NULL ? -1 : ASN1_STRING_type(s));
    ok = ok && s != NULL && ASN1_STRING_length(s) == 0 && ASN1_STRING_get0_data(s) == NULL;
    ASN1_IA5STRING_free((ASN1_IA5STRING *)s);
    s = (ASN1_STRING *)ASN1_GENERALSTRING_new();
    printf(" ASN1_GENERALSTRING=%d", s == NULL ? -1 : ASN1_STRING_type(s));
    ok = ok && s != NULL && ASN1_STRING_length(s) == 0 && ASN1_STRING_get0_data(s) == NULL;
    ASN1_GENERALSTRING_free((ASN1_GENERALSTRING *)s);
    s = (ASN1_STRING *)ASN1_UTCTIME_new();
    printf(" ASN1_UTCTIME=%d", s == NULL ? -1 : ASN1_STRING_type(s));
    ok = ok && s != NULL && ASN1_STRING_length(s) == 0 && ASN1_STRING_get0_data(s) == NULL;
    ASN1_UTCTIME_free((ASN1_UTCTIME *)s);
    s = (ASN1_STRING *)ASN1_GENERALIZEDTIME_new();
    printf(" ASN1_GENERALIZEDTIME=%d", s == NULL ? -1 : ASN1_STRING_type(s));
    ok = ok && s != NULL && ASN1_STRING_length(s) == 0 && ASN1_STRING_get0_data(s) == NULL;
    ASN1_GENERALIZEDTIME_free((ASN1_GENERALIZEDTIME *)s);
    s = (ASN1_STRING *)ASN1_VISIBLESTRING_new();
    printf(" ASN1_VISIBLESTRING=%d", s == NULL ? -1 : ASN1_STRING_type(s));
    ok = ok && s != NULL && ASN1_STRING_length(s) == 0 && ASN1_STRING_get0_data(s) == NULL;
    ASN1_VISIBLESTRING_free((ASN1_VISIBLESTRING *)s);
    s = (ASN1_STRING *)ASN1_UNIVERSALSTRING_new();
    printf(" ASN1_UNIVERSALSTRING=%d", s == NULL ? -1 : ASN1_STRING_type(s));
    ok = ok && s != NULL && ASN1_STRING_length(s) == 0 && ASN1_STRING_get0_data(s) == NULL;
    ASN1_UNIVERSALSTRING_free((ASN1_UNIVERSALSTRING *)s);
    s = (ASN1_STRING *)ASN1_BMPSTRING_new();
    printf(" ASN1_BMPSTRING=%d", s == NULL ? -1 : ASN1_STRING_type(s));
    ok = ok && s != NULL && ASN1_STRING_length(s) == 0 && ASN1_STRING_get0_data(s) == NULL;
    ASN1_BMPSTRING_free((ASN1_BMPSTRING *)s);
    printf("\n");
    check(ok, "each type's new is an empty string of the type, and free frees it");
}

int main(void)
{
    basics();
    comparing();
    ownership();
    types();
    ERR_clear_error();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
