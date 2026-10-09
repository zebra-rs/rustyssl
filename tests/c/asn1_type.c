/*
 * Conformance test for ASN1_TYPE (ASN1_TYPE_get(3), ASN1_TYPE_set(3), ASN1_TYPE_set1,
 * ASN1_TYPE_cmp, ASN1_TYPE_set_octetstring, ASN1_TYPE_get_octetstring), in TAP format. The
 * structs are made with OPENSSL_zalloc (ASN1_TYPE_new comes from the template engine) and
 * emptied with ASN1_TYPE_set before OPENSSL_free.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/crypto.h>
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

static ASN1_TYPE *make(void)
{
    return OPENSSL_zalloc(sizeof(ASN1_TYPE));
}

static void dispose(ASN1_TYPE *t)
{
    ASN1_TYPE_set(t, V_ASN1_NULL, NULL);
    OPENSSL_free(t);
}

static ASN1_STRING *text(int type, const char *s)
{
    ASN1_STRING *str = ASN1_STRING_type_new(type);

    ASN1_STRING_set(str, s, -1);
    return str;
}

static void basics(void)
{
    ASN1_TYPE *t = make(), *inner = make();
    ASN1_STRING *s;

    check(ASN1_TYPE_get(t) == 0, "an empty ASN1_TYPE has no type");
    t->type = V_ASN1_NULL;
    check(ASN1_TYPE_get(t) == V_ASN1_NULL, "NULL counts without a value");
    t->type = V_ASN1_BOOLEAN;
    check(ASN1_TYPE_get(t) == V_ASN1_BOOLEAN, "so does BOOLEAN");
    t->type = V_ASN1_OCTET_STRING;
    check(ASN1_TYPE_get(t) == 0, "a string type without a value doesn't");

    ASN1_TYPE_set(t, V_ASN1_BOOLEAN, (void *)1);
    check(ASN1_TYPE_get(t) == V_ASN1_BOOLEAN && t->value.boolean == 0xff, "BOOLEAN true is 0xff");
    ASN1_TYPE_set(t, V_ASN1_BOOLEAN, NULL);
    check(t->value.boolean == 0, "and false is 0");
    s = text(V_ASN1_UTF8STRING, "hello");
    ASN1_TYPE_set(t, V_ASN1_UTF8STRING, s);
    check(ASN1_TYPE_get(t) == V_ASN1_UTF8STRING && t->value.utf8string == s, "a string is taken");
    ASN1_TYPE_set(t, V_ASN1_OBJECT, OBJ_nid2obj(NID_sha256));
    check(ASN1_TYPE_get(t) == V_ASN1_OBJECT, "replacing frees the string");
    ASN1_TYPE_set(inner, V_ASN1_IA5STRING, text(V_ASN1_IA5STRING, "inner"));
    ASN1_TYPE_set(t, V_ASN1_ANY, inner);
    check(ASN1_TYPE_get(t) == V_ASN1_ANY, "an ANY holds another ASN1_TYPE");
    ASN1_TYPE_set(t, V_ASN1_NULL, NULL);
    check(ASN1_TYPE_get(t) == V_ASN1_NULL && t->value.ptr == NULL, "replacing frees it, and its value");
    dispose(t);
}

static void copies(void)
{
    ASN1_TYPE *a = make(), *b = make();
    ASN1_STRING *s = text(V_ASN1_PRINTABLESTRING, "copy me");
    ASN1_OBJECT *o = OBJ_txt2obj("1.2.3.4", 1);

    check(ASN1_TYPE_set1(a, V_ASN1_PRINTABLESTRING, s) == 1 && a->value.printablestring != s
              && ASN1_STRING_cmp(a->value.printablestring, s) == 0,
          "ASN1_TYPE_set1 copies a string");
    check(ASN1_TYPE_set1(b, V_ASN1_OBJECT, o) == 1 && b->value.object != o && OBJ_cmp(b->value.object, o) == 0,
          "and a dynamic object");
    check(ASN1_TYPE_set1(b, V_ASN1_OBJECT, OBJ_nid2obj(NID_sha1)) == 1 && b->value.object == OBJ_nid2obj(NID_sha1),
          "a built-in object is shared");
    check(ASN1_TYPE_set1(b, V_ASN1_BOOLEAN, (void *)1) == 1 && b->value.boolean == 0xff
              && ASN1_TYPE_set1(b, V_ASN1_OCTET_STRING, NULL) == 1 && ASN1_TYPE_get(b) == 0,
          "BOOLEAN and NULL values are set as they are");
    ASN1_STRING_free(s);
    ASN1_OBJECT_free(o);
    dispose(a);
    dispose(b);
}

static void comparing(void)
{
    ASN1_TYPE *a = make(), *b = make();

    ASN1_TYPE_set(a, V_ASN1_UTF8STRING, text(V_ASN1_UTF8STRING, "abc"));
    ASN1_TYPE_set(b, V_ASN1_UTF8STRING, text(V_ASN1_UTF8STRING, "abc"));
    check(ASN1_TYPE_cmp(a, b) == 0, "equal strings");
    ASN1_TYPE_set(b, V_ASN1_UTF8STRING, text(V_ASN1_UTF8STRING, "abcd"));
    printf("# cmp longer: %d\n", ASN1_TYPE_cmp(a, b));
    ASN1_TYPE_set(b, V_ASN1_IA5STRING, text(V_ASN1_IA5STRING, "abc"));
    check(ASN1_TYPE_cmp(a, b) == -1 && ASN1_TYPE_cmp(a, NULL) == -1 && ASN1_TYPE_cmp(NULL, NULL) == -1,
          "different types and NULL are -1");
    ASN1_TYPE_set(a, V_ASN1_OBJECT, OBJ_nid2obj(NID_sha256));
    ASN1_TYPE_set(b, V_ASN1_OBJECT, OBJ_nid2obj(NID_sha256));
    check(ASN1_TYPE_cmp(a, b) == 0, "equal objects");
    ASN1_TYPE_set(b, V_ASN1_OBJECT, OBJ_nid2obj(NID_sha1));
    printf("# cmp objects: %d\n", ASN1_TYPE_cmp(a, b) > 0);
    ASN1_TYPE_set(a, V_ASN1_BOOLEAN, (void *)1);
    ASN1_TYPE_set(b, V_ASN1_BOOLEAN, NULL);
    printf("# cmp booleans: %d %d\n", ASN1_TYPE_cmp(a, b), ASN1_TYPE_cmp(b, a));
    ASN1_TYPE_set(a, V_ASN1_NULL, NULL);
    ASN1_TYPE_set(b, V_ASN1_NULL, NULL);
    check(ASN1_TYPE_cmp(a, b) == 0, "NULLs are equal");
    dispose(a);
    dispose(b);
}

static void octets(void)
{
    ASN1_TYPE *t = make();
    unsigned char buf[8];
    int n;

    check(ASN1_TYPE_set_octetstring(t, (unsigned char *)"\x01\x02\x03\x04\x05", 5) == 1
              && ASN1_TYPE_get(t) == V_ASN1_OCTET_STRING,
          "ASN1_TYPE_set_octetstring");
    memset(buf, 0xee, sizeof(buf));
    n = ASN1_TYPE_get_octetstring(t, buf, 3);
    check(n == 5 && memcmp(buf, "\x01\x02\x03\xee", 4) == 0, "get copies up to max_len, returning the length");
    check(ASN1_TYPE_get_octetstring(t, NULL, 10) == 5 && ASN1_TYPE_get_octetstring(t, buf, -2) == 5,
          "or only measures");
    ASN1_TYPE_set(t, V_ASN1_BOOLEAN, NULL);
    check(ASN1_TYPE_get_octetstring(t, buf, 8) == -1 && ERR_GET_REASON(ERR_get_error()) == ASN1_R_DATA_IS_WRONG,
          "not from another type");
    dispose(t);
}

int main(void)
{
    basics();
    copies();
    comparing();
    octets();
    ERR_clear_error();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
