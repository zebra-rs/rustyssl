/*
 * Conformance test for extensions as structures (X509_EXTENSION_create_by_NID(3),
 * X509_EXTENSION_get_critical(3), X509v3_get_ext_by_NID(3), X509v3_add_ext(3)), in TAP format:
 * extensions made by NID and object, critical and not, their DER (a FALSE critical flag left
 * out) and copies; extensions decoded from DER with an explicit FALSE, a TRUE, a non-DER TRUE,
 * no value, and malformed; stacks of them added to at each place, searched by NID, object,
 * and criticality from each position, deleted from, and merged with X509v3_add_extensions; a
 * SEQUENCE OF them encoded and decoded; and NULL arguments.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

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
    unsigned long e;
    const char *data;
    int flags;

    printf("  errors:");
    while ((e = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
        if ((flags & ERR_TXT_STRING) != 0 && data != NULL && *data != '\0')
            printf(" [%s]", data);
    }
    printf("\n");
}

static void hex(const char *label, const unsigned char *p, long n)
{
    long i;

    printf("  %s (%ld):", label, n);
    for (i = 0; i < n; i++)
        printf(" %02x", p[i]);
    printf("\n");
}

static void show(const char *label, X509_EXTENSION *ex)
{
    unsigned char *der = NULL;
    int len;
    char obj[80] = "";
    ASN1_OCTET_STRING *d = X509_EXTENSION_get_data(ex);

    if (ex == NULL) {
        printf("  %s: none\n", label);
        return;
    }
    OBJ_obj2txt(obj, sizeof(obj), X509_EXTENSION_get_object(ex), 0);
    printf("  %s: %s critical %d, value", label, obj, X509_EXTENSION_get_critical(ex));
    if (d != NULL)
        hex("", ASN1_STRING_get0_data(d), ASN1_STRING_length(d));
    len = i2d_X509_EXTENSION(ex, &der);
    if (len > 0)
        hex("der", der, len);
    else
        printf("  der: %d\n", len);
    OPENSSL_free(der);
}

static X509_EXTENSION *make(int nid, int crit, const char *value)
{
    ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
    X509_EXTENSION *ex;

    ASN1_OCTET_STRING_set(os, (const unsigned char *)value, (int)strlen(value));
    ex = X509_EXTENSION_create_by_NID(NULL, nid, crit, os);
    ASN1_OCTET_STRING_free(os);
    return ex;
}

static void test_make(void)
{
    X509_EXTENSION *a = make(NID_basic_constraints, 1, "\x30\x03\x01\x01\xff");
    X509_EXTENSION *b = make(NID_key_usage, 0, "\x03\x02\x05\xa0");
    X509_EXTENSION *c = NULL, *r, *d;
    ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
    ASN1_OBJECT *obj = OBJ_txt2obj("1.2.3.4.5.6", 1);

    printf("# making\n");
    check(a != NULL && b != NULL, "made by NID");
    show("basic constraints, critical", a);
    show("key usage", b);
    ASN1_OCTET_STRING_set(os, (const unsigned char *)"\x05\x00", 2);
    r = X509_EXTENSION_create_by_OBJ(&c, obj, 42, os);
    check(r != NULL && r == c, "made by OBJ into *ex");
    show("by OBJ, crit 42", c);
    r = X509_EXTENSION_create_by_OBJ(&c, obj, 0, os);
    check(r == c, "made again into the same");
    show("reused, not critical", c);
    r = X509_EXTENSION_create_by_NID(NULL, 88888, 0, os);
    printf("  unknown NID: %p\n", (void *)r);
    errors();
    r = X509_EXTENSION_create_by_OBJ(NULL, NULL, 0, os);
    printf("  NULL object: %p\n", (void *)r);
    errors();
    d = X509_EXTENSION_dup(a);
    check(d != NULL && X509_EXTENSION_get_critical(d) == 1, "a copy keeps critical");
    show("copy", d);
    printf("  set_critical(NULL) %d, set_object(NULL) %d, set_data(NULL) %d, get_critical(NULL) %d\n",
           X509_EXTENSION_set_critical(NULL, 1), X509_EXTENSION_set_object(a, NULL),
           X509_EXTENSION_set_data(NULL, os), X509_EXTENSION_get_critical(NULL));
    printf("  getters of NULL: %p %p\n", (void *)X509_EXTENSION_get_object(NULL),
           (void *)X509_EXTENSION_get_data(NULL));
    X509_EXTENSION_set_critical(d, 0);
    X509_EXTENSION_set_data(d, os);
    X509_EXTENSION_set_object(d, obj);
    show("changed copy", d);
    {
        X509_EXTENSION *e = X509_EXTENSION_new();
        STACK_OF(X509_EXTENSION) *sk = sk_X509_EXTENSION_new_null();
        unsigned char *der = NULL;
        int len;

        printf("  new: object %d critical %d data length %d\n",
               OBJ_obj2nid(X509_EXTENSION_get_object(e)), X509_EXTENSION_get_critical(e),
               ASN1_STRING_length(X509_EXTENSION_get_data(e)));
        len = ASN1_item_i2d((ASN1_VALUE *)e, &der, ASN1_ITEM_rptr(X509_EXTENSION));
        printf("  new der %d\n", len);
        errors();
        OPENSSL_free(der);
        der = NULL;
        len = ASN1_item_i2d((ASN1_VALUE *)a, &der, ASN1_ITEM_rptr(X509_EXTENSION));
        hex("item der", der, len);
        OPENSSL_free(der);
        der = NULL;
        sk_X509_EXTENSION_push(sk, a);
        sk_X509_EXTENSION_push(sk, b);
        len = ASN1_item_i2d((ASN1_VALUE *)sk, &der, ASN1_ITEM_rptr(X509_EXTENSIONS));
        hex("extensions item der", der, len);
        OPENSSL_free(der);
        sk_X509_EXTENSION_free(sk);
        X509_EXTENSION_free(e);
    }
    X509_EXTENSION_free(a);
    X509_EXTENSION_free(b);
    X509_EXTENSION_free(c);
    X509_EXTENSION_free(d);
    X509_EXTENSION_free(NULL);
    ASN1_OCTET_STRING_free(os);
    ASN1_OBJECT_free(obj);
}

static void decode(const char *label, const unsigned char *der, long len)
{
    const unsigned char *p = der;
    X509_EXTENSION *ex = d2i_X509_EXTENSION(NULL, &p, len);

    if (ex == NULL) {
        printf("  %s: none\n", label);
        errors();
        return;
    }
    printf("  %s: consumed %ld\n", label, (long)(p - der));
    show(label, ex);
    X509_EXTENSION_free(ex);
}

static void test_decode(void)
{
    static const unsigned char plain[] = { 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x02, 0x03, 0x00 };
    static const unsigned char crit_true[] = { 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00 };
    static const unsigned char crit_false[] = { 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0x00, 0x04, 0x02, 0x30, 0x00 };
    static const unsigned char crit_one[] = { 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0x01, 0x04, 0x02, 0x30, 0x00 };
    static const unsigned char no_value[] = { 0x30, 0x05, 0x06, 0x03, 0x55, 0x1d, 0x13 };
    static const unsigned char bad_bool[] = { 0x30, 0x0d, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x02, 0xff, 0xff, 0x04, 0x02, 0x30, 0x00 };
    static const unsigned char trailing[] = { 0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x02, 0x03, 0x00, 0x05, 0x00 };
    static const unsigned char unknown[] = { 0x30, 0x0a, 0x06, 0x04, 0x2a, 0x03, 0x04, 0x05, 0x04, 0x02, 0xab, 0xcd };

    printf("# decoding\n");
    decode("plain", plain, sizeof(plain));
    decode("critical TRUE", crit_true, sizeof(crit_true));
    decode("critical FALSE (BER)", crit_false, sizeof(crit_false));
    decode("critical 01", crit_one, sizeof(crit_one));
    decode("no value", no_value, sizeof(no_value));
    decode("two-octet BOOLEAN", bad_bool, sizeof(bad_bool));
    decode("extra element", trailing, sizeof(trailing));
    decode("unknown OID", unknown, sizeof(unknown));
}

static void list(const STACK_OF(X509_EXTENSION) *sk)
{
    int i;

    printf("  %d:", X509v3_get_ext_count(sk));
    for (i = 0; i < X509v3_get_ext_count(sk); i++) {
        X509_EXTENSION *e = X509v3_get_ext(sk, i);

        printf(" %d%s", OBJ_obj2nid(X509_EXTENSION_get_object(e)), X509_EXTENSION_get_critical(e) ? "!" : "");
    }
    printf("\n");
}

static void test_stack(void)
{
    STACK_OF(X509_EXTENSION) *sk = NULL, *other = NULL, *r;
    X509_EXTENSION *bc = make(NID_basic_constraints, 1, "\x30\x00");
    X509_EXTENSION *ku = make(NID_key_usage, 1, "\x03\x01\x00");
    X509_EXTENSION *ski = make(NID_subject_key_identifier, 0, "\x04\x01\x01");
    X509_EXTENSION *ku2 = make(NID_key_usage, 0, "\x03\x02\x01\x02");
    X509_EXTENSION *e;
    unsigned char *der = NULL;
    const unsigned char *p;
    int len, i;

    printf("# stacks\n");
    r = X509v3_add_ext(&sk, bc, -1);
    check(r != NULL && r == sk, "added to a new stack");
    X509v3_add_ext(&sk, ku, 0);
    X509v3_add_ext(&sk, ski, 1);
    X509v3_add_ext(&sk, ku2, 50);
    list(sk);
    printf("  by NID key usage: %d, after 0: %d, after 3: %d, unknown NID: %d, of NULL: %d\n",
           X509v3_get_ext_by_NID(sk, NID_key_usage, -1), X509v3_get_ext_by_NID(sk, NID_key_usage, 0),
           X509v3_get_ext_by_NID(sk, NID_key_usage, 3), X509v3_get_ext_by_NID(sk, 99999, -1),
           X509v3_get_ext_by_NID(NULL, NID_key_usage, -1));
    printf("  by OBJ: %d, lastpos -10: %d\n", X509v3_get_ext_by_OBJ(sk, OBJ_nid2obj(NID_subject_key_identifier), -1),
           X509v3_get_ext_by_OBJ(sk, OBJ_nid2obj(NID_key_usage), -10));
    for (i = -2; i < 4; i++)
        printf("  critical after %d: %d, not: %d, crit 7: %d\n", i, X509v3_get_ext_by_critical(sk, 1, i),
               X509v3_get_ext_by_critical(sk, 0, i), X509v3_get_ext_by_critical(sk, 7, i));
    printf("  get -1 %p, 4 %p, NULL %p, count(NULL) %d\n", (void *)X509v3_get_ext(sk, -1),
           (void *)X509v3_get_ext(sk, 4), (void *)X509v3_get_ext(NULL, 0), X509v3_get_ext_count(NULL));

    /* Merging replaces every extension of an object the added ones have. */
    X509v3_add_ext(&other, ku2, -1);
    X509v3_add_ext(&other, bc, -1);
    r = X509v3_add_extensions(&sk, other);
    check(r == sk, "merged");
    list(sk);
    printf("  add_extensions(NULL target) %p, NULL exts is the target %d\n", (void *)X509v3_add_extensions(NULL, other),
           X509v3_add_extensions(&sk, NULL) == sk);
    errors();
    printf("  add_ext(NULL) %p\n", (void *)X509v3_add_ext(NULL, bc, 0));
    errors();

    len = i2d_X509_EXTENSIONS(sk, &der);
    hex("extensions der", der, len);
    p = der;
    r = d2i_X509_EXTENSIONS(NULL, &p, len);
    check(r != NULL && X509v3_get_ext_count(r) == X509v3_get_ext_count(sk), "decoded back");
    list(r);
    sk_X509_EXTENSION_pop_free(r, X509_EXTENSION_free);
    OPENSSL_free(der);

    e = X509v3_delete_ext(sk, 1);
    check(e != NULL, "deleted 1");
    X509_EXTENSION_free(e);
    list(sk);
    printf("  delete -1 %p, 9 %p, NULL %p\n", (void *)X509v3_delete_ext(sk, -1), (void *)X509v3_delete_ext(sk, 9),
           (void *)X509v3_delete_ext(NULL, 0));
    sk_X509_EXTENSION_pop_free(sk, X509_EXTENSION_free);
    sk_X509_EXTENSION_pop_free(other, X509_EXTENSION_free);
    X509_EXTENSION_free(bc);
    X509_EXTENSION_free(ku);
    X509_EXTENSION_free(ski);
    X509_EXTENSION_free(ku2);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("TAP version 13\n");
    test_make();
    test_decode();
    test_stack();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
