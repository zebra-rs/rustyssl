/*
 * Conformance test for RFC 5755's IetfAttrSyntax (OSSL_IETF_ATTR_SYNTAX, x509_acert.h), in TAP
 * format. A new structure already has its (empty) values and the type octets, so only octets
 * can be added to it, as in OpenSSL; strings and OIDs come from decoding, after which values
 * of the decoded type can be added. Then the errors (another type, an unknown type, NULL
 * data); the policy authority; the DER both ways, a decode whose values mix types (refused,
 * the slot cleared) and one into an existing structure; the accessors' edges; the items; and
 * the print, byte for byte, at several indents, including 0, where OpenSSL's print stops at
 * its first indent (which writes nothing) and fails.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/x509_acert.h>
#include <openssl/x509v3.h>

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
    const char *func;

    printf("  errors:");
    while ((code = ERR_get_error_all(NULL, NULL, &func, NULL, NULL)) != 0)
        printf(" %d/%d(%s)", ERR_GET_LIB(code), ERR_GET_REASON(code), func);
    printf("\n");
}

static void hex(const char *label, const unsigned char *p, int n)
{
    int i;

    printf("  %s:", label);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static void der(const char *label, const OSSL_IETF_ATTR_SYNTAX *a)
{
    unsigned char *out = NULL;
    int n = i2d_OSSL_IETF_ATTR_SYNTAX(a, &out);

    if (n > 0)
        hex(label, out, n);
    else
        printf("  %s: %d\n", label, n);
    OPENSSL_free(out);
}

/* The print into a memory BIO, shown with its result and length. */
static void print(const char *label, OSSL_IETF_ATTR_SYNTAX *a, int indent)
{
    BIO *b = BIO_new(BIO_s_mem());
    char *p;
    long n;
    int r = OSSL_IETF_ATTR_SYNTAX_print(b, a, indent);

    n = BIO_get_mem_data(b, &p);
    printf("  %s (indent %d): %d, %ld octets\n", label, indent, r, n);
    printf("---\n%.*s---\n", (int)n, p);
    BIO_free(b);
}

static ASN1_OCTET_STRING *octets(const char *s)
{
    ASN1_OCTET_STRING *o = ASN1_OCTET_STRING_new();

    ASN1_OCTET_STRING_set(o, (const unsigned char *)s, (int)strlen(s));
    return o;
}

static ASN1_UTF8STRING *utf8(const char *s)
{
    ASN1_UTF8STRING *u = ASN1_UTF8STRING_new();

    ASN1_STRING_set(u, s, (int)strlen(s));
    return u;
}

static void show_values(const OSSL_IETF_ATTR_SYNTAX *a)
{
    int i, n = OSSL_IETF_ATTR_SYNTAX_get_value_num(a);

    printf("  %d values:", n);
    for (i = 0; i < n; i++) {
        int type = -9;
        void *v = OSSL_IETF_ATTR_SYNTAX_get0_value(a, i, &type);

        printf(" [%d type %d %s]", i, type, v != NULL ? "set" : "NULL");
    }
    printf("\n");
}

/*
 * A new structure: OSSL_IETF_ATTR_SYNTAX_new makes the values' (empty) stack, and its type is
 * 0 (octets), so only octets can be added to it; strings and OIDs come from decoding.
 */
static void test_new(void)
{
    OSSL_IETF_ATTR_SYNTAX *a = OSSL_IETF_ATTR_SYNTAX_new();
    ASN1_UTF8STRING *u = utf8("group-a");
    ASN1_OBJECT *obj = OBJ_txt2obj("1.2.3.4.5.6.7.8.9", 1);
    GENERAL_NAMES *names = GENERAL_NAMES_new();
    GENERAL_NAME *gn = GENERAL_NAME_new();
    ASN1_IA5STRING *dns = ASN1_IA5STRING_new();
    int type = -9;

    printf("# a new structure\n");
    check(OSSL_IETF_ATTR_SYNTAX_get_value_num(a) == 0, "no values at first");
    check(OSSL_IETF_ATTR_SYNTAX_get0_value(a, 0, &type) == NULL && type == -9,
          "nothing at index 0");
    check(OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority(a) == NULL, "no policy authority");
    der("empty", a);
    print("empty", a, 0);
    print("empty", a, 2);
    check(OSSL_IETF_ATTR_SYNTAX_add1_value(a, OSSL_IETFAS_STRING, u) == 0,
          "a string (the type is octets)");
    errors();
    check(OSSL_IETF_ATTR_SYNTAX_add1_value(a, OSSL_IETFAS_OID, obj) == 0, "an OID");
    errors();
    check(OSSL_IETF_ATTR_SYNTAX_add1_value(a, 7, u) == 0, "type 7");
    errors();
    check(OSSL_IETF_ATTR_SYNTAX_add1_value(a, OSSL_IETFAS_OCTETS, NULL) == 0, "NULL data");
    errors();
    check(OSSL_IETF_ATTR_SYNTAX_add1_value(a, OSSL_IETFAS_OCTETS, octets("\x01\x02xyz")) == 1,
          "octets");
    check(OSSL_IETF_ATTR_SYNTAX_add1_value(a, OSSL_IETFAS_OCTETS, octets("second")) == 1,
          "more octets");
    check(OSSL_IETF_ATTR_SYNTAX_add1_value(a, OSSL_IETFAS_STRING, u) == 0,
          "a string after octets");
    errors();
    show_values(a);
    check(OSSL_IETF_ATTR_SYNTAX_get0_value(a, 2, NULL) == NULL
              && OSSL_IETF_ATTR_SYNTAX_get0_value(a, -1, NULL) == NULL,
          "nothing past the ends");
    check(OSSL_IETF_ATTR_SYNTAX_get0_value(a, 1, NULL) != NULL, "a value without its type");
    der("octets", a);
    print("octets", a, 1);
    print("octets", a, 0);

    ASN1_STRING_set(dns, "authority.example", -1);
    GENERAL_NAME_set0_value(gn, GEN_DNS, dns);
    sk_GENERAL_NAME_push(names, gn);
    OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority(a, names);
    check(OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority(a) == names, "the policy authority");
    der("with the authority", a);
    print("with the authority", a, 2);
    print("with the authority", a, 0);
    OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority(a, NULL);
    check(OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority(a) == NULL, "the authority removed");
    print("without the authority", a, 4);
    ASN1_UTF8STRING_free(u);
    ASN1_OBJECT_free(obj);
    OSSL_IETF_ATTR_SYNTAX_free(a);
}

static void test_decode(void)
{
    /* SEQUENCE { [0] { dNSName "a.example" }, SEQUENCE { UTF8 "x", UTF8 "yz" } }. */
    static const unsigned char good[] = {
        0x30, 0x16, 0xa0, 0x0b, 0x82, 0x09, 'a', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x30, 0x07, 0x0c, 0x01, 'x', 0x0c, 0x02, 'y', 'z'
    };
    /* SEQUENCE { SEQUENCE { UTF8 "x", OCTET STRING "y" } }: mixed types. */
    static const unsigned char mixed[] = {
        0x30, 0x08, 0x30, 0x06, 0x0c, 0x01, 'x', 0x04, 0x01, 'y'
    };
    /* SEQUENCE { SEQUENCE { OID 2.5.4.3 } }. */
    static const unsigned char oid[] = { 0x30, 0x07, 0x30, 0x05, 0x06, 0x03, 0x55, 0x04, 0x03 };
    /* SEQUENCE { SEQUENCE { INTEGER 1 } }: not a value's type. */
    static const unsigned char wrong[] = { 0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01 };
    const unsigned char *p;
    OSSL_IETF_ATTR_SYNTAX *a, *reuse = NULL;

    printf("# decoding\n");
    p = good;
    a = d2i_OSSL_IETF_ATTR_SYNTAX(NULL, &p, sizeof(good));
    check(a != NULL && p == good + sizeof(good), "a good encoding");
    show_values(a);
    der("again", a);
    print("decoded", a, 2);
    check(sk_GENERAL_NAME_num(OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority(a)) == 1,
          "its policy authority");
    OSSL_IETF_ATTR_SYNTAX_free(a);

    p = mixed;
    reuse = OSSL_IETF_ATTR_SYNTAX_new();
    a = d2i_OSSL_IETF_ATTR_SYNTAX(&reuse, &p, sizeof(mixed));
    check(a == NULL && reuse == NULL, "mixed types fail, the slot cleared");
    errors();

    p = oid;
    a = d2i_OSSL_IETF_ATTR_SYNTAX(&reuse, &p, sizeof(oid));
    check(a != NULL && a == reuse, "an OID into the slot");
    show_values(a);
    print("decoded OID", a, 1);
    if (a == NULL)
        return;
    check(OSSL_IETF_ATTR_SYNTAX_add1_value(a, OSSL_IETFAS_OID, OBJ_nid2obj(NID_title)) == 1,
          "the decoded type is kept for adding");
    {
        ASN1_UTF8STRING *no = utf8("no");

        check(OSSL_IETF_ATTR_SYNTAX_add1_value(a, OSSL_IETFAS_STRING, no) == 0, "and enforced");
        errors();
        ASN1_UTF8STRING_free(no);
    }
    OSSL_IETF_ATTR_SYNTAX_free(a);

    p = wrong;
    a = d2i_OSSL_IETF_ATTR_SYNTAX(NULL, &p, sizeof(wrong));
    check(a == NULL, "an INTEGER value");
    ERR_clear_error();
    p = good;
    a = d2i_OSSL_IETF_ATTR_SYNTAX(NULL, &p, sizeof(good) - 1);
    check(a == NULL, "a truncated encoding");
    ERR_clear_error();
}

static void test_items(void)
{
    const ASN1_ITEM *it = OSSL_IETF_ATTR_SYNTAX_it(), *vit = OSSL_IETF_ATTR_SYNTAX_VALUE_it();
    OSSL_IETF_ATTR_SYNTAX_VALUE *v = OSSL_IETF_ATTR_SYNTAX_VALUE_new();

    printf("# the items\n");
    printf("  %s: itype %d, %ld templates; %s: itype %d, %ld templates\n", it->sname,
           it->itype, it->tcount, vit->sname, vit->itype, vit->tcount);
    check(v != NULL, "a value");
    OSSL_IETF_ATTR_SYNTAX_VALUE_free(v);
    OSSL_IETF_ATTR_SYNTAX_VALUE_free(NULL);
    OSSL_IETF_ATTR_SYNTAX_free(NULL);
}

int main(void)
{
    test_new();
    test_decode();
    test_items();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
