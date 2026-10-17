/*
 * Conformance test for the admission extension (ADMISSION_SYNTAX_new(3) and the getters and
 * setters of ADMISSION_SYNTAX, ADMISSIONS, PROFESSION_INFO, and NAMING_AUTHORITY), in TAP
 * format: an admission built through the setters, read through the getters, encoded, decoded,
 * and printed (including the failure an empty naming authority causes), the items' empty
 * encodings, and a decoded extension.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/stack.h>
#include <openssl/x509.h>
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
        printf("%s%02x", i % 32 == 0 && i > 0 ? "\n    " : " ", p[i]);
    printf("\n");
}

static BIO *out;

static void flush_out(void)
{
    char *data;
    long n = BIO_get_mem_data(out, &data);

    fwrite(data, 1, (size_t)n, stdout);
    (void)BIO_reset(out);
}

static void print_out(const char *label)
{
    printf("  %s: [", label);
    flush_out();
    printf("]\n");
}

static void show_ext(const char *label, X509_EXTENSION *e)
{
    unsigned char *der = NULL;
    int len;

    if (e == NULL) {
        printf("  %s: none\n", label);
        errors();
        return;
    }
    len = i2d_X509_EXTENSION(e, &der);
    hex(label, der, len);
    OPENSSL_free(der);
    printf("  print: %d\n", X509V3_EXT_print(out, e, 0, 2));
    print_out("printed");
    printf("  multiline: %d\n", X509V3_EXT_print(out, e, X509V3_EXT_MULTILINE, 2));
    print_out("printed");
    errors();
}


static void print_syntax(const char *label, ADMISSION_SYNTAX *as)
{
    X509_EXTENSION *e = X509V3_EXT_i2d(NID_x509ExtAdmission, 0, as);

    printf("# %s\n", label);
    show_ext("extension", e);
    X509_EXTENSION_free(e);
}

static ASN1_STRING *dirstr(const char *s)
{
    ASN1_STRING *a = ASN1_STRING_type_new(V_ASN1_UTF8STRING);

    ASN1_STRING_set(a, s, -1);
    return a;
}

static GENERAL_NAME *uri(const char *s)
{
    GENERAL_NAME *g = GENERAL_NAME_new();
    ASN1_IA5STRING *u = ASN1_IA5STRING_new();

    ASN1_STRING_set(u, s, -1);
    GENERAL_NAME_set0_value(g, GEN_URI, u);
    return g;
}

static NAMING_AUTHORITY *authority(int id, int url, int text)
{
    NAMING_AUTHORITY *na = NAMING_AUTHORITY_new();

    if (id == 1)
        NAMING_AUTHORITY_set0_authorityId(na, OBJ_txt2obj("1.3.36.8.3.11.1.1", 1));
    if (id == 2)
        NAMING_AUTHORITY_set0_authorityId(na, OBJ_nid2obj(NID_commonName));
    if (id == 3)
        NAMING_AUTHORITY_set0_authorityId(na, OBJ_txt2obj(
            "1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17.18.19.20.21.22.23.24.25.26.27.28.29.30.31.32.33.34.35.36.37.38.39.40.41.42.43.44.45.46.47.48.49.50",
            1));
    if (url) {
        ASN1_IA5STRING *u = ASN1_IA5STRING_new();

        ASN1_STRING_set(u, "http://na.example/", -1);
        NAMING_AUTHORITY_set0_authorityURL(na, u);
    }
    if (text)
        NAMING_AUTHORITY_set0_authorityText(na, dirstr("Naming Authority"));
    return na;
}

static void test_admission(void)
{
    ADMISSION_SYNTAX *as = ADMISSION_SYNTAX_new(), *copy;
    STACK_OF(ADMISSIONS) *list = sk_ADMISSIONS_new_null();
    ADMISSIONS *ad = ADMISSIONS_new(), *ad2 = ADMISSIONS_new();
    PROFESSION_INFOS *infos = sk_PROFESSION_INFO_new_null();
    PROFESSION_INFO *pi = PROFESSION_INFO_new(), *pi2 = PROFESSION_INFO_new();
    STACK_OF(ASN1_STRING) *items = sk_ASN1_STRING_new_null();
    STACK_OF(ASN1_OBJECT) *oids = sk_ASN1_OBJECT_new_null();
    ASN1_PRINTABLESTRING *reg = ASN1_PRINTABLESTRING_new();
    ASN1_OCTET_STRING *add = ASN1_OCTET_STRING_new();
    unsigned char *der = NULL;
    const unsigned char *q;
    int len;

    printf("# admission\n");
    print_syntax("empty", as);
    check(ADMISSION_SYNTAX_get0_admissionAuthority(as) == NULL, "no authority");
    check(ADMISSION_SYNTAX_get0_contentsOfAdmissions(as) != NULL, "empty admissions");
    ADMISSION_SYNTAX_set0_admissionAuthority(as, uri("http://aa.example/"));
    sk_ASN1_STRING_push(items, dirstr("Apotheker"));
    sk_ASN1_STRING_push(items, dirstr("Pharmacist"));
    PROFESSION_INFO_set0_professionItems(pi, items);
    sk_ASN1_OBJECT_push(oids, OBJ_txt2obj("1.3.36.8.3.11.1.6", 1));
    sk_ASN1_OBJECT_push(oids, OBJ_nid2obj(NID_organizationName));
    PROFESSION_INFO_set0_professionOIDs(pi, oids);
    ASN1_STRING_set(reg, "12345", -1);
    PROFESSION_INFO_set0_registrationNumber(pi, reg);
    ASN1_OCTET_STRING_set(add, (const unsigned char *)"\x01\x02", 2);
    PROFESSION_INFO_set0_addProfessionInfo(pi, add);
    PROFESSION_INFO_set0_namingAuthority(pi, authority(1, 1, 1));
    sk_PROFESSION_INFO_push(infos, pi);
    sk_PROFESSION_INFO_push(infos, pi2);
    ADMISSIONS_set0_professionInfos(ad, infos);
    ADMISSIONS_set0_admissionAuthority(ad, uri("http://entry.example/"));
    ADMISSIONS_set0_namingAuthority(ad, authority(2, 0, 1));
    sk_ADMISSIONS_push(list, ad);
    ADMISSIONS_set0_namingAuthority(ad2, authority(3, 1, 0));
    sk_ADMISSIONS_push(list, ad2);
    ADMISSION_SYNTAX_set0_contentsOfAdmissions(as, list);
    print_syntax("full", as);
    printf("  getters: %d %d %d %d %d %d %d %d\n",
           ADMISSIONS_get0_admissionAuthority(ad) != NULL, ADMISSIONS_get0_namingAuthority(ad) != NULL,
           sk_PROFESSION_INFO_num(ADMISSIONS_get0_professionInfos(ad)),
           sk_ASN1_STRING_num(PROFESSION_INFO_get0_professionItems(pi)),
           sk_ASN1_OBJECT_num(PROFESSION_INFO_get0_professionOIDs(pi)),
           ASN1_STRING_length(PROFESSION_INFO_get0_registrationNumber(pi)),
           ASN1_STRING_length(PROFESSION_INFO_get0_addProfessionInfo(pi)),
           PROFESSION_INFO_get0_namingAuthority(pi2) == NULL);
    {
        const NAMING_AUTHORITY *na = PROFESSION_INFO_get0_namingAuthority(pi);

        printf("  naming authority: %d %d %d\n", OBJ_obj2nid(NAMING_AUTHORITY_get0_authorityId(na)),
               ASN1_STRING_length(NAMING_AUTHORITY_get0_authorityURL(na)),
               ASN1_STRING_length(NAMING_AUTHORITY_get0_authorityText(na)));
    }
    len = i2d_ADMISSION_SYNTAX(as, &der);
    hex("DER", der, len);
    q = der;
    copy = d2i_ADMISSION_SYNTAX(NULL, &q, len);
    check(copy != NULL && q == der + len, "decoded");
    print_syntax("decoded", copy);
    ADMISSION_SYNTAX_free(copy);
    OPENSSL_free(der);

    /* A naming authority without parts fails the whole printing. */
    ADMISSIONS_set0_namingAuthority(ad2, NAMING_AUTHORITY_new());
    print_syntax("an empty naming authority", as);
    ADMISSION_SYNTAX_free(as);

    {
        NAMING_AUTHORITY *na = authority(1, 1, 1);
        PROFESSION_INFO *p = PROFESSION_INFO_new();
        ADMISSIONS *a = ADMISSIONS_new();

        der = NULL;
        len = i2d_NAMING_AUTHORITY(na, &der);
        hex("naming authority", der, len);
        q = der;
        NAMING_AUTHORITY_free(na);
        na = d2i_NAMING_AUTHORITY(NULL, &q, len);
        check(na != NULL, "decoded the naming authority");
        OPENSSL_free(der);
        der = NULL;
        len = i2d_PROFESSION_INFO(p, &der);
        hex("empty profession information", der, len);
        q = der;
        PROFESSION_INFO_free(p);
        p = d2i_PROFESSION_INFO(NULL, &q, len);
        check(p != NULL, "decoded it");
        OPENSSL_free(der);
        /* Without its required items, it encodes without them and can't be decoded. */
        PROFESSION_INFO_set0_professionItems(p, NULL);
        der = NULL;
        len = i2d_PROFESSION_INFO(p, &der);
        hex("profession information without items", der, len);
        q = der;
        PROFESSION_INFO_free(d2i_PROFESSION_INFO(NULL, &q, len));
        errors();
        OPENSSL_free(der);
        der = NULL;
        len = i2d_ADMISSIONS(a, &der);
        hex("empty admissions", der, len);
        q = der;
        ADMISSIONS_free(a);
        a = d2i_ADMISSIONS(NULL, &q, len);
        check(a != NULL, "decoded them");
        OPENSSL_free(der);
        NAMING_AUTHORITY_free(na);
        PROFESSION_INFO_free(p);
        ADMISSIONS_free(a);
    }
    NAMING_AUTHORITY_free(NULL);
    PROFESSION_INFO_free(NULL);
    ADMISSIONS_free(NULL);
    ADMISSION_SYNTAX_free(NULL);
}

static void test_decoded(void)
{
    /* An admission with a directory-name authority and a profession of BMP text. */
    static const unsigned char der[] = {
        0x30, 0x2c, 0xa4, 0x0f, 0x30, 0x0d, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x02, 0x43, 0x41,
        0x30, 0x19, 0x30, 0x17, 0x30, 0x15, 0x30, 0x13, 0x30, 0x06, 0x1e, 0x04, 0x00, 0x41, 0x00, 0x42,
        0x30, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x13, 0x02, 0x39, 0x39,
    };
    ASN1_OCTET_STRING *oct = ASN1_OCTET_STRING_new();
    X509_EXTENSION *e;

    printf("# decoded\n");
    ASN1_OCTET_STRING_set(oct, der, sizeof(der));
    e = X509_EXTENSION_create_by_NID(NULL, NID_x509ExtAdmission, 0, oct);
    show_ext("extension", e);
    X509_EXTENSION_free(e);
    ASN1_OCTET_STRING_set(oct, der, sizeof(der) - 3);
    e = X509_EXTENSION_create_by_NID(NULL, NID_x509ExtAdmission, 0, oct);
    show_ext("truncated", e);
    X509_EXTENSION_free(e);
    ASN1_OCTET_STRING_free(oct);
}

/* Each item: a new value encoded through it. */
static void items(void)
{
    const struct {
        const char *name;
        const ASN1_ITEM *it;
    } list[] = {
        {"ADMISSION_SYNTAX", ASN1_ITEM_rptr(ADMISSION_SYNTAX)},
        {"ADMISSIONS", ASN1_ITEM_rptr(ADMISSIONS)},
        {"PROFESSION_INFO", ASN1_ITEM_rptr(PROFESSION_INFO)},
        {"NAMING_AUTHORITY", ASN1_ITEM_rptr(NAMING_AUTHORITY)},
    };
    size_t i;

    printf("# items\n");
    for (i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        ASN1_VALUE *v = ASN1_item_new(list[i].it);
        unsigned char *der = NULL;
        int len = ASN1_item_i2d(v, &der, list[i].it);

        printf("  %s: %d\n", list[i].name, len);
        OPENSSL_free(der);
        ASN1_item_free(v, list[i].it);
    }
    ERR_clear_error();
}

int main(void)
{
    out = BIO_new(BIO_s_mem());
    test_admission();
    test_decoded();
    items();
    BIO_free(out);
    printf("1..%d\n", number);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
