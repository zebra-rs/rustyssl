/*
 * Conformance test for the smaller extensions: Thawte's strong extranet IDs (SXNET_new(3),
 * SXNET_add_id_asc, SXNET_get_id_asc, and their ulong and INTEGER forms), the TLS feature
 * (TLS_FEATURE_new), the issuer's signing tools (ISSUER_SIGN_TOOL_new), and the audit
 * identity, in TAP format: each made from text through its method, encoded, decoded, and
 * printed, with the errors of bad input.
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

/* An extension of `nid` made from `text` through its method's v2i. */
static void make(const char *label, int nid, const char *text)
{
    const X509V3_EXT_METHOD *m = X509V3_EXT_get_nid(nid);
    STACK_OF(CONF_VALUE) *in = X509V3_parse_list(text);
    void *v = m->v2i(m, NULL, in);
    X509_EXTENSION *e = v == NULL ? NULL : X509V3_EXT_i2d(nid, 0, v);

    sk_CONF_VALUE_pop_free(in, X509V3_conf_free);
    printf("# %s\n", label);
    show_ext("extension", e);
    X509_EXTENSION_free(e);
    if (v != NULL)
        ASN1_item_free(v, ASN1_ITEM_ptr(m->it));
}

/* An extension decoded from DER and printed. */
static void decoded(const char *label, int nid, const unsigned char *der, int len)
{
    ASN1_OCTET_STRING *oct = ASN1_OCTET_STRING_new();
    X509_EXTENSION *e;

    ASN1_OCTET_STRING_set(oct, der, len);
    e = X509_EXTENSION_create_by_NID(NULL, nid, 0, oct);
    printf("# %s\n", label);
    show_ext("extension", e);
    X509_EXTENSION_free(e);
    ASN1_OCTET_STRING_free(oct);
}

static void show_user(const char *label, ASN1_OCTET_STRING *user)
{
    if (user == NULL) {
        printf("  %s: none\n", label);
        errors();
        return;
    }
    printf("  %s: [%.*s]\n", label, ASN1_STRING_length(user), (const char *)ASN1_STRING_get0_data(user));
}

static void test_sxnet(void)
{
    SXNET *sx = NULL, *copy;
    ASN1_INTEGER *zone = ASN1_INTEGER_new(), *other = ASN1_INTEGER_new();
    unsigned char *der = NULL;
    const unsigned char *q;
    int len;
    char longuser[66];

    printf("# SXNET\n");
    check(SXNET_add_id_asc(&sx, "1", "alice", -1) == 1, "added zone 1");
    check(sx != NULL, "made the SXNET");
    check(SXNET_add_id_ulong(&sx, 2, "bob\0x", 5) == 1, "added zone 2 with five octets");
    ASN1_INTEGER_set(zone, 0x7fffffff);
    check(SXNET_add_id_INTEGER(&sx, zone, "carol", 3) == 1, "added a large zone");
    check(SXNET_add_id_asc(&sx, "0x10", "dave", -1) == 1, "added zone 0x10");
    check(SXNET_add_id_asc(&sx, "1", "again", -1) == 0, "zone 1 twice fails");
    errors();
    check(SXNET_add_id_ulong(&sx, 2, "again", -1) == 0, "zone 2 twice fails");
    errors();
    check(SXNET_add_id_asc(&sx, "zone", "x", -1) == 0, "a bad zone fails");
    errors();
    memset(longuser, 'u', sizeof(longuser));
    longuser[65] = '\0';
    check(SXNET_add_id_asc(&sx, "3", longuser, -1) == 0, "65 octets is too long");
    errors();
    check(SXNET_add_id_asc(&sx, "3", longuser, 64) == 1, "64 octets is fine");
    check(SXNET_add_id_INTEGER(NULL, other, "x", -1) == 0, "no SXNET slot fails");
    errors();
    check(SXNET_add_id_INTEGER(&sx, NULL, "x", -1) == 0, "no zone fails");
    errors();
    check(SXNET_add_id_INTEGER(&sx, other, NULL, -1) == 0, "no user fails");
    errors();
    show_user("zone 1", SXNET_get_id_asc(sx, "1"));
    show_user("zone 2", SXNET_get_id_ulong(sx, 2));
    show_user("zone 16", SXNET_get_id_asc(sx, "16"));
    ASN1_INTEGER_set(other, 0x7fffffff);
    show_user("large zone", SXNET_get_id_INTEGER(sx, other));
    show_user("zone 9", SXNET_get_id_ulong(sx, 9));
    show_user("bad zone", SXNET_get_id_asc(sx, "nine"));
    printf("  ids: %d\n", sk_SXNETID_num(sx->ids));
    len = i2d_SXNET(sx, &der);
    hex("SXNET", der, len);
    q = der;
    copy = d2i_SXNET(NULL, &q, len);
    check(copy != NULL && q == der + len, "decoded");
    show_user("copy zone 2", SXNET_get_id_ulong(copy, 2));
    decoded("SXNET extension", NID_sxnet, der, len);
    OPENSSL_free(der);
    SXNET_free(copy);
    SXNET_free(sx);
    ASN1_INTEGER_free(other);

    {
        SXNETID *id = SXNETID_new();

        der = NULL;
        len = i2d_SXNETID(id, &der);
        hex("empty SXNETID", der, len);
        SXNETID_free(id);
        q = der;
        id = d2i_SXNETID(NULL, &q, len);
        check(id != NULL, "decoded the empty ID");
        SXNETID_free(id);
        OPENSSL_free(der);
    }
    {
        static const unsigned char v5[] = {0x30, 0x0b, 0x02, 0x01, 0x05, 0x30, 0x06,
                                           0x30, 0x04, 0x02, 0x00, 0x04, 0x00};
        decoded("SXNET version 6 with an empty zone", NID_sxnet, v5, sizeof(v5));
    }
    make("SXNET from text", NID_sxnet, "1:alice,0x20:bob");
    make("SXNET duplicate", NID_sxnet, "1:alice,1:bob");
    make("SXNET bad zone", NID_sxnet, "zz:alice");
    make("SXNET empty", NID_sxnet, "");
    SXNET_free(SXNET_new());
}

static void test_tlsf(void)
{
    TLS_FEATURE *f = TLS_FEATURE_new();

    printf("# TLS feature\n");
    check(f != NULL, "TLS_FEATURE_new");
    printf("  features: %d\n", sk_ASN1_INTEGER_num(f));
    TLS_FEATURE_free(f);
    TLS_FEATURE_free(NULL);
    make("TLS feature names", NID_tlsfeature, "status_request,STATUS_REQUEST_V2");
    make("TLS feature numbers", NID_tlsfeature, "5,17,0,65535,1234");
    make("TLS feature with values", NID_tlsfeature, "x:status_request,y:22");
    make("TLS feature too big", NID_tlsfeature, "65536");
    make("TLS feature negative", NID_tlsfeature, "-1");
    make("TLS feature name", NID_tlsfeature, "status");
    make("TLS feature trailing", NID_tlsfeature, "5x");
    make("TLS feature empty", NID_tlsfeature, "");
}

static void test_ist(void)
{
    ISSUER_SIGN_TOOL *t = ISSUER_SIGN_TOOL_new();
    unsigned char *der = NULL;
    const unsigned char *q;
    int len;

    printf("# issuer sign tool\n");
    len = i2d_ISSUER_SIGN_TOOL(t, &der);
    hex("empty", der, len);
    q = der;
    ISSUER_SIGN_TOOL_free(t);
    t = d2i_ISSUER_SIGN_TOOL(NULL, &q, len);
    check(t != NULL, "decoded");
    ISSUER_SIGN_TOOL_free(t);
    decoded("empty extension", NID_issuerSignTool, der, len);
    OPENSSL_free(der);
    make("all four", NID_issuerSignTool,
         "signTool:tool one,cATool:ca tool,signToolCert:cert 1,cAToolCert:cert 2");
    make("two", NID_issuerSignTool, "cATool:ca,signToolCert:c");
    make("unknown", NID_issuerSignTool, "signtool:lower");
    make("no value", NID_issuerSignTool, "signTool");
    make("twice", NID_issuerSignTool, "signTool:a,signTool:b");
}

static void test_audit(void)
{
    const X509V3_EXT_METHOD *m = X509V3_EXT_get_nid(NID_ac_auditIdentity);
    ASN1_OCTET_STRING *oct;
    X509_EXTENSION *e;
    char *s;

    printf("# audit identity\n");
    check(m != NULL && m->s2i != NULL && m->i2s != NULL, "method");
    oct = m->s2i(m, NULL, "01:02:AB:cd");
    check(oct != NULL && ASN1_STRING_length(oct) == 4, "from hex");
    s = m->i2s(m, oct);
    printf("  text: %s\n", s);
    OPENSSL_free(s);
    e = X509V3_EXT_i2d(NID_ac_auditIdentity, 1, oct);
    show_ext("extension", e);
    X509_EXTENSION_free(e);
    ASN1_OCTET_STRING_free(oct);
    oct = m->s2i(m, NULL, "zz");
    check(oct == NULL, "bad hex");
    errors();
}

/* Each item: a new value encoded through it. */
static void items(void)
{
    const struct {
        const char *name;
        const ASN1_ITEM *it;
    } list[] = {
        {"SXNET", ASN1_ITEM_rptr(SXNET)},
        {"SXNETID", ASN1_ITEM_rptr(SXNETID)},
        {"ISSUER_SIGN_TOOL", ASN1_ITEM_rptr(ISSUER_SIGN_TOOL)},
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
    test_sxnet();
    test_tlsf();
    test_ist();
    test_audit();
    items();
    BIO_free(out);
    printf("1..%d\n", number);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
