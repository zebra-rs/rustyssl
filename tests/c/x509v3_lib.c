/*
 * Conformance test for the X509v3 extension methods (X509V3_EXT_add(3), X509V3_get_d2i(3),
 * X509V3_add1_i2d(3), X509V3_EXT_print(3), X509V3_extensions_print, X509V3_EXT_val_prn) and
 * the simple extensions: key usage and Netscape's certificate type, Netscape's strings, the
 * signing tool, the CRL numbers and reason, inhibitAnyPolicy, the subject key identifier,
 * basic constraints, extended key usage, and the private key usage period. In TAP format:
 * the methods found by NID, an application's method and an alias, values decoded, encoded,
 * added under each flag, and printed (unknown extensions under each flag), the conversions
 * to and from CONF_VALUEs, and the value helpers.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
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

static const char CA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBmTCCAT+gAwIBAgIIEjRWeJCrze8wCgYIKoZIzj0EAwIwMjELMAkGA1UEBhMC\n"
    "SlAxETAPBgNVBAoMCHJ1c3R5c3NsMRAwDgYDVQQDDAdUZXN0IENBMB4XDTI2MTAx\n"
    "NzExNTcyOVoXDTM2MTAxNDExNTcyOVowMjELMAkGA1UEBhMCSlAxETAPBgNVBAoM\n"
    "CHJ1c3R5c3NsMRAwDgYDVQQDDAdUZXN0IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0D\n"
    "AQcDQgAEG8QBqFVH9Y13H0s9Copsp8sUXZPYdQ3axAVnbqLSRU4/Ee5md40Qwqqy\n"
    "B/0BFFHesy61jWDP6FAWuBKm/Hibu6M/MD0wDwYDVR0TAQH/BAUwAwEB/zALBgNV\n"
    "HQ8EBAMCAQYwHQYDVR0OBBYEFFT/pnuNPm1SB+yJgcMJY5Cw5uK3MAoGCCqGSM49\n"
    "BAMCA0gAMEUCIHcVN0GtOf7I7yBYW9wwXEqBZhVMdJVutI2PwKohj1fhAiEA/yez\n"
    "gwPyEeIQYZLF0ykw0qkc1dxRgdA6ClD8WGALKOM=\n"
    "-----END CERTIFICATE-----\n";

static void flush_label(const char *label)
{
    printf("  %s: [", label);
    flush_out();
    printf("]\n");
}

static X509_EXTENSION *ext_of(int nid, int crit, const char *der, int len)
{
    ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
    X509_EXTENSION *e;

    ASN1_OCTET_STRING_set(os, (const unsigned char *)der, len);
    e = X509_EXTENSION_create_by_NID(NULL, nid, crit, os);
    ASN1_OCTET_STRING_free(os);
    return e;
}

static void print_ext(const char *label, X509_EXTENSION *e)
{
    unsigned long flags[] = { X509V3_EXT_DEFAULT, X509V3_EXT_ERROR_UNKNOWN,
                              X509V3_EXT_PARSE_UNKNOWN, X509V3_EXT_DUMP_UNKNOWN };
    int i, r;

    printf("# print %s\n", label);
    for (i = 0; i < 4; i++) {
        r = X509V3_EXT_print(out, e, flags[i], 2);
        printf("  flag %lx -> %d", flags[i], r);
        flush_label("");
    }
    errors();
}

static void test_methods(void)
{
    int nids[] = { NID_key_usage, NID_netscape_cert_type, NID_netscape_comment,
                   NID_subject_key_identifier, NID_basic_constraints, NID_ext_key_usage,
                   NID_crl_number, NID_delta_crl, NID_crl_reason, NID_inhibit_any_policy,
                   NID_private_key_usage_period, NID_subjectSignTool,
                   NID_id_pkix_OCSP_acceptableResponses, NID_subject_alt_name,
                   NID_certificate_policies, NID_associated_information, NID_commonName,
                   NID_undef, -5 };
    size_t i;
    X509V3_EXT_METHOD *mine, copy;
    const X509V3_EXT_METHOD *m;
    X509_EXTENSION *e;
    int nid;

    printf("# methods\n");
    for (i = 0; i < sizeof(nids) / sizeof(nids[0]); i++) {
        m = X509V3_EXT_get_nid(nids[i]);
        printf("  %d: %s", nids[i], m == NULL ? "none" : "found");
        if (m != NULL)
            printf(" nid %d flags %d", m->ext_nid, m->ext_flags);
        printf("\n");
    }
    check(X509V3_add_standard_extensions() == 1, "standard extensions");
    e = ext_of(NID_key_usage, 0, "\x03\x02\x05\xa0", 4);
    check(X509V3_EXT_get(e) == X509V3_EXT_get_nid(NID_key_usage), "found for an extension");
    X509_EXTENSION_free(e);
    nid = OBJ_create("1.2.3.4.55", "myExt", "My Extension");
    check(X509V3_EXT_get_nid(nid) == NULL, "none for a new NID");
    copy = *X509V3_EXT_get_nid(NID_netscape_comment);
    copy.ext_nid = nid;
    mine = &copy;
    check(X509V3_EXT_add(mine) == 1, "an application's method");
    check(X509V3_EXT_get_nid(nid) == mine, "found");
    check(X509V3_EXT_add_alias(NID_netscape_comment, nid) == 1, "an alias of a built-in NID");
    check(X509V3_EXT_get_nid(NID_netscape_comment) != mine, "the built-in one first");
    printf("  alias of nothing: %d\n", X509V3_EXT_add_alias(nid + 1, 99999));
    errors();
    e = ext_of(nid, 0, "\x16\x02hi", 4);
    print_ext("an application's", e);
    X509_EXTENSION_free(e);
    X509V3_EXT_cleanup();
    check(X509V3_EXT_get_nid(nid) == NULL, "gone after cleanup");
    {
        X509V3_EXT_METHOD list[3];

        list[0] = *X509V3_EXT_get_nid(NID_netscape_comment);
        list[0].ext_nid = nid;
        list[1] = list[0];
        list[1].ext_nid = OBJ_create("1.2.3.4.56", "myExt2", "My Extension 2");
        list[2].ext_nid = -1;
        check(X509V3_EXT_add_list(list) == 1, "a list added");
        check(X509V3_EXT_get_nid(list[1].ext_nid) == &list[1], "its second found");
        X509V3_EXT_cleanup();
    }
    check(X509V3_EXT_get_nid(NID_key_usage) != NULL, "the built-in ones stay");
}

static void test_print(void)
{
    X509_EXTENSION *e;
    STACK_OF(X509_EXTENSION) *sk = sk_X509_EXTENSION_new_null();
    struct {
        const char *label;
        int nid, crit;
        const char *der;
        int len;
    } cases[] = {
        { "key usage", NID_key_usage, 1, "\x03\x02\x05\xa0", 4 },
        { "key usage, decipher only", NID_key_usage, 0, "\x03\x03\x07\x00\x80", 5 },
        { "key usage, none", NID_key_usage, 0, "\x03\x01\x00", 3 },
        { "cert type", NID_netscape_cert_type, 0, "\x03\x02\x00\xff", 4 },
        { "comment", NID_netscape_comment, 0, "\x16\x0bHello world", 13 },
        { "empty comment", NID_netscape_comment, 0, "\x16\x00", 2 },
        { "base URL", NID_netscape_base_url, 0, "\x16\x05http:", 7 },
        { "sign tool", NID_subjectSignTool, 0, "\x0c\x06tool\xc3\xa9", 8 },
        { "empty sign tool", NID_subjectSignTool, 0, "\x0c\x00", 2 },
        { "CRL number", NID_crl_number, 0, "\x02\x02\x01\x00", 4 },
        { "big CRL number", NID_crl_number, 0, "\x02\x11\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 19 },
        { "delta", NID_delta_crl, 1, "\x02\x01\xff", 3 },
        { "reason", NID_crl_reason, 0, "\x0a\x01\x01", 3 },
        { "reason 7", NID_crl_reason, 0, "\x0a\x01\x07", 3 },
        { "reason 42", NID_crl_reason, 0, "\x0a\x01\x2a", 3 },
        { "inhibit", NID_inhibit_any_policy, 1, "\x02\x01\x00", 3 },
        { "skid", NID_subject_key_identifier, 0, "\x04\x04\xde\xad\xbe\xef", 6 },
        { "empty skid", NID_subject_key_identifier, 0, "\x04\x00", 2 },
        { "basic constraints CA", NID_basic_constraints, 1, "\x30\x06\x01\x01\xff\x02\x01\x03", 8 },
        { "basic constraints empty", NID_basic_constraints, 0, "\x30\x00", 2 },
        { "basic constraints, broken", NID_basic_constraints, 0, "\x30\x03\x01\x01", 4 },
        { "eku", NID_ext_key_usage, 0, "\x30\x14\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x02", 22 },
        { "eku, unknown OID", NID_ext_key_usage, 0, "\x30\x05\x06\x03\x2a\x03\x04", 7 },
        { "eku, empty", NID_ext_key_usage, 0, "\x30\x00", 2 },
        { "OCSP acceptable responses", NID_id_pkix_OCSP_acceptableResponses, 0, "\x30\x0b\x06\x09\x2b\x06\x01\x05\x05\x07\x30\x01\x01", 13 },
        { "usage period", NID_private_key_usage_period, 0, "\x30\x22\x80\x0f" "20240101000000Z" "\x81\x0f" "20250101000000Z", 36 },
        { "usage period, start", NID_private_key_usage_period, 0, "\x30\x11\x80\x0f" "20240101000000Z", 19 },
        { "usage period, end", NID_private_key_usage_period, 0, "\x30\x11\x81\x0f" "20250101000000Z", 19 },
        { "usage period, none", NID_private_key_usage_period, 0, "\x30\x00", 2 },
        { "unknown", NID_commonName, 0, "\x30\x03\x02\x01\x05", 5 },
        { "unknown, not DER", NID_commonName, 0, "\xff\x00\x01", 3 },
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        e = ext_of(cases[i].nid, cases[i].crit, cases[i].der, cases[i].len);
        print_ext(cases[i].label, e);
        sk_X509_EXTENSION_push(sk, e);
    }
    printf("# extensions_print\n");
    check(X509V3_extensions_print(out, "X509v3 extensions", sk, 0, 4) == 1, "printed");
    flush_label("titled");
    check(X509V3_extensions_print(out, NULL, sk, X509V3_EXT_ERROR_UNKNOWN, 0) == 1, "printed");
    flush_label("untitled, errors shown");
    check(X509V3_extensions_print(out, "kid", sk, X509_FLAG_EXTENSIONS_ONLY_KID, 2) == 1, "printed");
    flush_label("key identifiers only");
    check(X509V3_extensions_print(out, "none", NULL, 0, 2) == 1, "none");
    flush_label("no extensions");
    {
        FILE *f = tmpfile();
        char buf[256];
        size_t n;

        check(X509V3_EXT_print_fp(f, sk_X509_EXTENSION_value(sk, 0), 0, 3) == 1, "to a FILE");
        rewind(f);
        n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        printf("  [%s]\n", buf);
        fclose(f);
    }
    sk_X509_EXTENSION_pop_free(sk, X509_EXTENSION_free);
}

static void test_d2i(void)
{
    STACK_OF(X509_EXTENSION) *sk = NULL;
    BASIC_CONSTRAINTS *bc;
    ASN1_BIT_STRING *ku;
    EXTENDED_KEY_USAGE *eku;
    ASN1_OCTET_STRING *skid;
    ASN1_INTEGER *num;
    int crit = 99, idx = -1, r;
    X509_EXTENSION *e;
    unsigned char *der = NULL;

    printf("# get_d2i and add1_i2d\n");
    bc = X509V3_get_d2i(NULL, NID_basic_constraints, &crit, &idx);
    printf("  no stack: %p crit %d idx %d\n", (void *)bc, crit, idx);
    bc = BASIC_CONSTRAINTS_new();
    bc->ca = 0xff;
    bc->pathlen = ASN1_INTEGER_new();
    ASN1_INTEGER_set(bc->pathlen, 2);
    check(X509V3_add1_i2d(&sk, NID_basic_constraints, bc, 1, X509V3_ADD_DEFAULT) == 1, "added");
    printf("  again, default: %d\n", X509V3_add1_i2d(&sk, NID_basic_constraints, bc, 1, X509V3_ADD_DEFAULT));
    errors();
    printf("  again, silent: %d\n", X509V3_add1_i2d(&sk, NID_basic_constraints, bc, 1, X509V3_ADD_DEFAULT | X509V3_ADD_SILENT));
    errors();
    check(X509V3_add1_i2d(&sk, NID_basic_constraints, bc, 0, X509V3_ADD_KEEP_EXISTING) == 1, "kept");
    ASN1_INTEGER_set(bc->pathlen, 7);
    check(X509V3_add1_i2d(&sk, NID_basic_constraints, bc, 0, X509V3_ADD_REPLACE_EXISTING) == 1, "replaced");
    check(X509V3_add1_i2d(&sk, NID_basic_constraints, bc, 0, X509V3_ADD_APPEND) == 1, "appended");
    BASIC_CONSTRAINTS_free(bc);
    printf("  count %d\n", sk_X509_EXTENSION_num(sk));
    bc = X509V3_get_d2i(sk, NID_basic_constraints, &crit, NULL);
    printf("  two without idx: %p crit %d\n", (void *)bc, crit);
    idx = -1;
    bc = X509V3_get_d2i(sk, NID_basic_constraints, &crit, &idx);
    check(bc != NULL, "the first with idx");
    printf("  crit %d idx %d ca %d pathlen %ld\n", crit, idx, bc->ca, ASN1_INTEGER_get(bc->pathlen));
    BASIC_CONSTRAINTS_free(bc);
    bc = X509V3_get_d2i(sk, NID_basic_constraints, &crit, &idx);
    printf("  the next: crit %d idx %d\n", crit, idx);
    BASIC_CONSTRAINTS_free(bc);
    bc = X509V3_get_d2i(sk, NID_basic_constraints, &crit, &idx);
    printf("  none after: %p crit %d idx %d\n", (void *)bc, crit, idx);
    printf("  delete absent: %d\n", X509V3_add1_i2d(&sk, NID_key_usage, NULL, 0, X509V3_ADD_DELETE));
    errors();
    printf("  replace absent: %d\n", X509V3_add1_i2d(&sk, NID_key_usage, NULL, 0, X509V3_ADD_REPLACE_EXISTING));
    errors();
    check(X509V3_add1_i2d(&sk, NID_basic_constraints, NULL, 0, X509V3_ADD_DELETE) == 1, "deleted");
    printf("  count %d\n", sk_X509_EXTENSION_num(sk));
    ku = ASN1_BIT_STRING_new();
    ASN1_BIT_STRING_set_bit(ku, 0, 1);
    ASN1_BIT_STRING_set_bit(ku, 5, 1);
    check(X509V3_add1_i2d(&sk, NID_key_usage, ku, 1, 0) == 1, "key usage added");
    ASN1_BIT_STRING_free(ku);
    eku = sk_ASN1_OBJECT_new_null();
    sk_ASN1_OBJECT_push(eku, OBJ_nid2obj(NID_server_auth));
    sk_ASN1_OBJECT_push(eku, OBJ_nid2obj(NID_code_sign));
    check(X509V3_add1_i2d(&sk, NID_ext_key_usage, eku, 0, 0) == 1, "extended key usage added");
    sk_ASN1_OBJECT_pop_free(eku, ASN1_OBJECT_free);
    printf("  unknown NID: %d\n", X509V3_add1_i2d(&sk, NID_commonName, ku, 0, 0));
    errors();
    e = X509V3_EXT_i2d(NID_commonName, 0, NULL);
    printf("  EXT_i2d unknown: %p\n", (void *)e);
    errors();
    skid = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(skid, (const unsigned char *)"\x01\x02\x03", 3);
    e = X509V3_EXT_i2d(NID_subject_key_identifier, 0, skid);
    ASN1_OCTET_STRING_free(skid);
    r = i2d_X509_EXTENSION(e, &der);
    hex("skid extension", der, r);
    OPENSSL_free(der);
    skid = X509V3_EXT_d2i(e);
    check(skid != NULL && ASN1_STRING_length(skid) == 3, "decoded back");
    ASN1_OCTET_STRING_free(skid);
    X509_EXTENSION_free(e);
    num = ASN1_INTEGER_new();
    ASN1_INTEGER_set(num, 1234);
    check(X509V3_add1_i2d(&sk, NID_crl_number, num, 0, 0) == 1, "CRL number added");
    ASN1_INTEGER_free(num);
    ku = X509V3_get_d2i(sk, NID_key_usage, &crit, NULL);
    check(ku != NULL && ASN1_BIT_STRING_get_bit(ku, 5) == 1 && crit == 1, "key usage read");
    ASN1_BIT_STRING_free(ku);
    eku = X509V3_get_d2i(sk, NID_ext_key_usage, NULL, NULL);
    check(eku != NULL && sk_ASN1_OBJECT_num(eku) == 2, "eku read");
    EXTENDED_KEY_USAGE_free(eku);
    check(X509V3_extensions_print(out, "built", sk, 0, 0) == 1, "printed");
    flush_label("built");
    e = ext_of(NID_basic_constraints, 0, "\x30\x03\x01\x01", 4);
    printf("  EXT_d2i of broken: %p\n", X509V3_EXT_d2i(e));
    errors();
    X509_EXTENSION_free(e);
    e = ext_of(NID_commonName, 0, "\x30\x00", 2);
    printf("  EXT_d2i of unknown: %p\n", X509V3_EXT_d2i(e));
    X509_EXTENSION_free(e);
    sk_X509_EXTENSION_pop_free(sk, X509_EXTENSION_free);
}

static void show_vals(const char *label, STACK_OF(CONF_VALUE) *v)
{
    printf("  %s:", label);
    if (v == NULL) {
        printf(" NULL\n");
        errors();
        return;
    }
    X509V3_EXT_val_prn(out, v, 0, 0);
    flush_label(" one line");
    X509V3_EXT_val_prn(out, v, 3, 1);
    flush_label(" lines");
    sk_CONF_VALUE_pop_free(v, X509V3_conf_free);
}

static void test_conversions(void)
{
    const X509V3_EXT_METHOD *ku = X509V3_EXT_get_nid(NID_key_usage);
    const X509V3_EXT_METHOD *bcm = X509V3_EXT_get_nid(NID_basic_constraints);
    const X509V3_EXT_METHOD *ekum = X509V3_EXT_get_nid(NID_ext_key_usage);
    const X509V3_EXT_METHOD *skm = X509V3_EXT_get_nid(NID_subject_key_identifier);
    const X509V3_EXT_METHOD *ia = X509V3_EXT_get_nid(NID_inhibit_any_policy);
    STACK_OF(CONF_VALUE) *v = NULL, *in;
    ASN1_BIT_STRING *bs;
    BASIC_CONSTRAINTS *bc;
    EXTENDED_KEY_USAGE *eku;
    ASN1_OCTET_STRING *os;
    ASN1_IA5STRING *ia5;
    ASN1_UTF8STRING *u8;
    ASN1_INTEGER *n;
    char *s;
    unsigned char *der = NULL;
    int len;
    X509V3_CTX ctx;

    printf("# conversions\n");
    in = X509V3_parse_list("digitalSignature, Key Encipherment,cRLSign");
    bs = v2i_ASN1_BIT_STRING((X509V3_EXT_METHOD *)ku, NULL, in);
    sk_CONF_VALUE_pop_free(in, X509V3_conf_free);
    len = i2d_ASN1_BIT_STRING(bs, &der);
    hex("key usage", der, len);
    OPENSSL_free(der);
    der = NULL;
    show_vals("i2v", i2v_ASN1_BIT_STRING((X509V3_EXT_METHOD *)ku, bs, NULL));
    ASN1_BIT_STRING_free(bs);
    in = X509V3_parse_list("digitalSignature,bogus");
    bs = v2i_ASN1_BIT_STRING((X509V3_EXT_METHOD *)ku, NULL, in);
    printf("  unknown bit: %p\n", (void *)bs);
    errors();
    sk_CONF_VALUE_pop_free(in, X509V3_conf_free);
    in = X509V3_parse_list("CA:TRUE,pathlen:0");
    bc = bcm->v2i(bcm, NULL, in);
    sk_CONF_VALUE_pop_free(in, X509V3_conf_free);
    len = i2d_BASIC_CONSTRAINTS(bc, &der);
    hex("basic constraints", der, len);
    OPENSSL_free(der);
    der = NULL;
    show_vals("i2v", bcm->i2v(bcm, bc, NULL));
    BASIC_CONSTRAINTS_free(bc);
    in = X509V3_parse_list("CA:maybe");
    printf("  bad CA: %p\n", bcm->v2i(bcm, NULL, in));
    errors();
    sk_CONF_VALUE_pop_free(in, X509V3_conf_free);
    in = X509V3_parse_list("pathlen:abc");
    printf("  bad pathlen: %p\n", bcm->v2i(bcm, NULL, in));
    errors();
    sk_CONF_VALUE_pop_free(in, X509V3_conf_free);
    in = X509V3_parse_list("ca:TRUE");
    printf("  bad name: %p\n", bcm->v2i(bcm, NULL, in));
    errors();
    sk_CONF_VALUE_pop_free(in, X509V3_conf_free);
    in = X509V3_parse_list("serverAuth,1.2.3.4,emailProtection");
    eku = ekum->v2i(ekum, NULL, in);
    sk_CONF_VALUE_pop_free(in, X509V3_conf_free);
    len = i2d_EXTENDED_KEY_USAGE(eku, &der);
    hex("eku", der, len);
    OPENSSL_free(der);
    der = NULL;
    show_vals("i2v", ekum->i2v(ekum, eku, NULL));
    EXTENDED_KEY_USAGE_free(eku);
    in = X509V3_parse_list("serverAuth,notAnOID");
    printf("  bad OID: %p\n", ekum->v2i(ekum, NULL, in));
    errors();
    sk_CONF_VALUE_pop_free(in, X509V3_conf_free);
    show_vals("empty", sk_CONF_VALUE_new_null());

    os = skm->s2i(skm, NULL, "01:02:aB");
    s = skm->i2s(skm, os);
    printf("  skid hex: %s\n", s);
    OPENSSL_free(s);
    ASN1_OCTET_STRING_free(os);
    os = skm->s2i(skm, NULL, "none");
    printf("  skid none: %d\n", ASN1_STRING_length(os));
    ASN1_OCTET_STRING_free(os);
    printf("  skid hash without a subject: %p\n", skm->s2i(skm, NULL, "hash"));
    errors();
    memset(&ctx, 0, sizeof(ctx));
    ctx.flags = X509V3_CTX_TEST;
    os = skm->s2i(skm, &ctx, "hash");
    printf("  skid hash in a test context: %d\n", ASN1_STRING_length(os));
    ASN1_OCTET_STRING_free(os);
    {
        BIO *b = BIO_new_mem_buf(CA_PEM, -1);
        X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);

        BIO_free(b);
        memset(&ctx, 0, sizeof(ctx));
        ctx.subject_cert = x;
        os = skm->s2i(skm, &ctx, "hash");
        s = skm->i2s(skm, os);
        printf("  skid hash of the CA's key: %s\n", s);
        OPENSSL_free(s);
        ASN1_OCTET_STRING_free(os);
        X509_free(x);
    }
    printf("  skid bad hex: %p\n", skm->s2i(skm, NULL, "0g"));
    errors();
    n = ia->s2i(ia, NULL, "0x10");
    s = ia->i2s(ia, n);
    printf("  inhibit 0x10: %s\n", s);
    OPENSSL_free(s);
    ASN1_INTEGER_free(n);

    ia5 = s2i_ASN1_IA5STRING(NULL, NULL, "an IA5 string");
    s = i2s_ASN1_IA5STRING(NULL, ia5);
    printf("  ia5: %s type %d\n", s, ASN1_STRING_type(ia5));
    OPENSSL_free(s);
    ASN1_STRING_set(ia5, "", 0);
    printf("  empty ia5: %p\n", (void *)i2s_ASN1_IA5STRING(NULL, ia5));
    ASN1_IA5STRING_free(ia5);
    printf("  NULL: %p %p\n", (void *)s2i_ASN1_IA5STRING(NULL, NULL, NULL),
           (void *)i2s_ASN1_IA5STRING(NULL, NULL));
    errors();
    u8 = s2i_ASN1_UTF8STRING(NULL, NULL, "caf\xc3\xa9");
    s = i2s_ASN1_UTF8STRING(NULL, u8);
    printf("  utf8: %s type %d\n", s, ASN1_STRING_type(u8));
    OPENSSL_free(s);
    ASN1_STRING_set(u8, "", 0);
    printf("  empty utf8: %p\n", (void *)i2s_ASN1_UTF8STRING(NULL, u8));
    errors();
    ASN1_UTF8STRING_free(u8);
    printf("  NULL: %p\n", (void *)s2i_ASN1_UTF8STRING(NULL, NULL, NULL));
    errors();

    printf("# value helpers\n");
    n = ASN1_INTEGER_new();
    ASN1_INTEGER_set(n, -300);
    check(X509V3_add_value_bool("yes", 1, &v) == 1 && X509V3_add_value_bool("no", 0, &v) == 1,
          "booleans");
    check(X509V3_add_value_bool_nf("nf yes", 7, &v) == 1 && X509V3_add_value_bool_nf("nf no", 0, &v) == 1,
          "booleans, false left out");
    check(X509V3_add_value_int("int", n, &v) == 1 && X509V3_add_value_int("none", NULL, &v) == 1,
          "integers");
    check(X509V3_add_value_uchar("uchar", (const unsigned char *)"octets", &v) == 1, "octets");
    check(X509V3_add_value_uchar(NULL, NULL, &v) == 1, "nothing");
    X509V3_conf_free(sk_CONF_VALUE_pop(v));
    ASN1_INTEGER_free(n);
    n = NULL;
    printf("  get_value_int %d", X509V3_get_value_int(sk_CONF_VALUE_value(v, 3), &n));
    printf(" -> %ld\n", ASN1_INTEGER_get(n));
    ASN1_INTEGER_free(n);
    n = NULL;
    printf("  get_value_int of TRUE: %d\n", X509V3_get_value_int(sk_CONF_VALUE_value(v, 0), &n));
    errors();
    show_vals("values", v);
}

static void test_items(void)
{
    BASIC_CONSTRAINTS *bc = BASIC_CONSTRAINTS_new();
    PKEY_USAGE_PERIOD *pku = PKEY_USAGE_PERIOD_new();
    EXTENDED_KEY_USAGE *eku = EXTENDED_KEY_USAGE_new();
    unsigned char *der = NULL;
    const unsigned char *q;
    int len;

    printf("# items\n");
    len = i2d_BASIC_CONSTRAINTS(bc, &der);
    hex("empty basic constraints", der, len);
    q = der;
    BASIC_CONSTRAINTS_free(bc);
    bc = d2i_BASIC_CONSTRAINTS(NULL, &q, len);
    check(bc != NULL && bc->ca == 0 && bc->pathlen == NULL, "decoded");
    OPENSSL_free(der);
    der = NULL;
    len = i2d_PKEY_USAGE_PERIOD(pku, &der);
    hex("empty usage period", der, len);
    q = der;
    PKEY_USAGE_PERIOD_free(pku);
    pku = d2i_PKEY_USAGE_PERIOD(NULL, &q, len);
    check(pku != NULL, "decoded");
    OPENSSL_free(der);
    der = NULL;
    len = i2d_EXTENDED_KEY_USAGE(eku, &der);
    hex("empty eku", der, len);
    q = der;
    EXTENDED_KEY_USAGE_free(eku);
    eku = d2i_EXTENDED_KEY_USAGE(NULL, &q, len);
    check(eku != NULL && sk_ASN1_OBJECT_num(eku) == 0, "decoded");
    OPENSSL_free(der);
    check(ASN1_ITEM_rptr(BASIC_CONSTRAINTS) != NULL && ASN1_ITEM_rptr(PKEY_USAGE_PERIOD) != NULL
              && ASN1_ITEM_rptr(EXTENDED_KEY_USAGE) != NULL, "the items");
    BASIC_CONSTRAINTS_free(bc);
    PKEY_USAGE_PERIOD_free(pku);
    EXTENDED_KEY_USAGE_free(eku);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("TAP version 13\n");
    out = BIO_new(BIO_s_mem());
    test_methods();
    test_print();
    test_d2i();
    test_conversions();
    test_items();
    BIO_free(out);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
