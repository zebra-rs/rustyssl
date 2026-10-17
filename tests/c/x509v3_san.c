/*
 * Conformance test for general names and alternative names (GENERAL_NAME_new(3),
 * GENERAL_NAME_cmp, GENERAL_NAME_print, i2v_GENERAL_NAMES, v2i_GENERAL_NAME(_ex),
 * a2i_GENERAL_NAME, a2i_IPADDRESS(_NC), X509V3_set_ctx(3), X509V3_get_section,
 * X509V3_NAME_from_section), in TAP format: a certificate's subject alternative names of every
 * type printed, listed, compared, and copied; names made from text (each type, IP addresses
 * and networks of both families, directory names from a configuration's section, e-mail
 * addresses copied and moved from the subject, the issuer's names copied), with the errors of
 * bad input; and the extension context's setters and configuration.
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

static const char SAN_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICaTCCAg6gAwIBAgIBCTAKBggqhkjOPQQDAjA1MRQwEgYDVQQDDAtzYW4uZXhh\n"
    "bXBsZTEdMBsGCSqGSIb3DQEJARYObWVAc2FuLmV4YW1wbGUwHhcNMjYxMDE3MTMw\n"
    "ODE3WhcNMjYxMTE2MTMwODE3WjA1MRQwEgYDVQQDDAtzYW4uZXhhbXBsZTEdMBsG\n"
    "CSqGSIb3DQEJARYObWVAc2FuLmV4YW1wbGUwWTATBgcqhkjOPQIBBggqhkjOPQMB\n"
    "BwNCAAQbxAGoVUf1jXcfSz0KimynyxRdk9h1DdrEBWduotJFTj8R7mZ3jRDCqrIH\n"
    "/QEUUd6zLrWNYM/oUBa4Eqb8eJu7o4IBDTCCAQkwgecGA1UdEQSB3zCB3IILc2Fu\n"
    "LmV4YW1wbGWCDSouc2FuLmV4YW1wbGWHBMAAAgGHECABDbgAAAAAAAAAAAAAAAGB\n"
    "C2FAYi5leGFtcGxlhhVodHRwczovL3Nhbi5leGFtcGxlL3iIAyoDBKQiMCAxCzAJ\n"
    "BgNVBAYTAkpQMREwDwYDVQQDDAhkaXIgbmFtZaAbBgorBgEEAYI3FAIDoA0MC3Vw\n"
    "bkBleGFtcGxloCAGCCsGAQUFBwgHoBQWEl9odHRwLl90Y3AuZXhhbXBsZaANBgQq\n"
    "AwQFoAUWA3Jhd6ALBgQqAwQGoAMCAQcwHQYDVR0OBBYEFFT/pnuNPm1SB+yJgcMJ\n"
    "Y5Cw5uK3MAoGCCqGSM49BAMCA0kAMEYCIQCD6dNPpeBMXWBOjrsYKbX7IZhSJUEz\n"
    "P6uLCHvGRUZ5nAIhAO4wmSaCs/gts7VHNVlZLSllnGzlP+9/w6VCT7Th3ENh\n"
    "-----END CERTIFICATE-----\n";
static const char CA_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOemUpeykgSE1rLlH\n"
    "3fPOAKOIoMBM0znLrB7aLijA3A6hRANCAAQbxAGoVUf1jXcfSz0KimynyxRdk9h1\n"
    "DdrEBWduotJFTj8R7mZ3jRDCqrIH/QEUUd6zLrWNYM/oUBa4Eqb8eJu7\n"
    "-----END PRIVATE KEY-----\n";

static const char CONF_TEXT[] =
    "[dir]\n"
    "C=JP\n"
    "1.OU=one\n"
    "2.OU=two\n"
    "+CN=joined\n"
    "[empty]\n";

static X509 *read_cert(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);

    BIO_free(b);
    return x;
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
    printf(" [");
    flush_out();
    printf("]\n");
    sk_CONF_VALUE_pop_free(v, X509V3_conf_free);
}

static void show_names(const char *label, GENERAL_NAMES *gens)
{
    int i;
    unsigned char *der = NULL;
    int len;

    if (gens == NULL) {
        printf("  %s: NULL\n", label);
        errors();
        return;
    }
    printf("  %s: %d\n", label, sk_GENERAL_NAME_num(gens));
    for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
        printf("    %d [", sk_GENERAL_NAME_value(gens, i)->type);
        printf("%d", GENERAL_NAME_print(out, sk_GENERAL_NAME_value(gens, i)));
        printf("] ");
        flush_out();
        printf("\n");
    }
    len = i2d_GENERAL_NAMES(gens, &der);
    hex("der", der, len);
    OPENSSL_free(der);
}

static GENERAL_NAME *from_der(const char *der, long len)
{
    const unsigned char *p = (const unsigned char *)der;

    return d2i_GENERAL_NAME(NULL, &p, len);
}

static void test_decoded(void)
{
    X509 *x = read_cert(SAN_PEM);
    GENERAL_NAMES *gens;
    X509_EXTENSION *e = X509_get_ext(x, X509_get_ext_by_NID(x, NID_subject_alt_name, -1));
    GENERAL_NAME *a, *b;
    int i, j;

    printf("# decoded\n");
    gens = X509V3_EXT_d2i(e);
    show_names("subject alternative names", gens);
    show_vals("i2v", i2v_GENERAL_NAMES(NULL, gens, NULL));
    check(X509V3_EXT_print(out, e, 0, 2) == 1, "printed");
    printf("  [");
    flush_out();
    printf("]\n");
    printf("  cmp:");
    for (i = 0; i < sk_GENERAL_NAME_num(gens); i++)
        for (j = 0; j < sk_GENERAL_NAME_num(gens); j++)
            printf("%s%d", j == 0 ? " " : "", GENERAL_NAME_cmp(sk_GENERAL_NAME_value(gens, i),
                                                              sk_GENERAL_NAME_value(gens, j)) == 0);
    printf("\n");
    for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
        int type;
        a = sk_GENERAL_NAME_value(gens, i);
        b = GENERAL_NAME_dup(a);
        check(b != NULL && GENERAL_NAME_cmp(a, b) == 0, "a copy compares equal");
        check(GENERAL_NAME_get0_value(b, &type) != NULL && type == a->type, "its value");
        GENERAL_NAME_free(b);
    }
    {
        ASN1_OBJECT *oid;
        ASN1_TYPE *val;
        a = sk_GENERAL_NAME_value(gens, 8);
        printf("  get0_otherName: %d", GENERAL_NAME_get0_otherName(a, &oid, &val));
        printf(" %d %d\n", OBJ_obj2nid(oid), val->type);
        printf("  of a DNS name: %d\n", GENERAL_NAME_get0_otherName(sk_GENERAL_NAME_value(gens, 0), NULL, NULL));
        printf("  OTHERNAME_cmp: %d %d %d\n",
               OTHERNAME_cmp(sk_GENERAL_NAME_value(gens, 8)->d.otherName, sk_GENERAL_NAME_value(gens, 8)->d.otherName),
               OTHERNAME_cmp(sk_GENERAL_NAME_value(gens, 8)->d.otherName, sk_GENERAL_NAME_value(gens, 9)->d.otherName) != 0,
               OTHERNAME_cmp(NULL, NULL));
    }
    GENERAL_NAMES_free(gens);
    X509_free(x);

    printf("# odd names\n");
    {
        struct {
            const char *label;
            const char *der;
            long len;
        } cases[] = {
            { "x400", "\xa3\x03\x02\x01\x01", 5 },
            { "edi party", "\xa5\x08\xa1\x06\x0c\x04\x70\x61\x72\x74", 10 },
            { "edi party, assigner", "\xa5\x0f\xa0\x05\x0c\x03\x61\x73\x73\xa1\x06\x0c\x04\x70\x61\x72\x74", 17 },
            { "IP of 3 octets", "\x87\x03\x01\x02\x03", 5 },
            { "IP of 0 octets", "\x87\x00", 2 },
            { "IPv4 network", "\x87\x08\x0a\x00\x00\x00\xff\x00\x00\x00", 10 },
            { "empty DNS", "\x82\x00", 2 },
            { "DNS with a NUL", "\x82\x03\x61\x00\x62", 5 },
            { "SmtpUTF8Mailbox", "\xa0\x15\x06\x08\x2b\x06\x01\x05\x05\x07\x08\x09\xa0\x09\x0c\x07\x61\x40\x62\x2e\x63\x6f\x6d", 23 },
            { "XmppAddr as IA5", "\xa0\x10\x06\x08\x2b\x06\x01\x05\x05\x07\x08\x05\xa0\x04\x16\x02\x68\x69", 18 },
            { "NAIRealm", "\xa0\x12\x06\x08\x2b\x06\x01\x05\x05\x07\x08\x08\xa0\x06\x0c\x04\x72\x65\x61\x6c", 20 },
            { "not DER", "\x82\x80\x00\x00", 4 },
        };
        size_t k;

        for (k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
            GENERAL_NAMES *one;

            a = from_der(cases[k].der, cases[k].len);
            if (a == NULL) {
                printf("  %s: no name\n", cases[k].label);
                errors();
                continue;
            }
            one = sk_GENERAL_NAME_new_null();
            sk_GENERAL_NAME_push(one, a);
            show_names(cases[k].label, one);
            show_vals("i2v", i2v_GENERAL_NAME(NULL, a, NULL));
            b = GENERAL_NAME_dup(a);
            printf("  cmp with a copy: %d\n", GENERAL_NAME_cmp(a, b));
            GENERAL_NAME_free(b);
            GENERAL_NAMES_free(one);
        }
    }
}

static void test_set(void)
{
    GENERAL_NAME *g = GENERAL_NAME_new(), *h = NULL;
    X509_NAME *n = X509_NAME_new();
    ASN1_IA5STRING *s = ASN1_IA5STRING_new();
    ASN1_TYPE *t = ASN1_TYPE_new();
    int type = -1;

    printf("# setting\n");
    ASN1_STRING_set(s, "set.example", -1);
    GENERAL_NAME_set0_value(g, GEN_DNS, s);
    check(GENERAL_NAME_get0_value(g, &type) == s && type == GEN_DNS, "set0 and get0");
    GENERAL_NAME_free(g);
    g = GENERAL_NAME_new();
    ASN1_TYPE_set(t, V_ASN1_NULL, NULL);
    check(GENERAL_NAME_set0_othername(g, OBJ_nid2obj(NID_ms_upn), t) == 1, "an other name");
    GENERAL_NAME_print(out, g);
    printf("  [");
    flush_out();
    printf("]\n");
    GENERAL_NAME_free(g);
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)"dn", -1, -1, 0);
    check(GENERAL_NAME_set1_X509_NAME(&h, n) == 1 && h->type == GEN_DIRNAME, "a directory name");
    check(GENERAL_NAME_set1_X509_NAME(&h, NULL) == 1 && X509_NAME_entry_count(h->d.dirn) == 0,
          "an empty one");
    printf("  NULL target: %d\n", GENERAL_NAME_set1_X509_NAME(NULL, n));
    errors();
    printf("  get0_value of an unknown type: ");
    h->type = 42;
    printf("%p\n", GENERAL_NAME_get0_value(h, &type));
    h->type = GEN_DIRNAME;
    printf("  cmp NULL %d, types differ %d\n", GENERAL_NAME_cmp(NULL, h), 0);
    GENERAL_NAME_free(h);
    X509_NAME_free(n);
    {
        GENERAL_NAMES *gn = GENERAL_NAMES_new();
        OTHERNAME *on = OTHERNAME_new();
        EDIPARTYNAME *ed = EDIPARTYNAME_new();
        unsigned char *der = NULL;
        int len;

        len = i2d_GENERAL_NAMES(gn, &der);
        hex("empty names", der, len);
        {
            const unsigned char *q = der;
            GENERAL_NAMES *g2 = d2i_GENERAL_NAMES(NULL, &q, len);
            GENERAL_NAME *one = GENERAL_NAME_new();
            unsigned char *d2 = NULL;
            int l2;

            check(g2 != NULL && sk_GENERAL_NAME_num(g2) == 0, "empty names decoded");
            GENERAL_NAMES_free(g2);
            GENERAL_NAME_set0_value(one, GEN_RID, OBJ_nid2obj(NID_commonName));
            l2 = i2d_GENERAL_NAME(one, &d2);
            hex("a registered ID", d2, l2);
            OPENSSL_free(d2);
            GENERAL_NAME_free(one);
        }
        OPENSSL_free(der);
        der = NULL;
        len = i2d_OTHERNAME(on, &der);
        printf("  empty other name: %d\n", len);
        errors();
        OPENSSL_free(der);
        der = NULL;
        len = i2d_EDIPARTYNAME(ed, &der);
        printf("  empty EDI party name: %d\n", len);
        errors();
        OPENSSL_free(der);
        check(ASN1_ITEM_rptr(GENERAL_NAME) != NULL && ASN1_ITEM_rptr(GENERAL_NAMES) != NULL
                  && ASN1_ITEM_rptr(OTHERNAME) != NULL && ASN1_ITEM_rptr(EDIPARTYNAME) != NULL,
              "the items");
        {
            const unsigned char *p = (const unsigned char *)"\x30\x00";
            OTHERNAME *o2 = d2i_OTHERNAME(NULL, &p, 2);
            EDIPARTYNAME *e2;

            printf("  empty OTHERNAME decoded: %p\n", (void *)o2);
            errors();
            p = (const unsigned char *)"\x30\x06\xa1\x04\x0c\x02\x70\x6e";
            e2 = d2i_EDIPARTYNAME(NULL, &p, 8);
            check(e2 != NULL && e2->nameAssigner == NULL, "an EDI party name decoded");
            EDIPARTYNAME_free(e2);
        }
        GENERAL_NAMES_free(gn);
        OTHERNAME_free(on);
        EDIPARTYNAME_free(ed);
    }
}

static void v2i(const char *label, const X509V3_EXT_METHOD *m, X509V3_CTX *ctx, const char *text)
{
    STACK_OF(CONF_VALUE) *in = X509V3_parse_list(text);
    GENERAL_NAMES *gens = m->v2i(m, ctx, in);

    sk_CONF_VALUE_pop_free(in, X509V3_conf_free);
    show_names(label, gens);
    GENERAL_NAMES_free(gens);
}

static void test_text(void)
{
    const X509V3_EXT_METHOD *san = X509V3_EXT_get_nid(NID_subject_alt_name);
    const X509V3_EXT_METHOD *ian = X509V3_EXT_get_nid(NID_issuer_alt_name);
    const X509V3_EXT_METHOD *ci = X509V3_EXT_get_nid(NID_certificate_issuer);
    X509V3_CTX ctx;
    X509 *x = read_cert(SAN_PEM);
    X509_REQ *req = X509_REQ_new();
    X509_NAME *nm = X509_NAME_new();
    BIO *b = BIO_new_mem_buf(CONF_TEXT, -1);
    CONF *conf = NCONF_new(NULL);
    long eline = 0;
    const char *ips[] = { "1.2.3.4", "0.0.0.0", "255.255.255.255", "256.0.0.1", "01.2.3.4",
                          "1.2.3", "1.2.3.4.5", " 1.2.3.4", "::", "::1", "1::", "1:2:3:4:5:6:7:8",
                          "1:2:3:4:5:6:7:8:9", "1::2::3", ":1", "1:", "1:::2", "::ffff:10.1.2.3",
                          "::10.1.2.3:1", "fe80::1%eth0", "ABCD:EF01::", "12345::", "g::",
                          "1.2.3.4::", "", NULL };
    const char *nets[] = { "10.0.0.0/255.0.0.0", "10.0.0.0/8", "2001:db8::/ffff:ffff::",
                           "10.0.0.0/::", "10.0.0.0", "/", NULL };
    size_t k;

    printf("# from text\n");
    printf("  methods: v2i %d %d %d\n", san->v2i != NULL, ian->v2i != NULL, ci->v2i != NULL);
    v2i("each type", san, NULL,
        "DNS:a.example,IP:1.2.3.4,IP:2001:db8::5,email:x@y.example,URI:http://u/,RID:1.2.3.4,RID:commonName,DNS.2:b.example");
    v2i("a bad IP", san, NULL, "IP:1.2.3");
    v2i("a bad RID", san, NULL, "RID:not.an.oid");
    v2i("an unknown name", san, NULL, "FOO:bar");
    v2i("a missing value", san, NULL, "DNS");
    v2i("otherName without ;", san, NULL, "otherName:1.2.3.4");
    v2i("email:copy without a subject", san, NULL, "email:copy");
    memset(&ctx, 0, sizeof(ctx));
    X509V3_set_ctx(&ctx, NULL, NULL, NULL, NULL, X509V3_CTX_TEST);
    v2i("email:copy, a test context", san, &ctx, "email:copy,DNS:x");
    v2i("issuer:copy, a test context", ian, &ctx, "issuer:copy");
    X509V3_set_ctx(&ctx, x, x, NULL, NULL, 0);
    v2i("email:copy", san, &ctx, "email:copy,email.2:copy");
    v2i("issuer:copy", ian, &ctx, "issuer:copy,DNS:extra");
    v2i("dirName without a configuration", san, &ctx, "dirName:dir");
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char *)"req", -1, -1, 0);
    X509_NAME_add_entry_by_txt(nm, "emailAddress", MBSTRING_ASC, (const unsigned char *)"one@x", -1, -1, 0);
    X509_NAME_add_entry_by_txt(nm, "emailAddress", MBSTRING_ASC, (const unsigned char *)"two@x", -1, -1, 0);
    X509_REQ_set_subject_name(req, nm);
    X509V3_set_ctx(&ctx, NULL, NULL, req, NULL, 0);
    v2i("email:move from a request", san, &ctx, "email:move");
    printf("  the request's subject now has %d entries\n", X509_NAME_entry_count(X509_REQ_get_subject_name(req)));
    v2i("issuer:copy without an issuer", ian, &ctx, "issuer:copy");
    check(NCONF_load_bio(conf, b, &eline) == 1, "a configuration");
    X509V3_set_nconf(&ctx, conf);
    v2i("dirName", san, &ctx, "dirName:dir");
    v2i("dirName, no such section", san, &ctx, "dirName:nosuch");
    v2i("dirName, empty section", san, &ctx, "dirName:empty");
    printf("  get_string: %s, get_section: %d values\n", X509V3_get_string(&ctx, "C", "dir"),
           sk_CONF_VALUE_num(X509V3_get_section(&ctx, "dir")));
    X509V3_string_free(&ctx, NULL);
    X509V3_section_free(&ctx, NULL);
    X509V3_section_free(&ctx, X509V3_get_section(&ctx, "dir"));

    printf("# names from sections\n");
    {
        X509_NAME *dn = X509_NAME_new();
        char buf[256];

        check(X509V3_NAME_from_section(dn, X509V3_get_section(&ctx, "dir"), MBSTRING_ASC) == 1, "made");
        printf("  %s, %d entries\n", X509_NAME_oneline(dn, buf, sizeof(buf)), X509_NAME_entry_count(dn));
        X509_NAME_free(dn);
        printf("  NULL name: %d\n", X509V3_NAME_from_section(NULL, NULL, MBSTRING_ASC));
    }

    printf("# IP addresses\n");
    for (k = 0; ips[k] != NULL; k++) {
        ASN1_OCTET_STRING *ip = a2i_IPADDRESS(ips[k]);

        printf("  [%s]:", ips[k]);
        if (ip == NULL) {
            printf(" none\n");
        } else {
            int i;
            for (i = 0; i < ip->length; i++)
                printf(" %02x", ip->data[i]);
            printf("\n");
        }
        ASN1_OCTET_STRING_free(ip);
    }
    for (k = 0; nets[k] != NULL; k++) {
        ASN1_OCTET_STRING *ip = a2i_IPADDRESS_NC(nets[k]);

        printf("  net [%s]: %d\n", nets[k], ip == NULL ? -1 : ip->length);
        ASN1_OCTET_STRING_free(ip);
    }
    errors();
    {
        CONF_VALUE cnf;
        GENERAL_NAME *g;

        cnf.section = NULL;
        cnf.name = "IP";
        cnf.value = "192.168.0.0/255.255.0.0";
        g = v2i_GENERAL_NAME_ex(NULL, san, NULL, &cnf, 1);
        printf("  a network name: %d\n", g == NULL ? -1 : g->d.ip->length);
        GENERAL_NAME_print(out, g);
        printf("  [");
        flush_out();
        printf("]\n");
        GENERAL_NAME_free(g);
        g = v2i_GENERAL_NAME(san, NULL, &cnf);
        printf("  not a network: %p\n", (void *)g);
        errors();
        g = GENERAL_NAME_new();
        check(a2i_GENERAL_NAME(g, san, NULL, GEN_DNS, "into.example", 0) == g, "into a name");
        GENERAL_NAME_free(g);
        printf("  unsupported type: %p\n", (void *)a2i_GENERAL_NAME(NULL, san, NULL, GEN_X400, "x", 0));
        errors();
        printf("  no value: %p\n", (void *)a2i_GENERAL_NAME(NULL, san, NULL, GEN_DNS, NULL, 0));
        errors();
        {
            STACK_OF(CONF_VALUE) *in = X509V3_parse_list("DNS:one,URI:two");
            GENERAL_NAMES *gens = v2i_GENERAL_NAMES(san, NULL, in);

            show_names("v2i_GENERAL_NAMES", gens);
            GENERAL_NAMES_free(gens);
            sk_CONF_VALUE_pop_free(in, X509V3_conf_free);
        }
    }

    printf("# context\n");
    {
        BIO *kb = BIO_new_mem_buf(CA_KEY_PEM, -1);
        EVP_PKEY *k2 = PEM_read_bio_PrivateKey(kb, NULL, NULL, NULL);

        BIO_free(kb);
        X509V3_set_ctx(&ctx, NULL, NULL, NULL, NULL, 0);
        printf("  issuer key without a subject: %d\n", X509V3_set_issuer_pkey(&ctx, k2));
        errors();
        printf("  NULL key: %d\n", X509V3_set_issuer_pkey(&ctx, NULL));
        X509V3_set_ctx(&ctx, NULL, x, NULL, NULL, 0);
        printf("  with a subject: %d\n", X509V3_set_issuer_pkey(&ctx, k2));
        printf("  get_string without a configuration: %p\n", (void *)X509V3_get_string(&ctx, "a", "b"));
        errors();
        X509V3_set_conf_lhash(&ctx, NULL);
        printf("  get_section of a NULL hash: %p\n", (void *)X509V3_get_section(&ctx, "dir"));
        errors();
        X509V3_set_ctx(NULL, NULL, NULL, NULL, NULL, 0);
        X509V3_set_nconf(NULL, conf);
        X509V3_set_conf_lhash(NULL, NULL);
        printf("  NULL context: %d\n", X509V3_set_issuer_pkey(NULL, NULL));
        errors();
        EVP_PKEY_free(k2);
    }
    NCONF_free(conf);
    BIO_free(b);
    X509_NAME_free(nm);
    X509_REQ_free(req);
    X509_free(x);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("TAP version 13\n");
    out = BIO_new(BIO_s_mem());
    test_decoded();
    test_set();
    test_text();
    BIO_free(out);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
