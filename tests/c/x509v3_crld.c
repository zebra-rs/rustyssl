/*
 * Conformance test for the authority key identifier, the information access extensions, and
 * CRL distribution points (AUTHORITY_KEYID_new(3), ACCESS_DESCRIPTION_new(3),
 * DIST_POINT_new(3), ISSUING_DIST_POINT_new(3), DIST_POINT_set_dpname,
 * OSSL_GENERAL_NAMES_print), in TAP format: a leaf certificate's extensions printed and
 * decoded; each made from text in a context (the issuer's key identifier, name, and serial
 * number, with and without `always`; access descriptions; distribution points from names and
 * from sections, full and relative), with the errors of bad input; issuing distribution
 * points; and the invalidity date and hold instruction of CRL entries.
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

static const char LEAF_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDVzCCAv2gAwIBAgIBTTAKBggqhkjOPQQDAjAyMQswCQYDVQQGEwJKUDERMA8G\n"
    "A1UECgwIcnVzdHlzc2wxEDAOBgNVBAMMB1Rlc3QgQ0EwHhcNMjYxMDE3MTMyNTIx\n"
    "WhcNMjcxMDE3MTMyNTIxWjA3MQswCQYDVQQGEwJKUDERMA8GA1UECgwIcnVzdHlz\n"
    "c2wxFTATBgNVBAMMDGxlYWYuZXhhbXBsZTCBnzANBgkqhkiG9w0BAQEFAAOBjQAw\n"
    "gYkCgYEAyLiWzDdX6nR/I0PFfqQMjmzOaP3k2chLl6bgnw/56uRbutdllHGiZYW1\n"
    "WzX5oFvgjGw+ZBQL08v/+SZERezdBninEkAfJy2yk2tuEJUVPpOS9g6v60Lr92wh\n"
    "E2pi+U0lNnCCw8UUZ5jMvMxk3EswcvFn0qHOxp/49Rnu8LafswECAwEAAaOCAbYw\n"
    "ggGyMGEGA1UdIwRaMFiAFFT/pnuNPm1SB+yJgcMJY5Cw5uK3oTakNDAyMQswCQYD\n"
    "VQQGEwJKUDERMA8GA1UECgwIcnVzdHlzc2wxEDAOBgNVBAMMB1Rlc3QgQ0GCCBI0\n"
    "VniQq83vMFYGCCsGAQUFBwEBBEowSDAgBggrBgEFBQcwAYYUaHR0cDovL29jc3Au\n"
    "ZXhhbXBsZS8wJAYIKwYBBQUHMAKGGGh0dHA6Ly9jYS5leGFtcGxlL2NhLmNydDAw\n"
    "BggrBgEFBQcBCwQkMCIwIAYIKwYBBQUHMAWGFGh0dHA6Ly9yZXBvLmV4YW1wbGUv\n"
    "MHUGA1UdHwRuMGwwHqAcoBqGGGh0dHA6Ly9jcmwuZXhhbXBsZS9hLmNybDBKoCmg\n"
    "J4YYaHR0cDovL2NybC5leGFtcGxlL2IuY3JsgQtjcmxAZXhhbXBsZYECBWCiGaQX\n"
    "MBUxEzARBgNVBAMMCkNSTCBJc3N1ZXIwLQYDVR0uBCYwJDAioCCgHoYcaHR0cDov\n"
    "L2NybC5leGFtcGxlL2RlbHRhLmNybDAdBgNVHQ4EFgQUoIyUcXdwWBeZM+sRqKEJ\n"
    "iUvCQdQwCgYIKoZIzj0EAwIDSAAwRQIgcL2qF1jDGNiqEHdNzVJTOUAOQ4gJoM3v\n"
    "8M9JN0Zz8YcCIQDKBxhgsnBU0Cn6bx7sGulsQ5go7z4nT493UUkLEOwXVA==\n"
    "-----END CERTIFICATE-----\n";

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

static const char CA_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOemUpeykgSE1rLlH\n"
    "3fPOAKOIoMBM0znLrB7aLijA3A6hRANCAAQbxAGoVUf1jXcfSz0KimynyxRdk9h1\n"
    "DdrEBWduotJFTj8R7mZ3jRDCqrIH/QEUUd6zLrWNYM/oUBa4Eqb8eJu7\n"
    "-----END PRIVATE KEY-----\n";

static const char SELF_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBjTCB96ADAgECAgEFMA0GCSqGSIb3DQEBCwUAMA0xCzAJBgNVBAMMAnYxMB4X\n"
    "DTI2MTAxNzExNTczOVoXDTI2MTExNjExNTczOVowDTELMAkGA1UEAwwCdjEwgZ8w\n"
    "DQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMi4lsw3V+p0fyNDxX6kDI5szmj95NnI\n"
    "S5em4J8P+erkW7rXZZRxomWFtVs1+aBb4IxsPmQUC9PL//kmREXs3QZ4pxJAHyct\n"
    "spNrbhCVFT6TkvYOr+tC6/dsIRNqYvlNJTZwgsPFFGeYzLzMZNxLMHLxZ9Khzsaf\n"
    "+PUZ7vC2n7MBAgMBAAEwDQYJKoZIhvcNAQELBQADgYEAZsU650HfVdIg8uaCTmFx\n"
    "bMwMfIRx89JRzPkFVktdcykxtv9oIRnStMRmqJgCiLs9076aTtIIuuzudW1QaCIh\n"
    "wqlfzrEGWGL3Vkvt7iVu8PFMTTtsUhGk36nJAb6kw9XebUjkLnQwjWKCBkVxbbHY\n"
    "0rsQQ/NSrOe/UH/WvIGwj0U=\n"
    "-----END CERTIFICATE-----\n";

static const char RSA_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAMi4lsw3V+p0fyND\n"
    "xX6kDI5szmj95NnIS5em4J8P+erkW7rXZZRxomWFtVs1+aBb4IxsPmQUC9PL//km\n"
    "REXs3QZ4pxJAHyctspNrbhCVFT6TkvYOr+tC6/dsIRNqYvlNJTZwgsPFFGeYzLzM\n"
    "ZNxLMHLxZ9Khzsaf+PUZ7vC2n7MBAgMBAAECgYEAna18MMLNGo4XjgFgNOL0RjIt\n"
    "WAcTbw3MbD6Yt/uZ7S8k7DrnPlyiITSPSi61gYaLeGRUAtRIkkHwPK4V9gRjf5r0\n"
    "+ddHrpzJKpQlMV0QEhuOXfIpRQK0coyUV9Aug7LmxfRIJqdyyVDCgwknlN7SO1Go\n"
    "2leIw4ewwnrzxzNPzBECQQD6uCGV2ZOSlXTFDNEb3LFH0Z3jnOC3OrGSlMxc7Lzj\n"
    "r3gDCjpO6ZkFSS42I8uB0hG0zfcKE1yr3RZskAz0WBYNAkEAzPLekFt+97fO0dIm\n"
    "vnIz0oSbjFXwyH/D5eAXoc9sccL+GvnunAkjo2lxPaVWElW40/+SETH34HdLLIlW\n"
    "23XnxQJALdidy5kNszBBOgct9bpVcJyUEpsNPHQvJG6xMAzaPYhImcW1A9kTcjP/\n"
    "j0bcX9DaDAXdtqnzuDmlcBSnSccRwQJBAJOpQHWdlmMACYDe+o8oVPIOHMwFd0/d\n"
    "zdSnmh85BRcJuG7TN/kwFH8+DxqtLtBS9rG3ZxQAfmk5Se4ynWPNFUkCQQCIE0V3\n"
    "+0aLGAjIN2UVYnm0ySml9rRU1fyu5n7+VjTMZESK4drPYcHUIIw/SSPRnqIqjtb5\n"
    "h7EBN26AcOWkTIGi\n"
    "-----END PRIVATE KEY-----\n";

static const char CONF_TEXT[] =
    "[dp]\n"
    "fullname=URI:http://a.example/x.crl,URI:http://b.example/y.crl\n"
    "reasons=superseded,AACompromise\n"
    "CRLissuer=@issuers\n"
    "[issuers]\n"
    "DNS=issuer.example\n"
    "[rel]\n"
    "relativename=rdn\n"
    "[rdn]\n"
    "CN=Relative\n"
    "[badrel]\n"
    "relativename=rdn2\n"
    "[rdn2]\n"
    "CN=one\n"
    "+OU=two\n"
    "[twice]\n"
    "fullname=URI:http://a/\n"
    "relativename=rdn\n"
    "[badreason]\n"
    "reasons=notAReason\n"
    "[idp]\n"
    "fullname=URI:http://idp.example/\n"
    "onlyuser=TRUE\n"
    "onlysomereasons=keyCompromise\n";

static X509 *read_cert(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);

    BIO_free(b);
    return x;
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
    X509V3_EXT_print(out, e, 0, 2);
    print_out("printed");
}

/* An extension of `nid` made from `text` in `ctx` through its method's v2i. */
static void make(const char *label, int nid, X509V3_CTX *ctx, const char *text)
{
    const X509V3_EXT_METHOD *m = X509V3_EXT_get_nid(nid);
    STACK_OF(CONF_VALUE) *in = X509V3_parse_list(text);
    void *v = m->v2i(m, ctx, in);
    X509_EXTENSION *e = v == NULL ? NULL : X509V3_EXT_i2d(nid, 0, v);

    sk_CONF_VALUE_pop_free(in, X509V3_conf_free);
    printf("# %s\n", label);
    show_ext("extension", e);
    X509_EXTENSION_free(e);
    if (v != NULL)
        ASN1_item_free(v, ASN1_ITEM_ptr(m->it));
}

static void test_leaf(void)
{
    X509 *x = read_cert(LEAF_PEM);
    AUTHORITY_KEYID *akid;
    AUTHORITY_INFO_ACCESS *aia;
    CRL_DIST_POINTS *crld;
    int crit = 0, i;

    printf("# the leaf\n");
    check(X509V3_extensions_print(out, "X509v3 extensions", X509_get0_extensions(x), 0, 4) == 1, "printed");
    print_out("extensions");
    akid = X509V3_get_d2i(X509_get0_extensions(x), NID_authority_key_identifier, &crit, NULL);
    check(akid != NULL && akid->keyid != NULL && akid->issuer != NULL && akid->serial != NULL, "AKID decoded");
    printf("  AKID: keyid %d octets, %d issuer names, serial %ld\n", ASN1_STRING_length(akid->keyid),
           sk_GENERAL_NAME_num(akid->issuer), ASN1_INTEGER_get(akid->serial));
    AUTHORITY_KEYID_free(akid);
    aia = X509V3_get_d2i(X509_get0_extensions(x), NID_info_access, NULL, NULL);
    printf("  AIA: %d descriptions\n", sk_ACCESS_DESCRIPTION_num(aia));
    for (i = 0; i < sk_ACCESS_DESCRIPTION_num(aia); i++) {
        printf("    %d: ", i2a_ACCESS_DESCRIPTION(out, sk_ACCESS_DESCRIPTION_value(aia, i)));
        flush_out();
        printf(" ");
        GENERAL_NAME_print(out, sk_ACCESS_DESCRIPTION_value(aia, i)->location);
        flush_out();
        printf("\n");
    }
    AUTHORITY_INFO_ACCESS_free(aia);
    crld = X509V3_get_d2i(X509_get0_extensions(x), NID_crl_distribution_points, NULL, NULL);
    printf("  CRLDP: %d points\n", sk_DIST_POINT_num(crld));
    for (i = 0; i < sk_DIST_POINT_num(crld); i++) {
        DIST_POINT *dp = sk_DIST_POINT_value(crld, i);
        DIST_POINT_NAME *copy = DIST_POINT_NAME_dup(dp->distpoint);

        printf("    type %d, reasons %s, issuer %s, copy %s\n", dp->distpoint->type,
               dp->reasons ? "yes" : "no", dp->CRLissuer ? "yes" : "no", copy ? "made" : "none");
        OSSL_GENERAL_NAMES_print(out, dp->distpoint->name.fullname, 4);
        print_out("names");
        DIST_POINT_NAME_free(copy);
    }
    CRL_DIST_POINTS_free(crld);
    X509_free(x);
}

static void test_akid(void)
{
    X509 *ca = read_cert(CA_PEM), *self = read_cert(SELF_PEM), *subj = X509_new();
    BIO *b = BIO_new_mem_buf(CA_KEY_PEM, -1);
    EVP_PKEY *cakey = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL), *rsa;
    X509V3_CTX ctx;

    BIO_free(b);
    b = BIO_new_mem_buf(RSA_KEY_PEM, -1);
    rsa = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
    BIO_free(b);
    X509V3_set_ctx(&ctx, ca, subj, NULL, NULL, 0);
    make("AKID keyid", NID_authority_key_identifier, &ctx, "keyid");
    make("AKID issuer", NID_authority_key_identifier, &ctx, "issuer");
    make("AKID keyid, issuer", NID_authority_key_identifier, &ctx, "keyid,issuer");
    make("AKID keyid:always, issuer:always", NID_authority_key_identifier, &ctx, "keyid:always,issuer:always");
    make("AKID none", NID_authority_key_identifier, &ctx, "none");
    make("AKID bad option", NID_authority_key_identifier, &ctx, "keyid:sometimes");
    make("AKID twice", NID_authority_key_identifier, &ctx, "keyid,keyid");
    make("AKID none with more", NID_authority_key_identifier, &ctx, "none,keyid");
    make("AKID unknown", NID_authority_key_identifier, &ctx, "serial");
    X509V3_set_ctx(&ctx, self, self, NULL, NULL, 0);
    make("AKID self-signed, keyid", NID_authority_key_identifier, &ctx, "keyid");
    make("AKID self-signed, keyid:always", NID_authority_key_identifier, &ctx, "keyid:always");
    make("AKID self-signed, issuer", NID_authority_key_identifier, &ctx, "issuer");
    X509_set_pubkey(self, rsa);
    X509V3_set_issuer_pkey(&ctx, rsa);
    make("AKID self-signed with the key, keyid:always", NID_authority_key_identifier, &ctx, "keyid:always");
    X509V3_set_ctx(&ctx, NULL, subj, NULL, NULL, 0);
    make("AKID without an issuer", NID_authority_key_identifier, &ctx, "keyid");
    X509V3_set_ctx(&ctx, NULL, NULL, NULL, NULL, X509V3_CTX_TEST);
    make("AKID in a test context", NID_authority_key_identifier, &ctx, "keyid:always");
    make("AKID without a context", NID_authority_key_identifier, NULL, "keyid");
    {
        AUTHORITY_KEYID *a = AUTHORITY_KEYID_new();
        unsigned char *der = NULL;
        int len = i2d_AUTHORITY_KEYID(a, &der);
        const unsigned char *q = der;

        hex("empty AKID", der, len);
        AUTHORITY_KEYID_free(a);
        a = d2i_AUTHORITY_KEYID(NULL, &q, len);
        check(a != NULL, "decoded");
        AUTHORITY_KEYID_free(a);
        OPENSSL_free(der);
    }
    EVP_PKEY_free(cakey);
    EVP_PKEY_free(rsa);
    X509_free(ca);
    X509_free(self);
    X509_free(subj);
}

static void test_info(void)
{
    make("AIA", NID_info_access, NULL, "OCSP;URI:http://ocsp/,caIssuers;URI:http://ca/,1.2.3.4;DNS:x.example");
    make("SIA", NID_sinfo_access, NULL, "caRepository;URI:http://repo/");
    make("AIA without ;", NID_info_access, NULL, "OCSP:URI:http://ocsp/");
    make("AIA bad method", NID_info_access, NULL, "notAMethod;URI:http://x/");
    make("AIA bad name", NID_info_access, NULL, "OCSP;FOO:x");
    make("AIA empty", NID_info_access, NULL, "");
    {
        ACCESS_DESCRIPTION *ad = ACCESS_DESCRIPTION_new();
        AUTHORITY_INFO_ACCESS *aia = AUTHORITY_INFO_ACCESS_new();
        unsigned char *der = NULL;
        int len;

        printf("  new description: method NID %d, location type %d\n", OBJ_obj2nid(ad->method), ad->location->type);
        len = i2d_AUTHORITY_INFO_ACCESS(aia, &der);
        hex("empty AIA", der, len);
        OPENSSL_free(der);
        der = NULL;
        len = i2d_ACCESS_DESCRIPTION(ad, &der);
        printf("  empty description: %d\n", len);
        errors();
        OPENSSL_free(der);
        {
            const unsigned char *q = (const unsigned char *)"\x30\x0c\x06\x08\x2b\x06\x01\x05\x05\x07\x30\x01\x82\x00";
            ACCESS_DESCRIPTION *d2 = d2i_ACCESS_DESCRIPTION(NULL, &q, 14);
            AUTHORITY_INFO_ACCESS *a2;

            check(d2 != NULL && d2->location->type == GEN_DNS, "a description decoded");
            ACCESS_DESCRIPTION_free(d2);
            q = (const unsigned char *)"\x30\x00";
            a2 = d2i_AUTHORITY_INFO_ACCESS(NULL, &q, 2);
            check(a2 != NULL && sk_ACCESS_DESCRIPTION_num(a2) == 0, "an empty AIA decoded");
            AUTHORITY_INFO_ACCESS_free(a2);
        }
        ACCESS_DESCRIPTION_free(ad);
        AUTHORITY_INFO_ACCESS_free(aia);
    }
}

static void test_crld(void)
{
    BIO *b = BIO_new_mem_buf(CONF_TEXT, -1);
    CONF *conf = NCONF_new(NULL);
    long eline = 0;
    X509V3_CTX ctx;

    check(NCONF_load_bio(conf, b, &eline) == 1, "a configuration");
    X509V3_set_ctx(&ctx, NULL, NULL, NULL, NULL, 0);
    X509V3_set_nconf(&ctx, conf);
    make("CRLDP names", NID_crl_distribution_points, &ctx, "URI:http://one/,URI:http://two/");
    make("CRLDP section", NID_crl_distribution_points, &ctx, "dp");
    make("CRLDP relative", NID_crl_distribution_points, &ctx, "rel");
    make("CRLDP relative, two RDNs", NID_crl_distribution_points, &ctx, "badrel");
    make("CRLDP name twice", NID_crl_distribution_points, &ctx, "twice");
    make("CRLDP bad reason", NID_crl_distribution_points, &ctx, "badreason");
    make("CRLDP no such section", NID_crl_distribution_points, &ctx, "nosuch");
    make("CRLDP bad name", NID_crl_distribution_points, &ctx, "FOO:bar");
    make("freshest CRL", NID_freshest_crl, &ctx, "URI:http://delta/");
    make("IDP", NID_issuing_distribution_point, &ctx, "fullname:URI:http://idp/,onlyCA:TRUE,indirectCRL:yes,onlyAA:N");
    make("IDP from a relative name", NID_issuing_distribution_point, &ctx, "relativename:rdn,onlysomereasons:superseded");
    make("IDP empty", NID_issuing_distribution_point, &ctx, "");
    make("IDP bad boolean", NID_issuing_distribution_point, &ctx, "onlyuser:maybe");
    make("IDP bad name", NID_issuing_distribution_point, &ctx, "onlyEverything:TRUE");
    make("IDP reasons twice", NID_issuing_distribution_point, &ctx, "onlysomereasons:superseded,onlysomereasons:unused");
    make("IDP missing value", NID_issuing_distribution_point, &ctx, "fullname");
    {
        STACK_OF(CONF_VALUE) *sect = X509V3_get_section(&ctx, "idp");
        const X509V3_EXT_METHOD *m = X509V3_EXT_get_nid(NID_issuing_distribution_point);
        ISSUING_DIST_POINT *idp = m->v2i(m, &ctx, sect);
        X509_EXTENSION *e = X509V3_EXT_i2d(NID_issuing_distribution_point, 1, idp);

        printf("# IDP from a section\n");
        show_ext("extension", e);
        X509_EXTENSION_free(e);
        ISSUING_DIST_POINT_free(idp);
    }
    {
        X509_NAME *issuer = X509_NAME_new();
        STACK_OF(CONF_VALUE) *in = X509V3_parse_list("rel");
        const X509V3_EXT_METHOD *m = X509V3_EXT_get_nid(NID_crl_distribution_points);
        CRL_DIST_POINTS *pts = m->v2i(m, &ctx, in);
        DIST_POINT *dp = sk_DIST_POINT_value(pts, 0);
        char buf[256];

        printf("# set_dpname\n");
        X509_NAME_add_entry_by_txt(issuer, "C", MBSTRING_ASC, (const unsigned char *)"JP", -1, -1, 0);
        X509_NAME_add_entry_by_txt(issuer, "O", MBSTRING_ASC, (const unsigned char *)"Org", -1, -1, 0);
        check(DIST_POINT_set_dpname(dp->distpoint, issuer) == 1, "set");
        printf("  %s\n", X509_NAME_oneline(dp->distpoint->dpname, buf, sizeof(buf)));
        check(DIST_POINT_set_dpname(dp->distpoint, issuer) == 1, "set again");
        check(DIST_POINT_set_dpname(NULL, issuer) == 1, "NULL is left alone");
        sk_CONF_VALUE_pop_free(in, X509V3_conf_free);
        CRL_DIST_POINTS_free(pts);
        in = X509V3_parse_list("URI:http://x/");
        pts = m->v2i(m, &ctx, in);
        check(DIST_POINT_set_dpname(sk_DIST_POINT_value(pts, 0)->distpoint, issuer) == 1, "a full name is left alone");
        check(sk_DIST_POINT_value(pts, 0)->distpoint->dpname == NULL, "without a dpname");
        sk_CONF_VALUE_pop_free(in, X509V3_conf_free);
        CRL_DIST_POINTS_free(pts);
        X509_NAME_free(issuer);
    }
    {
        DIST_POINT *dp = DIST_POINT_new();
        DIST_POINT_NAME *dpn = DIST_POINT_NAME_new();
        ISSUING_DIST_POINT *idp = ISSUING_DIST_POINT_new();
        CRL_DIST_POINTS *pts = CRL_DIST_POINTS_new();
        unsigned char *der = NULL;
        int len;

        printf("# items\n");
        len = i2d_DIST_POINT(dp, &der);
        hex("empty point", der, len);
        OPENSSL_free(der);
        der = NULL;
        len = i2d_ISSUING_DIST_POINT(idp, &der);
        hex("empty IDP", der, len);
        OPENSSL_free(der);
        der = NULL;
        len = i2d_CRL_DIST_POINTS(pts, &der);
        hex("empty points", der, len);
        OPENSSL_free(der);
        der = NULL;
        len = i2d_DIST_POINT_NAME(dpn, &der);
        printf("  empty name: %d\n", len);
        errors();
        OPENSSL_free(der);
        {
            const unsigned char *q = (const unsigned char *)"\xa0\x04\x86\x02\x68\x69";
            DIST_POINT_NAME *n2 = d2i_DIST_POINT_NAME(NULL, &q, 6);
            DIST_POINT *p2;
            ISSUING_DIST_POINT *i2;
            CRL_DIST_POINTS *c2;

            check(n2 != NULL && n2->type == 0, "a name decoded");
            DIST_POINT_NAME_free(n2);
            q = (const unsigned char *)"\x30\x00";
            p2 = d2i_DIST_POINT(NULL, &q, 2);
            check(p2 != NULL, "a point decoded");
            DIST_POINT_free(p2);
            q = (const unsigned char *)"\x30\x03\x81\x01\xff";
            i2 = d2i_ISSUING_DIST_POINT(NULL, &q, 5);
            check(i2 != NULL && i2->onlyuser == 255, "an IDP decoded");
            ISSUING_DIST_POINT_free(i2);
            q = (const unsigned char *)"\x30\x02\x30\x00";
            c2 = d2i_CRL_DIST_POINTS(NULL, &q, 4);
            check(c2 != NULL && sk_DIST_POINT_num(c2) == 1, "points decoded");
            CRL_DIST_POINTS_free(c2);
        }
        check(ASN1_ITEM_rptr(DIST_POINT) && ASN1_ITEM_rptr(DIST_POINT_NAME) && ASN1_ITEM_rptr(CRL_DIST_POINTS)
                  && ASN1_ITEM_rptr(ISSUING_DIST_POINT) && ASN1_ITEM_rptr(AUTHORITY_KEYID)
                  && ASN1_ITEM_rptr(ACCESS_DESCRIPTION) && ASN1_ITEM_rptr(AUTHORITY_INFO_ACCESS),
              "the items");
        DIST_POINT_free(dp);
        DIST_POINT_NAME_free(dpn);
        ISSUING_DIST_POINT_free(idp);
        CRL_DIST_POINTS_free(pts);
    }
    NCONF_free(conf);
    BIO_free(b);
}

static X509_EXTENSION *ext_of(int nid, const char *der, int len)
{
    ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
    X509_EXTENSION *e;

    ASN1_OCTET_STRING_set(os, (const unsigned char *)der, len);
    e = X509_EXTENSION_create_by_NID(NULL, nid, 0, os);
    ASN1_OCTET_STRING_free(os);
    return e;
}

static void test_entries(void)
{
    struct {
        const char *label;
        int nid;
        const char *der;
        int len;
    } cases[] = {
        { "invalidity date", NID_invalidity_date, "\x18\x0f" "20240102030405Z", 17 },
        { "hold instruction", NID_hold_instruction_code, "\x06\x07\x2a\x86\x48\xce\x38\x02\x02", 9 },
        { "IDP, every flag", NID_issuing_distribution_point,
          "\x30\x13\xa0\x08\xa0\x06\x86\x04\x68\x74\x74\x70\x81\x01\xff\x82\x01\xff\x84\x01\xff\x85\x01\xff", 21 },
        { "IDP, reasons", NID_issuing_distribution_point, "\x30\x04\x83\x02\x07\x80", 6 },
        { "IDP, no reasons set", NID_issuing_distribution_point, "\x30\x03\x83\x01\x00", 5 },
        { "IDP, relative name", NID_issuing_distribution_point,
          "\x30\x13\xa0\x11\xa1\x0f\x30\x0d\x06\x03\x55\x04\x03\x0c\x06\x52\x65\x6c\x61\x74\x76", 21 },
        { "CRLDP, relative name and issuer", NID_crl_distribution_points,
          "\x30\x1d\x30\x1b\xa0\x0e\xa1\x0c\x30\x0a\x06\x03\x55\x04\x0b\x0c\x03\x6f\x6e\x65\xa2\x09\x82\x07\x63\x72\x6c\x2e\x6f\x72\x67", 31 },
        { "CRLDP, empty point", NID_crl_distribution_points, "\x30\x02\x30\x00", 4 },
        { "AKID, keyid only", NID_authority_key_identifier, "\x30\x05\x80\x03\x01\x02\x03", 7 },
        { "AKID, serial only", NID_authority_key_identifier, "\x30\x04\x82\x02\x01\x00", 6 },
        { "AKID, empty", NID_authority_key_identifier, "\x30\x00", 2 },
        { "AIA, otherName", NID_info_access,
          "\x30\x18\x30\x16\x06\x08\x2b\x06\x01\x05\x05\x07\x30\x01\xa0\x0a\x06\x03\x2a\x03\x04\xa0\x03\x16\x01\x78", 26 },
    };
    size_t k;

    for (k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        X509_EXTENSION *e = ext_of(cases[k].nid, cases[k].der, cases[k].len);

        printf("# %s\n", cases[k].label);
        printf("  print %d", X509V3_EXT_print(out, e, X509V3_EXT_ERROR_UNKNOWN, 2));
        print_out("");
        X509_EXTENSION_free(e);
    }
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("TAP version 13\n");
    out = BIO_new(BIO_s_mem());
    test_leaf();
    test_akid();
    test_info();
    test_crld();
    test_entries();
    BIO_free(out);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
