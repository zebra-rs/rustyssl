/*
 * Conformance test for the identity checks (X509_check_host(3), X509_check_email(3),
 * X509_check_ip(3), X509_check_ip_asc(3)) and the names behind them (X509_get1_email(3),
 * X509_REQ_get1_email, X509_get1_ocsp, X509_email_free), in TAP format: host names against
 * wildcard, partial, IDNA, and exact alternative names under each X509_CHECK_FLAG_*, and
 * against common names; subdomains of a leading dot; email addresses, including an
 * SmtpUTF8Mailbox other name; IP addresses in binary and text; names with NULs; and the
 * email addresses and OCSP responders of certificates and requests.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
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

    printf("  errors:");
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
}

static const char SAN_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICFjCCAb2gAwIBAgIBATAKBggqhkjOPQQDAjA9MRcwFQYDVQQDDA5jbi5leGFt\n"
    "cGxlLmNvbTEiMCAGCSqGSIb3DQEJARYTU3ViamVjdEBFeGFtcGxlLmNvbTAeFw0y\n"
    "NjEwMTcxNzQxMzhaFw0zNjEwMTQxNzQxMzhaMD0xFzAVBgNVBAMMDmNuLmV4YW1w\n"
    "bGUuY29tMSIwIAYJKoZIhvcNAQkBFhNTdWJqZWN0QEV4YW1wbGUuY29tMFkwEwYH\n"
    "KoZIzj0CAQYIKoZIzj0DAQcDQgAE3i4qKFNxqJdx02lNo5h7ROhmZp6h5Qtriryg\n"
    "DOAwAMQNWaXmgiYO+9hEs5Immc3cE61GiN6U1YcZMJL9WJeKE6OBrTCBqjCBiAYD\n"
    "VR0RBIGAMH6CDSouZXhhbXBsZS5jb22CFmYqLnBhcnRpYWwuZXhhbXBsZS5uZXSC\n"
    "EWV4YWN0LmV4YW1wbGUub3JnghcqLnhuLS1iY2hlci1rdmEuZXhhbXBsZYERYWxp\n"
    "Y2VARXhhbXBsZS5DT02HBMAAAgeHECABDbgAAAAAAAAAAAAAAAEwHQYDVR0OBBYE\n"
    "FDY/B8O42LX7E1HwVlcFpxC6z/FyMAoGCCqGSM49BAMCA0cAMEQCICHUwXAZBoJf\n"
    "HqKOJkS7cIIWxZ78k8mRpCxv5CrGxEeHAiAxUeIq7bU1vlUYAt42J49w7Z3anN9C\n"
    "qgd5VJleOkaozQ==\n"
    "-----END CERTIFICATE-----\n";

static const char CNONLY_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBwTCCAWagAwIBAgIBATAKBggqhkjOPQQDAjBYMRgwFgYDVQQDDA93d3cuZXhh\n"
    "bXBsZS5jb20xGzAZBgNVBAMMEnNlY29uZC5leGFtcGxlLmNvbTEfMB0GCSqGSIb3\n"
    "DQEJARYQcm9vdEBleGFtcGxlLmNvbTAeFw0yNjEwMTcxNzQxMjlaFw0zNjEwMTQx\n"
    "NzQxMjlaMFgxGDAWBgNVBAMMD3d3dy5leGFtcGxlLmNvbTEbMBkGA1UEAwwSc2Vj\n"
    "b25kLmV4YW1wbGUuY29tMR8wHQYJKoZIhvcNAQkBFhByb290QGV4YW1wbGUuY29t\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3i4qKFNxqJdx02lNo5h7ROhmZp6h\n"
    "5QtrirygDOAwAMQNWaXmgiYO+9hEs5Immc3cE61GiN6U1YcZMJL9WJeKE6MhMB8w\n"
    "HQYDVR0OBBYEFDY/B8O42LX7E1HwVlcFpxC6z/FyMAoGCCqGSM49BAMCA0kAMEYC\n"
    "IQD9v1MBWC29uzQH+mBU4S1zMctfh0mbI5/eLgJtDBYXRQIhAM+XI4YQM6vp1/xE\n"
    "NyBHXmJjoJeZMYang6fdtu+QcZtd\n"
    "-----END CERTIFICATE-----\n";

static const char SMTP_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBhjCCAS2gAwIBAgIBATAKBggqhkjOPQQDAjAbMRkwFwYDVQQDDBBtYWlsLmV4\n"
    "YW1wbGUuY29tMB4XDTI2MTAxNzE3NDEzOFoXDTM2MTAxNDE3NDEzOFowGzEZMBcG\n"
    "A1UEAwwQbWFpbC5leGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA\n"
    "BN4uKihTcaiXcdNpTaOYe0ToZmaeoeULa4q8oAzgMADEDVml5oImDvvYRLOSJpnN\n"
    "3BOtRojelNWHGTCS/ViXihOjYjBgMD8GA1UdEQQ4MDagIQYIKwYBBQUHCAmgFQwT\n"
    "dW5pY29kZUBleGFtcGxlLmNvbYERbGF0ZXJAZXhhbXBsZS5jb20wHQYDVR0OBBYE\n"
    "FDY/B8O42LX7E1HwVlcFpxC6z/FyMAoGCCqGSM49BAMCA0cAMEQCIHSIt3oiNM/9\n"
    "pz0R4KG0HeT0fb/ujGz376ZbFpaLRzzvAiBp4p5sqTuxwCuh/osViWzWu+lD/gor\n"
    "DNUi2gui2ruhOw==\n"
    "-----END CERTIFICATE-----\n";

static const char STAR_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBizCCATGgAwIBAgIBATAKBggqhkjOPQQDAjAPMQ0wCwYDVQQDDARzdGFyMB4X\n"
    "DTI2MTAxNzE3NDEzOFoXDTM2MTAxNDE3NDEzOFowDzENMAsGA1UEAwwEc3RhcjBZ\n"
    "MBMGByqGSM49AgEGCCqGSM49AwEHA0IABN4uKihTcaiXcdNpTaOYe0ToZmaeoeUL\n"
    "a4q8oAzgMADEDVml5oImDvvYRLOSJpnN3BOtRojelNWHGTCS/ViXihOjfjB8MFsG\n"
    "A1UdEQRUMFKCASqCBSouY29tgg9hLiouZXhhbXBsZS5jb22CDyoteC5leGFtcGxl\n"
    "LmNvbYIPeCp5LmV4YW1wbGUuY29tghMqLk11bHRpLkV4YW1wbGUuY29tMB0GA1Ud\n"
    "DgQWBBQ2PwfDuNi1+xNR8FZXBacQus/xcjAKBggqhkjOPQQDAgNIADBFAiEAjNTW\n"
    "bL446PPgEZR6cQwk7pRpuUq+bdjmc7HTw32Jn7YCIBVjQOidgCtn0od9dBTSbW5h\n"
    "DbQ9zJ1990AGS8aqyi5X\n"
    "-----END CERTIFICATE-----\n";

static X509 *read_cert(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);

    BIO_free(b);
    return x;
}

static const unsigned int FLAGS[] = {
    0,
    X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT,
    X509_CHECK_FLAG_NO_WILDCARDS,
    X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS,
    X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS,
    X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS,
    X509_CHECK_FLAG_NEVER_CHECK_SUBJECT,
};

static void hosts(const char *label, X509 *x, const char *const *names, size_t n)
{
    size_t i, f;

    printf("# hosts: %s\n", label);
    for (i = 0; i < n; i++) {
        printf("  %-28s", names[i]);
        for (f = 0; f < sizeof(FLAGS) / sizeof(FLAGS[0]); f++) {
            char *peer = NULL;
            int r = X509_check_host(x, names[i], 0, FLAGS[f], &peer);

            printf(" %d%s%s", r, peer == NULL ? "" : "=", peer == NULL ? "" : peer);
            OPENSSL_free(peer);
        }
        printf("\n");
    }
}

static void emails(const char *label, X509 *x, const char *const *names, size_t n)
{
    size_t i;

    printf("# emails: %s\n", label);
    for (i = 0; i < n; i++)
        printf("  %-28s %d %d %d\n", names[i], X509_check_email(x, names[i], 0, 0),
               X509_check_email(x, names[i], 0, X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT),
               X509_check_email(x, names[i], 0, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT));
}

static void show_list(const char *label, STACK_OF(OPENSSL_STRING) *sk)
{
    int i;

    printf("  %s:", label);
    if (sk == NULL)
        printf(" (none)");
    for (i = 0; i < sk_OPENSSL_STRING_num(sk); i++)
        printf(" [%s]", sk_OPENSSL_STRING_value(sk, i));
    printf("\n");
    X509_email_free(sk);
}

/* A certificate with a DNS name and a common name holding a NUL. */
static X509 *with_nuls(void)
{
    X509 *x = X509_new();
    GENERAL_NAMES *gens = GENERAL_NAMES_new();
    GENERAL_NAME *g = GENERAL_NAME_new();
    ASN1_IA5STRING *ia5 = ASN1_IA5STRING_new();
    X509_NAME *n = X509_NAME_new();

    ASN1_STRING_set(ia5, "bad\0.example.com", 16);
    GENERAL_NAME_set0_value(g, GEN_DNS, ia5);
    sk_GENERAL_NAME_push(gens, g);
    X509_add1_ext_i2d(x, NID_subject_alt_name, gens, 0, X509V3_ADD_DEFAULT);
    GENERAL_NAMES_free(gens);
    X509_NAME_add_entry_by_NID(n, NID_commonName, MBSTRING_ASC, (const unsigned char *)"cn\0x.example.com", 16, -1, 0);
    X509_NAME_add_entry_by_NID(n, NID_commonName, MBSTRING_UTF8, (const unsigned char *)"b\xc3\xbc" "cher.example", -1, -1, 0);
    X509_NAME_add_entry_by_NID(n, NID_commonName, V_ASN1_BMPSTRING, (const unsigned char *)"\0b\0m\0p\0.\0e\0x", 14, -1, 0);
    X509_set_subject_name(x, n);
    X509_NAME_free(n);
    return x;
}

int main(void)
{
    X509 *san = read_cert(SAN_PEM), *cnonly = read_cert(CNONLY_PEM), *smtp = read_cert(SMTP_PEM);
    X509 *star = read_cert(STAR_PEM), *nuls = with_nuls();
    static const char *const host_names[] = {
        "www.example.com", "WWW.EXAMPLE.COM", "example.com", "a.b.example.com", "cn.example.com",
        "foo.partial.example.net", "f.partial.example.net", "partial.example.net", "exact.example.org",
        "Exact.Example.Org.", ".example.org", ".example.com", "x.xn--bcher-kva.example",
        "xn--a.example.com", "192.0.2.7",
    };
    static const char *const cn_names[] = {
        "www.example.com", "second.example.com", ".example.com", "example.com", "WWW.example.COM",
    };
    static const char *const star_names[] = {
        "x", "a.com", "a.b.example.com", "y-x.example.com", "xay.example.com", "a.b.multi.example.com",
        "a.multi.example.com",
    };
    static const char *const nul_names[] = { "bad", "cn", ("b\xc3\xbc" "cher.example"), "bmp.ex", "ok.example.com" };
    static const char *const email_names[] = {
        "alice@example.com", "alice@EXAMPLE.com", "Alice@example.com", "subject@example.com",
        "Subject@example.COM", "root@example.com", "unicode@example.com", "later@example.com", "nobody@x",
    };
    static const unsigned char v4[4] = { 192, 0, 2, 7 }, v6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    X509_REQ *req = X509_REQ_new();

    hosts("alternative names", san, host_names, sizeof(host_names) / sizeof(host_names[0]));
    hosts("common names", cnonly, cn_names, sizeof(cn_names) / sizeof(cn_names[0]));
    hosts("wildcards", star, star_names, sizeof(star_names) / sizeof(star_names[0]));
    hosts("NULs and other strings", nuls, nul_names, sizeof(nul_names) / sizeof(nul_names[0]));
    printf("# malformed hosts\n");
    printf("  NULL %d, inner NUL %d, trailing NUL %d, length %d\n", X509_check_host(san, NULL, 0, 0, NULL),
           X509_check_host(san, "www\0x.example.com", 17, 0, NULL), X509_check_host(san, "www.example.com", 16, 0, NULL),
           X509_check_host(san, "www.example.comXXX", 15, 0, NULL));
    emails("alternative names", san, email_names, sizeof(email_names) / sizeof(email_names[0]));
    emails("subject only", cnonly, email_names, sizeof(email_names) / sizeof(email_names[0]));
    emails("SmtpUTF8Mailbox", smtp, email_names, sizeof(email_names) / sizeof(email_names[0]));
    printf("# malformed emails: NULL %d, inner NUL %d, trailing NUL %d\n", X509_check_email(san, NULL, 0, 0),
           X509_check_email(san, "a\0lice@example.com", 18, 0), X509_check_email(san, "alice@example.com", 18, 0));
    printf("# IP addresses\n");
    printf("  binary: v4 %d, v6 %d, wrong %d, short %d, NULL %d\n", X509_check_ip(san, v4, 4, 0),
           X509_check_ip(san, v6, 16, 0), X509_check_ip(san, v6, 4, 0), X509_check_ip(san, v4, 3, 0),
           X509_check_ip(san, NULL, 4, 0));
    printf("  text: %d %d %d %d %d %d\n", X509_check_ip_asc(san, "192.0.2.7", 0), X509_check_ip_asc(san, "2001:db8::1", 0),
           X509_check_ip_asc(san, "2001:DB8:0::1", 0), X509_check_ip_asc(san, "192.0.2.8", 0),
           X509_check_ip_asc(san, "not an address", 0), X509_check_ip_asc(san, NULL, 0));
    printf("  common names never: %d\n", X509_check_ip_asc(cnonly, "192.0.2.7", X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT));
    printf("# email lists\n");
    show_list("alternative names", X509_get1_email(san));
    show_list("subject only", X509_get1_email(cnonly));
    show_list("SmtpUTF8Mailbox", X509_get1_email(smtp));
    show_list("none", X509_get1_email(star));
    {
        X509_NAME *n = X509_NAME_new();
        STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
        GENERAL_NAMES *gens = GENERAL_NAMES_new();
        GENERAL_NAME *g = GENERAL_NAME_new();
        ASN1_IA5STRING *ia5 = ASN1_IA5STRING_new();

        X509_NAME_add_entry_by_txt(n, "emailAddress", MBSTRING_ASC, (const unsigned char *)"req@example.com", -1, -1, 0);
        X509_NAME_add_entry_by_txt(n, "emailAddress", MBSTRING_ASC, (const unsigned char *)"req@example.com", -1, -1, 0);
        X509_REQ_set_subject_name(req, n);
        ASN1_STRING_set(ia5, "alt@example.com", -1);
        GENERAL_NAME_set0_value(g, GEN_EMAIL, ia5);
        sk_GENERAL_NAME_push(gens, g);
        X509V3_add1_i2d(&exts, NID_subject_alt_name, gens, 0, X509V3_ADD_DEFAULT);
        X509_REQ_add_extensions(req, exts);
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        GENERAL_NAMES_free(gens);
        X509_NAME_free(n);
        show_list("request", X509_REQ_get1_email(req));
    }
    {
        AUTHORITY_INFO_ACCESS *aia = AUTHORITY_INFO_ACCESS_new();
        X509 *x = X509_dup(star);
        int i;
        static const char *const uris[] = { "http://ocsp.example/", "http://b.example/", "http://ocsp.example/" };

        for (i = 0; i < 3; i++) {
            ACCESS_DESCRIPTION *ad = ACCESS_DESCRIPTION_new();
            ASN1_IA5STRING *uri = ASN1_IA5STRING_new();

            ASN1_OBJECT_free(ad->method);
            ad->method = OBJ_nid2obj(i == 1 ? NID_ad_ca_issuers : NID_ad_OCSP);
            ASN1_STRING_set(uri, uris[i], -1);
            GENERAL_NAME_set0_value(ad->location, GEN_URI, uri);
            sk_ACCESS_DESCRIPTION_push(aia, ad);
        }
        X509_add1_ext_i2d(x, NID_info_access, aia, 0, X509V3_ADD_DEFAULT);
        AUTHORITY_INFO_ACCESS_free(aia);
        show_list("OCSP", X509_get1_ocsp(x));
        show_list("no OCSP", X509_get1_ocsp(star));
        X509_free(x);
    }
    X509_email_free(NULL);
    errors();
    check(1, "done");
    X509_REQ_free(req);
    X509_free(san);
    X509_free(cnonly);
    X509_free(smtp);
    X509_free(star);
    X509_free(nuls);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
