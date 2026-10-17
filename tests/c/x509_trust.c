/*
 * Conformance test for trust settings (X509_check_trust(3), X509_TRUST_get0(3),
 * X509_add1_trust_object(3), X509_alias_set1, X509_keyid_set1), in TAP format: the trust table
 * (with entries added and changed, and the default check replaced); each check for a
 * self-signed certificate and a leaf, with and without auxiliary data naming trusted and
 * rejected uses (any extended key usage included); and the alias and key ID, through the
 * trusted encoding.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static const char CA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBXzCCAQSgAwIBAgIBATAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApQdXJwb3Nl\n"
    "IENBMB4XDTI2MTAxNzE0NDYxOVoXDTM2MTAxNDE0NDYxOVowFTETMBEGA1UEAwwK\n"
    "UHVycG9zZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBWjWIRih6WIPZH9\n"
    "yyM92OMGrP0IA1y4D9r8UFgmiVhQ2yk9byExM1oXjHDR9dt6q1lEA9jpqNZ3bnJc\n"
    "62luj0mjRTBDMBIGA1UdEwEB/wQIMAYBAf8CAQIwDgYDVR0PAQH/BAQDAgEGMB0G\n"
    "A1UdDgQWBBQ0lsw8dOxP91kYhXzdnHH3mpLhNTAKBggqhkjOPQQDAgNJADBGAiEA\n"
    "kj2rk1mD4ySwCZoobiJ9MdfoCxdvK6omAzn5TXDujQ8CIQD+Ns1YYa12PfODJ3Fy\n"
    "twUt2FgdVL8c5pnN7he1zcvVCQ==\n"
    "-----END CERTIFICATE-----\n";

static const char SERVER_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBvjCCAWSgAwIBAgIBBzAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApQdXJwb3Nl\n"
    "IENBMB4XDTI2MTAxNzE0NDYxOVoXDTM2MTAxNDE0NDYxOVowETEPMA0GA1UEAwwG\n"
    "c2VydmVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEJmU/wZeX86icApfkgw1\n"
    "Vpwhan4WCwtpPNtvP4/ErxhATPYxrjMQqlv00olStwd324fXxDMKZEuBAO3ucJmK\n"
    "lqOBqDCBpTAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggr\n"
    "BgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFCQZP0LkcWQzli7s4uZl9Y/W6N11\n"
    "MB8GA1UdIwQYMBaAFDSWzDx07E/3WRiFfN2ccfeakuE1MBYGA1UdEQQPMA2CC3d3\n"
    "dy5leGFtcGxlMBEGCWCGSAGG+EIBAQQEAwIGwDAKBggqhkjOPQQDAgNIADBFAiEA\n"
    "xpq7e4/INYzqjxGr0AfLJor5LyrRKl9ea0cR7htWCh4CIECo8YuCNq4t5xl6eRH1\n"
    "xspB6WRZ5yKS6EC7pnA7E+4o\n"
    "-----END CERTIFICATE-----\n";

static X509 *read_cert(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);

    BIO_free(b);
    return x;
}


static void checks(const char *label, X509 *x)
{
    int i;

    printf("  %s:", label);
    for (i = 0; i < X509_TRUST_get_count(); i++) {
        X509_TRUST *t = X509_TRUST_get0(i);

        printf(" %d=%d", X509_TRUST_get_trust(t), X509_check_trust(x, X509_TRUST_get_trust(t), 0));
    }
    printf(" default=%d unknown=%d nossc=%d\n", X509_check_trust(x, X509_TRUST_DEFAULT, 0),
           X509_check_trust(x, 99, 0), X509_check_trust(x, X509_TRUST_COMPAT, X509_TRUST_NO_SS_COMPAT));
}

static int my_default(int id, X509 *x, int flags)
{
    (void)x;
    return id * 100 + flags;
}

static int my_check(X509_TRUST *t, X509 *x, int flags)
{
    (void)x;
    return X509_TRUST_get_trust(t) + flags;
}

int main(void)
{
    X509 *ca = read_cert(CA_PEM), *server = read_cert(SERVER_PEM), *copy;
    int i, t = -5, len = -1;
    unsigned char *p;
    int (*old)(int, X509 *, int);

    printf("# the table\n");
    printf("  count %d\n", X509_TRUST_get_count());
    for (i = 0; i < X509_TRUST_get_count(); i++) {
        X509_TRUST *tr = X509_TRUST_get0(i);

        printf("  %d: id %d, flags %d, %s, by id %d\n", i, X509_TRUST_get_trust(tr), X509_TRUST_get_flags(tr),
               X509_TRUST_get0_name(tr), X509_TRUST_get_by_id(X509_TRUST_get_trust(tr)));
    }
    check(X509_TRUST_get0(-1) == NULL && X509_TRUST_get0(8) == NULL, "out of range");
    check(X509_TRUST_set(&t, X509_TRUST_EMAIL) == 1 && t == X509_TRUST_EMAIL, "set");
    check(X509_TRUST_set(&t, 99) == 0 && t == X509_TRUST_EMAIL, "set an unknown one");
    errors();

    printf("# without auxiliary data\n");
    checks("self-signed CA", ca);
    checks("leaf", server);
    printf("  trusted %d %d\n", X509_trusted(ca), X509_trusted(server));

    printf("# with auxiliary data\n");
    copy = X509_dup(server);
    check(X509_add1_trust_object(copy, OBJ_nid2obj(NID_server_auth)) == 1, "trusted for servers");
    checks("server-trusted leaf", copy);
    check(X509_add1_reject_object(copy, OBJ_nid2obj(NID_client_auth)) == 1, "rejected for clients");
    checks("and client-rejected", copy);
    check(X509_add1_trust_object(copy, OBJ_nid2obj(NID_anyExtendedKeyUsage)) == 1, "trusted for any");
    checks("and any", copy);
    check(X509_add1_reject_object(copy, OBJ_nid2obj(NID_anyExtendedKeyUsage)) == 1, "rejected for any");
    checks("and rejected for any", copy);
    printf("  lists: trust %d, reject %d\n", sk_ASN1_OBJECT_num(X509_get0_trust_objects(copy)),
           sk_ASN1_OBJECT_num(X509_get0_reject_objects(copy)));
    X509_reject_clear(copy);
    checks("rejections cleared", copy);
    X509_trust_clear(copy);
    checks("trust cleared", copy);
    printf("  lists: trust %d, reject %d, trusted %d\n", X509_get0_trust_objects(copy) != NULL,
           X509_get0_reject_objects(copy) != NULL, X509_trusted(copy));
    check(X509_add1_trust_object(copy, NULL) == 1, "an empty trust list");
    checks("empty trust list", copy);
    check(X509_add1_reject_object(copy, NULL) == 0, "no object to reject");

    printf("# alias and key ID\n");
    check(X509_alias_set1(copy, (const unsigned char *)"my server", -1) == 1, "alias");
    check(X509_keyid_set1(copy, (const unsigned char *)"\x01\x02\x03", 3) == 1, "key ID");
    p = X509_alias_get0(copy, &len);
    printf("  alias %.*s (%d)\n", len, (const char *)p, len);
    p = X509_keyid_get0(copy, &len);
    printf("  key ID %d: %02x %02x %02x\n", len, p[0], p[1], p[2]);
    {
        unsigned char *der = NULL;
        int n = i2d_X509_AUX(copy, &der), n2;
        const unsigned char *q = der;
        X509 *back = d2i_X509_AUX(NULL, &q, n);

        n2 = i2d_X509(copy, NULL);
        printf("  trusted encoding %d octets past the certificate\n", n - n2);
        check(back != NULL && X509_alias_get0(back, NULL) != NULL, "read back");
        X509_free(back);
        OPENSSL_free(der);
    }
    check(X509_alias_set1(copy, NULL, 0) == 1 && X509_alias_get0(copy, NULL) == NULL, "alias removed");
    check(X509_keyid_set1(copy, NULL, 0) == 1 && X509_keyid_get0(copy, NULL) == NULL, "key ID removed");
    check(X509_alias_set1(server, NULL, 0) == 1 && X509_trusted(server) == 0, "removing none makes nothing");
    check(X509_alias_get0(server, &len) == NULL, "no alias");

    printf("# added entries and the default check\n");
    check(X509_TRUST_add(1000, X509_TRUST_DYNAMIC, my_check, "mine", 7, NULL) == 1, "added");
    check(X509_TRUST_add(999, 0, my_check, "lower", 0, NULL) == 1, "added a lower id");
    check(X509_TRUST_add(X509_TRUST_EMAIL, 0, my_check, "Changed email", 0, NULL) == 1, "changed a built-in one");
    printf("  count %d, 999 at %d, 1000 at %d\n", X509_TRUST_get_count(), X509_TRUST_get_by_id(999),
           X509_TRUST_get_by_id(1000));
    for (i = 0; i < X509_TRUST_get_count(); i++) {
        X509_TRUST *tr = X509_TRUST_get0(i);

        printf("  %d: id %d, flags %d, %s\n", i, X509_TRUST_get_trust(tr), X509_TRUST_get_flags(tr),
               X509_TRUST_get0_name(tr));
    }
    checks("with them", server);
    old = X509_TRUST_set_default(my_default);
    printf("  my default: unknown %d, 1000 %d\n", X509_check_trust(server, 77, 3), X509_check_trust(server, 1000, 3));
    check(X509_TRUST_set_default(old) == my_default, "the old default back");
    printf("  unknown again %d\n", X509_check_trust(server, 77, 0));
    X509_TRUST_cleanup();
    printf("  after cleanup: count %d, email: %s\n", X509_TRUST_get_count(),
           X509_TRUST_get0_name(X509_TRUST_get0(X509_TRUST_get_by_id(X509_TRUST_EMAIL))));

    X509_free(copy);
    X509_free(ca);
    X509_free(server);
    printf("1..%d\n", number);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
