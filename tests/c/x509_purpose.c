/*
 * Conformance test for the certificate's extension cache and purposes (X509_check_purpose(3),
 * X509_check_ca(3), X509_check_issued(3), X509_get_extension_flags(3), X509_PURPOSE_get0(3),
 * X509_cmp, X509_add_cert, X509_self_signed, X509_get_signature_info), in TAP format:
 * certificates of each kind (CA, TLS server, code signing, time stamping, S/MIME, proxy,
 * invalid extensions, an unknown critical extension, RSA-PSS, Ed25519, and a version 1
 * self-signed one) with their flags, usages, path lengths, and key identifiers; every
 * purpose for each, as leaf and as CA; issuer checks; comparisons; adding to lists; the
 * purpose table, including added purposes; signature information; certificate types
 * (X509_certificate_type); and adding extensions (X509_add1_ext_i2d).
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
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

static const char CODE_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBezCCASCgAwIBAgIBBzAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApQdXJwb3Nl\n"
    "IENBMB4XDTI2MTAxNzE0NDYxOVoXDTM2MTAxNDE0NDYxOVowDzENMAsGA1UEAwwE\n"
    "Y29kZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBCZlP8GXl/OonAKX5IMNVac\n"
    "IWp+FgsLaTzbbz+PxK8YQEz2Ma4zEKpb9NKJUrcHd9uH18QzCmRLgQDt7nCZipaj\n"
    "ZzBlMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4E\n"
    "FgQUJBk/QuRxZDOWLuzi5mX1j9bo3XUwHwYDVR0jBBgwFoAUNJbMPHTsT/dZGIV8\n"
    "3Zxx95qS4TUwCgYIKoZIzj0EAwIDSQAwRgIhAIVgg0RMQ8bDQlhD8icHocyLig/A\n"
    "y9WfUVdsqWhKdSZQAiEAj4HR1L28UCDayevgsacGU99CiWthXZcUmNircgZAcgI=\n"
    "-----END CERTIFICATE-----\n";

static const char TSA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBfDCCASKgAwIBAgIBBzAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApQdXJwb3Nl\n"
    "IENBMB4XDTI2MTAxNzE0NDYxOVoXDTM2MTAxNDE0NDYxOVowDjEMMAoGA1UEAwwD\n"
    "dHNhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEJmU/wZeX86icApfkgw1Vpwh\n"
    "an4WCwtpPNtvP4/ErxhATPYxrjMQqlv00olStwd324fXxDMKZEuBAO3ucJmKlqNq\n"
    "MGgwDgYDVR0PAQH/BAQDAgZAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMB0GA1Ud\n"
    "DgQWBBQkGT9C5HFkM5Yu7OLmZfWP1ujddTAfBgNVHSMEGDAWgBQ0lsw8dOxP91kY\n"
    "hXzdnHH3mpLhNTAKBggqhkjOPQQDAgNIADBFAiEAkFBqLqkprCnqhen4xI9izLHp\n"
    "4EsWV8DoK/pq7gQlqn8CIGH1DUZn5GzaXaVq4tSuZZ1B7DMMOza4MwdNkC9CzbXf\n"
    "-----END CERTIFICATE-----\n";

static const char BAD_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBcTCCARegAwIBAgIBBzAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApQdXJwb3Nl\n"
    "IENBMB4XDTI2MTAxNzE0NDYxOVoXDTM2MTAxNDE0NDYxOVowDjEMMAoGA1UEAwwD\n"
    "YmFkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEJmU/wZeX86icApfkgw1Vpwh\n"
    "an4WCwtpPNtvP4/ErxhATPYxrjMQqlv00olStwd324fXxDMKZEuBAO3ucJmKlqNf\n"
    "MF0wDwYDVR0TBAgwBgEB/wIB/zAKBgNVHQ8EAwMBADAdBgNVHQ4EFgQUJBk/QuRx\n"
    "ZDOWLuzi5mX1j9bo3XUwHwYDVR0jBBgwFoAUNJbMPHTsT/dZGIV83Zxx95qS4TUw\n"
    "CgYIKoZIzj0EAwIDSAAwRQIhAN4AoMeamtDteTTTmzHsV8PJjR9pvI5Vmwz042z3\n"
    "dCzDAiBUXeY049Xc2q42CGj73uXwRXiPkbS/e3thzhAlSeQXug==\n"
    "-----END CERTIFICATE-----\n";

static const char CRIT_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBjTCCATSgAwIBAgIBBzAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApQdXJwb3Nl\n"
    "IENBMB4XDTI2MTAxNzE0NDYxOVoXDTM2MTAxNDE0NDYxOVowDzENMAsGA1UEAwwE\n"
    "Y3JpdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBCZlP8GXl/OonAKX5IMNVac\n"
    "IWp+FgsLaTzbbz+PxK8YQEz2Ma4zEKpb9NKJUrcHd9uH18QzCmRLgQDt7nCZipaj\n"
    "ezB5MAwGAyoDBAEB/wQCBQAwKQYDVR0uBCIwIDAeoBygGoYYaHR0cDovL2NybC5l\n"
    "eGFtcGxlL2QuY3JsMB0GA1UdDgQWBBQkGT9C5HFkM5Yu7OLmZfWP1ujddTAfBgNV\n"
    "HSMEGDAWgBQ0lsw8dOxP91kYhXzdnHH3mpLhNTAKBggqhkjOPQQDAgNHADBEAiBm\n"
    "0T1PZ0gKgRuSjvogirMAumkVaaIxgDZ81UoHcHx8tgIgfB26vplgkBhv0PFazFRN\n"
    "UfBUt5WiuaL1pmDyOYT0+Jk=\n"
    "-----END CERTIFICATE-----\n";

static const char PROXY_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBhTCCASugAwIBAgIBBzAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApQdXJwb3Nl\n"
    "IENBMB4XDTI2MTAxNzE0NDYxOVoXDTM2MTAxNDE0NDYxOVowEDEOMAwGA1UEAwwF\n"
    "cHJveHkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQQmZT/Bl5fzqJwCl+SDDVW\n"
    "nCFqfhYLC2k8228/j8SvGEBM9jGuMxCqW/TSiVK3B3fbh9fEMwpkS4EA7e5wmYqW\n"
    "o3EwbzAgBggrBgEFBQcBDgEB/wQRMA8CAQMwCgYIKwYBBQUHFQAwCwYDVR0PBAQD\n"
    "AgeAMB0GA1UdDgQWBBQkGT9C5HFkM5Yu7OLmZfWP1ujddTAfBgNVHSMEGDAWgBQ0\n"
    "lsw8dOxP91kYhXzdnHH3mpLhNTAKBggqhkjOPQQDAgNIADBFAiBzDa2vrtBP4grZ\n"
    "QQL9UlW4wjYiDU46uJxC25x44VCncQIhAOfN959vWjzsRhNiLdf5cmAhaE7zEpZt\n"
    "5g83SvQZtB/+\n"
    "-----END CERTIFICATE-----\n";

static const char SMIME_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBfjCCASSgAwIBAgIBBzAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApQdXJwb3Nl\n"
    "IENBMB4XDTI2MTAxNzE0NDYxOVoXDTM2MTAxNDE0NDYxOVowEDEOMAwGA1UEAwwF\n"
    "c21pbWUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQQmZT/Bl5fzqJwCl+SDDVW\n"
    "nCFqfhYLC2k8228/j8SvGEBM9jGuMxCqW/TSiVK3B3fbh9fEMwpkS4EA7e5wmYqW\n"
    "o2owaDATBgNVHSUEDDAKBggrBgEFBQcDBDARBglghkgBhvhCAQEEBAMCBSAwHQYD\n"
    "VR0OBBYEFCQZP0LkcWQzli7s4uZl9Y/W6N11MB8GA1UdIwQYMBaAFDSWzDx07E/3\n"
    "WRiFfN2ccfeakuE1MAoGCCqGSM49BAMCA0gAMEUCIDCkucryJ/AoZc493K8L8Go9\n"
    "vu/ttXoH6vU/8CFHhJz0AiEA6XDWgRZWrrM7yuXXsiHU7bkV57xkJHBFbZUDnVnX\n"
    "sXE=\n"
    "-----END CERTIFICATE-----\n";

static const char PSS_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICGzCCAVCgAwIBAgIBAzBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAgUA\n"
    "oRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAgUAogMCATAwDjEMMAoGA1UEAwwD\n"
    "UFNTMB4XDTI2MTAxNzExNTczOVoXDTI2MTExNjExNTczOVowDjEMMAoGA1UEAwwD\n"
    "UFNTMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIuJbMN1fqdH8jQ8V+pAyO\n"
    "bM5o/eTZyEuXpuCfD/nq5Fu612WUcaJlhbVbNfmgW+CMbD5kFAvTy//5JkRF7N0G\n"
    "eKcSQB8nLbKTa24QlRU+k5L2Dq/rQuv3bCETamL5TSU2cILDxRRnmMy8zGTcSzBy\n"
    "8WfSoc7Gn/j1Ge7wtp+zAQIDAQABoyEwHzAdBgNVHQ4EFgQUoIyUcXdwWBeZM+sR\n"
    "qKEJiUvCQdQwQQYJKoZIhvcNAQEKMDSgDzANBglghkgBZQMEAgIFAKEcMBoGCSqG\n"
    "SIb3DQEBCDANBglghkgBZQMEAgIFAKIDAgEwA4GBAHjZXpIPcBM8Qyazzc4IS2NV\n"
    "uUiGNJXCdUQhq5qeBgCqN+e+GHE1Vp4fQEjGlHbwbNYLHisG4dgN7SWq7RuJOJ8O\n"
    "tiLKYIKpXozJsxajb/ODL6rxaaO5zNpr9pfoItSgT52bhTUHjUSaJ1sr5DWZREUe\n"
    "GEJi1GO7f5BuBjlPrXZT\n"
    "-----END CERTIFICATE-----\n";

static const char ED_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIHzMIGmoAMCAQICAQQwBQYDK2VwMBIxEDAOBgNVBAMMB0VkMjU1MTkwHhcNMjYx\n"
    "MDE3MTE1NzM5WhcNMjYxMTE2MTE1NzM5WjASMRAwDgYDVQQDDAdFZDI1NTE5MCow\n"
    "BQYDK2VwAyEAuNhxQSv61lvhzOw9ja9vUr7Ox3zmUjSLdY9uES9cEnqjITAfMB0G\n"
    "A1UdDgQWBBQF9XKRzyTHVxOlkwHteKrmtgyGAjAFBgMrZXADQQAqO/w+PludG6b4\n"
    "gaRBPE3Fq7TZpNXylLKYTBTXlsdvkrgJUURfV8bQZldJkNxTxHyk6tsncza1p7GX\n"
    "OtQ25cEE\n"
    "-----END CERTIFICATE-----\n";


static X509 *read_cert(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);

    BIO_free(b);
    return x;
}

static void hexs(const char *label, const ASN1_OCTET_STRING *s)
{
    int i;

    printf("  %s:", label);
    if (s == NULL) {
        printf(" none\n");
        return;
    }
    for (i = 0; i < ASN1_STRING_length(s); i++)
        printf(" %02x", ASN1_STRING_get0_data(s)[i]);
    printf("\n");
}

static void show(const char *label, X509 *x)
{
    int i, md = -2, pk = -2, bits = -2, valid;
    uint32_t sflags = 0;

    printf("# %s\n", label);
    printf("  flags %08x, key usage %08x, extended %08x\n", (unsigned)X509_get_extension_flags(x),
           (unsigned)X509_get_key_usage(x), (unsigned)X509_get_extended_key_usage(x));
    errors();
    printf("  pathlen %ld, proxy pathlen %ld, ca %d, self-signed %d %d\n", X509_get_pathlen(x),
           X509_get_proxy_pathlen(x), X509_check_ca(x), X509_self_signed(x, 0), X509_self_signed(x, 1));
    errors();
    hexs("subject key id", X509_get0_subject_key_id(x));
    hexs("authority key id", X509_get0_authority_key_id(x));
    printf("  authority issuer %d, serial %ld\n", X509_get0_authority_issuer(x) != NULL
               ? sk_GENERAL_NAME_num(X509_get0_authority_issuer(x)) : -1,
           X509_get0_authority_serial(x) != NULL ? ASN1_INTEGER_get(X509_get0_authority_serial(x)) : -1);
    printf("  purposes:");
    for (i = 0; i < X509_PURPOSE_get_count(); i++) {
        X509_PURPOSE *p = X509_PURPOSE_get0(i);

        printf(" %s=%d/%d", X509_PURPOSE_get0_sname(p), X509_check_purpose(x, X509_PURPOSE_get_id(p), 0),
               X509_check_purpose(x, X509_PURPOSE_get_id(p), 1));
    }
    printf("\n");
    printf("  unknown purpose %d, cache only %d\n", X509_check_purpose(x, 99, 0), X509_check_purpose(x, -1, 0));
    valid = X509_get_signature_info(x, &md, &pk, &bits, &sflags);
    printf("  signature info %d: md %d, pk %d, bits %d, flags %u\n", valid, md, pk, bits, (unsigned)sflags);
    errors();
    for (i = 0; i < X509_get_ext_count(x); i++)
        printf("  extension %d supported %d\n", OBJ_obj2nid(X509_EXTENSION_get_object(X509_get_ext(x, i))),
               X509_supported_extension(X509_get_ext(x, i)));
}

static int ck_any(const X509_PURPOSE *xp, const X509 *x, int non_leaf)
{
    (void)x;
    return non_leaf ? 7 : X509_PURPOSE_get_id(xp);
}

static void test_table(X509 *leaf)
{
    int i, id, p = -5;

    printf("# the purpose table\n");
    printf("  count %d, unused id %d\n", X509_PURPOSE_get_count(), X509_PURPOSE_get_unused_id(NULL));
    for (i = 0; i < X509_PURPOSE_get_count(); i++) {
        X509_PURPOSE *xp = X509_PURPOSE_get0(i);

        printf("  %d: id %d, trust %d, %s (%s), by id %d, by name %d\n", i, X509_PURPOSE_get_id(xp),
               X509_PURPOSE_get_trust(xp), X509_PURPOSE_get0_name(xp), X509_PURPOSE_get0_sname(xp),
               X509_PURPOSE_get_by_id(X509_PURPOSE_get_id(xp)), X509_PURPOSE_get_by_sname(X509_PURPOSE_get0_sname(xp)));
    }
    check(X509_PURPOSE_get0(-1) == NULL && X509_PURPOSE_get0(99) == NULL, "out of range");
    printf("  by id 0 %d, 11 %d, 99 %d; by name nothing %d\n", X509_PURPOSE_get_by_id(0), X509_PURPOSE_get_by_id(11),
           X509_PURPOSE_get_by_id(99), X509_PURPOSE_get_by_sname("nothing"));
    check(X509_PURPOSE_set(&p, X509_PURPOSE_SSL_SERVER) == 1 && p == X509_PURPOSE_SSL_SERVER, "set");
    check(X509_PURPOSE_set(&p, X509_PURPOSE_DEFAULT_ANY) == 1 && p == 0, "set the default");
    check(X509_PURPOSE_set(&p, 99) == 0 && p == 0, "set an unknown one");
    errors();

    id = X509_PURPOSE_get_unused_id(NULL);
    check(X509_PURPOSE_add(id, X509_TRUST_DEFAULT, 0, ck_any, "Mine", "mine", NULL) == 1, "add");
    check(X509_PURPOSE_add(id + 1, X509_TRUST_DEFAULT, 0, ck_any, "Other", "mine", NULL) == 1, "change its id");
    check(X509_PURPOSE_add(id + 2, X509_TRUST_DEFAULT, 0, ck_any, "Third", "third", NULL) == 1, "add another");
    check(X509_PURPOSE_add(id + 2, X509_TRUST_DEFAULT, 0, ck_any, "Clash", "clash", NULL) == 0, "same id fails");
    errors();
    check(X509_PURPOSE_add(0, X509_TRUST_DEFAULT, 0, ck_any, "Low", "low", NULL) == 0, "too low an id fails");
    errors();
    check(X509_PURPOSE_add(id + 3, -1, 0, ck_any, "x", "x", NULL) == 0, "a bad trust fails");
    check(X509_PURPOSE_add(id + 3, X509_TRUST_DEFAULT, 0, NULL, "x", "x", NULL) == 0, "no check fails");
    check(X509_PURPOSE_add(id + 3, X509_TRUST_DEFAULT, 0, ck_any, NULL, "x", NULL) == 0, "no name fails");
    errors();
    check(X509_PURPOSE_add(X509_PURPOSE_ANY, X509_TRUST_EMAIL, 0, ck_any, "Any Changed", "any", NULL) == 1,
          "change a built-in one");
    printf("  count %d, unused id %d\n", X509_PURPOSE_get_count(), X509_PURPOSE_get_unused_id(NULL));
    for (i = 0; i < X509_PURPOSE_get_count(); i++) {
        X509_PURPOSE *xp = X509_PURPOSE_get0(i);

        printf("  %d: id %d, trust %d, %s (%s), by id %d, check %d/%d\n", i, X509_PURPOSE_get_id(xp),
               X509_PURPOSE_get_trust(xp), X509_PURPOSE_get0_name(xp), X509_PURPOSE_get0_sname(xp),
               X509_PURPOSE_get_by_id(X509_PURPOSE_get_id(xp)), X509_check_purpose(leaf, X509_PURPOSE_get_id(xp), 0),
               X509_check_purpose(leaf, X509_PURPOSE_get_id(xp), 1));
    }
    X509_PURPOSE_cleanup();
    printf("  after cleanup: count %d, any: %s\n", X509_PURPOSE_get_count(),
           X509_PURPOSE_get0_name(X509_PURPOSE_get0(X509_PURPOSE_get_by_id(X509_PURPOSE_ANY))));
    check(X509_PURPOSE_add(X509_PURPOSE_ANY, X509_TRUST_DEFAULT, 0, X509_PURPOSE_get0(1)->check_purpose,
                           "Any Purpose", "any", NULL) == 1, "change it back");
    printf("  any: %d\n", X509_check_purpose(leaf, X509_PURPOSE_ANY, 0));
    X509_PURPOSE_cleanup();
}

static int siginf_calls;

/* An application's siginf_set: sets the information, then reads it back. */
static int my_siginf(X509_SIG_INFO *siginf, const X509_ALGOR *alg, const ASN1_STRING *sig)
{
    int md = 0, pk = 0, bits = 0;
    uint32_t flags = 0;

    (void)alg;
    (void)sig;
    siginf_calls++;
    X509_SIG_INFO_set(siginf, NID_sha384, NID_rsaEncryption, 99, X509_SIG_INFO_TLS);
    printf("  in siginf_set: get %d", X509_SIG_INFO_get(siginf, &md, &pk, &bits, &flags));
    printf(" md %d, pk %d, bits %d, flags %u\n", md, pk, bits, (unsigned)flags);
    X509_SIG_INFO_set(siginf, NID_sha384, NID_rsaEncryption, 99, X509_SIG_INFO_TLS | X509_SIG_INFO_VALID);
    return 1;
}

static void test_siginf(X509 *server)
{
    int pknid = OBJ_create("1.3.6.1.4.1.99999.1", "myPkey", "my key type");
    int signid = OBJ_create("1.3.6.1.4.1.99999.2", "mySig", "my signature");
    EVP_PKEY_ASN1_METHOD *am = EVP_PKEY_asn1_new(pknid, 0, "MYKEY", "my key");
    X509 *x = X509_dup(server);
    const X509_ALGOR *alg = NULL;
    int md = -2, pk = -2, bits = -2, valid;
    uint32_t flags = 0;

    printf("# an application's siginf_set\n");
    EVP_PKEY_asn1_set_siginf(am, my_siginf);
    check(EVP_PKEY_asn1_add0(am) == 1, "method added");
    check(OBJ_add_sigid(signid, NID_undef, pknid) == 1, "signature algorithm added");
    X509_get0_signature(NULL, &alg, x);
    X509_ALGOR_set0((X509_ALGOR *)alg, OBJ_nid2obj(signid), V_ASN1_UNDEF, NULL);
    valid = X509_get_signature_info(x, &md, &pk, &bits, &flags);
    printf("  info %d: md %d, pk %d, bits %d, flags %u, calls %d\n", valid, md, pk, bits, (unsigned)flags, siginf_calls);
    X509_set_proxy_flag(x);
    X509_set_proxy_pathlen(x, 5);
    printf("  proxy: flags %08x, pathlen %ld\n", (unsigned)X509_get_extension_flags(x), X509_get_proxy_pathlen(x));
    X509_free(x);
    ERR_clear_error();
}

int main(void)
{
    X509 *ca = read_cert(CA_PEM), *server = read_cert(SERVER_PEM), *code = read_cert(CODE_PEM);
    X509 *tsa = read_cert(TSA_PEM), *bad = read_cert(BAD_PEM), *crit = read_cert(CRIT_PEM);
    X509 *proxy = read_cert(PROXY_PEM), *smime = read_cert(SMIME_PEM), *pss = read_cert(PSS_PEM);
    X509 *ed = read_cert(ED_PEM), *copy, *v1 = X509_new(), *fresh = X509_new();
    STACK_OF(X509) *sk = sk_X509_new_null(), *more = sk_X509_new_null();
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    X509_NAME *n = X509_NAME_new();

    show("CA", ca);
    show("server", server);
    show("code signing", code);
    show("time stamping", tsa);
    show("invalid extensions", bad);
    show("unknown critical extension", crit);
    show("proxy", proxy);
    show("S/MIME", smime);
    show("RSA-PSS", pss);
    show("Ed25519", ed);
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)"v1", -1, -1, 0);
    X509_set_version(v1, X509_VERSION_1);
    X509_set_subject_name(v1, n);
    X509_set_issuer_name(v1, n);
    X509_set_pubkey(v1, key);
    ASN1_INTEGER_set(X509_get_serialNumber(v1), 9);
    X509_sign(v1, key, NULL);
    show("version 1, self-signed", v1);
    show("empty", fresh);

    printf("# issuers\n");
    printf("  ca->server %d, ca->code %d, server->ca %d, ca->ca %d, server->server %d, ca->proxy %d\n",
           X509_check_issued(ca, server), X509_check_issued(ca, code), X509_check_issued(server, ca),
           X509_check_issued(ca, ca), X509_check_issued(server, server), X509_check_issued(ca, proxy));
    printf("  akid: NULL of ca %d, of server %d\n", X509_check_akid(ca, NULL), X509_check_akid(server, NULL));
    {
        AUTHORITY_KEYID *akid = X509_get_ext_d2i(server, NID_authority_key_identifier, NULL, NULL);

        printf("  server's akid: of ca %d, of server %d, of pss %d\n", X509_check_akid(ca, akid),
               X509_check_akid(server, akid), X509_check_akid(pss, akid));
        AUTHORITY_KEYID_free(akid);
    }
    {
        int crit_flag = -2, idx = -1;
        BASIC_CONSTRAINTS *bs = X509_get_ext_d2i(ca, NID_basic_constraints, &crit_flag, &idx);

        printf("  get_ext_d2i: %d, crit %d, idx %d\n", bs != NULL && bs->ca, crit_flag, idx);
        BASIC_CONSTRAINTS_free(bs);
        bs = X509_get_ext_d2i(ca, NID_basic_constraints, &crit_flag, &idx);
        printf("  again from idx: %d, crit %d, idx %d\n", bs != NULL, crit_flag, idx);
        BASIC_CONSTRAINTS_free(bs);
    }

    printf("# comparisons\n");
    copy = X509_dup(server);
    printf("  server/copy %d, server/ca %d, ca/server %d, self %d\n", X509_cmp(server, copy),
           X509_cmp(server, ca) == -X509_cmp(ca, server), X509_cmp(ca, server) != 0, X509_cmp(ca, ca));

    {
        unsigned char before[EVP_MAX_MD_SIZE], after[EVP_MAX_MD_SIZE], s256[EVP_MAX_MD_SIZE], s256b[EVP_MAX_MD_SIZE];
        unsigned int n1 = 0, n2 = 0, n3 = 0, n4 = 0;
        X509 *c2 = X509_dup(server);

        X509_digest(c2, EVP_sha1(), before, &n1);
        X509_digest(c2, EVP_sha256(), s256, &n3);
        X509_check_purpose(c2, -1, 0);
        ASN1_INTEGER_set(X509_get_serialNumber(c2), 99);
        X509_digest(c2, EVP_sha1(), after, &n2);
        X509_digest(c2, EVP_sha256(), s256b, &n4);
        printf("  after a change: SHA-1 cached %d (%u), SHA-256 fresh %d\n", n1 == n2 && memcmp(before, after, n1) == 0, n2,
               n3 != n4 || memcmp(s256, s256b, n3) != 0);
        X509_free(c2);
    }
    printf("# adding\n");
    check(X509_add_cert(sk, ca, X509_ADD_FLAG_UP_REF) == 1, "add the CA");
    check(X509_add_cert(sk, copy, X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_PREPEND) == 1, "prepend the copy");
    check(X509_add_cert(sk, server, X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_DUP) == 1, "a duplicate isn't added");
    check(X509_add_cert(sk, ed, X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_SS) == 1, "self-signed? not added");
    check(X509_add_cert(sk, v1, X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_SS) == 1, "a self-signed one isn't added");
    check(X509_add_cert(sk, NULL, 0) == 0, "NULL isn't");
    check(X509_add_cert(NULL, ca, 0) == 0, "no list");
    errors();
    printf("  list: %d\n", sk_X509_num(sk));
    check(X509_add_certs(more, sk, X509_ADD_FLAG_UP_REF) == 1, "add them all");
    check(X509_add_certs(more, sk, X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_PREPEND | X509_ADD_FLAG_NO_DUP) == 1,
          "again, no duplicates");
    check(X509_add_certs(more, NULL, 0) == 1, "none");
    check(X509_add_certs(NULL, sk, 0) == 0, "no list");
    errors();
    printf("  more: %d, first is the copy %d\n", sk_X509_num(more), X509_cmp(sk_X509_value(more, 0), copy) == 0);

    printf("# certificate types\n");
    printf("  CA %#x, server %#x, PSS %#x, Ed25519 %#x, v1 %#x, empty %#x, NULL %#x\n",
           (unsigned)X509_certificate_type(ca, NULL), (unsigned)X509_certificate_type(server, NULL),
           (unsigned)X509_certificate_type(pss, NULL), (unsigned)X509_certificate_type(ed, NULL),
           (unsigned)X509_certificate_type(v1, NULL), (unsigned)X509_certificate_type(fresh, NULL),
           (unsigned)X509_certificate_type(NULL, key));
    printf("  server with the Ed25519 key %#x\n", (unsigned)X509_certificate_type(server, key));
    errors();

    printf("# X509_add1_ext_i2d\n");
    {
        ASN1_IA5STRING *comment = ASN1_IA5STRING_new();

        ASN1_STRING_set(comment, "a comment", -1);
        check(X509_add1_ext_i2d(fresh, NID_netscape_comment, comment, 0, X509V3_ADD_DEFAULT) == 1, "added");
        check(X509_add1_ext_i2d(fresh, NID_netscape_comment, comment, 0, X509V3_ADD_DEFAULT) == 0,
              "added again fails");
        errors();
        check(X509_add1_ext_i2d(fresh, NID_netscape_comment, comment, 1, X509V3_ADD_REPLACE) == 1, "replaced");
        check(X509_add1_ext_i2d(fresh, NID_netscape_comment, NULL, 0, X509V3_ADD_DELETE) == 1, "deleted");
        printf("  extensions: %d\n", X509_get_ext_count(fresh));
        ASN1_IA5STRING_free(comment);
    }

    test_table(server);
    test_siginf(server);

    OSSL_STACK_OF_X509_free(sk);
    OSSL_STACK_OF_X509_free(more);
    X509_NAME_free(n);
    EVP_PKEY_free(key);
    X509_free(ca);
    X509_free(server);
    X509_free(code);
    X509_free(tsa);
    X509_free(bad);
    X509_free(crit);
    X509_free(proxy);
    X509_free(smime);
    X509_free(pss);
    X509_free(ed);
    X509_free(copy);
    X509_free(v1);
    X509_free(fresh);
    printf("1..%d\n", number);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
