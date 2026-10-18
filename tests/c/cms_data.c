/*
 * Conformance test for the CMS structures and library (CMS_ContentInfo_new(3), d2i_CMS_bio(3),
 * CMS_get0_type(3), CMS_get0_content, CMS_set1_eContentType, CMS_add1_cert(3),
 * CMS_get1_certs, CMS_get0_SignerInfos, CMS_signed_get_attr and the other attribute functions,
 * CMS_ReceiptRequest_create0(3)), the simple content types (CMS_data_create(3),
 * CMS_digest_create(3), CMS_digest_verify, CMS_EncryptedData_encrypt(3),
 * CMS_EncryptedData_decrypt), their data path (CMS_dataInit, CMS_dataFinal, CMS_final(3)),
 * streaming (CMS_stream, BIO_new_CMS(3), i2d_CMS_bio_stream(3), PEM_write_bio_CMS_stream(3)),
 * PEM and S/MIME (SMIME_write_CMS(3), SMIME_read_CMS(3)), and CMS_SharedInfo_encode: objects
 * the reference's tool wrote read, printed, verified, and decrypted; objects made here
 * round-tripped. Outputs with a random IV or identifier are checked, not printed.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/evp.h>
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
            printf(" (%s)", data);
    }
    printf("\n");
}

/*
 * Made with the reference's openssl tool: an EC root; an RSA signer and an RSA recipient;
 * cms -data_create, -digest_create -md sha256, -EncryptedData_encrypt -aes128 (key
 * 000102...0F), -sign -nodetach (RSA), and -encrypt -aes128 (to the recipient).
 */
static const char CA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBlDCCATqgAwIBAgIUQs8ZErMWPIenaD/uOzlwoxywlnkwCgYIKoZIzj0EAwIw\n"
    "JzEQMA4GA1UECgwHRXhhbXBsZTETMBEGA1UEAwwKU01JTUUgUm9vdDAgFw0yNjEw\n"
    "MTcyMjE3MTVaGA8yMTI2MDkyMzIyMTcxNVowJzEQMA4GA1UECgwHRXhhbXBsZTET\n"
    "MBEGA1UEAwwKU01JTUUgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABB/A\n"
    "LTVcONUfVNJW+I8m+pFZZv2E1nueaotIxtyuCuU7vgtX+B5ipx7qLqbCpXc7uTw5\n"
    "+VUU035P3665HlhlE0+jQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQD\n"
    "AgEGMB0GA1UdDgQWBBR1tdNQedtUtDillwMhWwDwHWigRTAKBggqhkjOPQQDAgNI\n"
    "ADBFAiEAmd7Q2H6po4/J8cf3XXtIff8eg2y6AK2SNxOz6Q0JHJkCIHMhga44JyLn\n"
    "b8qaJPtNes6gug+NZqD0WNA58tYqngmQ\n"
    "-----END CERTIFICATE-----\n";

static const char RSA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICaTCCAg+gAwIBAgIBZTAKBggqhkjOPQQDAjAnMRAwDgYDVQQKDAdFeGFtcGxl\n"
    "MRMwEQYDVQQDDApTTUlNRSBSb290MCAXDTI2MTAxNzIyMTcxNVoYDzIxMjYwOTIz\n"
    "MjIxNzE1WjAUMRIwEAYDVQQDDAlTTUlNRSByc2EwggEiMA0GCSqGSIb3DQEBAQUA\n"
    "A4IBDwAwggEKAoIBAQCTF3DR1lrRhjc9u1jEVzgYclC+L3X6x88IGgzCdKPaNwhL\n"
    "QlWsDXmluMlqa0Tvb4Ob392Ufxmkn1W30XhYTypLjGOL5bksoiGDiQZn1ovA/Gnd\n"
    "mCq1J47pSNhz6SL1/uOZvmj6vdpr0p26BtqGCr1hXowWKIvmJGdr5JV4fPgRXO/n\n"
    "FCqYvwzm0hxCCWF+cpACJgB/NkB54nSqeYdRhwJvU9D8glmTuwO4UY035FDYcYKa\n"
    "jiIMtnJnGlo/IJMEyI1+lQGWWFOSCPhld5B3etvb8Yz+LC51w4jlroXJw7q1HmTG\n"
    "i2IR4fugKC8lLugmbONeFXjeCawPRVhZPR2/1AHNAgMBAAGjcjBwMAkGA1UdEwQC\n"
    "MAAwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMEMB0GA1UdDgQW\n"
    "BBQTEOssjmFffw9DHdfYXG+4qmqEvDAfBgNVHSMEGDAWgBR1tdNQedtUtDillwMh\n"
    "WwDwHWigRTAKBggqhkjOPQQDAgNIADBFAiAJ6N2sNNdSNa+IDpskcT9WoVcNF5gK\n"
    "YOWbDzbJFIJTZQIhAOTlwtgT1PhcURW6WGxpnKHrkg8l+RbzadUEJJAksG/w\n"
    "-----END CERTIFICATE-----\n";

static const char RCPT_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICaTCCAhCgAwIBAgIBZzAKBggqhkjOPQQDAjAnMRAwDgYDVQQKDAdFeGFtcGxl\n"
    "MRMwEQYDVQQDDApTTUlNRSBSb290MCAXDTI2MTAxNzIyMTcxNVoYDzIxMjYwOTIz\n"
    "MjIxNzE1WjAVMRMwEQYDVQQDDApTTUlNRSByY3B0MIIBIjANBgkqhkiG9w0BAQEF\n"
    "AAOCAQ8AMIIBCgKCAQEA18QxOUhaJRisASI6xBIN16PV9WkdrTbE/yz4ahtxgElk\n"
    "YK1mXdFD5QYRplsnHqPevW2cVVbS0+vtxMTxGy0znDNWX8WMzrgJjk1vniMuibwn\n"
    "4j8IRqptUSj2060QIB/5DIX0cHSz5xfvpv4D++K72tVvmL+KMSYSNdLxGMzPQ9Ci\n"
    "f8Fr/LEMOpibDj+kTPIk/n65w+W+Uno5NUqQ8uFsxgTbkuWh3lfXyRoIKT4rkGXg\n"
    "NL+myxIyTtT2wJRMOW4uGjKcfEH7ZteXkV23KMVBsZGZGRiEfaIHhnUGyWPFp5Ue\n"
    "a+YxR3MbbLd4OO4r8wS4l9ZNqE6lN/M7UimNxfz56wIDAQABo3IwcDAJBgNVHRME\n"
    "AjAAMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDBDAdBgNVHQ4E\n"
    "FgQUUmeYW6EuzZLObWOj5T/p6KmKoPswHwYDVR0jBBgwFoAUdbXTUHnbVLQ4pZcD\n"
    "IVsA8B1ooEUwCgYIKoZIzj0EAwIDRwAwRAIgDRHniyVkaNrc4o4cD1JaVMtTO7qB\n"
    "FP3kjU4I72ipOKMCIFLvIE2lHC/XU7tOaJGloo9z/c4NP027HPqwm/Mnl8yh\n"
    "-----END CERTIFICATE-----\n";

static const char DATA_PEM[] =
    "-----BEGIN CMS-----\n"
    "MDQGCSqGSIb3DQEHAaAnBCVIZWxsbywgUy9NSU1FLg0KU2Vjb25kIGxpbmUgIA0K\n"
    "DQpsYXN0\n"
    "-----END CMS-----\n";

static const char DIGEST_PEM[] =
    "-----BEGIN CMS-----\n"
    "MHcGCSqGSIb3DQEHBaBqMGgCAQAwCwYJYIZIAWUDBAIBMDQGCSqGSIb3DQEHAaAn\n"
    "BCVIZWxsbywgUy9NSU1FLg0KU2Vjb25kIGxpbmUgIA0KDQpsYXN0BCA+c+poW/0n\n"
    "sXU6Hh10kKDSnZk++amUAvJbRkQM7jyllA==\n"
    "-----END CMS-----\n";

static const char ENCDATA_PEM[] =
    "-----BEGIN CMS-----\n"
    "MHAGCSqGSIb3DQEHBqBjMGECAQAwXAYJKoZIhvcNAQcBMB0GCWCGSAFlAwQBAgQQ\n"
    "w2xoiI0vf4ix9a2dqf3bXIAwq8T6ELgJQq9P6Tl+pdilZjWteGt/H/Hx7xLyEE/R\n"
    "URNcmcW1YR5spwzaSLXwsTsT\n"
    "-----END CMS-----\n";

static const char SIGNED_PEM[] =
    "-----BEGIN CMS-----\n"
    "MIIFDAYJKoZIhvcNAQcCoIIE/TCCBPkCAQExDTALBglghkgBZQMEAgEwNAYJKoZI\n"
    "hvcNAQcBoCcEJUhlbGxvLCBTL01JTUUuDQpTZWNvbmQgbGluZSAgDQoNCmxhc3Sg\n"
    "ggJtMIICaTCCAg+gAwIBAgIBZTAKBggqhkjOPQQDAjAnMRAwDgYDVQQKDAdFeGFt\n"
    "cGxlMRMwEQYDVQQDDApTTUlNRSBSb290MCAXDTI2MTAxNzIyMTcxNVoYDzIxMjYw\n"
    "OTIzMjIxNzE1WjAUMRIwEAYDVQQDDAlTTUlNRSByc2EwggEiMA0GCSqGSIb3DQEB\n"
    "AQUAA4IBDwAwggEKAoIBAQCTF3DR1lrRhjc9u1jEVzgYclC+L3X6x88IGgzCdKPa\n"
    "NwhLQlWsDXmluMlqa0Tvb4Ob392Ufxmkn1W30XhYTypLjGOL5bksoiGDiQZn1ovA\n"
    "/GndmCq1J47pSNhz6SL1/uOZvmj6vdpr0p26BtqGCr1hXowWKIvmJGdr5JV4fPgR\n"
    "XO/nFCqYvwzm0hxCCWF+cpACJgB/NkB54nSqeYdRhwJvU9D8glmTuwO4UY035FDY\n"
    "cYKajiIMtnJnGlo/IJMEyI1+lQGWWFOSCPhld5B3etvb8Yz+LC51w4jlroXJw7q1\n"
    "HmTGi2IR4fugKC8lLugmbONeFXjeCawPRVhZPR2/1AHNAgMBAAGjcjBwMAkGA1Ud\n"
    "EwQCMAAwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMEMB0GA1Ud\n"
    "DgQWBBQTEOssjmFffw9DHdfYXG+4qmqEvDAfBgNVHSMEGDAWgBR1tdNQedtUtDil\n"
    "lwMhWwDwHWigRTAKBggqhkjOPQQDAgNIADBFAiAJ6N2sNNdSNa+IDpskcT9WoVcN\n"
    "F5gKYOWbDzbJFIJTZQIhAOTlwtgT1PhcURW6WGxpnKHrkg8l+RbzadUEJJAksG/w\n"
    "MYICPDCCAjgCAQEwLDAnMRAwDgYDVQQKDAdFeGFtcGxlMRMwEQYDVQQDDApTTUlN\n"
    "RSBSb290AgFlMAsGCWCGSAFlAwQCAaCB5DAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN\n"
    "AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjEwMTcyMzQ3MTVaMC8GCSqGSIb3DQEJBDEi\n"
    "BCA+c+poW/0nsXU6Hh10kKDSnZk++amUAvJbRkQM7jyllDB5BgkqhkiG9w0BCQ8x\n"
    "bDBqMAsGCWCGSAFlAwQBKjALBglghkgBZQMEARYwCwYJYIZIAWUDBAECMAoGCCqG\n"
    "SIb3DQMHMA4GCCqGSIb3DQMCAgIAgDANBggqhkiG9w0DAgIBQDAHBgUrDgMCBzAN\n"
    "BggqhkiG9w0DAgIBKDANBgkqhkiG9w0BAQEFAASCAQCBSj9YzW0ixtQPlkbANkOu\n"
    "ywrFUaIIdcV84noL++ceKVQqH6FPX+gPxW/eHc6WiHemzo/uVWOO7p/WC7sSj7dU\n"
    "3bwCCsaDsNUELq/NWbJJwUFXdp5qWPRVS/HU/CKLXynwoUJvixJX94aZ2zRkYB+7\n"
    "M3W8LOgMhYSS5krg0og/4045USDXNuk+CIbW2WlzAfWqWcy4h8Q0LrffZ95AoVOn\n"
    "8LRSpAQ0JxTnXZRiIp+buLV/38KUaZPOUUcWEmschB7wqUEpu9ATCEE+zwNOyWW9\n"
    "E+ajyC4+/l37oBAJ6tDH8h+ov0BrWErJxGv+iD5RMLcyceZohiRLdf9ixg1TEQna\n"
    "-----END CMS-----\n";

static const char ENV_PEM[] =
    "-----BEGIN CMS-----\n"
    "MIIBwAYJKoZIhvcNAQcDoIIBsTCCAa0CAQAxggFIMIIBRAIBADAsMCcxEDAOBgNV\n"
    "BAoMB0V4YW1wbGUxEzARBgNVBAMMClNNSU1FIFJvb3QCAWcwDQYJKoZIhvcNAQEB\n"
    "BQAEggEAPTw/zfraS0mT3UmwAH271LsQ1MMAkXCXiqE0eU+pBXnM3ulZ/7w98/1I\n"
    "nhz2S+tB6Ft8UzsipweLmf4iMQC3H8pX8pIvk2ElKRA5ZXKPLxe4cU4d01gLvxYy\n"
    "gC6tukZSFYFnCtFhZmRvmj50kc9WJKatqu2KSIDsTubP40oCz+/ZDddSQxb5pZjm\n"
    "ktA4WGph/pw1OYPZ1MFlqAV9DsT2hcktQ7Xj9UvSqIl3p9snSGe2XzTdR6hPCVxz\n"
    "Kt2P3tgdfkYtbdkDoXaspdIcRULHwZjHvTpuVXrWZji4F+Yp0Shfb3qSy3Kn+2Vs\n"
    "sn0Ij4KVCq45te3zIDxP54bS1PB68TBcBgkqhkiG9w0BBwEwHQYJYIZIAWUDBAEC\n"
    "BBDltGKcHHSaK4cyoFaMvi77gDAW8tFbzwLUZhcgmZHFRzBR1aJHtnFS2/eRXGT/\n"
    "QadxpjqBb/AIC6Q4chi3elkxrLw=\n"
    "-----END CMS-----\n";
static const char msg[] = "Hello, S/MIME.\nSecond line  \r\n\nlast";
static const unsigned char aes_key[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

static BIO *mem(const char *s)
{
    return BIO_new_mem_buf(s, -1);
}

static X509 *cert(const char *pem)
{
    BIO *b = mem(pem);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);

    BIO_free(b);
    return x;
}

static CMS_ContentInfo *load(const char *pem)
{
    BIO *b = mem(pem);
    CMS_ContentInfo *cms = PEM_read_bio_CMS(b, NULL, NULL, NULL);

    BIO_free(b);
    return cms;
}

static void hex(const char *label, const unsigned char *p, int n)
{
    int i;

    printf("  %s (%d):", label, n);
    for (i = 0; i < n; i++)
        printf("%s%02x", i % 32 == 0 ? "\n    " : "", p[i]);
    printf("\n");
}

static void show(const char *label, BIO *b)
{
    char *p;
    long n = BIO_get_mem_data(b, &p), i;

    printf("  %s (%ld): \"", label, n);
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)p[i];

        if (c == '\r')
            printf("\\r");
        else if (c == '\n')
            printf("\\n");
        else if (c < 32 || c > 126)
            printf("\\x%02x", c);
        else
            putchar(c);
    }
    printf("\"\n");
}

static void der(const char *label, CMS_ContentInfo *cms)
{
    unsigned char *d = NULL;
    int n = i2d_CMS_ContentInfo(cms, &d);

    hex(label, d, n);
    OPENSSL_free(d);
}

static const char *oid(const ASN1_OBJECT *o)
{
    static char bufs[4][80];
    static int k;
    char *buf = bufs[k++ % 4];

    if (o == NULL)
        return "(none)";
    OBJ_obj2txt(buf, 80, o, 0);
    return buf;
}

static void describe(const char *label, CMS_ContentInfo *cms)
{
    ASN1_OCTET_STRING **pos;

    if (cms == NULL) {
        printf("# %s: NULL\n", label);
        errors();
        return;
    }
    pos = CMS_get0_content(cms);
    printf("# %s: type %s, eContentType %s, detached %d, content %s\n", label, oid(CMS_get0_type(cms)),
           oid(CMS_get0_eContentType(cms)), CMS_is_detached(cms),
           pos == NULL ? "-" : *pos == NULL ? "none" : "present");
    errors();
}

static void print(CMS_ContentInfo *cms)
{
    BIO *out = BIO_new(BIO_s_mem());
    char *p;
    long n;

    CMS_ContentInfo_print_ctx(out, cms, 2, NULL);
    n = BIO_get_mem_data(out, &p);
    printf("%.*s", (int)n, p);
    BIO_free(out);
}

static void attrs(CMS_SignerInfo *si)
{
    int i, n = CMS_signed_get_attr_count(si);

    printf("  signed attributes %d:", n);
    for (i = 0; i < n; i++)
        printf(" %s", oid(X509_ATTRIBUTE_get0_object(CMS_signed_get_attr(si, i))));
    n = CMS_unsigned_get_attr_count(si);
    printf("; unsigned %d:", n);
    for (i = 0; i < n; i++)
        printf(" %s", oid(X509_ATTRIBUTE_get0_object(CMS_unsigned_get_attr(si, i))));
    printf("\n");
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    X509 *root = cert(CA_PEM), *rsa = cert(RSA_PEM), *rcpt = cert(RCPT_PEM);
    CMS_ContentInfo *cms;
    BIO *in, *out;

    check(root != NULL && rsa != NULL && rcpt != NULL, "fixtures");

    /* The reference's objects */
    {
        static const char *const pems[] = {DATA_PEM, DIGEST_PEM, ENCDATA_PEM, SIGNED_PEM, ENV_PEM};
        static const char *const names[] = {"data", "digest", "encrypted data", "signed", "enveloped"};
        size_t i;

        for (i = 0; i < 5; i++) {
            unsigned char *d = NULL, *d2 = NULL;
            const unsigned char *q;
            CMS_ContentInfo *again;
            int n, n2;

            cms = load(pems[i]);
            describe(names[i], cms);
            n = i2d_CMS_ContentInfo(cms, &d);
            q = d;
            again = d2i_CMS_ContentInfo(NULL, &q, n);
            n2 = i2d_CMS_ContentInfo(again, &d2);
            printf("  DER %d, again %d, same %d\n", n, n2, n == n2 && memcmp(d, d2, n) == 0);
            if (i < 3)
                print(cms);
            OPENSSL_free(d);
            OPENSSL_free(d2);
            CMS_ContentInfo_free(again);
            CMS_ContentInfo_free(cms);
        }
        check(1, "the reference's objects read, printed, and encoded again");
    }
    cms = load(DATA_PEM);
    out = BIO_new(BIO_s_mem());
    printf("# CMS_data: %d\n", CMS_data(cms, out, 0));
    show("content", out);
    BIO_free(out);
    out = BIO_new(BIO_s_mem());
    printf("# CMS_data, as text: %d\n", CMS_data(cms, out, CMS_TEXT));
    show("content", out);
    errors();
    BIO_free(out);
    CMS_ContentInfo_free(cms);

    cms = load(DIGEST_PEM);
    out = BIO_new(BIO_s_mem());
    check(CMS_digest_verify(cms, NULL, out, 0) == 1, "verify the reference's DigestedData");
    show("content", out);
    BIO_free(out);
    {
        ASN1_OCTET_STRING **pos = CMS_get0_content(cms);

        (*pos)->data[0] ^= 1;
        printf("# tampered: %d\n", CMS_digest_verify(cms, NULL, NULL, 0));
        errors();
        (*pos)->data[0] ^= 1;
        printf("# not data: %d\n", CMS_data(cms, NULL, 0));
        errors();
    }
    CMS_ContentInfo_free(cms);

    cms = load(ENCDATA_PEM);
    out = BIO_new(BIO_s_mem());
    check(CMS_EncryptedData_decrypt(cms, aes_key, sizeof(aes_key), NULL, out, 0) == 1,
          "decrypt the reference's EncryptedData");
    show("content", out);
    BIO_free(out);
    printf("# no key: %d\n", CMS_EncryptedData_decrypt(cms, NULL, 0, NULL, NULL, 0));
    errors();
    CMS_ContentInfo_free(cms);

    /* Made here */
    {
        unsigned int flags[] = {0, CMS_BINARY, CMS_TEXT};
        size_t i;

        for (i = 0; i < 3; i++) {
            in = mem(msg);
            cms = CMS_data_create(in, flags[i]);
            describe("data_create", cms);
            der("DER", cms);
            out = BIO_new(BIO_s_mem());
            printf("  CMS_data: %d\n", CMS_data(cms, out, flags[i] & CMS_TEXT));
            show("content", out);
            BIO_free(out);
            CMS_ContentInfo_free(cms);
            BIO_free(in);
        }
        check(1, "CMS_data_create");
    }
    {
        const EVP_MD *mds[] = {NULL, EVP_sha256(), EVP_sha512()};
        size_t i;

        for (i = 0; i < 3; i++) {
            in = mem(msg);
            cms = CMS_digest_create(in, mds[i], 0);
            describe("digest_create", cms);
            der("DER", cms);
            check(CMS_digest_verify(cms, NULL, NULL, 0) == 1, "CMS_digest_create and verify");
            CMS_ContentInfo_free(cms);
            BIO_free(in);
        }
        in = mem(msg);
        cms = CMS_digest_create(in, EVP_sha256(), CMS_DETACHED | CMS_BINARY);
        describe("digest_create detached", cms);
        der("DER", cms);
        BIO_free(in);
        in = mem(msg);
        check(CMS_digest_verify(cms, in, NULL, CMS_BINARY) == 1, "a detached digest");
        BIO_free(in);
        printf("# detached, no content: %d\n", CMS_digest_verify(cms, NULL, NULL, 0));
        errors();
        CMS_ContentInfo_free(cms);
    }
    {
        const EVP_CIPHER *ciphers[] = {EVP_aes_128_cbc(), EVP_aes_256_cbc(), EVP_des_ede3_cbc()};
        unsigned char key[32];
        size_t i;

        memset(key, 0x5a, sizeof(key));
        for (i = 0; i < 3; i++) {
            size_t klen = (size_t)EVP_CIPHER_get_key_length(ciphers[i]);
            unsigned char *d = NULL;
            int n;

            in = mem(msg);
            cms = CMS_EncryptedData_encrypt(in, ciphers[i], key, klen, 0);
            describe("EncryptedData_encrypt", cms);
            n = i2d_CMS_ContentInfo(cms, &d);
            printf("  DER %d\n", n);
            OPENSSL_free(d);
            out = BIO_new(BIO_s_mem());
            check(CMS_EncryptedData_decrypt(cms, key, klen, NULL, out, 0) == 1, "EncryptedData round trip");
            show("content", out);
            BIO_free(out);
            CMS_ContentInfo_free(cms);
            BIO_free(in);
        }
        in = mem(msg);
        printf("# no cipher: %s\n", CMS_EncryptedData_encrypt(in, NULL, key, 16, 0) == NULL ? "NULL" : "made");
        printf("# GCM: %s\n", CMS_EncryptedData_encrypt(in, EVP_aes_128_gcm(), key, 16, 0) == NULL ? "NULL" : "made");
        printf("# no key: %s\n", CMS_EncryptedData_encrypt(in, EVP_aes_128_cbc(), NULL, 0, 0) == NULL ? "NULL" : "made");
        errors();
        BIO_free(in);
        cms = load(DATA_PEM);
        printf("# set1_key on data: %d\n", CMS_EncryptedData_set1_key(cms, NULL, key, 16));
        errors();
        CMS_ContentInfo_free(cms);
        cms = CMS_EncryptedData_encrypt(NULL, EVP_aes_128_cbc(), key, 16, CMS_PARTIAL);
        in = mem(msg);
        printf("# partial, then final: %d\n", CMS_final(cms, in, NULL, 0));
        BIO_free(in);
        out = BIO_new(BIO_s_mem());
        check(CMS_EncryptedData_decrypt(cms, key, 16, NULL, out, 0) == 1, "CMS_PARTIAL and CMS_final");
        BIO_free(out);
        CMS_ContentInfo_free(cms);
    }

    /* Streaming */
    {
        BIO *b;

        cms = CMS_data_create(NULL, CMS_STREAM);
        in = mem(msg);
        out = BIO_new(BIO_s_mem());
        printf("# stream data: %d\n", i2d_CMS_bio_stream(out, cms, in, CMS_STREAM));
        errors();
        {
            char *p;
            long n = BIO_get_mem_data(out, &p);

            hex("DER", (unsigned char *)p, (int)n);
        }
        BIO_free(in);
        CMS_ContentInfo_free(cms);
        cms = d2i_CMS_bio(out, NULL);
        describe("streamed, read back", cms);
        BIO_free(out);
        out = BIO_new(BIO_s_mem());
        printf("  CMS_data: %d\n", CMS_data(cms, out, 0));
        show("content", out);
        BIO_free(out);
        CMS_ContentInfo_free(cms);

        cms = CMS_digest_create(NULL, EVP_sha256(), CMS_STREAM);
        in = mem(msg);
        out = BIO_new(BIO_s_mem());
        printf("# PEM stream digest: %d\n", PEM_write_bio_CMS_stream(out, cms, in, CMS_STREAM));
        {
            char *p;
            long n = BIO_get_mem_data(out, &p);

            printf("%.*s", (int)n, p);
        }
        BIO_free(in);
        CMS_ContentInfo_free(cms);
        cms = PEM_read_bio_CMS(out, NULL, NULL, NULL);
        check(cms != NULL && CMS_digest_verify(cms, NULL, NULL, 0) == 1, "a streamed digest");
        CMS_ContentInfo_free(cms);
        BIO_free(out);

        cms = CMS_digest_create(NULL, EVP_sha256(), CMS_STREAM);
        out = BIO_new(BIO_s_mem());
        b = BIO_new_CMS(out, cms);
        printf("# BIO_new_CMS: %s\n", b == NULL ? "NULL" : "made");
        BIO_write(b, "one, ", 5);
        BIO_write(b, "two", 3);
        printf("  flush: %d\n", BIO_flush(b));
        while (b != NULL && b != out) {
            BIO *next = BIO_pop(b);

            BIO_free(b);
            b = next;
        }
        {
            char *p;
            long n = BIO_get_mem_data(out, &p);

            hex("DER", (unsigned char *)p, (int)n);
        }
        CMS_ContentInfo_free(cms);
        BIO_free(out);

        cms = CMS_data_create(NULL, CMS_STREAM);
        {
            unsigned char **boundary = NULL;

            printf("# CMS_stream: %d, boundary %s\n", CMS_stream(&boundary, cms), boundary == NULL ? "NULL" : "set");
        }
        CMS_ContentInfo_free(cms);
        check(1, "streaming");
    }

    /* The data path by hand */
    {
        BIO *chain;

        cms = CMS_digest_create(NULL, EVP_sha256(), CMS_PARTIAL | CMS_STREAM);
        chain = CMS_dataInit(cms, NULL);
        BIO_write(chain, msg, (int)strlen(msg));
        (void)BIO_flush(chain);
        printf("# dataInit, dataFinal: %d\n", CMS_dataFinal(cms, chain));
        BIO_free_all(chain);
        der("DER", cms);
        check(CMS_digest_verify(cms, NULL, NULL, 0) == 1, "CMS_dataInit and CMS_dataFinal");
        CMS_ContentInfo_free(cms);

        cms = CMS_data_create(NULL, CMS_STREAM);
        printf("# final_digest on Data: %d\n", CMS_final_digest(cms, (const unsigned char *)"abc", 3, NULL, 0));
        errors();
        der("DER", cms);
        CMS_ContentInfo_free(cms);

        /* An empty object's content: OpenSSL reads through NULL (docs/DEVIATIONS.md). */
        cms = CMS_ContentInfo_new();
        printf("# empty: type %s\n", oid(CMS_get0_type(cms)));
        CMS_ContentInfo_free(cms);
    }

    /* The library functions */
    {
        OSSL_LIB_CTX *lc = OSSL_LIB_CTX_new();
        CMS_ContentInfo *c2 = CMS_ContentInfo_new_ex(lc, "provider=default");
        STACK_OF(X509) *certs;
        STACK_OF(X509_CRL) *crls;

        printf("# new_ex: %s, type %s\n", c2 == NULL ? "NULL" : "made", oid(CMS_get0_type(c2)));
        CMS_ContentInfo_free(c2);
        OSSL_LIB_CTX_free(lc);

        cms = load(SIGNED_PEM);
        certs = CMS_get1_certs(cms);
        printf("# certs %d\n", sk_X509_num(certs));
        OSSL_STACK_OF_X509_free(certs);
        printf("# add1 the same cert: %d, add1 another: %d, add0: %d\n", CMS_add1_cert(cms, rsa), CMS_add1_cert(cms, root),
               CMS_add0_cert(cms, X509_dup(rcpt)));
        certs = CMS_get1_certs(cms);
        printf("  certs %d\n", sk_X509_num(certs));
        OSSL_STACK_OF_X509_free(certs);
        crls = CMS_get1_crls(cms);
        printf("# crls %s\n", crls == NULL ? "none" : "some");
        printf("  choices: %s %s\n", CMS_add0_CertificateChoices(cms) == NULL ? "NULL" : "added",
               CMS_add0_RevocationInfoChoice(cms) == NULL ? "NULL" : "added");
        errors();
        print(cms);
        printf("# eContentType set: %d %d\n", CMS_set1_eContentType(cms, OBJ_nid2obj(NID_id_smime_ct_receipt)),
               CMS_set1_eContentType(cms, NULL));
        describe("signed, after", cms);
        printf("  detached: %d -> ", CMS_is_detached(cms));
        printf("%d %d\n", CMS_set_detached(cms, 1), CMS_is_detached(cms));
        printf("  SignerInfos %d, RecipientInfos %s\n", sk_CMS_SignerInfo_num(CMS_get0_SignerInfos(cms)),
               CMS_get0_RecipientInfos(cms) == NULL ? "NULL" : "set");
        errors();
        {
            CMS_SignerInfo *si = sk_CMS_SignerInfo_value(CMS_get0_SignerInfos(cms), 0);
            ASN1_OBJECT *ct = OBJ_nid2obj(NID_pkcs9_contentType);
            X509_ATTRIBUTE *a;
            ASN1_OBJECT *got;
            CMS_ReceiptRequest *rr, *back = NULL;
            STACK_OF(GENERAL_NAMES) *to = sk_GENERAL_NAMES_new_null();
            GENERAL_NAMES *gns = GENERAL_NAMES_new();
            GENERAL_NAME *gn = GENERAL_NAME_new();
            ASN1_STRING *cid = NULL;
            int allorfirst = 9;
            STACK_OF(GENERAL_NAMES) *list = NULL, *rto = NULL;
            unsigned char *id = OPENSSL_malloc(4), *rd = NULL;
            int n;

            attrs(si);
            printf("  contentType at %d, by OBJ %d, next %d\n", CMS_signed_get_attr_by_NID(si, NID_pkcs9_contentType, -1),
                   CMS_signed_get_attr_by_OBJ(si, ct, -1), CMS_signed_get_attr_by_NID(si, NID_pkcs9_contentType, 0));
            got = CMS_signed_get0_data_by_OBJ(si, ct, -3, V_ASN1_OBJECT);
            printf("  contentType %s\n", oid(got));
            printf("  add1 by NID %d, by OBJ %d, by txt %d\n",
                   CMS_signed_add1_attr_by_NID(si, NID_pkcs9_contentType, V_ASN1_OBJECT, OBJ_nid2obj(NID_pkcs7_data), -1),
                   CMS_signed_add1_attr_by_OBJ(si, OBJ_nid2obj(NID_pkcs9_signingTime), V_ASN1_UTCTIME, "260101000000Z", 13),
                   CMS_signed_add1_attr_by_txt(si, "1.2.3.4", V_ASN1_UTF8STRING, "hello", 5));
            attrs(si);
            a = CMS_signed_delete_attr(si, CMS_signed_get_attr_count(si) - 1);
            printf("  deleted %s\n", oid(X509_ATTRIBUTE_get0_object(a)));
            printf("  add1 %d\n", CMS_signed_add1_attr(si, a));
            X509_ATTRIBUTE_free(a);
            printf("  unsigned: add1 by NID %d, by OBJ %d, by txt %d\n",
                   CMS_unsigned_add1_attr_by_NID(si, NID_pkcs9_countersignature, V_ASN1_OCTET_STRING, "sig", 3),
                   CMS_unsigned_add1_attr_by_OBJ(si, OBJ_nid2obj(NID_pkcs9_unstructuredName), V_ASN1_IA5STRING, "name", 4),
                   CMS_unsigned_add1_attr_by_txt(si, "1.2.3.5", V_ASN1_UTF8STRING, "x", 1));
            attrs(si);
            printf("  unsigned at %d, by OBJ %d, data %s\n", CMS_unsigned_get_attr_by_NID(si, NID_pkcs9_countersignature, -1),
                   CMS_unsigned_get_attr_by_OBJ(si, OBJ_nid2obj(NID_pkcs9_unstructuredName), -1),
                   CMS_unsigned_get0_data_by_OBJ(si, OBJ_nid2obj(NID_pkcs9_countersignature), -3, V_ASN1_OCTET_STRING) == NULL
                       ? "NULL" : "found");
            a = CMS_unsigned_delete_attr(si, 0);
            printf("  unsigned deleted %s, add1 %d\n", oid(X509_ATTRIBUTE_get0_object(a)), CMS_unsigned_add1_attr(si, a));
            X509_ATTRIBUTE_free(a);
            attrs(si);
            errors();

            memcpy(id, "abcd", 4);
            gn->type = GEN_EMAIL;
            gn->d.rfc822Name = ASN1_IA5STRING_new();
            ASN1_STRING_set(gn->d.rfc822Name, "a@example.com", -1);
            sk_GENERAL_NAME_push(gns, gn);
            sk_GENERAL_NAMES_push(to, gns);
            rr = CMS_ReceiptRequest_create0(id, 4, 1, NULL, to);
            CMS_ReceiptRequest_get0_values(rr, &cid, &allorfirst, &list, &rto);
            printf("# receipt request: id %d octets, all or first %d, list %s, to %d\n", ASN1_STRING_length(cid), allorfirst,
                   list == NULL ? "NULL" : "set", sk_GENERAL_NAMES_num(rto));
            n = i2d_CMS_ReceiptRequest(rr, &rd);
            hex("DER", rd, n);
            {
                const unsigned char *q = rd;
                CMS_ReceiptRequest *dec = d2i_CMS_ReceiptRequest(NULL, &q, n);

                printf("  decoded %s\n", dec == NULL ? "NULL" : "yes");
                CMS_ReceiptRequest_free(dec);
            }
            OPENSSL_free(rd);
            printf("  get1 before: %d\n", CMS_get1_ReceiptRequest(si, NULL));
            printf("  add1: %d\n", CMS_add1_ReceiptRequest(si, rr));
            printf("  get1: %d\n", CMS_get1_ReceiptRequest(si, &back));
            CMS_ReceiptRequest_get0_values(back, &cid, &allorfirst, &list, &rto);
            printf("  back: id %d octets, all or first %d, to %d\n", ASN1_STRING_length(cid), allorfirst, sk_GENERAL_NAMES_num(rto));
            attrs(si);
            CMS_ReceiptRequest_free(back);
            CMS_ReceiptRequest_free(rr);
            rr = CMS_ReceiptRequest_create0_ex(NULL, 0, 0, NULL, NULL, NULL);
            CMS_ReceiptRequest_get0_values(rr, &cid, &allorfirst, &list, &rto);
            printf("  random id %d octets, all or first %d\n", ASN1_STRING_length(cid), allorfirst);
            CMS_ReceiptRequest_free(rr);
            rr = CMS_ReceiptRequest_new();
            printf("  new: %s\n", rr == NULL ? "NULL" : "made");
            CMS_ReceiptRequest_free(rr);
            errors();
        }
        sk_X509_CRL_pop_free(crls, X509_CRL_free);
        CMS_ContentInfo_free(cms);

        cms = load(ENV_PEM);
        printf("# enveloped: RecipientInfos %d, certs %s, crls %s\n", sk_CMS_RecipientInfo_num(CMS_get0_RecipientInfos(cms)),
               CMS_get1_certs(cms) == NULL ? "none" : "some", CMS_get1_crls(cms) == NULL ? "none" : "some");
        printf("  SignerInfos %s, add1_cert %d\n", CMS_get0_SignerInfos(cms) == NULL ? "NULL" : "set", CMS_add1_cert(cms, rsa));
        errors();
        {
            /* The content alone, as an EnvelopedData. */
            unsigned char *d = NULL, *d2 = NULL;
            const unsigned char *q;
            int n = i2d_CMS_ContentInfo(cms, &d), n2;
            long len;
            int tag, xclass;
            CMS_EnvelopedData *ed, *dup;

            q = d;
            ASN1_get_object(&q, &len, &tag, &xclass, n);
            ASN1_get_object(&q, &len, &tag, &xclass, n);
            q += len;
            ASN1_get_object(&q, &len, &tag, &xclass, n);
            ed = (CMS_EnvelopedData *)ASN1_item_d2i(NULL, &q, len, ASN1_ITEM_rptr(CMS_EnvelopedData));
            dup = CMS_EnvelopedData_dup(ed);
            n2 = ASN1_item_i2d((ASN1_VALUE *)dup, &d2, ASN1_ITEM_rptr(CMS_EnvelopedData));
            {
                unsigned char *d3 = NULL;
                int n3 = ASN1_item_i2d((ASN1_VALUE *)ed, &d3, ASN1_ITEM_rptr(CMS_EnvelopedData));

                printf("# EnvelopedData: %s, dup %s, %d octets, same %d\n", ed == NULL ? "NULL" : "read",
                       dup == NULL ? "NULL" : "made", n2, n2 == n3 && memcmp(d2, d3, (size_t)n2) == 0);
                OPENSSL_free(d3);
            }
            ASN1_item_free((ASN1_VALUE *)ed, ASN1_ITEM_rptr(CMS_EnvelopedData));
            ASN1_item_free((ASN1_VALUE *)dup, ASN1_ITEM_rptr(CMS_EnvelopedData));
            OPENSSL_free(d);
            OPENSSL_free(d2);
        }
        CMS_ContentInfo_free(cms);

        cms = CMS_ContentInfo_new();
        printf("# empty: eContentType %s, certs %s\n", oid(CMS_get0_eContentType(cms)), CMS_get1_certs(cms) == NULL ? "NULL" : "set");
        errors();
        CMS_ContentInfo_free(cms);
        check(1, "library functions");
    }

    /* PEM, BIO, FILE, and S/MIME */
    {
        FILE *f = tmpfile();
        CMS_ContentInfo *back;
        BIO *bcont = NULL;

        cms = load(DIGEST_PEM);
        out = BIO_new(BIO_s_mem());
        printf("# i2d_CMS_bio %d", i2d_CMS_bio(out, cms));
        back = d2i_CMS_bio(out, NULL);
        printf(", d2i_CMS_bio %s\n", back == NULL ? "NULL" : "read");
        CMS_ContentInfo_free(back);
        (void)BIO_reset(out);
        printf("# PEM_write_bio_CMS %d\n", PEM_write_bio_CMS(out, cms));
        printf("  PEM_write_CMS %d\n", PEM_write_CMS(f, cms));
        rewind(f);
        back = PEM_read_CMS(f, NULL, NULL, NULL);
        printf("  PEM_read_CMS %s\n", back == NULL ? "NULL" : "read");
        CMS_ContentInfo_free(back);
        fclose(f);
        BIO_free(out);

        out = BIO_new(BIO_s_mem());
        printf("# SMIME_write_CMS: %d\n", SMIME_write_CMS(out, cms, NULL, 0));
        {
            char *p;
            long n = BIO_get_mem_data(out, &p);

            printf("%.*s", (int)n, p);
        }
        back = SMIME_read_CMS(out, &bcont);
        printf("  read back %s, content %s\n", back == NULL ? "NULL" : "yes", bcont == NULL ? "none" : "set");
        check(back != NULL && CMS_digest_verify(back, NULL, NULL, 0) == 1, "SMIME_write_CMS and SMIME_read_CMS");
        CMS_ContentInfo_free(back);
        BIO_free(out);
        out = BIO_new(BIO_s_mem());
        printf("# SMIME_write_CMS, streamed without input: %d\n", SMIME_write_CMS(out, cms, NULL, CMS_STREAM));
        errors();
        (void)BIO_reset(out);
        SMIME_write_CMS(out, cms, NULL, 0);
        {
            OSSL_LIB_CTX *lc = OSSL_LIB_CTX_new();
            CMS_ContentInfo *held = CMS_ContentInfo_new_ex(lc, NULL);

            back = SMIME_read_CMS_ex(out, 0, NULL, &held);
            printf("  streamed, read_ex into an object: %s, same %d\n", back == NULL ? "NULL" : "read", back == held);
            errors();
            CMS_ContentInfo_free(back);
            OSSL_LIB_CTX_free(lc);
        }
        BIO_free(out);
        CMS_ContentInfo_free(cms);
        errors();
    }

    /* In a library context, the items, and CRLs */
    {
        OSSL_LIB_CTX *lc = OSSL_LIB_CTX_new();
        unsigned char key[16] = {0};
        X509_CRL *crl = X509_CRL_new();
        STACK_OF(X509_CRL) *crls;
        unsigned char *d = NULL;
        int n;

        in = mem(msg);
        cms = CMS_data_create_ex(in, 0, lc, NULL);
        describe("data_create_ex", cms);
        n = ASN1_item_i2d((ASN1_VALUE *)cms, &d, ASN1_ITEM_rptr(CMS_ContentInfo));
        printf("  via the item: %d octets\n", n);
        OPENSSL_free(d);
        CMS_ContentInfo_free(cms);
        BIO_free(in);
        in = mem(msg);
        cms = CMS_digest_create_ex(in, EVP_sha384(), 0, lc, "provider=default");
        describe("digest_create_ex", cms);
        check(CMS_digest_verify(cms, NULL, NULL, 0) == 1, "CMS_digest_create_ex");
        CMS_ContentInfo_free(cms);
        BIO_free(in);
        in = mem(msg);
        cms = CMS_EncryptedData_encrypt_ex(in, EVP_aes_128_cbc(), key, 16, 0, lc, NULL);
        describe("EncryptedData_encrypt_ex", cms);
        check(CMS_EncryptedData_decrypt(cms, key, 16, NULL, NULL, 0) == 1, "CMS_EncryptedData_encrypt_ex");
        CMS_ContentInfo_free(cms);
        BIO_free(in);
        {
            CMS_ReceiptRequest *rr = (CMS_ReceiptRequest *)ASN1_item_new(ASN1_ITEM_rptr(CMS_ReceiptRequest));

            printf("# receipt request via the item: %s\n", rr == NULL ? "NULL" : "made");
            ASN1_item_free((ASN1_VALUE *)rr, ASN1_ITEM_rptr(CMS_ReceiptRequest));
        }
        cms = load(SIGNED_PEM);
        printf("# add1_crl %d, add0_crl %d\n", CMS_add1_crl(cms, crl), CMS_add0_crl(cms, X509_CRL_new()));
        crls = CMS_get1_crls(cms);
        printf("  crls %d\n", sk_X509_CRL_num(crls));
        sk_X509_CRL_pop_free(crls, X509_CRL_free);
        CMS_ContentInfo_free(cms);
        cms = load(DATA_PEM);
        printf("# add1_crl to Data: %d\n", CMS_add1_crl(cms, crl));
        errors();
        CMS_ContentInfo_free(cms);
        X509_CRL_free(crl);
        OSSL_LIB_CTX_free(lc);
    }

    /* Compression, which the default build lacks */
    in = mem(msg);
    printf("# compress %s, uncompress %d\n", CMS_compress(in, 0, 0) == NULL ? "NULL" : "made", CMS_uncompress(NULL, NULL, NULL, 0));
    errors();
    BIO_free(in);

    /* CMS_SharedInfo_encode */
    {
        X509_ALGOR *alg = X509_ALGOR_new();
        ASN1_OCTET_STRING *ukm = ASN1_OCTET_STRING_new();
        unsigned char *d = NULL;
        int n;

        X509_ALGOR_set0(alg, OBJ_nid2obj(NID_id_aes128_wrap), V_ASN1_UNDEF, NULL);
        ASN1_OCTET_STRING_set(ukm, (const unsigned char *)"ukm!", 4);
        n = CMS_SharedInfo_encode(&d, alg, ukm, 16);
        hex("SharedInfo", d, n);
        OPENSSL_free(d);
        d = NULL;
        n = CMS_SharedInfo_encode(&d, alg, NULL, 32);
        hex("SharedInfo, no UKM", d, n);
        OPENSSL_free(d);
        X509_ALGOR_free(alg);
        ASN1_OCTET_STRING_free(ukm);
        check(1, "CMS_SharedInfo_encode");
    }

    X509_free(root);
    X509_free(rsa);
    X509_free(rcpt);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
