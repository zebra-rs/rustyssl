/*
 * Conformance test for CRMF (OSSL_CRMF_MSG_set1_regCtrl_regToken(3), OSSL_CRMF_MSG_set0_validity(3),
 * OSSL_CRMF_MSG_get0_tmpl(3), OSSL_CRMF_pbmp_new(3), OSSL_CRMF_ENCRYPTEDVALUE_decrypt): a
 * certificate request message built field by field (template, validity, extensions, every
 * control and registration info) and compared by its DER; proof-of-possession made and
 * checked (RA-verified, an RSA signature, key encipherment); central key generation; the
 * password-based MAC over fixed parameters; encrypted values and keys decrypted; with the
 * errors of bad arguments.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/crmf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
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

static void hex(const char *label, const unsigned char *d, int n)
{
    int i;

    printf("  %s (%d):", label, n);
    for (i = 0; i < n; i++)
        printf("%s%02x", i % 32 == 0 ? "\n    " : "", d[i]);
    printf("\n");
}

/* The CMS and OCSP tests' RSA end entity and its key, and the EC root. */
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

static const char RSA_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCTF3DR1lrRhjc9\n"
    "u1jEVzgYclC+L3X6x88IGgzCdKPaNwhLQlWsDXmluMlqa0Tvb4Ob392Ufxmkn1W3\n"
    "0XhYTypLjGOL5bksoiGDiQZn1ovA/GndmCq1J47pSNhz6SL1/uOZvmj6vdpr0p26\n"
    "BtqGCr1hXowWKIvmJGdr5JV4fPgRXO/nFCqYvwzm0hxCCWF+cpACJgB/NkB54nSq\n"
    "eYdRhwJvU9D8glmTuwO4UY035FDYcYKajiIMtnJnGlo/IJMEyI1+lQGWWFOSCPhl\n"
    "d5B3etvb8Yz+LC51w4jlroXJw7q1HmTGi2IR4fugKC8lLugmbONeFXjeCawPRVhZ\n"
    "PR2/1AHNAgMBAAECggEABvLN1BCcGrC/h4C3P6zFGOm+WBwJQG8G7Mfz2VqSncDV\n"
    "+SqP8U0NQl+TBQSk0+paXVcucip5s7w8W67sA42Kntk2n9aBMGAT7p3e+eT5lh5c\n"
    "zxu2MyrEUzXeb8W2iC6U+6xlUvViZ4+7/rX+X0px/TMIfnvgDyxu33rQkTAKG4iZ\n"
    "J4Lyon+aTmqTnZQetFk0eeQUxVnKg9RUSqWVgbPbZ9HncgXAtJ8BTXkEmkjqpjQ8\n"
    "4LWpP9pueGaDESPZy86UG18q4pUoozv/HFrEo7vGLjUUCXK5G1mL0GUKMIrhle1t\n"
    "GPSVrg+bKDRM9naGQkWGECar/Mu7K1PODe4Ck06PSwKBgQDDNwQhfPdhlvCP4xjt\n"
    "7rey1/Dpw8XUwjIbvwzbjQhJm001Ty3qP4p9uf9my1TcKHA5HdcNDssH40uEbMVY\n"
    "+3YVqkqviljVV8ifSJvdOsvaPX133bqtFBLeSnIlFrEhiLHSDdwdS5RbyLqu1r2X\n"
    "5O3X0aHUORAyTIL2EW9hLN94YwKBgQDA5GnboAw8P9+pDSwlkATA8W+aeKUyRWY7\n"
    "BVmOkAPAxLPa1WByihYE8OPtJPt4kGCOQ8nD2vF7y2Crh5yEB+sjMzyyXkmZIqxx\n"
    "7Hx9yT0skdae3H32VRNTreUAIJb3VxdXrIwW4ttz6mzVibuATI/HWRcPapxA+QOt\n"
    "bSIDi6R8DwKBgQCX22NOPa0e8FDgTXPmGw4xhIP3BQEO+aYLKXpyC+rHf5T3BEoe\n"
    "cCFmnlrMdx3jSV3LQKg6kyhjUXA8anS2PJ7mSZthpIhoJap+JfiBhyxu7+h7ZzPB\n"
    "Ud0/qL/UlCtkf7Z8RaXV8CZPo/185rWDxGU0vvFZaq5rwlMZ4gQ3nrWUKwKBgH5p\n"
    "s05x91LM8YFS1qnPVq40DFYJ1wm5HaR0fxrFGxCMWOqDiG/IO2IFlPpnkD6VMBJM\n"
    "LsCijjv5L2N6voJwxhMNkyu6SzWG2cjXmUa+Sc8ZzLPUAOEdJEtk3X1V3lo+w1d8\n"
    "B1tAVV4ENktDtpQAmQGmS0yZK8oQ5+4SZYY5UBTVAoGBAMB2u6z9vtsnzhjQkYzw\n"
    "1Cj9d5B6yU0PVlvMtx3gvN695KJirNu9J97uH/l0ChwRaQLKHDbHDxUesdNC+3OS\n"
    "XxACwAu74Hz+oNnN+vRC+dFoQv8F0VUCTkBALqPF5uOtbMHeo4Cd7INRu7Q0x8zY\n"
    "qRa6RR43B+gY9X3Ln41yewDZ\n"
    "-----END PRIVATE KEY-----\n";

static const char CA_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgjJmHRKIDeWJqELpS\n"
    "dxp2/0yprDyKdPRlyAZUtZaRHe+hRANCAAQfwC01XDjVH1TSVviPJvqRWWb9hNZ7\n"
    "nmqLSMbcrgrlO74LV/geYqce6i6mwqV3O7k8OflVFNN+T9+uuR5YZRNP\n"
    "-----END PRIVATE KEY-----\n";

static X509 *cert(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);

    BIO_free(b);
    return x;
}

static EVP_PKEY *key(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    EVP_PKEY *k = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);

    BIO_free(b);
    return k;
}

#define DER(type, obj, label)                                                   \
    do {                                                                        \
        unsigned char *p_ = NULL;                                               \
        int n_ = i2d_##type(obj, &p_);                                          \
        hex(label, p_, n_);                                                     \
        OPENSSL_free(p_);                                                       \
    } while (0)

#define ROUNDTRIP(type, obj, label)                                             \
    do {                                                                        \
        unsigned char *p_ = NULL, *q_ = NULL;                                   \
        int n_ = i2d_##type(obj, &p_), m_;                                      \
        const unsigned char *r_ = p_;                                           \
        type *b_ = d2i_##type(NULL, &r_, n_);                                   \
        m_ = i2d_##type(b_, &q_);                                               \
        check(b_ != NULL && r_ == p_ + n_ && m_ == n_ && memcmp(p_, q_, n_) == 0, label); \
        type##_free(b_);                                                        \
        OPENSSL_free(p_);                                                       \
        OPENSSL_free(q_);                                                       \
    } while (0)

static void print_name(const char *label, const X509_NAME *n)
{
    printf("  %s: ", label);
    if (n == NULL)
        printf("(null)");
    else
        X509_NAME_print_ex_fp(stdout, n, 0, XN_FLAG_ONELINE);
    printf("\n");
}

static const char *str(const ASN1_STRING *s)
{
    return s == NULL ? "(none)" : (const char *)ASN1_STRING_get0_data(s);
}

static OSSL_CRMF_MSG *build(EVP_PKEY *k, X509 *ee, X509 *ca)
{
    OSSL_CRMF_MSG *msg = OSSL_CRMF_MSG_new();
    OSSL_CRMF_CERTTEMPLATE *tmpl;
    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    ASN1_TIME *nb = ASN1_TIME_new(), *na = ASN1_TIME_new();
    STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
    X509_EXTENSION *ext;
    ASN1_UTF8STRING *s = ASN1_UTF8STRING_new();
    OSSL_CRMF_PKIPUBLICATIONINFO *pi = OSSL_CRMF_PKIPUBLICATIONINFO_new();
    OSSL_CRMF_SINGLEPUBINFO *spi = OSSL_CRMF_SINGLEPUBINFO_new();
    OSSL_CRMF_CERTID *cid;
    X509_PUBKEY *xpk = NULL;

    printf("# building a message\n");
    check(OSSL_CRMF_MSG_set_certReqId(msg, 5) == 1 && OSSL_CRMF_MSG_get_certReqId(msg) == 5, "certReqId");
    tmpl = OSSL_CRMF_MSG_get0_tmpl(msg);
    ASN1_INTEGER_set(serial, 0x1234);
    check(OSSL_CRMF_CERTTEMPLATE_fill(tmpl, k, X509_get_subject_name(ee), X509_get_subject_name(ca), serial) == 1,
          "OSSL_CRMF_CERTTEMPLATE_fill");
    print_name("subject", OSSL_CRMF_CERTTEMPLATE_get0_subject(tmpl));
    print_name("issuer", OSSL_CRMF_CERTTEMPLATE_get0_issuer(tmpl));
    printf("  serial %ld, key %s\n", ASN1_INTEGER_get(OSSL_CRMF_CERTTEMPLATE_get0_serialNumber(tmpl)),
           OSSL_CRMF_CERTTEMPLATE_get0_publicKey(tmpl) != NULL ? "set" : "none");
    ASN1_TIME_set_string(nb, "20260101000000Z");
    ASN1_TIME_set_string(na, "20360101000000Z");
    check(OSSL_CRMF_MSG_set0_validity(msg, nb, na) == 1, "OSSL_CRMF_MSG_set0_validity");
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, "critical,digitalSignature");
    sk_X509_EXTENSION_push(exts, ext);
    check(OSSL_CRMF_MSG_set0_extensions(msg, exts) == 1, "OSSL_CRMF_MSG_set0_extensions");
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, "DNS:ee.example");
    check(OSSL_CRMF_MSG_push0_extension(msg, ext) == 1, "OSSL_CRMF_MSG_push0_extension");
    printf("  extensions %d\n", sk_X509_EXTENSION_num(OSSL_CRMF_CERTTEMPLATE_get0_extensions(tmpl)));

    ASN1_STRING_set(s, "token", -1);
    check(OSSL_CRMF_MSG_set1_regCtrl_regToken(msg, s) == 1, "regToken");
    ASN1_STRING_set(s, "secret", -1);
    check(OSSL_CRMF_MSG_set1_regCtrl_authenticator(msg, s) == 1, "authenticator");
    check(OSSL_CRMF_MSG_set_PKIPublicationInfo_action(pi, OSSL_CRMF_PUB_ACTION_PLEASEPUBLISH) == 1, "action");
    check(OSSL_CRMF_MSG_set0_SinglePubInfo(spi, OSSL_CRMF_PUB_METHOD_WEB,
                                           a2i_GENERAL_NAME(NULL, NULL, NULL, GEN_URI, "http://pub.example/", 0)) == 1,
          "OSSL_CRMF_MSG_set0_SinglePubInfo");
    check(OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo(pi, spi) == 1, "push0_SinglePubInfo");
    check(OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo(msg, pi) == 1, "pkiPublicationInfo");
    cid = OSSL_CRMF_CERTID_gen(X509_get_issuer_name(ee), X509_get0_serialNumber(ee));
    print_name("certid issuer", OSSL_CRMF_CERTID_get0_issuer(cid));
    printf("  certid serial %ld\n", ASN1_INTEGER_get(OSSL_CRMF_CERTID_get0_serialNumber(cid)));
    check(OSSL_CRMF_MSG_set1_regCtrl_oldCertID(msg, cid) == 1, "oldCertID");
    X509_PUBKEY_set(&xpk, k);
    check(OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey(msg, xpk) == 1, "protocolEncrKey");
    ASN1_STRING_set(s, "version?1%corp?ex%", -1);
    check(OSSL_CRMF_MSG_set1_regInfo_utf8Pairs(msg, s) == 1, "utf8Pairs");
    check(OSSL_CRMF_MSG_set1_regInfo_certReq(msg, NULL) == 0, "no certReq");

    printf("  regToken %s, authenticator %s, pubinfo %s, oldCertID %s, encrKey %s, utf8Pairs %s, certReq %s\n",
           str(OSSL_CRMF_MSG_get0_regCtrl_regToken(msg)),
           str(OSSL_CRMF_MSG_get0_regCtrl_authenticator(msg)),
           OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo(msg) ? "set" : "none",
           OSSL_CRMF_MSG_get0_regCtrl_oldCertID(msg) ? "set" : "none",
           OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey(msg) ? "set" : "none",
           str(OSSL_CRMF_MSG_get0_regInfo_utf8Pairs(msg)),
           OSSL_CRMF_MSG_get0_regInfo_certReq(msg) ? "set" : "none");
    DER(OSSL_CRMF_CERTID, cid, "certid");
    ROUNDTRIP(OSSL_CRMF_CERTID, cid, "d2i_OSSL_CRMF_CERTID");
    DER(OSSL_CRMF_PKIPUBLICATIONINFO, pi, "pubinfo");
    ROUNDTRIP(OSSL_CRMF_PKIPUBLICATIONINFO, pi, "d2i_OSSL_CRMF_PKIPUBLICATIONINFO");
    DER(OSSL_CRMF_SINGLEPUBINFO, spi, "singlepubinfo");
    ROUNDTRIP(OSSL_CRMF_SINGLEPUBINFO, spi, "d2i_OSSL_CRMF_SINGLEPUBINFO");
    DER(OSSL_CRMF_CERTTEMPLATE, tmpl, "template");
    ROUNDTRIP(OSSL_CRMF_CERTTEMPLATE, tmpl, "d2i_OSSL_CRMF_CERTTEMPLATE");
    {
        OSSL_CRMF_CERTTEMPLATE *t2 = OSSL_CRMF_CERTTEMPLATE_dup(tmpl);
        OSSL_CRMF_CERTID *c2 = OSSL_CRMF_CERTID_dup(cid);

        check(t2 != NULL && c2 != NULL, "the dups");
        OSSL_CRMF_CERTTEMPLATE_free(t2);
        OSSL_CRMF_CERTID_free(c2);
    }
    X509_PUBKEY_free(xpk);
    OSSL_CRMF_CERTID_free(cid);
    OSSL_CRMF_PKIPUBLICATIONINFO_free(pi);
    ASN1_UTF8STRING_free(s);
    ASN1_INTEGER_free(serial);
    return msg;
}

static void popo(OSSL_CRMF_MSG *msg, EVP_PKEY *k, EVP_PKEY *other)
{
    OSSL_CRMF_MSGS *msgs = OSSL_CRMF_MSGS_new();
    OSSL_CRMF_MSG *m2;

    printf("# proof-of-possession\n");
    check(OSSL_CRMF_MSG_centralkeygen_requested(msg, NULL) == -2, "a key and no POPO");
    errors();
    check(OSSL_CRMF_MSG_create_popo(OSSL_CRMF_POPO_SIGNATURE, msg, k, EVP_sha256(), NULL, NULL) == 1,
          "an RSA signature");
    check(OSSL_CRMF_MSG_centralkeygen_requested(msg, NULL) == 0, "not central key generation");
    sk_OSSL_CRMF_MSG_push(msgs, msg);
    check(OSSL_CRMF_MSGS_verify_popo(msgs, 0, 0, NULL, NULL) == 1, "OSSL_CRMF_MSGS_verify_popo");
    errors();
    DER(OSSL_CRMF_MSG, msg, "message");
    ROUNDTRIP(OSSL_CRMF_MSG, msg, "d2i_OSSL_CRMF_MSG");
    DER(OSSL_CRMF_MSGS, msgs, "messages");
    ROUNDTRIP(OSSL_CRMF_MSGS, msgs, "d2i_OSSL_CRMF_MSGS");
    check(OSSL_CRMF_MSGS_verify_popo(msgs, 1, 0, NULL, NULL) == 0, "no such request");
    errors();
    check(OSSL_CRMF_MSG_create_popo(OSSL_CRMF_POPO_SIGNATURE, msg, other, EVP_sha256(), NULL, NULL) == 0,
          "a key that isn't the template's");
    errors();

    m2 = OSSL_CRMF_MSG_dup(msg);
    check(OSSL_CRMF_MSG_create_popo(OSSL_CRMF_POPO_RAVERIFIED, m2, NULL, NULL, NULL, NULL) == 1, "RA-verified");
    sk_OSSL_CRMF_MSG_push(msgs, m2);
    check(OSSL_CRMF_MSGS_verify_popo(msgs, 1, 0, NULL, NULL) == 0, "RA-verified not accepted");
    errors();
    check(OSSL_CRMF_MSGS_verify_popo(msgs, 1, 1, NULL, NULL) == 1, "RA-verified accepted");
    check(OSSL_CRMF_MSG_create_popo(OSSL_CRMF_POPO_KEYENC, m2, NULL, NULL, NULL, NULL) == 1, "key encipherment");
    DER(OSSL_CRMF_MSG, m2, "keyenc message");
    check(OSSL_CRMF_MSGS_verify_popo(msgs, 1, 1, NULL, NULL) == 0, "key encipherment not checked");
    errors();
    check(OSSL_CRMF_MSG_create_popo(OSSL_CRMF_POPO_KEYAGREE, m2, NULL, NULL, NULL, NULL) == 0, "key agreement");
    errors();
    check(OSSL_CRMF_MSG_create_popo(OSSL_CRMF_POPO_NONE, m2, NULL, NULL, NULL, NULL) == 1, "none");
    check(OSSL_CRMF_MSGS_verify_popo(msgs, 1, 1, NULL, NULL) == 0, "missing");
    errors();
    check(OSSL_CRMF_MSG_create_popo(OSSL_CRMF_POPO_SIGNATURE, m2, NULL, NULL, NULL, NULL) == 0, "a signature with no key");
    errors();

    printf("# central key generation\n");
    {
        OSSL_CRMF_MSG *m3 = OSSL_CRMF_MSG_new();
        X509_REQ *req = X509_REQ_new();

        check(OSSL_CRMF_MSG_centralkeygen_requested(m3, NULL) == 1, "no key, no POPO");
        OSSL_CRMF_MSG_create_popo(OSSL_CRMF_POPO_RAVERIFIED, m3, NULL, NULL, NULL, NULL);
        check(OSSL_CRMF_MSG_centralkeygen_requested(m3, NULL) == -2, "no key and a POPO");
        errors();
        check(OSSL_CRMF_MSG_centralkeygen_requested(NULL, req) == 1, "a request without a key");
        X509_REQ_set_pubkey(req, k);
        check(OSSL_CRMF_MSG_centralkeygen_requested(NULL, req) == 0, "a request with a key");
        check(OSSL_CRMF_MSG_centralkeygen_requested(NULL, NULL) == -1, "neither");
        errors();
        X509_REQ_free(req);
        OSSL_CRMF_MSG_free(m3);
    }
    sk_OSSL_CRMF_MSG_pop(msgs);
    sk_OSSL_CRMF_MSG_pop(msgs);
    OSSL_CRMF_MSG_free(m2);
    OSSL_CRMF_MSGS_free(msgs);
}

/* A TLV: the tag, the DER length, the content. */
static size_t tlv(unsigned char *out, unsigned char tag, const unsigned char *c, size_t n)
{
    size_t h = 0;

    out[h++] = tag;
    if (n < 0x80) {
        out[h++] = (unsigned char)n;
    } else if (n < 0x100) {
        out[h++] = 0x81;
        out[h++] = (unsigned char)n;
    } else {
        out[h++] = 0x82;
        out[h++] = (unsigned char)(n >> 8);
        out[h++] = (unsigned char)n;
    }
    memcpy(out + h, c, n);
    return h + n;
}

/*
 * An EncryptedValue of `plain` for `k`: AES-128-CBC under a fixed key and IV, the key wrapped
 * with RSA PKCS #1 v1.5 (randomized, so the DER isn't fixed, but what decrypts is).
 */
static size_t encrypted_value(unsigned char *out, const unsigned char *plain, int plen, EVP_PKEY *k,
                              const unsigned char *aeskey)
{
    static const unsigned char iv[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    unsigned char body[4096], ct[4096], wrapped[512], bits[4096], *alg_der = NULL;
    size_t b = 0, wlen = sizeof(wrapped);
    int ctlen = 0, fin = 0, alen;
    X509_ALGOR *alg = X509_ALGOR_new();
    ASN1_OCTET_STRING *ivs = ASN1_OCTET_STRING_new();
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    EVP_PKEY_CTX *pc = EVP_PKEY_CTX_new(k, NULL);

    ASN1_OCTET_STRING_set(ivs, iv, 16);
    X509_ALGOR_set0(alg, OBJ_nid2obj(NID_aes_128_cbc), V_ASN1_OCTET_STRING, ivs);
    alen = i2d_X509_ALGOR(alg, &alg_der);
    alg_der[0] = 0xa1; /* [1] IMPLICIT */
    memcpy(body + b, alg_der, alen);
    b += alen;
    EVP_PKEY_encrypt_init(pc);
    EVP_PKEY_CTX_set_rsa_padding(pc, RSA_PKCS1_PADDING);
    EVP_PKEY_encrypt(pc, wrapped, &wlen, aeskey, 16);
    bits[0] = 0;
    memcpy(bits + 1, wrapped, wlen);
    b += tlv(body + b, 0x82, bits, wlen + 1); /* [2] IMPLICIT BIT STRING */
    EVP_EncryptInit_ex(c, EVP_aes_128_cbc(), NULL, aeskey, iv);
    EVP_EncryptUpdate(c, ct, &ctlen, plain, plen);
    EVP_EncryptFinal_ex(c, ct + ctlen, &fin);
    bits[0] = 0;
    memcpy(bits + 1, ct, ctlen + fin);
    b += tlv(body + b, 0x03, bits, (size_t)(ctlen + fin) + 1);
    OPENSSL_free(alg_der);
    X509_ALGOR_free(alg);
    EVP_CIPHER_CTX_free(c);
    EVP_PKEY_CTX_free(pc);
    return tlv(out, 0x30, body, b);
}

static void encrypted(EVP_PKEY *k, X509 *ee)
{
    static const unsigned char aeskey[16] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66 };
    unsigned char der[4096], *cert_der = NULL, *key_der = NULL;
    const unsigned char *p;
    size_t n;
    int clen = i2d_X509(ee, &cert_der), klen = i2d_PrivateKey(k, &key_der), outlen = 0;
    OSSL_CRMF_ENCRYPTEDVALUE *ev;
    OSSL_CRMF_ENCRYPTEDKEY *ek;
    unsigned char *plain;
    X509 *x;
    EVP_PKEY *got;

    printf("# encrypted values\n");
    n = encrypted_value(der, cert_der, clen, k, aeskey);
    p = der;
    ev = d2i_OSSL_CRMF_ENCRYPTEDVALUE(NULL, &p, (long)n);
    check(ev != NULL && p == der + n, "d2i_OSSL_CRMF_ENCRYPTEDVALUE");
    ROUNDTRIP(OSSL_CRMF_ENCRYPTEDVALUE, ev, "i2d_OSSL_CRMF_ENCRYPTEDVALUE");
    plain = OSSL_CRMF_ENCRYPTEDVALUE_decrypt(ev, NULL, NULL, k, &outlen);
    check(plain != NULL && outlen >= clen && memcmp(plain, cert_der, clen) == 0, "OSSL_CRMF_ENCRYPTEDVALUE_decrypt");
    printf("  %d octets (%d with the padding left on)\n", clen, outlen);
    OPENSSL_free(plain);
    x = OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert(ev, NULL, NULL, k);
    check(x != NULL && X509_cmp(x, ee) == 0, "OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert");
    X509_free(x);
    check(OSSL_CRMF_ENCRYPTEDVALUE_decrypt(ev, NULL, NULL, NULL, &outlen) == NULL, "no key");
    errors();
    check(OSSL_CRMF_ENCRYPTEDVALUE_decrypt(ev, NULL, NULL, k, NULL) == NULL, "no length");
    errors();
    {
        EVP_PKEY *wrong = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);

        unsigned long e;
        int first = 1, expected = 0;

        check(OSSL_CRMF_ENCRYPTEDVALUE_decrypt(ev, NULL, NULL, wrong, &outlen) == NULL, "the wrong key");
        /* Implicit rejection: the wrong key's RSA decryption yields a synthetic key of random
         * length, so whether the failure is reported as the key's (when that length isn't 16)
         * or as the content's (about 1 in 245 keys) varies by key, on the reference too. */
        while ((e = ERR_get_error()) != 0) {
            if (first)
                expected = ERR_GET_LIB(e) == ERR_LIB_CRMF
                    && ERR_GET_REASON(e) == CRMF_R_ERROR_DECRYPTING_SYMMETRIC_KEY;
            first = 0;
            if (ERR_GET_LIB(e) == ERR_LIB_CRMF
                && ERR_GET_REASON(e) == CRMF_R_ERROR_DECRYPTING_ENCRYPTEDVALUE)
                expected = 1;
        }
        check(expected, "the wrong key: the symmetric key or the content fails to decrypt");
        EVP_PKEY_free(wrong);
    }

    printf("# encrypted keys\n");
    p = der;
    ek = d2i_OSSL_CRMF_ENCRYPTEDKEY(NULL, &p, (long)n);
    check(ek != NULL, "d2i_OSSL_CRMF_ENCRYPTEDKEY of an EncryptedValue");
    ROUNDTRIP(OSSL_CRMF_ENCRYPTEDKEY, ek, "i2d_OSSL_CRMF_ENCRYPTEDKEY");
    x = OSSL_CRMF_ENCRYPTEDKEY_get1_encCert(ek, NULL, NULL, k, 0);
    check(x != NULL && X509_cmp(x, ee) == 0, "OSSL_CRMF_ENCRYPTEDKEY_get1_encCert");
    X509_free(x);
    OSSL_CRMF_ENCRYPTEDKEY_free(ek);
    n = encrypted_value(der, key_der, klen, k, aeskey);
    p = der;
    ek = d2i_OSSL_CRMF_ENCRYPTEDKEY(NULL, &p, (long)n);
    got = OSSL_CRMF_ENCRYPTEDKEY_get1_pkey(ek, NULL, NULL, k, NULL, NULL, NULL, NULL);
    check(got != NULL && EVP_PKEY_eq(got, k) == 1, "OSSL_CRMF_ENCRYPTEDKEY_get1_pkey");
    EVP_PKEY_free(got);
    OSSL_CRMF_ENCRYPTEDKEY_free(ek);
    check(OSSL_CRMF_ENCRYPTEDKEY_get1_pkey(NULL, NULL, NULL, k, NULL, NULL, NULL, NULL) == NULL, "of NULL");
    errors();
    ek = OSSL_CRMF_ENCRYPTEDKEY_init_envdata(NULL);
    check(ek != NULL, "OSSL_CRMF_ENCRYPTEDKEY_init_envdata");
    check(OSSL_CRMF_ENCRYPTEDKEY_get1_pkey(ek, NULL, NULL, k, NULL, NULL, NULL, NULL) == NULL, "envelopedData, no store");
    errors();
    OSSL_CRMF_ENCRYPTEDKEY_free(ek);
    {
        OSSL_CRMF_ENCRYPTEDKEY *e2 = OSSL_CRMF_ENCRYPTEDKEY_new();
        OSSL_CRMF_ENCRYPTEDVALUE *v2 = OSSL_CRMF_ENCRYPTEDVALUE_new();

        OSSL_CRMF_CERTID *c2 = OSSL_CRMF_CERTID_new();
        OSSL_CRMF_CERTTEMPLATE *t2 = OSSL_CRMF_CERTTEMPLATE_new();
        OSSL_CRMF_PBMPARAMETER *p2 = OSSL_CRMF_PBMPARAMETER_new();

        DER(OSSL_CRMF_ENCRYPTEDVALUE, v2, "an empty value");
        DER(OSSL_CRMF_ENCRYPTEDKEY, e2, "an empty key");
        DER(OSSL_CRMF_CERTTEMPLATE, t2, "an empty template");
        DER(OSSL_CRMF_CERTID, c2, "an empty CertId");
        DER(OSSL_CRMF_PBMPARAMETER, p2, "empty parameters");
        OSSL_CRMF_CERTID_free(c2);
        OSSL_CRMF_CERTTEMPLATE_free(t2);
        OSSL_CRMF_PBMPARAMETER_free(p2);
        OSSL_CRMF_ENCRYPTEDVALUE_free(v2);
        OSSL_CRMF_ENCRYPTEDKEY_free(e2);
    }
    OSSL_CRMF_ENCRYPTEDVALUE_free(ev);
    OPENSSL_free(cert_der);
    OPENSSL_free(key_der);
}

static void pbm(void)
{
    /* salt "saltsaltsaltsalt", OWF SHA-256, 500 iterations, MAC HMAC-SHA1 */
    static const unsigned char der[] = {
        0x30, 0x2f, 0x04, 0x10, 's', 'a', 'l', 't', 's', 'a', 'l', 't', 's', 'a', 'l', 't', 's', 'a', 'l', 't',
        0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x02, 0x02, 0x01, 0xf4,
        0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x08, 0x01, 0x02
    };
    static const unsigned char few[] = {
        0x30, 0x2e, 0x04, 0x10, 's', 'a', 'l', 't', 's', 'a', 'l', 't', 's', 'a', 'l', 't', 's', 'a', 'l', 't',
        0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x02, 0x01, 0x32,
        0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x08, 0x01, 0x02
    };
    const unsigned char *p = der;
    OSSL_CRMF_PBMPARAMETER *pbmp = d2i_OSSL_CRMF_PBMPARAMETER(NULL, &p, sizeof(der)), *r;
    unsigned char *mac = NULL;
    size_t maclen = 0;

    printf("# the password-based MAC\n");
    check(pbmp != NULL, "d2i_OSSL_CRMF_PBMPARAMETER");
    ROUNDTRIP(OSSL_CRMF_PBMPARAMETER, pbmp, "i2d_OSSL_CRMF_PBMPARAMETER");
    check(OSSL_CRMF_pbm_new(NULL, NULL, pbmp, (const unsigned char *)"message", 7, (const unsigned char *)"secret", 6,
                            &mac, &maclen) == 1,
          "OSSL_CRMF_pbm_new");
    hex("mac", mac, (int)maclen);
    OPENSSL_free(mac);
    OSSL_CRMF_PBMPARAMETER_free(pbmp);
    p = few;
    pbmp = d2i_OSSL_CRMF_PBMPARAMETER(NULL, &p, sizeof(few));
    check(OSSL_CRMF_pbm_new(NULL, NULL, pbmp, (const unsigned char *)"m", 1, (const unsigned char *)"s", 1, &mac,
                            &maclen) == 0,
          "50 iterations");
    errors();
    check(OSSL_CRMF_pbm_new(NULL, NULL, NULL, (const unsigned char *)"m", 1, (const unsigned char *)"s", 1, &mac,
                            &maclen) == 0,
          "no parameters");
    errors();
    OSSL_CRMF_PBMPARAMETER_free(pbmp);

    r = OSSL_CRMF_pbmp_new(NULL, 16, NID_sha256, 500, NID_hmac_sha1);
    check(r != NULL, "OSSL_CRMF_pbmp_new");
    {
        unsigned char *q = NULL;
        int n = i2d_OSSL_CRMF_PBMPARAMETER(r, &q);

        printf("  %d octets\n", n);
        OPENSSL_free(q);
    }
    check(OSSL_CRMF_pbm_new(NULL, NULL, r, (const unsigned char *)"m", 1, (const unsigned char *)"s", 1, &mac, &maclen) == 1
              && maclen == 20,
          "a MAC with random salt");
    OPENSSL_free(mac);
    OSSL_CRMF_PBMPARAMETER_free(r);
    check(OSSL_CRMF_pbmp_new(NULL, 16, NID_sha256, 99, NID_hmac_sha1) == NULL, "99 iterations");
    errors();
    check(OSSL_CRMF_pbmp_new(NULL, 16, NID_sha256, 100001, NID_hmac_sha1) == NULL, "too many iterations");
    errors();
    r = OSSL_CRMF_pbmp_new(NULL, 16, NID_sha256, 500, NID_sha256);
    check(OSSL_CRMF_pbm_new(NULL, NULL, r, (const unsigned char *)"m", 1, (const unsigned char *)"s", 1, &mac, &maclen) == 0,
          "a MAC that isn't an HMAC");
    errors();
    OSSL_CRMF_PBMPARAMETER_free(r);
}

static void nulls(void)
{
    OSSL_CRMF_MSG *m = OSSL_CRMF_MSG_new();

    printf("# NULL and bad arguments\n");
    check(OSSL_CRMF_MSG_get0_tmpl(NULL) == NULL, "OSSL_CRMF_MSG_get0_tmpl");
    errors();
    check(OSSL_CRMF_MSG_get_certReqId(NULL) == -1, "OSSL_CRMF_MSG_get_certReqId");
    errors();
    check(OSSL_CRMF_MSG_set_certReqId(NULL, 1) == 0, "OSSL_CRMF_MSG_set_certReqId");
    errors();
    check(OSSL_CRMF_MSG_set0_validity(NULL, NULL, NULL) == 0, "OSSL_CRMF_MSG_set0_validity");
    errors();
    check(OSSL_CRMF_MSG_set0_extensions(NULL, NULL) == 0, "OSSL_CRMF_MSG_set0_extensions");
    errors();
    check(OSSL_CRMF_MSG_push0_extension(m, NULL) == 0, "OSSL_CRMF_MSG_push0_extension");
    errors();
    check(OSSL_CRMF_MSG_set0_extensions(m, sk_X509_EXTENSION_new_null()) == 1, "an empty list");
    check(OSSL_CRMF_MSG_set1_regCtrl_regToken(NULL, NULL) == 0, "set1 with NULLs");
    check(OSSL_CRMF_MSG_get0_regCtrl_regToken(NULL) == NULL && OSSL_CRMF_MSG_get0_regCtrl_regToken(m) == NULL,
          "get0 with none");
    check(OSSL_CRMF_MSG_set0_SinglePubInfo(NULL, 0, NULL) == 0, "OSSL_CRMF_MSG_set0_SinglePubInfo");
    errors();
    {
        OSSL_CRMF_SINGLEPUBINFO *spi = OSSL_CRMF_SINGLEPUBINFO_new();
        OSSL_CRMF_PKIPUBLICATIONINFO *pi = OSSL_CRMF_PKIPUBLICATIONINFO_new();

        check(OSSL_CRMF_MSG_set0_SinglePubInfo(spi, 9, NULL) == 0, "a bad method");
        errors();
        check(OSSL_CRMF_MSG_set_PKIPublicationInfo_action(pi, 2) == 0, "a bad action");
        errors();
        check(OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo(pi, NULL) == 0, "no info");
        errors();
        OSSL_CRMF_SINGLEPUBINFO_free(spi);
        OSSL_CRMF_PKIPUBLICATIONINFO_free(pi);
    }
    check(OSSL_CRMF_CERTID_gen(NULL, NULL) == NULL, "OSSL_CRMF_CERTID_gen");
    errors();
    check(OSSL_CRMF_CERTTEMPLATE_fill(NULL, NULL, NULL, NULL, NULL) == 0, "OSSL_CRMF_CERTTEMPLATE_fill");
    errors();
    check(OSSL_CRMF_CERTTEMPLATE_get0_publicKey(NULL) == NULL && OSSL_CRMF_CERTTEMPLATE_get0_subject(NULL) == NULL
              && OSSL_CRMF_CERTTEMPLATE_get0_issuer(NULL) == NULL && OSSL_CRMF_CERTTEMPLATE_get0_serialNumber(NULL) == NULL
              && OSSL_CRMF_CERTTEMPLATE_get0_extensions(NULL) == NULL && OSSL_CRMF_CERTID_get0_issuer(NULL) == NULL
              && OSSL_CRMF_CERTID_get0_serialNumber(NULL) == NULL,
          "the template's and CertId's get0s");
    check(OSSL_CRMF_MSG_create_popo(OSSL_CRMF_POPO_NONE, NULL, NULL, NULL, NULL, NULL) == 0, "a POPO for NULL");
    errors();
    check(OSSL_CRMF_MSGS_verify_popo(NULL, 0, 0, NULL, NULL) == 0, "OSSL_CRMF_MSGS_verify_popo");
    errors();
    check(OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup(NULL) == NULL, "OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup");
    OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free(NULL);
    check(OSSL_CRMF_MSG_dup(NULL) == NULL, "OSSL_CRMF_MSG_dup");
    printf("  items %s\n", OSSL_CRMF_CERTID_it() && OSSL_CRMF_CERTTEMPLATE_it() && OSSL_CRMF_ENCRYPTEDKEY_it()
                               && OSSL_CRMF_ENCRYPTEDVALUE_it() && OSSL_CRMF_MSGS_it() && OSSL_CRMF_MSG_it()
                               && OSSL_CRMF_PBMPARAMETER_it() && OSSL_CRMF_PKIPUBLICATIONINFO_it()
                               && OSSL_CRMF_SINGLEPUBINFO_it()
                           ? "all"
                           : "missing");
    OSSL_CRMF_MSG_free(m);
}

int main(void)
{
    EVP_PKEY *k = key(RSA_KEY_PEM), *ec = key(CA_KEY_PEM);
    X509 *ee = cert(RSA_PEM), *ca = cert(CA_PEM);
    OSSL_CRMF_MSG *msg;

    setvbuf(stdout, NULL, _IONBF, 0);
    msg = build(k, ee, ca);
    popo(msg, k, ec);
    encrypted(k, ee);
    pbm();
    nulls();
    OSSL_CRMF_MSG_free(msg);
    X509_free(ee);
    X509_free(ca);
    EVP_PKEY_free(k);
    EVP_PKEY_free(ec);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
