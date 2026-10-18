/*
 * Conformance test for CMP (OSSL_CMP_CTX_new(3), OSSL_CMP_SRV_CTX_new(3), OSSL_CMP_exec_certreq(3),
 * OSSL_CMP_ITAV_new_caCerts(3), OSSL_CMP_ATAV_create(3), OSSL_CMP_MSG_get0_header(3),
 * OSSL_CMP_validate_msg(3), OSSL_CMP_log_open(3), OSSL_CMP_STATUSINFO_new(3)): a client and a
 * server in one process (the client's transfer callback is OSSL_CMP_CTX_server_perform), the
 * server answering through the test's callbacks; enrollment by ir, cr, kur, and p10cr under
 * password-based MAC and signature protection; revocation; general messages (CA certificates,
 * root CA key update, CRL update, certificate request template); rejections, a client refusing
 * its certificate, implicit confirmation, polling (by exec, by try, aborted, and after a
 * delayed delivery); the context's options and fields; InfoTypeAndValue, AttributeTypeAndValue,
 * and CRL status values; messages encoded, written, read, and validated; logging; and the
 * errors of bad arguments.
 *
 * Nothing random is printed (nonces, transaction IDs, times, signatures), nor the file and line
 * of log messages.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/cmp.h>
#include <openssl/cmp_util.h>
#include <openssl/crmf.h>
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

static void hex(const char *label, const unsigned char *d, int n)
{
    int i;

    printf("  %s (%d):", label, n);
    for (i = 0; i < n; i++)
        printf("%s%02x", i % 32 == 0 ? "\n    " : "", d[i]);
    printf("\n");
}

/* The CMS and OCSP tests' EC root and its key, and the RSA end entity it issued, with its key. */
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

static X509 *ca, *ee;
static EVP_PKEY *ca_key, *ee_key;

static void print_name(const char *label, const X509_NAME *n)
{
    char *s = n == NULL ? NULL : X509_NAME_oneline(n, NULL, 0);

    printf("  %s: %s\n", label, s == NULL ? "(none)" : s);
    OPENSSL_free(s);
}

static void print_obj(const char *label, const ASN1_OBJECT *o)
{
    char buf[128];

    if (o == NULL) {
        printf("  %s: (none)\n", label);
        return;
    }
    OBJ_obj2txt(buf, sizeof(buf), o, 0);
    printf("  %s: %s\n", label, buf);
}

/* Log messages: the level and the text, for everything but what embeds random IDs. */
static int log_cb(const char *func, const char *file, int line, OSSL_CMP_severity level, const char *msg)
{
    (void)func;
    (void)file;
    (void)line;
    if (strstr(msg, "transaction with ID=") != NULL)
        return 1;
    printf("  log %d: %s\n", (int)level, msg);
    return 1;
}

static void print_status(OSSL_CMP_CTX *ctx)
{
    char buf[OSSL_CMP_PKISI_BUFLEN];
    const char *s = OSSL_CMP_CTX_snprint_PKIStatus(ctx, buf, sizeof(buf));

    printf("  status %d, failInfo %d: %s\n", OSSL_CMP_CTX_get_status(ctx), OSSL_CMP_CTX_get_failInfoCode(ctx),
           s == NULL ? "(none)" : s);
}

static void print_si(const char *label, const OSSL_CMP_PKISI *si)
{
    char buf[OSSL_CMP_PKISI_BUFLEN];
    const char *s = OSSL_CMP_snprint_PKIStatusInfo(si, buf, sizeof(buf));

    printf("  %s: %s\n", label, s == NULL ? "(none)" : s);
}

/* ---------------------------------------------------------------- the server */

enum { MODE_ISSUE, MODE_REJECT, MODE_POLL, MODE_DELAY };

struct server {
    int mode;
    int serial;
    int released;
    int polls;
    int cleans;
    int delays;
    OSSL_CMP_MSG *saved;
};

static struct server state;

static X509 *issue(const X509_NAME *subject, EVP_PKEY *pub)
{
    X509 *x = X509_new();
    ASN1_TIME *t = ASN1_TIME_new();

    X509_set_version(x, X509_VERSION_3);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 100 + ++state.serial);
    X509_set_issuer_name(x, X509_get_subject_name(ca));
    X509_set_subject_name(x, subject);
    X509_set_pubkey(x, pub);
    ASN1_TIME_set_string(t, "20260101000000Z");
    X509_set1_notBefore(x, t);
    ASN1_TIME_set_string(t, "20360101000000Z");
    X509_set1_notAfter(x, t);
    X509_sign(x, ca_key, EVP_sha256());
    ASN1_TIME_free(t);
    return x;
}

static OSSL_CMP_PKISI *srv_cert_request(OSSL_CMP_SRV_CTX *srv_ctx, const OSSL_CMP_MSG *req, int certReqId,
                                        const OSSL_CRMF_MSG *crm, const X509_REQ *p10cr, X509 **certOut,
                                        STACK_OF(X509) **chainOut, STACK_OF(X509) **caPubs)
{
    struct server *st = OSSL_CMP_SRV_CTX_get0_custom_ctx(srv_ctx);
    const X509_NAME *subject;
    EVP_PKEY *pub;

    printf("  server: cert request, body %d, id %d, %s\n", OSSL_CMP_MSG_get_bodytype(req), certReqId,
           crm != NULL ? "crmf" : p10cr != NULL ? "pkcs10" : "none");
    if (st->mode == MODE_REJECT)
        return OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_rejection, 1 << OSSL_CMP_PKIFAILUREINFO_badCertTemplate,
                                       "not today");
    if (st->mode == MODE_POLL && !st->released) {
        OSSL_CMP_MSG_free(st->saved);
        st->saved = OSSL_CMP_MSG_dup(req);
        return OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_waiting, 0, NULL);
    }
    if (crm != NULL) {
        OSSL_CRMF_CERTTEMPLATE *tmpl = OSSL_CRMF_MSG_get0_tmpl(crm);

        subject = OSSL_CRMF_CERTTEMPLATE_get0_subject(tmpl);
        pub = X509_PUBKEY_get0(OSSL_CRMF_CERTTEMPLATE_get0_publicKey(tmpl));
    } else {
        subject = X509_REQ_get_subject_name(p10cr);
        pub = X509_REQ_get0_pubkey((X509_REQ *)p10cr);
    }
    print_name("server: subject", subject);
    *certOut = issue(subject, pub);
    *chainOut = NULL;
    *caPubs = sk_X509_new_null();
    sk_X509_push(*caPubs, X509_dup(ca));
    return OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_accepted, 0, NULL);
}

static OSSL_CMP_PKISI *srv_rr(OSSL_CMP_SRV_CTX *srv_ctx, const OSSL_CMP_MSG *req, const X509_NAME *issuer,
                              const ASN1_INTEGER *serial)
{
    struct server *st = OSSL_CMP_SRV_CTX_get0_custom_ctx(srv_ctx);

    printf("  server: rr, body %d, serial %ld\n", OSSL_CMP_MSG_get_bodytype(req), ASN1_INTEGER_get(serial));
    print_name("server: issuer", issuer);
    if (st->mode == MODE_REJECT)
        return OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_rejection, 1 << OSSL_CMP_PKIFAILUREINFO_badCertId,
                                       "unknown certificate");
    return OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_revocationWarning, 0, NULL);
}

static int srv_genm(OSSL_CMP_SRV_CTX *srv_ctx, const OSSL_CMP_MSG *req, const STACK_OF(OSSL_CMP_ITAV) *in,
                    STACK_OF(OSSL_CMP_ITAV) **out)
{
    int i;

    (void)srv_ctx;
    printf("  server: genm, body %d, %d ITAVs\n", OSSL_CMP_MSG_get_bodytype(req), sk_OSSL_CMP_ITAV_num(in));
    *out = sk_OSSL_CMP_ITAV_new_null();
    for (i = 0; i < sk_OSSL_CMP_ITAV_num(in); i++) {
        OSSL_CMP_ITAV *itav = sk_OSSL_CMP_ITAV_value(in, i), *rsp = NULL;
        int nid = OBJ_obj2nid(OSSL_CMP_ITAV_get0_type(itav));

        print_obj("server: infoType", OSSL_CMP_ITAV_get0_type(itav));
        if (nid == NID_id_it_caCerts) {
            STACK_OF(X509) *certs = sk_X509_new_null();

            sk_X509_push(certs, ca);
            rsp = OSSL_CMP_ITAV_new_caCerts(certs);
            sk_X509_free(certs);
        } else if (nid == NID_id_it_rootCaCert) {
            X509 *old = NULL;

            OSSL_CMP_ITAV_get0_rootCaCert(itav, &old);
            print_name("server: old root", old == NULL ? NULL : X509_get_subject_name(old));
            rsp = OSSL_CMP_ITAV_new_rootCaKeyUpdate(NULL, NULL, NULL);
        } else if (nid == NID_id_it_crlStatusList) {
            STACK_OF(OSSL_CMP_CRLSTATUS) *list = NULL;
            DIST_POINT_NAME *dpn = NULL;
            GENERAL_NAMES *issuer = NULL;
            ASN1_TIME *upd = NULL;

            OSSL_CMP_ITAV_get0_crlStatusList(itav, &list);
            printf("  server: %d CRL status\n", sk_OSSL_CMP_CRLSTATUS_num(list));
            if (OSSL_CMP_CRLSTATUS_get0(sk_OSSL_CMP_CRLSTATUS_value(list, 0), &dpn, &issuer, &upd))
                printf("  server: dpn %s, issuers %d, thisUpdate %s\n", dpn != NULL ? "set" : "none",
                       sk_GENERAL_NAME_num(issuer), upd != NULL ? "set" : "none");
            rsp = OSSL_CMP_ITAV_new_crls(NULL);
        } else if (nid == NID_id_it_certReqTemplate) {
            OSSL_CRMF_CERTTEMPLATE *tmpl = OSSL_CRMF_CERTTEMPLATE_new();
            OSSL_CMP_ATAVS *keySpec = NULL;
            OSSL_CMP_ATAV *atav = OSSL_CMP_ATAV_new_rsaKeyLen(2048);
            X509_NAME *n = X509_NAME_new();

            X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)"templated", -1, -1, 0);
            OSSL_CRMF_CERTTEMPLATE_fill(tmpl, NULL, n, NULL, NULL);
            OSSL_CMP_ATAV_push1(&keySpec, atav);
            OSSL_CMP_ATAV_free(atav);
            rsp = OSSL_CMP_ITAV_new0_certReqTemplate(tmpl, keySpec);
            X509_NAME_free(n);
        } else {
            rsp = OSSL_CMP_ITAV_dup(itav);
        }
        OSSL_CMP_ITAV_push0_stack_item(out, rsp);
    }
    return 1;
}

static void srv_error(OSSL_CMP_SRV_CTX *srv_ctx, const OSSL_CMP_MSG *req, const OSSL_CMP_PKISI *statusInfo,
                      const ASN1_INTEGER *errorCode, const OSSL_CMP_PKIFREETEXT *errDetails)
{
    int i;

    (void)srv_ctx;
    printf("  server: error, body %d, code %ld\n", OSSL_CMP_MSG_get_bodytype(req),
           errorCode == NULL ? -1 : ASN1_INTEGER_get(errorCode));
    print_si("server: error status", statusInfo);
    for (i = 0; i < sk_ASN1_UTF8STRING_num(errDetails); i++)
        printf("  server: detail %s\n", ASN1_STRING_get0_data(sk_ASN1_UTF8STRING_value(errDetails, i)));
}

static int srv_certConf(OSSL_CMP_SRV_CTX *srv_ctx, const OSSL_CMP_MSG *req, int certReqId,
                        const ASN1_OCTET_STRING *certHash, const OSSL_CMP_PKISI *si)
{
    (void)srv_ctx;
    printf("  server: certConf, body %d, id %d, hash %d octets\n", OSSL_CMP_MSG_get_bodytype(req), certReqId,
           ASN1_STRING_length(certHash));
    if (si != NULL)
        print_si("server: certConf status", si);
    return 1;
}

static int srv_pollReq(OSSL_CMP_SRV_CTX *srv_ctx, const OSSL_CMP_MSG *req, int certReqId, OSSL_CMP_MSG **certReq,
                       int64_t *check_after)
{
    struct server *st = OSSL_CMP_SRV_CTX_get0_custom_ctx(srv_ctx);

    st->polls++;
    printf("  server: pollReq %d, body %d, id %d\n", st->polls, OSSL_CMP_MSG_get_bodytype(req), certReqId);
    *certReq = NULL;
    *check_after = 0;
    if (st->polls < 2)
        return 1;
    st->released = 1;
    *certReq = st->saved;
    st->saved = NULL;
    return 1;
}

static int srv_delay(OSSL_CMP_SRV_CTX *srv_ctx, const OSSL_CMP_MSG *req)
{
    struct server *st = OSSL_CMP_SRV_CTX_get0_custom_ctx(srv_ctx);

    if (st->mode != MODE_DELAY || st->saved != NULL || st->released)
        return 0;
    st->delays++;
    printf("  server: delaying body %d\n", OSSL_CMP_MSG_get_bodytype(req));
    st->saved = OSSL_CMP_MSG_dup(req);
    return 1;
}

static int srv_clean(OSSL_CMP_SRV_CTX *srv_ctx, const ASN1_OCTET_STRING *id)
{
    struct server *st = OSSL_CMP_SRV_CTX_get0_custom_ctx(srv_ctx);

    (void)id;
    st->cleans++;
    return 1;
}

static OSSL_CMP_SRV_CTX *srv;
static OSSL_CMP_MSG *last_req, *last_rsp;

/* The client's transfer: the in-process server, keeping copies of the last request and response. */
static OSSL_CMP_MSG *transfer(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *req)
{
    OSSL_CMP_MSG *rsp = OSSL_CMP_CTX_server_perform(ctx, req);

    OSSL_CMP_MSG_free(last_req);
    OSSL_CMP_MSG_free(last_rsp);
    last_req = OSSL_CMP_MSG_dup(req);
    last_rsp = rsp == NULL ? NULL : OSSL_CMP_MSG_dup(rsp);
    return rsp;
}

static void reset_server(int mode)
{
    OSSL_CMP_MSG_free(state.saved);
    state.saved = NULL;
    state.mode = mode;
    state.released = 0;
    state.polls = 0;
}

static void make_server(void)
{
    OSSL_CMP_CTX *sctx;
    X509_STORE *ts = X509_STORE_new();

    srv = OSSL_CMP_SRV_CTX_new(NULL, NULL);
    check(srv != NULL, "OSSL_CMP_SRV_CTX_new");
    check(OSSL_CMP_SRV_CTX_init(srv, &state, srv_cert_request, srv_rr, srv_genm, srv_error, srv_certConf,
                                srv_pollReq)
              == 1,
          "OSSL_CMP_SRV_CTX_init");
    check(OSSL_CMP_SRV_CTX_init_trans(srv, srv_delay, srv_clean) == 1, "OSSL_CMP_SRV_CTX_init_trans");
    check(OSSL_CMP_SRV_CTX_get0_custom_ctx(srv) == &state, "OSSL_CMP_SRV_CTX_get0_custom_ctx");
    sctx = OSSL_CMP_SRV_CTX_get0_cmp_ctx(srv);
    check(sctx != NULL, "OSSL_CMP_SRV_CTX_get0_cmp_ctx");
    OSSL_CMP_CTX_set_log_cb(sctx, log_cb);
    OSSL_CMP_CTX_set_option(sctx, OSSL_CMP_OPT_LOG_VERBOSITY, OSSL_CMP_LOG_INFO);
    OSSL_CMP_CTX_set1_cert(sctx, ca);
    OSSL_CMP_CTX_set1_pkey(sctx, ca_key);
    OSSL_CMP_CTX_set1_referenceValue(sctx, (const unsigned char *)"user", 4);
    OSSL_CMP_CTX_set1_secretValue(sctx, (const unsigned char *)"password", 8);
    X509_STORE_add_cert(ts, ca);
    OSSL_CMP_CTX_set0_trustedStore(sctx, ts);
    check(OSSL_CMP_SRV_CTX_set_send_unprotected_errors(srv, 0) == 1, "set_send_unprotected_errors");
    check(OSSL_CMP_SRV_CTX_set_accept_unprotected(srv, 0) == 1, "set_accept_unprotected");
    check(OSSL_CMP_SRV_CTX_set_accept_raverified(srv, 1) == 1, "set_accept_raverified");
    check(OSSL_CMP_SRV_CTX_set_grant_implicit_confirm(srv, 1) == 1, "set_grant_implicit_confirm");
}

/* ---------------------------------------------------------------- clients */

static X509_NAME *name(const char *cn)
{
    X509_NAME *n = X509_NAME_new();

    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0);
    return n;
}

/* A client of the in-process server, protecting with the password (MAC) or with the RSA end entity. */
static OSSL_CMP_CTX *client(int mac, const char *subject)
{
    OSSL_CMP_CTX *ctx = OSSL_CMP_CTX_new(NULL, NULL);

    OSSL_CMP_CTX_set_log_cb(ctx, log_cb);
    OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_LOG_VERBOSITY, OSSL_CMP_LOG_INFO);
    OSSL_CMP_CTX_set_transfer_cb(ctx, transfer);
    OSSL_CMP_CTX_set_transfer_cb_arg(ctx, srv);
    if (mac) {
        OSSL_CMP_CTX_set1_referenceValue(ctx, (const unsigned char *)"user", 4);
        OSSL_CMP_CTX_set1_secretValue(ctx, (const unsigned char *)"password", 8);
    } else {
        OSSL_CMP_CTX_set1_cert(ctx, ee);
        OSSL_CMP_CTX_set1_pkey(ctx, ee_key);
        OSSL_CMP_CTX_set1_srvCert(ctx, ca);
        OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_IGNORE_KEYUSAGE, 1);
    }
    if (subject != NULL) {
        X509_NAME *n = name(subject);

        OSSL_CMP_CTX_set1_subjectName(ctx, n);
        X509_NAME_free(n);
    }
    EVP_PKEY_up_ref(ee_key);
    OSSL_CMP_CTX_set0_newPkey(ctx, 1, ee_key);
    return ctx;
}

static void print_cert(const char *label, const X509 *x)
{
    if (x == NULL) {
        printf("  %s: none\n", label);
        return;
    }
    print_name(label, X509_get_subject_name(x));
    printf("  serial %ld\n", ASN1_INTEGER_get(X509_get0_serialNumber(x)));
}

static void enroll(void)
{
    OSSL_CMP_CTX *ctx;
    X509 *x;
    STACK_OF(X509) *sk;

    printf("# ir with a MAC\n");
    reset_server(MODE_ISSUE);
    ctx = client(1, "ir");
    x = OSSL_CMP_exec_certreq(ctx, OSSL_CMP_IR, NULL);
    check(x != NULL && x == OSSL_CMP_CTX_get0_newCert(ctx), "OSSL_CMP_exec_certreq IR");
    errors();
    print_cert("new", x);
    print_status(ctx);
    sk = OSSL_CMP_CTX_get1_caPubs(ctx);
    printf("  caPubs %d\n", sk_X509_num(sk));
    OSSL_STACK_OF_X509_free(sk);
    sk = OSSL_CMP_CTX_get1_newChain(ctx);
    printf("  newChain %d\n", sk_X509_num(sk));
    OSSL_STACK_OF_X509_free(sk);
    sk = OSSL_CMP_CTX_get1_extraCertsIn(ctx);
    printf("  extraCertsIn %d\n", sk_X509_num(sk));
    OSSL_STACK_OF_X509_free(sk);
    printf("  statusString %d\n", sk_ASN1_UTF8STRING_num(OSSL_CMP_CTX_get0_statusString(ctx)));
    printf("  validatedSrvCert %s\n", OSSL_CMP_CTX_get0_validatedSrvCert(ctx) != NULL ? "set" : "none");
    check(OSSL_CMP_validate_msg(ctx, last_rsp) == 1, "OSSL_CMP_validate_msg");
    errors();
    OSSL_CMP_CTX_free(ctx);

    printf("# cr with a signature\n");
    ctx = client(0, "cr");
    x = OSSL_CMP_exec_certreq(ctx, OSSL_CMP_CR, NULL);
    check(x != NULL, "OSSL_CMP_exec_certreq CR");
    errors();
    print_cert("new", x);
    print_status(ctx);
    printf("  validatedSrvCert %s\n", OSSL_CMP_CTX_get0_validatedSrvCert(ctx) != NULL ? "set" : "none");
    check(OSSL_CMP_validate_msg(ctx, last_rsp) == 1, "OSSL_CMP_validate_msg signed");
    errors();
    OSSL_CMP_CTX_free(ctx);

    printf("# kur\n");
    ctx = client(0, NULL);
    x = OSSL_CMP_exec_certreq(ctx, OSSL_CMP_KUR, NULL);
    check(x != NULL, "OSSL_CMP_exec_certreq KUR");
    errors();
    print_cert("new", x);
    print_status(ctx);
    OSSL_CMP_CTX_free(ctx);

    printf("# p10cr\n");
    {
        X509_REQ *csr = X509_REQ_new();
        X509_NAME *n = name("p10");

        X509_REQ_set_subject_name(csr, n);
        X509_REQ_set_pubkey(csr, ee_key);
        X509_REQ_sign(csr, ee_key, EVP_sha256());
        ctx = client(1, NULL);
        check(OSSL_CMP_CTX_set1_p10CSR(ctx, csr) == 1, "OSSL_CMP_CTX_set1_p10CSR");
        x = OSSL_CMP_exec_certreq(ctx, OSSL_CMP_P10CR, NULL);
        check(x != NULL, "OSSL_CMP_exec_certreq P10CR");
        errors();
        print_cert("new", x);
        print_status(ctx);
        OSSL_CMP_CTX_free(ctx);
        X509_NAME_free(n);
        X509_REQ_free(csr);
    }

    printf("# implicit confirmation\n");
    ctx = client(1, "implicit");
    OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_IMPLICIT_CONFIRM, 1);
    x = OSSL_CMP_exec_certreq(ctx, OSSL_CMP_IR, NULL);
    check(x != NULL, "implicitly confirmed");
    errors();
    print_status(ctx);
    OSSL_CMP_CTX_free(ctx);

    printf("# a rejection\n");
    reset_server(MODE_REJECT);
    ctx = client(1, "rejected");
    check(OSSL_CMP_exec_certreq(ctx, OSSL_CMP_CR, NULL) == NULL, "rejected");
    errors();
    print_status(ctx);
    printf("  statusString %d\n", sk_ASN1_UTF8STRING_num(OSSL_CMP_CTX_get0_statusString(ctx)));
    OSSL_CMP_CTX_free(ctx);
    reset_server(MODE_ISSUE);
}

static int refuse(OSSL_CMP_CTX *ctx, X509 *cert, int fail_info, const char **txt)
{
    int *calls = OSSL_CMP_CTX_get_certConf_cb_arg(ctx);

    (*calls)++;
    printf("  certConf_cb: fail_info %d, subject ", fail_info);
    X509_NAME_print_ex_fp(stdout, X509_get_subject_name(cert), 0, XN_FLAG_ONELINE);
    printf("\n");
    *txt = "not wanted";
    return 1 << OSSL_CMP_PKIFAILUREINFO_badCertTemplate;
}

static void confirmation(void)
{
    OSSL_CMP_CTX *ctx = client(1, "refused");
    int calls = 0;

    printf("# the client refusing its certificate\n");
    check(OSSL_CMP_CTX_set_certConf_cb(ctx, refuse) == 1, "OSSL_CMP_CTX_set_certConf_cb");
    check(OSSL_CMP_CTX_set_certConf_cb_arg(ctx, &calls) == 1, "OSSL_CMP_CTX_set_certConf_cb_arg");
    check(OSSL_CMP_exec_certreq(ctx, OSSL_CMP_IR, NULL) == NULL, "refused");
    errors();
    printf("  calls %d\n", calls);
    print_status(ctx);
    OSSL_CMP_CTX_free(ctx);

    printf("# the default certConf callback\n");
    ctx = client(1, "default");
    check(OSSL_CMP_exec_certreq(ctx, OSSL_CMP_IR, NULL) != NULL, "enrolled");
    check(OSSL_CMP_certConf_cb(ctx, OSSL_CMP_CTX_get0_newCert(ctx), 0, NULL) == 0, "OSSL_CMP_certConf_cb");
    check(OSSL_CMP_certConf_cb(ctx, OSSL_CMP_CTX_get0_newCert(ctx), 4, NULL) == 4, "keeps a failure");
    errors();
    OSSL_CMP_CTX_free(ctx);
}

static void polling(void)
{
    OSSL_CMP_CTX *ctx;
    int after = -1, res;

    printf("# polling within exec\n");
    reset_server(MODE_POLL);
    ctx = client(1, "polled");
    check(OSSL_CMP_exec_certreq(ctx, OSSL_CMP_IR, NULL) != NULL, "enrolled after polling");
    errors();
    print_status(ctx);
    OSSL_CMP_CTX_free(ctx);

    printf("# polling by try\n");
    reset_server(MODE_POLL);
    ctx = client(1, "tried");
    res = OSSL_CMP_try_certreq(ctx, OSSL_CMP_CR, NULL, &after);
    printf("  first try %d, checkAfter %d\n", res, after);
    print_status(ctx);
    after = -1;
    res = OSSL_CMP_try_certreq(ctx, OSSL_CMP_CR, NULL, &after);
    printf("  second try %d, checkAfter %d\n", res, after);
    check(res == 1 && OSSL_CMP_CTX_get0_newCert(ctx) != NULL, "OSSL_CMP_try_certreq");
    errors();
    print_cert("new", OSSL_CMP_CTX_get0_newCert(ctx));
    OSSL_CMP_CTX_free(ctx);

    printf("# polling aborted\n");
    reset_server(MODE_POLL);
    ctx = client(1, "aborted");
    res = OSSL_CMP_try_certreq(ctx, OSSL_CMP_IR, NULL, &after);
    printf("  first try %d\n", res);
    res = OSSL_CMP_try_certreq(ctx, -1, NULL, &after);
    printf("  abort %d\n", res);
    errors();
    print_status(ctx);
    OSSL_CMP_CTX_free(ctx);

    printf("# delayed delivery\n");
    reset_server(MODE_DELAY);
    ctx = client(1, "delayed");
    {
        STACK_OF(X509) *certs = NULL;

        check(OSSL_CMP_get1_caCerts(ctx, &certs) == 1 && sk_X509_num(certs) == 1, "a delayed genp");
        errors();
        printf("  delays %d, polls %d\n", state.delays, state.polls);
        OSSL_STACK_OF_X509_free(certs);
    }
    OSSL_CMP_CTX_free(ctx);
    reset_server(MODE_ISSUE);
}

static void revocation(void)
{
    OSSL_CMP_CTX *ctx = client(0, NULL);

    printf("# rr\n");
    OSSL_CMP_CTX_set1_oldCert(ctx, ee);
    check(OSSL_CMP_exec_RR_ses(ctx) == 1, "OSSL_CMP_exec_RR_ses");
    errors();
    print_status(ctx);
    OSSL_CMP_CTX_free(ctx);

    printf("# rr rejected\n");
    reset_server(MODE_REJECT);
    ctx = client(1, NULL);
    check(OSSL_CMP_CTX_set1_oldCert(ctx, ee) == 1, "OSSL_CMP_CTX_set1_oldCert");
    check(OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_REVOCATION_REASON, CRL_REASON_KEY_COMPROMISE) == 1, "a reason");
    check(OSSL_CMP_exec_RR_ses(ctx) == 0, "rejected");
    errors();
    print_status(ctx);
    OSSL_CMP_CTX_free(ctx);
    reset_server(MODE_ISSUE);

    printf("# rr by issuer and serial\n");
    ctx = client(1, NULL);
    check(OSSL_CMP_CTX_set1_issuer(ctx, X509_get_subject_name(ca)) == 1, "OSSL_CMP_CTX_set1_issuer");
    check(OSSL_CMP_CTX_set1_serialNumber(ctx, X509_get0_serialNumber(ee)) == 1, "OSSL_CMP_CTX_set1_serialNumber");
    check(OSSL_CMP_exec_RR_ses(ctx) == 1, "revoked");
    errors();
    OSSL_CMP_CTX_free(ctx);

    printf("# rr without a certificate\n");
    ctx = client(1, NULL);
    check(OSSL_CMP_exec_RR_ses(ctx) == 0, "nothing to revoke");
    errors();
    OSSL_CMP_CTX_free(ctx);
}

static void general(void)
{
    OSSL_CMP_CTX *ctx = client(1, NULL);
    STACK_OF(OSSL_CMP_ITAV) *itavs;
    STACK_OF(X509) *certs = NULL;
    X509 *nwn = (X509 *)1, *nwo = (X509 *)1, *own = (X509 *)1;
    X509_CRL *crl = (X509_CRL *)1;
    OSSL_CRMF_CERTTEMPLATE *tmpl = NULL;
    OSSL_CMP_ATAVS *keySpec = NULL;
    int i;

    printf("# genm\n");
    check(OSSL_CMP_CTX_push0_genm_ITAV(ctx, OSSL_CMP_ITAV_create(OBJ_txt2obj("1.2.3.4", 1), NULL)) == 1,
          "OSSL_CMP_CTX_push0_genm_ITAV");
    check(OSSL_CMP_CTX_push0_genm_ITAV(ctx, OSSL_CMP_ITAV_new0_certProfile(NULL)) == 1, "a second ITAV");
    itavs = OSSL_CMP_exec_GENM_ses(ctx);
    check(itavs != NULL, "OSSL_CMP_exec_GENM_ses");
    errors();
    for (i = 0; i < sk_OSSL_CMP_ITAV_num(itavs); i++)
        print_obj("genp infoType", OSSL_CMP_ITAV_get0_type(sk_OSSL_CMP_ITAV_value(itavs, i)));
    sk_OSSL_CMP_ITAV_pop_free(itavs, OSSL_CMP_ITAV_free);
    print_status(ctx);

    printf("# caCerts\n");
    check(OSSL_CMP_get1_caCerts(ctx, &certs) == 0, "an unclean context");
    errors();
    check(OSSL_CMP_CTX_reinit(ctx) == 1, "OSSL_CMP_CTX_reinit");
    check(OSSL_CMP_get1_caCerts(ctx, &certs) == 1 && sk_X509_num(certs) == 1, "OSSL_CMP_get1_caCerts");
    errors();
    print_name("caCert", X509_get_subject_name(sk_X509_value(certs, 0)));
    OSSL_STACK_OF_X509_free(certs);

    printf("# rootCaKeyUpdate\n");
    OSSL_CMP_CTX_reinit(ctx);
    check(OSSL_CMP_get1_rootCaKeyUpdate(ctx, ca, &nwn, &nwo, &own) == 1, "OSSL_CMP_get1_rootCaKeyUpdate");
    errors();
    printf("  newWithNew %s\n", nwn == NULL ? "none" : "set");

    printf("# crlUpdate\n");
    OSSL_CMP_CTX_reinit(ctx);
    check(OSSL_CMP_get1_crlUpdate(ctx, ee, NULL, &crl) == 1, "OSSL_CMP_get1_crlUpdate");
    errors();
    printf("  crl %s\n", crl == NULL ? "none" : "set");

    printf("# certReqTemplate\n");
    OSSL_CMP_CTX_reinit(ctx);
    check(OSSL_CMP_get1_certReqTemplate(ctx, &tmpl, &keySpec) == 1, "OSSL_CMP_get1_certReqTemplate");
    errors();
    print_name("template subject", OSSL_CRMF_CERTTEMPLATE_get0_subject(tmpl));
    printf("  keySpec %d, rsaKeyLen %d\n", sk_OSSL_CMP_ATAV_num(keySpec),
           OSSL_CMP_ATAV_get_rsaKeyLen(sk_OSSL_CMP_ATAV_value(keySpec, 0)));
    OSSL_CRMF_CERTTEMPLATE_free(tmpl);
    sk_OSSL_CMP_ATAV_pop_free(keySpec, OSSL_CMP_ATAV_free);

    printf("# get1 with NULL\n");
    check(OSSL_CMP_get1_caCerts(ctx, NULL) == 0, "caCerts");
    errors();
    check(OSSL_CMP_get1_rootCaKeyUpdate(ctx, ca, NULL, NULL, NULL) == 0, "rootCaKeyUpdate");
    errors();
    check(OSSL_CMP_get1_crlUpdate(ctx, ee, NULL, NULL) == 0, "crlUpdate");
    errors();
    check(OSSL_CMP_get1_certReqTemplate(ctx, NULL, NULL) == 0, "certReqTemplate");
    errors();
    OSSL_CMP_CTX_free(ctx);
}

/* ---------------------------------------------------------------- messages */

static void messages(void)
{
    OSSL_CMP_CTX *ctx = client(1, "messages");
    OSSL_CMP_MSG *req, *rsp, *m;
    OSSL_CMP_PKIHEADER *hdr;
    unsigned char *der = NULL, *der2 = NULL;
    const unsigned char *p;
    int n, n2;
    char path[64];
    BIO *bio;

    printf("# messages\n");
    OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_IMPLICIT_CONFIRM, 1);
    check(OSSL_CMP_CTX_push0_geninfo_ITAV(ctx, OSSL_CMP_ITAV_create(OBJ_txt2obj("1.2.3.5", 1), NULL)) == 1,
          "OSSL_CMP_CTX_push0_geninfo_ITAV");
    printf("  geninfo %d\n", sk_OSSL_CMP_ITAV_num(OSSL_CMP_CTX_get0_geninfo_ITAVs(ctx)));
    check(OSSL_CMP_exec_certreq(ctx, OSSL_CMP_IR, NULL) != NULL, "enrolled");
    errors();
    req = OSSL_CMP_MSG_dup(last_req);
    rsp = OSSL_CMP_MSG_dup(last_rsp);
    printf("  last request body %d, response body %d\n", OSSL_CMP_MSG_get_bodytype(req),
           OSSL_CMP_MSG_get_bodytype(rsp));
    hdr = OSSL_CMP_MSG_get0_header(req);
    printf("  transactionID %d, recipNonce %s, geninfo %d\n",
           ASN1_STRING_length(OSSL_CMP_HDR_get0_transactionID(hdr)),
           OSSL_CMP_HDR_get0_recipNonce(hdr) != NULL ? "set" : "none",
           sk_OSSL_CMP_ITAV_num(OSSL_CMP_HDR_get0_geninfo_ITAVs(hdr)));
    check(OSSL_CMP_CTX_reset_geninfo_ITAVs(ctx) == 1 && OSSL_CMP_CTX_get0_geninfo_ITAVs(ctx) == NULL,
          "OSSL_CMP_CTX_reset_geninfo_ITAVs");
    printf("  certreq public key %s\n", OSSL_CMP_MSG_get0_certreq_publickey(req) == NULL ? "none" : "set");
    printf("  certreq public key of the pkiconf %s\n",
           OSSL_CMP_MSG_get0_certreq_publickey(rsp) == NULL ? "none" : "set");
    errors();

    n = i2d_OSSL_CMP_MSG(req, &der);
    p = der;
    m = d2i_OSSL_CMP_MSG(NULL, &p, n);
    n2 = i2d_OSSL_CMP_MSG(m, &der2);
    check(m != NULL && p == der + n && n == n2 && memcmp(der, der2, n) == 0, "d2i_OSSL_CMP_MSG");
    OSSL_CMP_MSG_free(m);
    OPENSSL_free(der2);
    der2 = NULL;

    bio = BIO_new(BIO_s_mem());
    check(i2d_OSSL_CMP_MSG_bio(bio, req) == 1, "i2d_OSSL_CMP_MSG_bio");
    m = d2i_OSSL_CMP_MSG_bio(bio, NULL);
    n2 = i2d_OSSL_CMP_MSG(m, &der2);
    check(m != NULL && n == n2 && memcmp(der, der2, n) == 0, "d2i_OSSL_CMP_MSG_bio");
    OSSL_CMP_MSG_free(m);
    OPENSSL_free(der2);
    der2 = NULL;
    BIO_free(bio);

    snprintf(path, sizeof(path), "/tmp/cmp-test-%ld.der", (long)getpid());
    check(OSSL_CMP_MSG_write(path, req) == 1, "OSSL_CMP_MSG_write");
    m = OSSL_CMP_MSG_read(path, NULL, NULL);
    n2 = i2d_OSSL_CMP_MSG(m, &der2);
    check(m != NULL && n == n2 && memcmp(der, der2, n) == 0, "OSSL_CMP_MSG_read");
    OSSL_CMP_MSG_free(m);
    OPENSSL_free(der2);
    der2 = NULL;
    remove(path);
    check(OSSL_CMP_MSG_read("/nonexistent/cmp.der", NULL, NULL) == NULL, "reading a missing file");
    errors();
    check(OSSL_CMP_MSG_write(NULL, req) == -1, "writing to NULL");
    errors();
    check(OSSL_CMP_MSG_write("/nonexistent/cmp.der", req) == -2, "writing to a missing directory");
    errors();
    OPENSSL_free(der);

    check(OSSL_CMP_MSG_update_transactionID(ctx, req) == 1, "OSSL_CMP_MSG_update_transactionID");
    errors();
    check(OSSL_CMP_validate_msg(ctx, req) == 1, "the updated request validates");
    errors();
    check(OSSL_CMP_MSG_update_recipNonce(ctx, req) == 1, "OSSL_CMP_MSG_update_recipNonce");
    errors();
    printf("  recipNonce now %s\n", OSSL_CMP_HDR_get0_recipNonce(OSSL_CMP_MSG_get0_header(req)) != NULL ? "set" : "none");

    printf("# a bad MAC\n");
    OSSL_CMP_CTX_set1_secretValue(ctx, (const unsigned char *)"wrong", 5);
    check(OSSL_CMP_validate_msg(ctx, rsp) == 0, "rejected");
    errors();
    OSSL_CMP_CTX_set1_secretValue(ctx, NULL, 0);
    check(OSSL_CMP_validate_msg(ctx, rsp) == 0, "no secret");
    errors();
    check(OSSL_CMP_validate_msg(NULL, rsp) == 0 && OSSL_CMP_validate_msg(ctx, NULL) == 0, "NULLs");
    errors();
    OSSL_CMP_MSG_free(req);
    OSSL_CMP_MSG_free(rsp);

    printf("# messages to the server directly\n");
    {
        OSSL_CMP_MSG *r = OSSL_CMP_SRV_process_request(srv, NULL);

        check(r == NULL, "OSSL_CMP_SRV_process_request with NULL");
        errors();
        check(OSSL_CMP_CTX_server_perform(NULL, NULL) == NULL, "OSSL_CMP_CTX_server_perform with NULL");
        errors();
        OSSL_CMP_CTX_set_transfer_cb_arg(ctx, NULL);
        check(OSSL_CMP_CTX_server_perform(ctx, last_req) == NULL, "no server");
        errors();
    }

    printf("# HTTP\n");
    check(OSSL_CMP_MSG_http_perform(ctx, NULL) == NULL, "OSSL_CMP_MSG_http_perform with NULL");
    errors();
    OSSL_CMP_CTX_free(ctx);

    printf("# a CRMF message from the context\n");
    {
        OSSL_CRMF_MSG *crm;

        ctx = client(1, "crm");
        crm = OSSL_CMP_CTX_setup_CRM(ctx, 0, 7);
        check(crm != NULL && OSSL_CRMF_MSG_get_certReqId(crm) == 7, "OSSL_CMP_CTX_setup_CRM");
        print_name("crm subject", OSSL_CRMF_CERTTEMPLATE_get0_subject(OSSL_CRMF_MSG_get0_tmpl(crm)));
        OSSL_CRMF_MSG_free(crm);
        crm = OSSL_CMP_CTX_setup_CRM(ctx, 1, 0);
        check(crm == NULL, "for a kur without an old certificate");
        errors();
        OSSL_CMP_CTX_free(ctx);
    }
}

/* ---------------------------------------------------------------- the context */

static const int opts[] = {
    OSSL_CMP_OPT_LOG_VERBOSITY, OSSL_CMP_OPT_KEEP_ALIVE, OSSL_CMP_OPT_MSG_TIMEOUT, OSSL_CMP_OPT_TOTAL_TIMEOUT,
    OSSL_CMP_OPT_USE_TLS, OSSL_CMP_OPT_VALIDITY_DAYS, OSSL_CMP_OPT_SUBJECTALTNAME_NODEFAULT,
    OSSL_CMP_OPT_SUBJECTALTNAME_CRITICAL, OSSL_CMP_OPT_POLICIES_CRITICAL, OSSL_CMP_OPT_POPO_METHOD,
    OSSL_CMP_OPT_IMPLICIT_CONFIRM, OSSL_CMP_OPT_DISABLE_CONFIRM, OSSL_CMP_OPT_REVOCATION_REASON,
    OSSL_CMP_OPT_UNPROTECTED_SEND, OSSL_CMP_OPT_UNPROTECTED_ERRORS, OSSL_CMP_OPT_OWF_ALGNID,
    OSSL_CMP_OPT_MAC_ALGNID, OSSL_CMP_OPT_DIGEST_ALGNID, OSSL_CMP_OPT_IGNORE_KEYUSAGE,
    OSSL_CMP_OPT_PERMIT_TA_IN_EXTRACERTS_FOR_IR, OSSL_CMP_OPT_NO_CACHE_EXTRACERTS
};

static BIO *my_http_cb(BIO *bio, void *arg, int connect, int detail)
{
    (void)arg;
    (void)connect;
    (void)detail;
    return bio;
}

static void context(void)
{
    OSSL_CMP_CTX *ctx = OSSL_CMP_CTX_new(NULL, NULL);
    size_t i;
    int x = 0;
    STACK_OF(X509) *sk;
    X509_STORE *ts;

    printf("# the context's options\n");
    OSSL_CMP_CTX_set_log_cb(ctx, log_cb);
    check(OSSL_CMP_CTX_get0_libctx(ctx) == NULL, "OSSL_CMP_CTX_get0_libctx");
    check(OSSL_CMP_CTX_get0_propq(ctx) == NULL, "OSSL_CMP_CTX_get0_propq");
    for (i = 0; i < sizeof(opts) / sizeof(opts[0]); i++)
        printf("  option %d = %d\n", opts[i], OSSL_CMP_CTX_get_option(ctx, opts[i]));
    check(OSSL_CMP_CTX_get_option(ctx, 1) == -1, "an unknown option");
    errors();
    check(OSSL_CMP_CTX_set_option(ctx, 1, 0) == 0, "setting an unknown option");
    errors();
    check(OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_LOG_VERBOSITY, OSSL_CMP_LOG_MAX + 1) == 0, "too verbose");
    errors();
    check(OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_POPO_METHOD, OSSL_CRMF_POPO_KEYAGREE + 1) == 0, "a bad POPO");
    errors();
    check(OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_REVOCATION_REASON, CRL_REASON_AA_COMPROMISE + 1) == 0,
          "a bad reason");
    errors();
    check(OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_MSG_TIMEOUT, -1) == 0, "a negative value");
    errors();
    check(OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_KEEP_ALIVE, 3) == 1, "keep alive 3");
    check(OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_VALIDITY_DAYS, 30) == 1, "30 days");
    check(OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_DIGEST_ALGNID, NID_sha384) == 1, "SHA-384");
    check(OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_OWF_ALGNID, NID_sha512) == 1, "SHA-512 OWF");
    check(OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_DIGEST_ALGNID, NID_undef) == 0, "no digest");
    errors();
    for (i = 0; i < sizeof(opts) / sizeof(opts[0]); i++)
        printf("  option %d = %d\n", opts[i], OSSL_CMP_CTX_get_option(ctx, opts[i]));

    printf("# the context's fields\n");
    check(OSSL_CMP_CTX_set1_serverPath(ctx, "/pkix/") == 1, "OSSL_CMP_CTX_set1_serverPath");
    check(OSSL_CMP_CTX_set1_server(ctx, "ca.example") == 1, "OSSL_CMP_CTX_set1_server");
    check(OSSL_CMP_CTX_set_serverPort(ctx, 8080) == 1, "OSSL_CMP_CTX_set_serverPort");
    check(OSSL_CMP_CTX_set_serverPort(ctx, -1) == 1, "a negative port is taken");
    errors();
    check(OSSL_CMP_CTX_set1_proxy(ctx, "proxy.example:3128") == 1, "OSSL_CMP_CTX_set1_proxy");
    check(OSSL_CMP_CTX_set1_no_proxy(ctx, "localhost") == 1, "OSSL_CMP_CTX_set1_no_proxy");
    check(OSSL_CMP_CTX_set_http_cb(ctx, my_http_cb) == 1, "OSSL_CMP_CTX_set_http_cb");
    check(OSSL_CMP_CTX_set_http_cb_arg(ctx, &x) == 1 && OSSL_CMP_CTX_get_http_cb_arg(ctx) == &x, "the HTTP argument");
    check(OSSL_CMP_CTX_set_transfer_cb_arg(ctx, &x) == 1 && OSSL_CMP_CTX_get_transfer_cb_arg(ctx) == &x,
          "the transfer argument");
    check(OSSL_CMP_CTX_set1_expected_sender(ctx, X509_get_subject_name(ca)) == 1, "OSSL_CMP_CTX_set1_expected_sender");
    check(OSSL_CMP_CTX_set1_recipient(ctx, X509_get_subject_name(ca)) == 1, "OSSL_CMP_CTX_set1_recipient");
    ts = X509_STORE_new();
    check(OSSL_CMP_CTX_set0_trustedStore(ctx, ts) == 1 && OSSL_CMP_CTX_get0_trustedStore(ctx) == ts,
          "the trusted store");
    sk = sk_X509_new_null();
    sk_X509_push(sk, ca);
    check(OSSL_CMP_CTX_set1_untrusted(ctx, sk) == 1 && sk_X509_num(OSSL_CMP_CTX_get0_untrusted(ctx)) == 1,
          "the untrusted certificates");
    check(OSSL_CMP_CTX_set1_extraCertsOut(ctx, sk) == 1, "OSSL_CMP_CTX_set1_extraCertsOut");
    check(OSSL_CMP_CTX_set1_cert(ctx, ee) == 1, "OSSL_CMP_CTX_set1_cert");
    check(OSSL_CMP_CTX_set1_pkey(ctx, ee_key) == 1, "OSSL_CMP_CTX_set1_pkey");
    X509_STORE_add_cert(ts, ca);
    check(OSSL_CMP_CTX_build_cert_chain(ctx, ts, NULL) == 1, "OSSL_CMP_CTX_build_cert_chain");
    errors();
    check(OSSL_CMP_validate_cert_path(ctx, ts, ee) == 1, "OSSL_CMP_validate_cert_path");
    errors();
    {
        X509_STORE *empty = X509_STORE_new();

        check(OSSL_CMP_validate_cert_path(ctx, empty, ee) == 0, "an empty store");
        errors();
        check(OSSL_CMP_validate_cert_path(ctx, NULL, ee) == 0, "no store");
        errors();
        X509_STORE_free(empty);
    }
    sk_X509_free(sk);
    check(OSSL_CMP_CTX_set1_referenceValue(ctx, (const unsigned char *)"ref", 3) == 1, "OSSL_CMP_CTX_set1_referenceValue");
    check(OSSL_CMP_CTX_set1_secretValue(ctx, (const unsigned char *)"sec", 3) == 1, "OSSL_CMP_CTX_set1_secretValue");
    check(OSSL_CMP_CTX_set1_srvCert(ctx, ca) == 1, "OSSL_CMP_CTX_set1_srvCert");
    {
        ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();

        ASN1_OCTET_STRING_set(os, (const unsigned char *)"0123456789abcdef", 16);
        check(OSSL_CMP_CTX_set1_transactionID(ctx, os) == 1, "OSSL_CMP_CTX_set1_transactionID");
        check(OSSL_CMP_CTX_set1_senderNonce(ctx, os) == 1, "OSSL_CMP_CTX_set1_senderNonce");
        ASN1_OCTET_STRING_free(os);
    }
    printf("# the template\n");
    check(OSSL_CMP_CTX_get0_newPkey(ctx, 0) == ee_key, "the new key defaults to the key");
    EVP_PKEY_up_ref(ee_key);
    check(OSSL_CMP_CTX_set0_newPkey(ctx, 0, ee_key) == 1, "OSSL_CMP_CTX_set0_newPkey");
    check(OSSL_CMP_CTX_get0_newPkey(ctx, 1) == NULL, "not private");
    errors();
    {
        X509_NAME *n = name("subject");
        GENERAL_NAME *gn = a2i_GENERAL_NAME(NULL, NULL, NULL, GEN_DNS, "ee.example", 0);
        X509_EXTENSIONS *exts = sk_X509_EXTENSION_new_null();
        POLICYINFO *pi = POLICYINFO_new();

        check(OSSL_CMP_CTX_set1_subjectName(ctx, n) == 1, "OSSL_CMP_CTX_set1_subjectName");
        check(OSSL_CMP_CTX_set1_issuer(ctx, X509_get_subject_name(ca)) == 1, "OSSL_CMP_CTX_set1_issuer");
        check(OSSL_CMP_CTX_set1_oldCert(ctx, ee) == 1, "OSSL_CMP_CTX_set1_oldCert");
        check(OSSL_CMP_CTX_reqExtensions_have_SAN(ctx) == 0, "no SAN yet");
        sk_X509_EXTENSION_push(exts, X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, "DNS:x.example"));
        check(OSSL_CMP_CTX_set0_reqExtensions(ctx, exts) == 1, "OSSL_CMP_CTX_set0_reqExtensions");
        check(OSSL_CMP_CTX_reqExtensions_have_SAN(ctx) == 1, "OSSL_CMP_CTX_reqExtensions_have_SAN");
        check(OSSL_CMP_CTX_push1_subjectAltName(ctx, gn) == 0, "a SAN with SAN extensions");
        errors();
        check(OSSL_CMP_CTX_set0_reqExtensions(ctx, NULL) == 1, "no extensions");
        check(OSSL_CMP_CTX_push1_subjectAltName(ctx, gn) == 1, "OSSL_CMP_CTX_push1_subjectAltName");
        pi->policyid = OBJ_txt2obj("1.2.3.6", 1);
        check(OSSL_CMP_CTX_push0_policy(ctx, pi) == 1, "OSSL_CMP_CTX_push0_policy");
        {
            OSSL_CRMF_MSG *crm = OSSL_CMP_CTX_setup_CRM(ctx, 0, 0);
            OSSL_CRMF_CERTTEMPLATE *t = OSSL_CRMF_MSG_get0_tmpl(crm);

            print_name("template subject", OSSL_CRMF_CERTTEMPLATE_get0_subject(t));
            print_name("template issuer", OSSL_CRMF_CERTTEMPLATE_get0_issuer(t));
            printf("  template extensions %d\n", sk_X509_EXTENSION_num(OSSL_CRMF_CERTTEMPLATE_get0_extensions(t)));
            OSSL_CRMF_MSG_free(crm);
        }
        GENERAL_NAME_free(gn);
        X509_NAME_free(n);
    }
    printf("  status %d, failInfo %d, newCert %s\n", OSSL_CMP_CTX_get_status(ctx), OSSL_CMP_CTX_get_failInfoCode(ctx),
           OSSL_CMP_CTX_get0_newCert(ctx) != NULL ? "set" : "none");
    print_status(ctx);
    check(OSSL_CMP_CTX_reinit(ctx) == 1, "OSSL_CMP_CTX_reinit");
    OSSL_CMP_CTX_free(ctx);
    OSSL_CMP_CTX_free(NULL);

    printf("# NULL contexts\n");
    check(OSSL_CMP_CTX_reinit(NULL) == 0, "OSSL_CMP_CTX_reinit");
    errors();
    check(OSSL_CMP_CTX_get_option(NULL, OSSL_CMP_OPT_KEEP_ALIVE) == -1, "OSSL_CMP_CTX_get_option");
    errors();
    check(OSSL_CMP_CTX_set1_server(NULL, "x") == 0, "OSSL_CMP_CTX_set1_server");
    errors();
    check(OSSL_CMP_CTX_get_status(NULL) == -1, "OSSL_CMP_CTX_get_status");
    errors();
    check(OSSL_CMP_CTX_get0_newCert(NULL) == NULL, "OSSL_CMP_CTX_get0_newCert");
    errors();
    check(OSSL_CMP_CTX_get1_caPubs(NULL) == NULL, "OSSL_CMP_CTX_get1_caPubs");
    errors();
    check(OSSL_CMP_CTX_snprint_PKIStatus(NULL, NULL, 0) == NULL, "OSSL_CMP_CTX_snprint_PKIStatus");
    errors();
    check(OSSL_CMP_exec_certreq(NULL, OSSL_CMP_IR, NULL) == NULL, "OSSL_CMP_exec_certreq");
    errors();
    check(OSSL_CMP_try_certreq(NULL, OSSL_CMP_IR, NULL, NULL) == 0, "OSSL_CMP_try_certreq");
    errors();
    check(OSSL_CMP_exec_RR_ses(NULL) == 0, "OSSL_CMP_exec_RR_ses");
    errors();
    check(OSSL_CMP_exec_GENM_ses(NULL) == NULL, "OSSL_CMP_exec_GENM_ses");
    errors();
    check(OSSL_CMP_SRV_CTX_init(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL) == 0, "OSSL_CMP_SRV_CTX_init");
    errors();
    check(OSSL_CMP_SRV_CTX_get0_cmp_ctx(NULL) == NULL, "OSSL_CMP_SRV_CTX_get0_cmp_ctx");
    errors();
    check(OSSL_CMP_SRV_CTX_set_accept_raverified(NULL, 1) == 0, "OSSL_CMP_SRV_CTX_set_accept_raverified");
    errors();
    check(OSSL_CMP_MSG_get_bodytype(NULL) == -1, "OSSL_CMP_MSG_get_bodytype");
    errors();
    check(OSSL_CMP_MSG_get0_header(NULL) == NULL, "OSSL_CMP_MSG_get0_header");
    errors();
    check(OSSL_CMP_HDR_get0_transactionID(NULL) == NULL && OSSL_CMP_HDR_get0_recipNonce(NULL) == NULL
              && OSSL_CMP_HDR_get0_geninfo_ITAVs(NULL) == NULL,
          "the header's get0s");
    errors();
    OSSL_CMP_SRV_CTX_free(NULL);
    OSSL_CMP_MSG_free(NULL);
}

/* ---------------------------------------------------------------- values */

static void values(void)
{
    OSSL_CMP_ITAV *itav, *dup;
    STACK_OF(OSSL_CMP_ITAV) *sk = NULL;
    STACK_OF(ASN1_UTF8STRING) *profiles = sk_ASN1_UTF8STRING_new_null(), *got = NULL;
    ASN1_UTF8STRING *s = ASN1_UTF8STRING_new();
    STACK_OF(X509) *certs = sk_X509_new_null(), *gotcerts = NULL;
    X509 *x1 = NULL, *x2 = NULL, *x3 = NULL;
    ASN1_TYPE *t = ASN1_TYPE_new();

    printf("# InfoTypeAndValue\n");
    ASN1_TYPE_set(t, V_ASN1_NULL, NULL);
    itav = OSSL_CMP_ITAV_create(OBJ_txt2obj("1.2.3.7", 1), t);
    check(itav != NULL && OSSL_CMP_ITAV_get0_value(itav) == t, "OSSL_CMP_ITAV_create");
    print_obj("type", OSSL_CMP_ITAV_get0_type(itav));
    dup = OSSL_CMP_ITAV_dup(itav);
    check(dup != NULL && ASN1_TYPE_get(OSSL_CMP_ITAV_get0_value(dup)) == V_ASN1_NULL, "OSSL_CMP_ITAV_dup");
    check(OSSL_CMP_ITAV_push0_stack_item(&sk, itav) == 1 && OSSL_CMP_ITAV_push0_stack_item(&sk, dup) == 1,
          "OSSL_CMP_ITAV_push0_stack_item");
    printf("  %d on the stack\n", sk_OSSL_CMP_ITAV_num(sk));
    sk_OSSL_CMP_ITAV_pop_free(sk, OSSL_CMP_ITAV_free);
    check(OSSL_CMP_ITAV_create(NULL, NULL) == NULL, "no type");
    check(OSSL_CMP_ITAV_push0_stack_item(NULL, NULL) == 0, "pushing to NULL");
    errors();
    itav = OSSL_CMP_ITAV_create(OBJ_txt2obj("1.2.3.8", 1), NULL);
    OSSL_CMP_ITAV_set0(itav, OBJ_nid2obj(NID_id_it_implicitConfirm), NULL);
    print_obj("set0 type", OSSL_CMP_ITAV_get0_type(itav));
    OSSL_CMP_ITAV_free(itav);
    check(OSSL_CMP_ITAV_get0_type(NULL) == NULL && OSSL_CMP_ITAV_get0_value(NULL) == NULL, "NULL ITAVs");
    OSSL_CMP_ITAV_free(NULL);

    ASN1_STRING_set(s, "profile1", -1);
    sk_ASN1_UTF8STRING_push(profiles, s);
    itav = OSSL_CMP_ITAV_new0_certProfile(profiles);
    check(OSSL_CMP_ITAV_get0_certProfile(itav, &got) == 1 && got == profiles, "OSSL_CMP_ITAV_get0_certProfile");
    check(OSSL_CMP_ITAV_get0_caCerts(itav, &gotcerts) == 0, "not caCerts");
    errors();
    OSSL_CMP_ITAV_free(itav);

    sk_X509_push(certs, ca);
    itav = OSSL_CMP_ITAV_new_caCerts(certs);
    check(OSSL_CMP_ITAV_get0_caCerts(itav, &gotcerts) == 1 && sk_X509_num(gotcerts) == 1, "OSSL_CMP_ITAV_new_caCerts");
    check(OSSL_CMP_ITAV_get0_certProfile(itav, &got) == 0, "not certProfile");
    errors();
    OSSL_CMP_ITAV_free(itav);
    itav = OSSL_CMP_ITAV_new_caCerts(NULL);
    check(OSSL_CMP_ITAV_get0_caCerts(itav, &gotcerts) == 1 && gotcerts == NULL, "no caCerts");
    OSSL_CMP_ITAV_free(itav);
    sk_X509_free(certs);

    itav = OSSL_CMP_ITAV_new_rootCaCert(ca);
    check(OSSL_CMP_ITAV_get0_rootCaCert(itav, &x1) == 1 && X509_cmp(x1, ca) == 0, "OSSL_CMP_ITAV_new_rootCaCert");
    check(OSSL_CMP_ITAV_get0_rootCaCert(itav, NULL) == 0, "no room");
    errors();
    OSSL_CMP_ITAV_free(itav);
    itav = OSSL_CMP_ITAV_new_rootCaKeyUpdate(ca, ee, NULL);
    check(OSSL_CMP_ITAV_get0_rootCaKeyUpdate(itav, &x1, &x2, &x3) == 1 && X509_cmp(x1, ca) == 0
              && X509_cmp(x2, ee) == 0 && x3 == NULL,
          "OSSL_CMP_ITAV_new_rootCaKeyUpdate");
    {
        OSSL_CMP_ITAV *back = OSSL_CMP_ITAV_dup(itav);

        check(back != NULL, "a dup of a rootCaKeyUpdate");
        OSSL_CMP_ITAV_free(back);
    }
    OSSL_CMP_ITAV_free(itav);

    printf("# CRL status\n");
    {
        OSSL_CMP_CRLSTATUS *st = OSSL_CMP_CRLSTATUS_create(NULL, ee, 1), *st2;
        STACK_OF(OSSL_CMP_CRLSTATUS) *list = sk_OSSL_CMP_CRLSTATUS_new_null(), *gotlist = NULL;
        DIST_POINT_NAME *dpn = NULL;
        GENERAL_NAMES *issuers = NULL;
        ASN1_TIME *upd = NULL;
        STACK_OF(X509_CRL) *crls = NULL;
        DIST_POINT_NAME *mine = DIST_POINT_NAME_new();

        check(st != NULL, "OSSL_CMP_CRLSTATUS_create");
        check(OSSL_CMP_CRLSTATUS_get0(st, &dpn, &issuers, &upd) == 1, "OSSL_CMP_CRLSTATUS_get0");
        printf("  dpn %s, issuers %d, thisUpdate %s\n", dpn != NULL ? "set" : "none", sk_GENERAL_NAME_num(issuers),
               upd != NULL ? "set" : "none");
        print_name("issuer", GENERAL_NAME_get0_value(sk_GENERAL_NAME_value(issuers, 0), NULL));
        sk_OSSL_CMP_CRLSTATUS_push(list, st);
        itav = OSSL_CMP_ITAV_new0_crlStatusList(list);
        check(OSSL_CMP_ITAV_get0_crlStatusList(itav, &gotlist) == 1 && gotlist == list,
              "OSSL_CMP_ITAV_new0_crlStatusList");
        OSSL_CMP_ITAV_free(itav);
        mine->type = 0;
        mine->name.fullname = sk_GENERAL_NAME_new_null();
        sk_GENERAL_NAME_push(mine->name.fullname, a2i_GENERAL_NAME(NULL, NULL, NULL, GEN_URI, "http://crl.example/", 0));
        st2 = OSSL_CMP_CRLSTATUS_new1(mine, NULL, X509_get0_notBefore(ee));
        check(st2 != NULL && OSSL_CMP_CRLSTATUS_get0(st2, &dpn, &issuers, &upd) == 1 && dpn != NULL && issuers == NULL
                  && upd != NULL,
              "OSSL_CMP_CRLSTATUS_new1");
        OSSL_CMP_CRLSTATUS_free(st2);
        check(OSSL_CMP_CRLSTATUS_new1(NULL, NULL, NULL) == NULL, "neither");
        errors();
        {
            GENERAL_NAMES *gns = sk_GENERAL_NAME_new_null();

            check(OSSL_CMP_CRLSTATUS_new1(mine, gns, NULL) == NULL, "both");
            errors();
            sk_GENERAL_NAME_free(gns);
        }
        check(OSSL_CMP_CRLSTATUS_create(NULL, NULL, 0) == NULL, "nothing to create from");
        errors();
        check(OSSL_CMP_CRLSTATUS_get0(NULL, &dpn, &issuers, NULL) == 0, "get0 of NULL");
        errors();
        DIST_POINT_NAME_free(mine);
        OSSL_CMP_CRLSTATUS_free(NULL);

        itav = OSSL_CMP_ITAV_new_crls(NULL);
        check(OSSL_CMP_ITAV_get0_crls(itav, &crls) == 1 && crls == NULL, "OSSL_CMP_ITAV_new_crls");
        check(OSSL_CMP_ITAV_get0_crlStatusList(itav, &gotlist) == 0, "not a list");
        errors();
        OSSL_CMP_ITAV_free(itav);
    }

    printf("# certificate request templates\n");
    {
        OSSL_CRMF_CERTTEMPLATE *tmpl = OSSL_CRMF_CERTTEMPLATE_new(), *tout = NULL;
        OSSL_CMP_ATAVS *ks = NULL, *kout = NULL;
        X509_ALGOR *alg = X509_ALGOR_new();
        OSSL_CMP_ATAV *a1, *a2, *a3;
        unsigned char *der = NULL;
        const unsigned char *p;
        int n;
        OSSL_CMP_ATAVS *back;

        X509_ALGOR_set0(alg, OBJ_nid2obj(NID_X9_62_id_ecPublicKey), V_ASN1_OBJECT, OBJ_nid2obj(NID_X9_62_prime256v1));
        a1 = OSSL_CMP_ATAV_new_algId(alg);
        check(a1 != NULL && OBJ_obj2nid(OSSL_CMP_ATAV_get0_type(a1)) == NID_id_regCtrl_algId, "OSSL_CMP_ATAV_new_algId");
        check(X509_ALGOR_cmp(OSSL_CMP_ATAV_get0_algId(a1), alg) == 0, "OSSL_CMP_ATAV_get0_algId");
        a2 = OSSL_CMP_ATAV_new_rsaKeyLen(3072);
        check(OSSL_CMP_ATAV_get_rsaKeyLen(a2) == 3072 && OSSL_CMP_ATAV_get_rsaKeyLen(a1) == -1, "OSSL_CMP_ATAV_get_rsaKeyLen");
        check(OSSL_CMP_ATAV_get0_algId(a2) == NULL, "not an algId");
        check(OSSL_CMP_ATAV_new_rsaKeyLen(0) == NULL, "a key length of 0");
        errors();
        check(OSSL_CMP_ATAV_new_algId(NULL) == NULL, "no algorithm");
        errors();
        check(OSSL_CMP_ATAV_push1(&ks, a1) == 1 && OSSL_CMP_ATAV_push1(&ks, a2) == 1, "OSSL_CMP_ATAV_push1");
        check(OSSL_CMP_ATAV_push1(NULL, a1) == 0, "pushing to NULL");
        errors();
        {
            ASN1_TYPE *v = ASN1_TYPE_new();

            ASN1_TYPE_set(v, V_ASN1_NULL, NULL);
            a3 = OSSL_CMP_ATAV_create(OBJ_txt2obj("1.2.3.9", 1), v);
            check(a3 != NULL && OSSL_CMP_ATAV_get0_value(a3) == v, "OSSL_CMP_ATAV_create");
            OSSL_CMP_ATAV_set0(a3, OBJ_txt2obj("1.2.3.10", 1), v);
            print_obj("ATAV type", OSSL_CMP_ATAV_get0_type(a3));
            check(OSSL_CMP_ATAV_get0_type(NULL) == NULL && OSSL_CMP_ATAV_get0_value(NULL) == NULL, "NULL ATAVs");
        }

        n = i2d_OSSL_CMP_ATAVS(ks, &der);
        hex("keySpec", der, n);
        p = der;
        back = d2i_OSSL_CMP_ATAVS(NULL, &p, n);
        check(back != NULL && p == der + n && sk_OSSL_CMP_ATAV_num(back) == 2, "d2i_OSSL_CMP_ATAVS");
        OSSL_CMP_ATAVS_free(back);
        OPENSSL_free(der);
        back = OSSL_CMP_ATAVS_new();
        check(back != NULL && OSSL_CMP_ATAVS_it() != NULL, "OSSL_CMP_ATAVS_new");
        OSSL_CMP_ATAVS_free(back);

        OSSL_CRMF_CERTTEMPLATE_fill(tmpl, ee_key, X509_get_subject_name(ee), NULL, NULL);
        check(OSSL_CMP_ITAV_new0_certReqTemplate(NULL, ks) == NULL, "keySpec without a template");
        errors();
        itav = OSSL_CMP_ITAV_new0_certReqTemplate(tmpl, ks);
        check(OSSL_CMP_ITAV_get1_certReqTemplate(itav, &tout, &kout) == 1 && tout != NULL
                  && sk_OSSL_CMP_ATAV_num(kout) == 2,
              "OSSL_CMP_ITAV_get1_certReqTemplate");
        print_name("template subject", OSSL_CRMF_CERTTEMPLATE_get0_subject(tout));
        OSSL_CRMF_CERTTEMPLATE_free(tout);
        sk_OSSL_CMP_ATAV_pop_free(kout, OSSL_CMP_ATAV_free);
        /* The ITAV owns the template and the keySpec. */
        OSSL_CMP_ITAV_free(itav);
        ks = NULL;

        /* A keySpec with another type. */
        tmpl = OSSL_CRMF_CERTTEMPLATE_new();
        OSSL_CMP_ATAV_push1(&ks, a3);
        itav = OSSL_CMP_ITAV_new0_certReqTemplate(tmpl, ks);
        tout = (OSSL_CRMF_CERTTEMPLATE *)1;
        check(OSSL_CMP_ITAV_get1_certReqTemplate(itav, &tout, &kout) == 0 && tout == NULL && kout == NULL,
              "an invalid keySpec");
        errors();
        OSSL_CMP_ITAV_free(itav);
        itav = OSSL_CMP_ITAV_new0_certReqTemplate(NULL, NULL);
        check(OSSL_CMP_ITAV_get1_certReqTemplate(itav, &tout, NULL) == 1 && tout == NULL, "no requirements");
        check(OSSL_CMP_ITAV_get1_certReqTemplate(itav, NULL, NULL) == 0, "no room");
        errors();
        OSSL_CMP_ITAV_free(itav);

        OSSL_CMP_ATAV_free(a1);
        OSSL_CMP_ATAV_free(a2);
        OSSL_CMP_ATAV_free(a3);
        X509_ALGOR_free(alg);
    }

    printf("# PKIStatusInfo\n");
    {
        OSSL_CMP_PKISI *si = OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_rejection,
                                                     1 << OSSL_CMP_PKIFAILUREINFO_badAlg
                                                         | 1 << OSSL_CMP_PKIFAILUREINFO_duplicateCertReq,
                                                     "go away");
        OSSL_CMP_PKISI *back, *d;
        unsigned char *der = NULL;
        const unsigned char *p;
        int n;
        char small[20];

        print_si("rejection", si);
        n = i2d_OSSL_CMP_PKISI(si, &der);
        hex("PKISI", der, n);
        p = der;
        back = d2i_OSSL_CMP_PKISI(NULL, &p, n);
        check(back != NULL && p == der + n, "d2i_OSSL_CMP_PKISI");
        d = OSSL_CMP_PKISI_dup(back);
        print_si("decoded", d);
        OSSL_CMP_PKISI_free(back);
        OSSL_CMP_PKISI_free(d);
        OPENSSL_free(der);
        printf("  in 20 octets: %s\n", OSSL_CMP_snprint_PKIStatusInfo(si, small, sizeof(small)) == NULL ? "NULL" : small);
        OSSL_CMP_PKISI_free(si);
        si = OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_waiting, 0, NULL);
        print_si("waiting", si);
        OSSL_CMP_PKISI_free(si);
        si = OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_accepted, 1 << OSSL_CMP_PKIFAILUREINFO_MAX, "x");
        print_si("the last failure bit", si);
        OSSL_CMP_PKISI_free(si);
        si = OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_grantedWithMods, -1, NULL);
        print_si("every failure bit", si);
        OSSL_CMP_PKISI_free(si);
        errors();
        si = OSSL_CMP_PKISI_new();
        print_si("empty", si);
        errors();
        check(OSSL_CMP_PKISI_it() != NULL && OSSL_CMP_PKISTATUS_it() != NULL, "the PKISI items");
        OSSL_CMP_PKISI_free(si);
        check(OSSL_CMP_snprint_PKIStatusInfo(NULL, small, sizeof(small)) == NULL, "of NULL");
        errors();
    }

    printf("# PKIHeader\n");
    {
        OSSL_CMP_PKIHEADER *h = OSSL_CMP_PKIHEADER_new(), *back;
        unsigned char *der = NULL;
        const unsigned char *p;
        int n = i2d_OSSL_CMP_PKIHEADER(h, &der);

        printf("  an empty header encodes to %d\n", n);
        errors();
        OPENSSL_free(der);
        der = NULL;
        check(OSSL_CMP_PKIHEADER_it() != NULL && OSSL_CMP_MSG_it() != NULL, "the items");
        OSSL_CMP_PKIHEADER_free(h);
        if (last_req != NULL) {
            n = i2d_OSSL_CMP_PKIHEADER(OSSL_CMP_MSG_get0_header(last_req), &der);
            p = der;
            back = d2i_OSSL_CMP_PKIHEADER(NULL, &p, n);
            check(back != NULL && p == der + n, "d2i_OSSL_CMP_PKIHEADER");
            printf("  transactionID %d\n", ASN1_STRING_length(OSSL_CMP_HDR_get0_transactionID(back)));
            OSSL_CMP_PKIHEADER_free(back);
            OPENSSL_free(der);
        }
    }
    ASN1_UTF8STRING_free(NULL);
}

/* ---------------------------------------------------------------- logging */

static void logging(void)
{
    BIO *bio = BIO_new(BIO_s_mem());
    char *data;
    long n;
    OSSL_CMP_CTX *ctx = OSSL_CMP_CTX_new(NULL, NULL);

    printf("# logging\n");
    check(OSSL_CMP_log_open() == 1, "OSSL_CMP_log_open");
    OSSL_CMP_log_close();
    check(OSSL_CMP_print_to_bio(bio, "func", "file.c", 1, OSSL_CMP_LOG_WARNING, "hello") == 1, "OSSL_CMP_print_to_bio");
    OSSL_CMP_print_to_bio(bio, NULL, NULL, 0, OSSL_CMP_LOG_DEBUG, "debug");
    OSSL_CMP_print_to_bio(bio, NULL, NULL, 0, 42, "odd");
    n = BIO_get_mem_data(bio, &data);
    printf("  %.*s", (int)n, data);
    BIO_free(bio);

    ERR_raise_data(ERR_LIB_CMP, CMP_R_INVALID_ARGS, "some %s", "data");
    ERR_raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT);
    OSSL_CMP_print_errors_cb(log_cb);
    errors();
    ERR_raise_data(ERR_LIB_CMP, CMP_R_ERROR_PARSING_PKISTATUS, "from the context");
    OSSL_CMP_CTX_set_log_cb(ctx, log_cb);
    OSSL_CMP_CTX_print_errors(ctx);
    errors();
    check(OSSL_CMP_CTX_set_log_cb(NULL, log_cb) == 0, "OSSL_CMP_CTX_set_log_cb");
    errors();
    OSSL_CMP_CTX_print_errors(NULL);
    OSSL_CMP_CTX_free(ctx);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    ca = cert(CA_PEM);
    ee = cert(RSA_PEM);
    ca_key = key(CA_KEY_PEM);
    ee_key = key(RSA_KEY_PEM);

    values();
    context();
    logging();
    make_server();
    enroll();
    confirmation();
    polling();
    revocation();
    general();
    messages();
    values();
    printf("  server transactions cleaned %d\n", state.cleans);
    OSSL_CMP_MSG_free(state.saved);
    OSSL_CMP_SRV_CTX_free(srv);
    OSSL_CMP_MSG_free(last_req);
    OSSL_CMP_MSG_free(last_rsp);
    X509_free(ca);
    X509_free(ee);
    EVP_PKEY_free(ca_key);
    EVP_PKEY_free(ee_key);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
