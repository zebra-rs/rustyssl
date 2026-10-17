/*
 * Conformance test for certificate revocation lists (X509_CRL_new(3), X509_CRL_get0_by_serial(3),
 * X509_CRL_sign(3), X509_CRL_diff(3), X509_REVOKED_new(3), and their getters, setters,
 * extension functions, and encodings), in TAP format: CRLs from the reference's openssl tool
 * decoded, read, verified, and looked up; CRLs built entry by entry (serial numbers out of
 * order, reasons, a certificate issuer for an indirect CRL, removal from the CRL), signed
 * deterministically with Ed25519, encoded, decoded, and looked up; a delta CRL; methods of the
 * application's own; and the PEM, BIO, and FILE forms.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
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

static const char CA_KEY_PEM[] =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEIEXyhsOYGXj+W51si2OB5nllDmT6VWUeoPtTQebkP+XboAoGCCqGSM49\n"
    "AwEHoUQDQgAEFaNYhGKHpYg9kf3LIz3Y4was/QgDXLgP2vxQWCaJWFDbKT1vITEz\n"
    "WheMcNH123qrWUQD2Omo1nduclzraW6PSQ==\n"
    "-----END EC PRIVATE KEY-----\n";

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

static const char CRL_PEM[] =
    "-----BEGIN X509 CRL-----\n"
    "MIIBIzCBygIBATAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApQdXJwb3NlIENBFw0y\n"
    "NjEwMTcxNTE1MTFaFw0yNjExMTYxNTE1MTFaMCIwIAIBBxcNMjYxMDE3MTUxNTEx\n"
    "WjAMMAoGA1UdFQQDCgEBoGAwXjAfBgNVHSMEGDAWgBQ0lsw8dOxP91kYhXzdnHH3\n"
    "mpLhNTAvBgNVHRwBAf8EJTAjoB2gG4YZaHR0cDovL2NybC5leGFtcGxlL2NhLmNy\n"
    "bIMCA0gwCgYDVR0UBAMCAREwCgYIKoZIzj0EAwIDSAAwRQIhAI76kr7OV6FMMqpS\n"
    "XIEpew38/kE+CMxyGYwejjVbjhyIAiBH9j8oiP2i3450dKVi0Mivw73uIdPqOT4M\n"
    "1teqCGXpXA==\n"
    "-----END X509 CRL-----\n";

static const char EMPTY_CRL_PEM[] =
    "-----BEGIN X509 CRL-----\n"
    "MIH+MIGmAgEBMAoGCCqGSM49BAMCMBUxEzARBgNVBAMMClB1cnBvc2UgQ0EXDTI2\n"
    "MTAxNzE1MTUxMVoXDTI2MTExNjE1MTUxMVqgYDBeMB8GA1UdIwQYMBaAFDSWzDx0\n"
    "7E/3WRiFfN2ccfeakuE1MC8GA1UdHAEB/wQlMCOgHaAbhhlodHRwOi8vY3JsLmV4\n"
    "YW1wbGUvY2EuY3JsgwIDSDAKBgNVHRQEAwIBEDAKBggqhkjOPQQDAgNHADBEAiA4\n"
    "6lXGdquAsE3ImzQrs5zgAcqjcMl76gREvVZJBZrFxwIgHdUgSR2hJL8mKUlTBA75\n"
    "lcKyjjBI/UsLKszeaJxU73A=\n"
    "-----END X509 CRL-----\n";


static X509 *read_cert(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);

    BIO_free(b);
    return x;
}

static X509_CRL *read_crl(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509_CRL *x = PEM_read_bio_X509_CRL(b, NULL, NULL, NULL);

    BIO_free(b);
    return x;
}

static void print_time(const char *label, const ASN1_TIME *t)
{
    if (t == NULL)
        printf("  %s: none\n", label);
    else
        printf("  %s: %.*s\n", label, ASN1_STRING_length(t), (const char *)ASN1_STRING_get0_data(t));
}

static void show_crl(const char *label, X509_CRL *crl)
{
    STACK_OF(X509_REVOKED) *revs = X509_CRL_get_REVOKED(crl);
    int i;
    char name[256];

    printf("# %s\n", label);
    printf("  version %ld, signature %d, extensions %d, entries %d\n", X509_CRL_get_version(crl),
           X509_CRL_get_signature_nid(crl), X509_CRL_get_ext_count(crl), sk_X509_REVOKED_num(revs));
    X509_NAME_oneline(X509_CRL_get_issuer(crl), name, sizeof(name));
    printf("  issuer %s\n", name);
    print_time("last update", X509_CRL_get0_lastUpdate(crl));
    print_time("next update", X509_CRL_get0_nextUpdate(crl));
    for (i = 0; i < X509_CRL_get_ext_count(crl); i++) {
        X509_EXTENSION *e = X509_CRL_get_ext(crl, i);

        printf("  extension %d: nid %d, critical %d\n", i, OBJ_obj2nid(X509_EXTENSION_get_object(e)),
               X509_EXTENSION_get_critical(e));
    }
    for (i = 0; i < sk_X509_REVOKED_num(revs); i++) {
        X509_REVOKED *r = sk_X509_REVOKED_value(revs, i);
        int crit = -2;
        ASN1_ENUMERATED *reason = X509_REVOKED_get_ext_d2i(r, NID_crl_reason, &crit, NULL);

        printf("  entry %d: serial %ld, extensions %d, reason %ld (critical %d)\n", i,
               ASN1_INTEGER_get(X509_REVOKED_get0_serialNumber(r)), X509_REVOKED_get_ext_count(r),
               reason == NULL ? -1 : ASN1_ENUMERATED_get(reason), crit);
        print_time("    revoked", X509_REVOKED_get0_revocationDate(r));
        ASN1_ENUMERATED_free(reason);
    }
}

static void lookup(X509_CRL *crl, long serial)
{
    ASN1_INTEGER *s = ASN1_INTEGER_new();
    X509_REVOKED *r = NULL;
    int ret;

    ASN1_INTEGER_set(s, serial);
    ret = X509_CRL_get0_by_serial(crl, &r, s);
    printf("  lookup %ld: %d%s\n", serial, ret, r != NULL ? " (found)" : "");
    ASN1_INTEGER_free(s);
}

static void encoded(const char *label, X509_CRL *crl)
{
    unsigned char *der = NULL;
    int len = i2d_X509_CRL(crl, &der);

    hex(label, der, len);
    OPENSSL_free(der);
}

static X509_CRL *reencoded(X509_CRL *crl)
{
    unsigned char *der = NULL;
    const unsigned char *q;
    int len = i2d_X509_CRL(crl, &der);
    X509_CRL *again;

    q = der;
    again = d2i_X509_CRL(NULL, &q, len);
    check(again != NULL && q == der + len, "decoded again");
    OPENSSL_free(der);
    return again;
}

static X509_REVOKED *entry(long serial, int reason, const char *issuer)
{
    X509_REVOKED *r = X509_REVOKED_new();
    ASN1_INTEGER *s = ASN1_INTEGER_new();
    ASN1_TIME *t = ASN1_TIME_new();

    ASN1_INTEGER_set(s, serial);
    X509_REVOKED_set_serialNumber(r, s);
    ASN1_TIME_set_string(t, "20260102030405Z");
    X509_REVOKED_set_revocationDate(r, t);
    if (reason >= 0) {
        ASN1_ENUMERATED *e = ASN1_ENUMERATED_new();

        ASN1_ENUMERATED_set(e, reason);
        X509_REVOKED_add1_ext_i2d(r, NID_crl_reason, e, 0, 0);
        ASN1_ENUMERATED_free(e);
    }
    if (issuer != NULL) {
        GENERAL_NAMES *gens = GENERAL_NAMES_new();
        GENERAL_NAME *g = GENERAL_NAME_new();
        X509_NAME *n = X509_NAME_new();

        X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)issuer, -1, -1, 0);
        GENERAL_NAME_set0_value(g, GEN_DIRNAME, n);
        sk_GENERAL_NAME_push(gens, g);
        X509_REVOKED_add1_ext_i2d(r, NID_certificate_issuer, gens, 1, 0);
        GENERAL_NAMES_free(gens);
    }
    ASN1_INTEGER_free(s);
    ASN1_TIME_free(t);
    return r;
}

static X509_CRL *build(EVP_PKEY *key, long number, int with_entries)
{
    X509_CRL *crl = X509_CRL_new();
    X509_NAME *n = X509_NAME_new();
    ASN1_TIME *t = ASN1_TIME_new();
    ASN1_INTEGER *num = ASN1_INTEGER_new();

    X509_CRL_set_version(crl, X509_CRL_VERSION_2);
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)"CRL Issuer", -1, -1, 0);
    X509_CRL_set_issuer_name(crl, n);
    ASN1_TIME_set_string(t, "20260101000000Z");
    X509_CRL_set1_lastUpdate(crl, t);
    ASN1_TIME_set_string(t, "20260201000000Z");
    X509_CRL_set1_nextUpdate(crl, t);
    ASN1_INTEGER_set(num, number);
    X509_CRL_add1_ext_i2d(crl, NID_crl_number, num, 0, 0);
    if (with_entries) {
        X509_CRL_add0_revoked(crl, entry(30, CRL_REASON_KEY_COMPROMISE, NULL));
        X509_CRL_add0_revoked(crl, entry(10, -1, NULL));
        X509_CRL_add0_revoked(crl, entry(20, CRL_REASON_REMOVE_FROM_CRL, NULL));
        X509_CRL_add0_revoked(crl, entry(40, CRL_REASON_CA_COMPROMISE, "Other CA"));
        X509_CRL_add0_revoked(crl, entry(50, -1, NULL));
    }
    X509_CRL_sign(crl, key, NULL);
    X509_NAME_free(n);
    ASN1_TIME_free(t);
    ASN1_INTEGER_free(num);
    return crl;
}

static int my_init_calls, my_free_calls;

static int my_init(X509_CRL *crl)
{
    (void)crl;
    my_init_calls++;
    return 1;
}

static int my_free(X509_CRL *crl)
{
    (void)crl;
    my_free_calls++;
    return 1;
}

static int my_lookup(X509_CRL *crl, X509_REVOKED **ret, const ASN1_INTEGER *ser, const X509_NAME *issuer)
{
    (void)crl;
    (void)issuer;
    if (ret != NULL)
        *ret = NULL;
    return ASN1_INTEGER_get(ser) == 7 ? 1 : 0;
}

static int my_verify(X509_CRL *crl, EVP_PKEY *pk)
{
    (void)crl;
    (void)pk;
    return 7;
}

/* Each item: a new value encoded through it. */
static void items(void)
{
    const struct {
        const char *name;
        const ASN1_ITEM *it;
    } list[] = {
        {"X509_CRL", ASN1_ITEM_rptr(X509_CRL)},
        {"X509_CRL_INFO", ASN1_ITEM_rptr(X509_CRL_INFO)},
        {"X509_REVOKED", ASN1_ITEM_rptr(X509_REVOKED)},
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

/* The rest of the CRL API: the deprecated getters, the signature, OBJ lookups, a library
 * context, signing through a context, and the TBSCertList's decoder. */
static void more_crl(X509_CRL *crl, EVP_PKEY *ed)
{
    const ASN1_BIT_STRING *sig = NULL;
    const X509_ALGOR *alg = NULL;
    X509_CRL *c = X509_CRL_new_ex(NULL, NULL);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char *der = NULL;
    const unsigned char *q;
    int len;
    X509_CRL_INFO *inf;

    printf("# more\n");
    X509_CRL_get0_signature(crl, &sig, &alg);
    printf("  signature %d octets, algorithm %d\n", ASN1_STRING_length(sig), OBJ_obj2nid(alg->algorithm));
    printf("  last %d, next %d, by OBJ %d\n", X509_CRL_get_lastUpdate(crl) == X509_CRL_get0_lastUpdate(crl),
           X509_CRL_get_nextUpdate(crl) == X509_CRL_get0_nextUpdate(crl),
           X509_CRL_get_ext_by_OBJ(crl, OBJ_nid2obj(NID_crl_number), -1));
    X509_CRL_set_issuer_name(c, X509_CRL_get_issuer(crl));
    X509_CRL_set1_lastUpdate(c, X509_CRL_get0_lastUpdate(crl));
    EVP_DigestSignInit(ctx, NULL, NULL, NULL, ed);
    printf("  sign_ctx %d, verify %d\n", X509_CRL_sign_ctx(c, ctx), X509_CRL_verify(c, ed));
    len = i2d_re_X509_CRL_tbs(c, &der);
    q = der;
    inf = d2i_X509_CRL_INFO(NULL, &q, len);
    printf("  TBSCertList %d, decoded %d\n", len, inf != NULL);
    X509_CRL_INFO_free(inf);
    OPENSSL_free(der);
    EVP_MD_CTX_free(ctx);
    X509_CRL_free(c);
}

int main(void)
{
    X509 *ca = read_cert(CA_PEM), *server = read_cert(SERVER_PEM);
    BIO *b = BIO_new_mem_buf(CA_KEY_PEM, -1);
    EVP_PKEY *cakey = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
    unsigned char seed[32];
    EVP_PKEY *ed;
    X509_CRL *crl = read_crl(CRL_PEM), *empty = read_crl(EMPTY_CRL_PEM), *built, *again, *newer, *delta;
    X509_REVOKED *r = NULL;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    int i;

    BIO_free(b);
    for (i = 0; i < 32; i++)
        seed[i] = (unsigned char)(i * 7 + 1);
    ed = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, sizeof(seed));

    /* The reference's CRLs. */
    show_crl("the tool's CRL", crl);
    check(X509_CRL_verify(crl, X509_get0_pubkey(ca)) == 1, "verifies with the CA's key");
    check(X509_CRL_verify(crl, ed) <= 0, "not with another");
    ERR_clear_error();
    printf("  by cert: %d", X509_CRL_get0_by_cert(crl, &r, server));
    printf(", entry serial %ld\n", r == NULL ? -1 : ASN1_INTEGER_get(X509_REVOKED_get0_serialNumber(r)));
    lookup(crl, 7);
    lookup(crl, 8);
    {
        ISSUING_DIST_POINT *idp = X509_CRL_get_ext_d2i(crl, NID_issuing_distribution_point, NULL, NULL);
        ASN1_INTEGER *num = X509_CRL_get_ext_d2i(crl, NID_crl_number, NULL, NULL);

        printf("  IDP %d, number %ld, akid index %d, critical index %d\n", idp != NULL, ASN1_INTEGER_get(num),
               X509_CRL_get_ext_by_NID(crl, NID_authority_key_identifier, -1), X509_CRL_get_ext_by_critical(crl, 1, -1));
        ISSUING_DIST_POINT_free(idp);
        ASN1_INTEGER_free(num);
    }
    X509_CRL_digest(crl, EVP_sha256(), md, &mdlen);
    hex("SHA-256", md, mdlen);
    X509_CRL_digest(crl, EVP_sha1(), md, &mdlen);
    hex("SHA-1", md, mdlen);
    check(X509_CRL_digest(crl, NULL, md, &mdlen) == 0, "no digest");
    ERR_clear_error();
    show_crl("the tool's empty CRL", empty);
    printf("  match self %d, other %d, cmp %d\n", X509_CRL_match(crl, crl), X509_CRL_match(crl, empty) != 0,
           X509_CRL_cmp(crl, empty));
    printf("  suite B %d, without the flag %d\n", X509_CRL_check_suiteb(crl, X509_get0_pubkey(ca), X509_V_FLAG_SUITEB_128_LOS),
           X509_CRL_check_suiteb(crl, X509_get0_pubkey(ca), 0));
    lookup(empty, 7);

    /* Built ones. */
    built = build(ed, 5, 1);
    show_crl("built", built);
    encoded("built", built);
    check(X509_CRL_verify(built, ed) == 1, "verifies");
    printf("  lookups before decoding:\n");
    lookup(built, 10);
    lookup(built, 20);
    lookup(built, 40);
    lookup(built, 99);
    again = reencoded(built);
    show_crl("decoded", again);
    printf("  lookups after decoding (with the cache):\n");
    lookup(again, 10);
    lookup(again, 20);
    lookup(again, 30);
    lookup(again, 40);
    lookup(again, 50);
    lookup(again, 99);
    show_crl("sorted by the lookup", again);
    {
        unsigned char *tbs = NULL;
        int len = i2d_re_X509_CRL_tbs(again, &tbs);

        hex("TBS afresh", tbs, len);
        OPENSSL_free(tbs);
    }
    check(X509_CRL_sort(built) == 1, "sorted");
    show_crl("sorted", built);
    printf("  match %d, cmp %d\n", X509_CRL_match(built, again), X509_CRL_cmp(built, again));

    /* A delta. */
    newer = build(ed, 6, 1);
    X509_CRL_add0_revoked(newer, entry(60, CRL_REASON_SUPERSEDED, NULL));
    X509_CRL_sign(newer, ed, NULL);
    {
        X509_CRL *base2 = reencoded(build(ed, 5, 0)), *newer2 = reencoded(newer);

        delta = X509_CRL_diff(base2, newer2, ed, NULL, 0);
        check(delta != NULL, "a delta");
        if (delta != NULL) {
            show_crl("delta", delta);
            encoded("delta", delta);
        }
        X509_CRL_free(delta);
        check(X509_CRL_diff(newer2, base2, NULL, NULL, 0) == NULL, "not newer");
        errors();
        check(X509_CRL_diff(base2, built, NULL, NULL, 0) == NULL, "not decoded: no numbers");
        errors();
        check(X509_CRL_diff(base2, crl, NULL, NULL, 0) == NULL, "another issuer");
        errors();
        X509_CRL_free(base2);
        X509_CRL_free(newer2);
    }

    /* Entries and extensions. */
    {
        X509_REVOKED *e = entry(77, CRL_REASON_AFFILIATION_CHANGED, "Indirect"), *copy;
        unsigned char *der = NULL;
        int len = i2d_X509_REVOKED(e, &der);
        const unsigned char *q = der;

        hex("entry", der, len);
        copy = d2i_X509_REVOKED(NULL, &q, len);
        check(copy != NULL, "decoded the entry");
        X509_REVOKED_free(copy);
        copy = X509_REVOKED_dup(e);
        check(copy != NULL && X509_REVOKED_get_ext_count(copy) == 2, "copied it");
        printf("  by NID %d, by critical %d, by OBJ %d\n", X509_REVOKED_get_ext_by_NID(e, NID_certificate_issuer, -1),
               X509_REVOKED_get_ext_by_critical(e, 1, -1),
               X509_REVOKED_get_ext_by_OBJ(e, OBJ_nid2obj(NID_crl_reason), -1));
        X509_EXTENSION_free(X509_REVOKED_delete_ext(copy, 0));
        X509_EXTENSION_free(X509_REVOKED_delete_ext(copy, 0));
        printf("  after deleting both: %d, list %s\n", X509_REVOKED_get_ext_count(copy),
               X509_REVOKED_get0_extensions(copy) == NULL ? "gone" : "kept");
        check(X509_REVOKED_add_ext(copy, X509_REVOKED_get_ext(e, 0), -1) == 1, "added one back");
        check(X509_REVOKED_set_serialNumber(copy, (ASN1_INTEGER *)X509_REVOKED_get0_serialNumber(copy)) == 1,
              "the same serial number");
        check(X509_REVOKED_set_revocationDate(copy, NULL) == 0, "no date");
        X509_REVOKED_free(copy);
        X509_REVOKED_free(e);
        OPENSSL_free(der);
    }
    {
        X509_CRL *c = X509_CRL_new();
        X509_EXTENSION *ext;

        check(X509_CRL_add1_ext_i2d(c, NID_crl_number, X509_CRL_get_ext_d2i(again, NID_crl_number, NULL, NULL), 0, 0) == 1,
              "added a number");
        ext = X509_CRL_get_ext(again, 0);
        check(X509_CRL_add_ext(c, ext, 0) == 1, "added an extension first");
        printf("  extensions %d, first nid %d\n", X509_CRL_get_ext_count(c),
               OBJ_obj2nid(X509_EXTENSION_get_object(X509_CRL_get_ext(c, 0))));
        X509_EXTENSION_free(X509_CRL_delete_ext(c, 0));
        X509_EXTENSION_free(X509_CRL_delete_ext(c, 0));
        printf("  after deleting: %d, list %s, version %ld\n", X509_CRL_get_ext_count(c),
               X509_CRL_get0_extensions(c) == NULL ? "gone" : "kept", X509_CRL_get_version(c));
        check(X509_CRL_set1_lastUpdate(c, NULL) == 0, "a NULL last update");
        check(X509_CRL_set1_nextUpdate(c, NULL) == 1, "no next update");
        check(X509_CRL_up_ref(c) == 1, "up_ref");
        X509_CRL_free(c);
        X509_CRL_free(c);
    }
    {
        X509_CRL_INFO *inf = X509_CRL_INFO_new();
        unsigned char *der = NULL;
        int len = i2d_X509_CRL_INFO(inf, &der);

        printf("  empty TBSCertList: %d\n", len);
        X509_CRL_INFO_free(inf);
        OPENSSL_free(der);
    }

    /* Methods. */
    {
        X509_CRL_METHOD *m = X509_CRL_METHOD_new(my_init, my_free, my_lookup, my_verify);
        X509_CRL *mine;

        X509_CRL_set_default_method(m);
        mine = reencoded(built);
        printf("  init %d, verify %d, lookup 7 -> %d, 10 -> %d\n", my_init_calls, X509_CRL_verify(mine, ed),
               X509_CRL_get0_by_serial(mine, NULL, X509_REVOKED_get0_serialNumber(sk_X509_REVOKED_value(X509_CRL_get_REVOKED(crl), 0))),
               X509_CRL_get0_by_cert(mine, NULL, ca));
        X509_CRL_set_meth_data(mine, (void *)"data");
        printf("  data %s\n", (const char *)X509_CRL_get_meth_data(mine));
        X509_CRL_free(mine);
        printf("  free %d\n", my_free_calls);
        X509_CRL_set_default_method(NULL);
        mine = reencoded(built);
        printf("  back to the default: verify %d, init %d\n", X509_CRL_verify(mine, ed), my_init_calls);
        X509_CRL_free(mine);
        X509_CRL_METHOD_free(m);
        X509_CRL_METHOD_free(NULL);
    }

    /* PEM, BIO, FILE. */
    {
        BIO *mem = BIO_new(BIO_s_mem());
        X509_CRL *back;
        FILE *fp = tmpfile();

        check(PEM_write_bio_X509_CRL(mem, built) == 1, "PEM written");
        back = PEM_read_bio_X509_CRL(mem, NULL, NULL, NULL);
        check(back != NULL && X509_CRL_match(back, again) == 0, "PEM read back");
        X509_CRL_free(back);
        check(i2d_X509_CRL_bio(mem, built) == 1, "BIO written");
        back = d2i_X509_CRL_bio(mem, NULL);
        check(back != NULL && X509_CRL_cmp(back, built) == 0, "BIO read back");
        X509_CRL_free(back);
        if (fp != NULL) {
            check(i2d_X509_CRL_fp(fp, built) == 1 && PEM_write_X509_CRL(fp, built) == 1, "FILE written");
            rewind(fp);
            back = d2i_X509_CRL_fp(fp, NULL);
            check(back != NULL, "FILE read back");
            X509_CRL_free(back);
            back = PEM_read_X509_CRL(fp, NULL, NULL, NULL);
            check(back != NULL, "FILE PEM read back");
            X509_CRL_free(back);
            fclose(fp);
        }
        BIO_free(mem);
    }
    {
        X509_CRL *d = X509_CRL_dup(again);

        printf("  copy: match %d, entries %d\n", X509_CRL_match(d, again), sk_X509_REVOKED_num(X509_CRL_get_REVOKED(d)));
        X509_CRL_free(d);
    }

    more_crl(crl, ed);
    items();
    X509_CRL_free(crl);
    X509_CRL_free(empty);
    X509_CRL_free(built);
    X509_CRL_free(again);
    X509_CRL_free(newer);
    EVP_PKEY_free(cakey);
    EVP_PKEY_free(ed);
    X509_free(ca);
    X509_free(server);
    printf("1..%d\n", number);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
