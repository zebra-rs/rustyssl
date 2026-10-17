/*
 * Conformance test for attribute certificates (X509_ACERT_new(3), X509_ACERT_get0_holder_*,
 * X509_ACERT_set1_*, X509_ACERT_add1_attr*, X509_ACERT_sign(3), X509_ACERT_verify, and the
 * OSSL_ISSUER_SERIAL and OSSL_OBJECT_DIGEST_INFO functions), in TAP format: one built (holder,
 * issuer, validity, attributes, extensions), signed deterministically with Ed25519, encoded,
 * decoded, read back, and verified; attributes from configuration; a v1Form issuer; and the
 * DER, BIO, FILE, and PEM forms.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_acert.h>
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

static void name_line(const char *label, const X509_NAME *n)
{
    char buf[256];

    if (n == NULL) {
        printf("  %s: none\n", label);
        return;
    }
    X509_NAME_oneline(n, buf, sizeof(buf));
    printf("  %s: %s\n", label, buf);
}

static void show(const char *label, X509_ACERT *a)
{
    const OSSL_ISSUER_SERIAL *bcid = X509_ACERT_get0_holder_baseCertId(a);
    const OSSL_OBJECT_DIGEST_INFO *odi = X509_ACERT_get0_holder_digest(a);
    const GENERAL_NAMES *ent = X509_ACERT_get0_holder_entityName(a);
    const ASN1_GENERALIZEDTIME *nb = X509_ACERT_get0_notBefore(a), *na = X509_ACERT_get0_notAfter(a);
    int i;

    printf("# %s\n", label);
    printf("  version %ld, serial %ld, signature %d, info sigalg %d\n", X509_ACERT_get_version(a),
           ASN1_INTEGER_get(X509_ACERT_get0_serialNumber(a)), X509_ACERT_get_signature_nid(a),
           OBJ_obj2nid(X509_ACERT_get0_info_sigalg(a)->algorithm));
    name_line("issuer", X509_ACERT_get0_issuerName(a));
    printf("  issuer UID %d\n", X509_ACERT_get0_issuerUID(a) != NULL);
    printf("  holder entities %d\n", ent == NULL ? -1 : sk_GENERAL_NAME_num(ent));
    if (bcid != NULL) {
        name_line("holder issuer", OSSL_ISSUER_SERIAL_get0_issuer(bcid));
        printf("  holder serial %ld, UID %d\n", ASN1_INTEGER_get(OSSL_ISSUER_SERIAL_get0_serial(bcid)),
               OSSL_ISSUER_SERIAL_get0_issuerUID(bcid) != NULL ? ASN1_STRING_length(OSSL_ISSUER_SERIAL_get0_issuerUID(bcid)) : -1);
    } else {
        printf("  no base certificate ID\n");
    }
    if (odi != NULL) {
        int type = -1;
        const X509_ALGOR *alg = NULL;
        const ASN1_BIT_STRING *dig = NULL;

        OSSL_OBJECT_DIGEST_INFO_get0_digest(odi, &type, &alg, &dig);
        printf("  digest: type %d, algorithm %d, %d octets\n", type, OBJ_obj2nid(alg->algorithm), ASN1_STRING_length(dig));
    }
    printf("  validity %.*s - %.*s\n", nb ? ASN1_STRING_length(nb) : 0, nb ? (const char *)ASN1_STRING_get0_data(nb) : "",
           na ? ASN1_STRING_length(na) : 0, na ? (const char *)ASN1_STRING_get0_data(na) : "");
    printf("  attributes %d:", X509_ACERT_get_attr_count(a));
    for (i = 0; i < X509_ACERT_get_attr_count(a); i++)
        printf(" %d", OBJ_obj2nid(X509_ATTRIBUTE_get0_object(X509_ACERT_get_attr(a, i))));
    printf("\n  extensions %d\n", sk_X509_EXTENSION_num(X509_ACERT_get0_extensions(a)));
}

static const char CONF_TEXT[] = "[attrs]\nrole = admin\n1.2.3.4 = some text\n[bad]\nnoSuchAttribute = x\n";

int main(void)
{
    BIO *b = BIO_new_mem_buf(CA_PEM, -1);
    X509 *ca = PEM_read_bio_X509(b, NULL, NULL, NULL);
    X509_ACERT *a = X509_ACERT_new(), *back;
    OSSL_ISSUER_SERIAL *isss = OSSL_ISSUER_SERIAL_new();
    OSSL_OBJECT_DIGEST_INFO *odi = OSSL_OBJECT_DIGEST_INFO_new();
    GENERAL_NAMES *ent = GENERAL_NAMES_new();
    GENERAL_NAME *g = GENERAL_NAME_new();
    ASN1_IA5STRING *uri = ASN1_IA5STRING_new();
    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    ASN1_GENERALIZEDTIME *t = ASN1_GENERALIZEDTIME_new();
    ASN1_UTCTIME *utc = ASN1_UTCTIME_new();
    ASN1_BIT_STRING *uid = ASN1_BIT_STRING_new(), *dig = ASN1_BIT_STRING_new();
    X509_ALGOR *alg = X509_ALGOR_new();
    unsigned char seed[32], *der = NULL;
    const unsigned char *q;
    EVP_PKEY *ed;
    int i, len;
    CONF *conf = NCONF_new(NULL);
    long eline;

    BIO_free(b);
    for (i = 0; i < 32; i++)
        seed[i] = (unsigned char)(i * 5 + 3);
    ed = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, sizeof(seed));

    show("new", a);
    check(X509_ACERT_set_version(a, X509_ACERT_VERSION_2) == 1, "version");
    ASN1_INTEGER_set(serial, 4242);
    check(X509_ACERT_set1_serialNumber(a, serial) == 1, "serial");
    check(X509_ACERT_set1_issuerName(a, X509_get_subject_name(ca)) == 1, "issuer");
    check(X509_ACERT_set1_issuerName(a, X509_get_issuer_name(ca)) == 1, "issuer again");
    check(OSSL_ISSUER_SERIAL_set1_issuer(isss, X509_get_issuer_name(ca)) == 1, "holder issuer");
    check(OSSL_ISSUER_SERIAL_set1_serial(isss, X509_get0_serialNumber(ca)) == 1, "holder serial");
    ASN1_BIT_STRING_set(uid, (unsigned char *)"\x01\x02", 2);
    check(OSSL_ISSUER_SERIAL_set1_issuerUID(isss, uid) == 1, "holder UID");
    X509_ACERT_set0_holder_baseCertId(a, isss);
    ASN1_STRING_set(uri, "https://holder.example/", -1);
    GENERAL_NAME_set0_value(g, GEN_URI, uri);
    sk_GENERAL_NAME_push(ent, g);
    X509_ACERT_set0_holder_entityName(a, ent);
    X509_ALGOR_set0(alg, OBJ_nid2obj(NID_sha256), V_ASN1_NULL, NULL);
    ASN1_BIT_STRING_set(dig, (unsigned char *)"0123456789abcdef0123456789abcdef", 32);
    check(OSSL_OBJECT_DIGEST_INFO_set1_digest(odi, 0, alg, dig) == 1, "digest info");
    X509_ACERT_set0_holder_digest(a, odi);
    ASN1_GENERALIZEDTIME_set_string(t, "20260101000000Z");
    check(X509_ACERT_set1_notBefore(a, t) == 1, "not before");
    ASN1_GENERALIZEDTIME_set_string(t, "20270101000000Z");
    check(X509_ACERT_set1_notAfter(a, t) == 1, "not after");
    ASN1_UTCTIME_set_string(utc, "260101000000Z");
    check(X509_ACERT_set1_notAfter(a, utc) == 0, "a UTCTime is refused");
    check(X509_ACERT_add1_attr_by_txt(a, "role", V_ASN1_UTF8STRING, (const unsigned char *)"auditor", 7) == 1, "attribute by text");
    check(X509_ACERT_add1_attr_by_NID(a, NID_pkcs9_emailAddress, V_ASN1_IA5STRING, "a@example", 9) == 1, "attribute by NID");
    check(X509_ACERT_add1_attr_by_OBJ(a, OBJ_nid2obj(NID_commonName), V_ASN1_UTF8STRING, "CN", 2) == 1, "attribute by OBJ");
    {
        X509_ATTRIBUTE *at = X509_ATTRIBUTE_create(NID_pkcs9_challengePassword, V_ASN1_PRINTABLESTRING,
                                                   ASN1_STRING_type_new(V_ASN1_PRINTABLESTRING));

        check(X509_ACERT_add1_attr(a, at) == 1, "an attribute");
        X509_ATTRIBUTE_free(at);
    }
    printf("  by NID %d, by OBJ %d\n", X509_ACERT_get_attr_by_NID(a, NID_commonName, -1),
           X509_ACERT_get_attr_by_OBJ(a, OBJ_nid2obj(NID_pkcs9_emailAddress), -1));
    X509_ATTRIBUTE_free(X509_ACERT_delete_attr(a, 3));
    {
        ASN1_OCTET_STRING *audit = ASN1_OCTET_STRING_new();

        ASN1_OCTET_STRING_set(audit, (unsigned char *)"\x05\x06", 2);
        check(X509_ACERT_add1_ext_i2d(a, NID_ac_auditIdentity, audit, 1, 0) == 1, "an extension");
        ASN1_OCTET_STRING_free(audit);
        audit = X509_ACERT_get_ext_d2i(a, NID_ac_auditIdentity, &i, NULL);
        printf("  extension back: %d octets, critical %d\n", ASN1_STRING_length(audit), i);
        ASN1_OCTET_STRING_free(audit);
    }
    b = BIO_new_mem_buf(CONF_TEXT, -1);
    NCONF_load_bio(conf, b, &eline);
    BIO_free(b);
    printf("  attributes from configuration: %d\n", X509_ACERT_add_attr_nconf(conf, "attrs", a));
    errors();
    check(X509_ACERT_add_attr_nconf(conf, "bad", a) == 0, "an unknown attribute name");
    errors();
    check(X509_ACERT_add_attr_nconf(conf, "nothing", a) == 0, "a missing section");
    errors();
    show("built", a);
    printf("  signed %d\n", X509_ACERT_sign(a, ed, NULL));
    check(X509_ACERT_verify(a, ed) == 1, "verifies");
    {
        const ASN1_BIT_STRING *sig;
        const X509_ALGOR *sa;

        X509_ACERT_get0_signature(a, &sig, &sa);
        printf("  signature %d octets, algorithm %d\n", ASN1_STRING_length(sig), OBJ_obj2nid(sa->algorithm));
    }
    len = i2d_X509_ACERT(a, &der);
    hex("DER", der, len);
    q = der;
    back = d2i_X509_ACERT(NULL, &q, len);
    check(back != NULL && q == der + len, "decoded");
    show("decoded", back);
    check(X509_ACERT_verify(back, ed) == 1, "verifies decoded");
    X509_ACERT_free(back);
    back = X509_ACERT_dup(a);
    check(back != NULL && X509_ACERT_verify(back, ed) == 1, "copy verifies");
    X509_ACERT_set_version(back, 5);
    check(X509_ACERT_verify(back, ed) == 0, "a changed copy doesn't");
    ERR_clear_error();
    X509_ACERT_free(back);
    OPENSSL_free(der);

    /* PEM, BIO, FILE. */
    {
        BIO *mem = BIO_new(BIO_s_mem());
        FILE *fp = tmpfile();

        check(PEM_write_bio_X509_ACERT(mem, a) == 1, "PEM written");
        back = PEM_read_bio_X509_ACERT(mem, NULL, NULL, NULL);
        check(back != NULL, "PEM read back");
        X509_ACERT_free(back);
        check(i2d_X509_ACERT_bio(mem, a) == 1, "BIO written");
        back = d2i_X509_ACERT_bio(mem, NULL);
        check(back != NULL, "BIO read back");
        X509_ACERT_free(back);
        if (fp != NULL) {
            check(i2d_X509_ACERT_fp(fp, a) == 1 && PEM_write_X509_ACERT(fp, a) == 1, "FILE written");
            rewind(fp);
            back = d2i_X509_ACERT_fp(fp, NULL);
            check(back != NULL, "FILE read back");
            X509_ACERT_free(back);
            back = PEM_read_X509_ACERT(fp, NULL, NULL, NULL);
            check(back != NULL, "FILE PEM read back");
            X509_ACERT_free(back);
            fclose(fp);
        }
        BIO_free(mem);
    }
    {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();

        EVP_DigestSignInit(ctx, NULL, NULL, NULL, ed);
        printf("  sign_ctx %d, verifies %d\n", X509_ACERT_sign_ctx(a, ctx), X509_ACERT_verify(a, ed));
        EVP_MD_CTX_free(ctx);
    }
    {
        X509_ACERT_INFO *inf = X509_ACERT_INFO_new();
        X509_ACERT_ISSUER_V2FORM *v2 = X509_ACERT_ISSUER_V2FORM_new();
        unsigned char *d = NULL;

        printf("  empty info encodes %d\n", ASN1_item_i2d((ASN1_VALUE *)inf, &d, ASN1_ITEM_rptr(X509_ACERT_INFO)));
        OPENSSL_free(d);
        ERR_clear_error();
        X509_ACERT_INFO_free(inf);
        X509_ACERT_ISSUER_V2FORM_free(v2);
        OSSL_ISSUER_SERIAL_free(OSSL_ISSUER_SERIAL_new());
        OSSL_OBJECT_DIGEST_INFO_free(OSSL_OBJECT_DIGEST_INFO_new());
        printf("  items: %d %d\n", ASN1_ITEM_rptr(X509_ACERT) != NULL, ASN1_ITEM_rptr(X509_ACERT_INFO) != NULL);
    }

    NCONF_free(conf);
    X509_ACERT_free(a);
    X509_ALGOR_free(alg);
    ASN1_BIT_STRING_free(uid);
    ASN1_BIT_STRING_free(dig);
    ASN1_INTEGER_free(serial);
    ASN1_GENERALIZEDTIME_free(t);
    ASN1_UTCTIME_free(utc);
    EVP_PKEY_free(ed);
    X509_free(ca);
    printf("1..%d\n", number);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
