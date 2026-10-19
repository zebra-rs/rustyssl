/*
 * Conformance test for OpenSSL 3.6's KEM recipients in CMS (RFC 9629; CMS_add1_recipient(3),
 * CMS_RecipientInfo_kemri_cert_cmp(3) and the other CMS_RecipientInfo_kemri_* functions), in
 * TAP format: an ML-KEM-768 recipient certificate made at run time, enveloped data encrypted
 * to it (with and without user keying material, AES-128 and AES-256 content), encoded,
 * decoded, and decrypted with its key; the KEM recipient's accessors; and the failures.
 */
#include <stdio.h>
#include <string.h>

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

    printf("  errors:");
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
}

static X509 *make_cert(const char *cn, long serial, EVP_PKEY *k, X509 *issuer, EVP_PKEY *ik)
{
    X509 *x = X509_new();
    X509_NAME *n = X509_NAME_new();

    X509_set_version(x, X509_VERSION_3);
    ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0);
    X509_set_subject_name(x, n);
    X509_set_issuer_name(x, issuer != NULL ? X509_get_subject_name(issuer) : n);
    X509_gmtime_adj(X509_getm_notBefore(x), -3600);
    X509_gmtime_adj(X509_getm_notAfter(x), 86400);
    X509_set_pubkey(x, k);
    {
        X509V3_CTX v3;
        X509_EXTENSION *e;

        X509V3_set_ctx(&v3, issuer != NULL ? issuer : x, x, NULL, NULL, 0);
        e = X509V3_EXT_conf_nid(NULL, &v3, NID_subject_key_identifier, "hash");
        X509_add_ext(x, e, -1);
        X509_EXTENSION_free(e);
    }
    X509_sign(x, ik != NULL ? ik : k, EVP_sha256());
    X509_NAME_free(n);
    return x;
}

static const char MSG[] = "a message for a KEM recipient";

static void hexalg(const char *label, const X509_ALGOR *alg)
{
    const ASN1_OBJECT *o = NULL;
    int ptype = 0;
    char name[80];

    X509_ALGOR_get0(&o, &ptype, NULL, alg);
    OBJ_obj2txt(name, sizeof(name), o, 0);
    printf("  %s: %s, parameter type %d\n", label, o != NULL ? name : "(none)", ptype);
}

static void roundtrip(X509 *rc, EVP_PKEY *rk, X509 *other, const EVP_CIPHER *cipher,
                      const char *ukm, unsigned int flags, const char *what)
{
    BIO *in = BIO_new_mem_buf(MSG, sizeof(MSG) - 1), *out = BIO_new(BIO_s_mem());
    CMS_ContentInfo *cms = CMS_EnvelopedData_create(cipher), *back = NULL;
    CMS_RecipientInfo *ri;
    unsigned char *der = NULL, *p;
    int len, ok;
    char *data = NULL;
    long n;

    printf("# %s\n", what);
    CMS_set_detached(cms, 0);
    ri = CMS_add1_recipient(cms, rc, NULL, NULL, flags);
    check(ri != NULL && CMS_RecipientInfo_type(ri) == CMS_RECIPINFO_KEM, "a KEM recipient");
    errors();
    check(CMS_RecipientInfo_kemri_get0_ctx(ri) != NULL, "its wrap context");
    hexalg("its KDF before", CMS_RecipientInfo_kemri_get0_kdf_alg(ri));
    check(CMS_RecipientInfo_kemri_cert_cmp(ri, rc) == 0, "it names the certificate");
    check(CMS_RecipientInfo_kemri_cert_cmp(ri, other) != 0, "not another");
    if (ukm != NULL)
        check(CMS_RecipientInfo_kemri_set_ukm(ri, (const unsigned char *)ukm, (int)strlen(ukm)) == 1,
              "user keying material");
    check(CMS_final(cms, in, NULL, CMS_BINARY) == 1, "encrypted");
    errors();
    hexalg("its KDF after", CMS_RecipientInfo_kemri_get0_kdf_alg(ri));
    len = i2d_CMS_ContentInfo(cms, &der);
    check(len > 0, "encoded");
    p = der;
    back = d2i_CMS_ContentInfo(NULL, (const unsigned char **)&p, len);
    check(back != NULL && p == der + len, "decoded");
    {
        STACK_OF(CMS_RecipientInfo) *ris = CMS_get0_RecipientInfos(back);
        CMS_RecipientInfo *bri = sk_CMS_RecipientInfo_value(ris, 0);

        check(sk_CMS_RecipientInfo_num(ris) == 1 && CMS_RecipientInfo_type(bri) == CMS_RECIPINFO_KEM,
              "one KEM recipient decoded");
        hexalg("decoded KDF", CMS_RecipientInfo_kemri_get0_kdf_alg(bri));
        check(CMS_RecipientInfo_kemri_cert_cmp(bri, rc) == 0, "naming the certificate");
        check(CMS_RecipientInfo_decrypt(back, bri) == 0, "no key, no decryption");
        errors();
    }
    ok = CMS_decrypt(back, rk, rc, NULL, out, 0);
    n = BIO_get_mem_data(out, &data);
    check(ok == 1 && n == (long)sizeof(MSG) - 1 && memcmp(data, MSG, (size_t)n) == 0,
          "decrypted with the key and certificate");
    errors();
    (void)BIO_reset(out);
    ok = CMS_decrypt(back, rk, NULL, NULL, out, 0);
    n = BIO_get_mem_data(out, &data);
    check(ok == 1 && n == (long)sizeof(MSG) - 1, "and with the key alone");
    errors();
    OPENSSL_free(der);
    CMS_ContentInfo_free(back);
    CMS_ContentInfo_free(cms);
    BIO_free(in);
    BIO_free(out);
}

int main(void)
{
    EVP_PKEY *cak = EVP_EC_gen("P-256");
    EVP_PKEY *mlkem = EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-768");
    EVP_PKEY *other_key = EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-768");
    X509 *ca = make_cert("KEM Test CA", 1, cak, NULL, NULL);
    X509 *rc = make_cert("kem recipient", 2, mlkem, ca, cak);
    X509 *other = make_cert("another recipient", 3, other_key, ca, cak);
    CMS_RecipientInfo *ri;
    CMS_ContentInfo *cms;

    check(mlkem != NULL && rc != NULL, "an ML-KEM-768 certificate");
    roundtrip(rc, mlkem, other, EVP_aes_128_cbc(), NULL, 0, "AES-128-CBC");
    roundtrip(rc, mlkem, other, EVP_aes_256_cbc(), "ukm", 0, "AES-256-CBC with keying material");
    roundtrip(rc, mlkem, other, EVP_aes_256_cbc(), NULL, CMS_USE_KEYID, "the key identifier");

    printf("# the wrong key\n");
    {
        BIO *in = BIO_new_mem_buf(MSG, sizeof(MSG) - 1), *out = BIO_new(BIO_s_mem());

        cms = CMS_encrypt(NULL, in, EVP_aes_128_cbc(), CMS_BINARY | CMS_PARTIAL);
        CMS_add1_recipient(cms, rc, NULL, NULL, 0);
        check(CMS_final(cms, in, NULL, CMS_BINARY) == 1, "encrypted");
        check(CMS_decrypt(cms, other_key, other, NULL, out, 0) == 0, "another certificate fails");
        errors();
        check(CMS_decrypt(cms, other_key, NULL, NULL, out, 0) <= 0, "another key fails");
        errors();
        CMS_ContentInfo_free(cms);
        BIO_free(in);
        BIO_free(out);
    }

    printf("# other recipient types\n");
    cms = CMS_EnvelopedData_create(EVP_aes_128_cbc());
    ri = CMS_add0_recipient_key(cms, NID_undef, (unsigned char *)OPENSSL_memdup("0123456789abcdef", 16),
                                16, (unsigned char *)OPENSSL_memdup("id", 2), 2, NULL, NULL, NULL);
    check(CMS_RecipientInfo_kemri_cert_cmp(ri, rc) == -2, "cert_cmp: -2");
    check(CMS_RecipientInfo_kemri_set0_pkey(ri, mlkem) == 0, "set0_pkey: 0");
    check(CMS_RecipientInfo_kemri_get0_ctx(ri) == NULL, "get0_ctx: NULL");
    check(CMS_RecipientInfo_kemri_get0_kdf_alg(ri) == NULL, "get0_kdf_alg: NULL");
    check(CMS_RecipientInfo_kemri_set_ukm(ri, (const unsigned char *)"x", 1) == 0, "set_ukm: 0");
    errors();
    ri = CMS_add1_recipient(cms, rc, NULL, NULL, 0);
    check(CMS_RecipientInfo_kemri_set_ukm(ri, NULL, 1) == 0, "keying material NULL with a length");
    check(CMS_RecipientInfo_kemri_set_ukm(ri, NULL, 0) == 1, "and empty");
    check(CMS_RecipientInfo_kemri_set0_pkey(ri, NULL) == 1, "no key");
    errors();
    CMS_ContentInfo_free(cms);

    X509_free(ca);
    X509_free(rc);
    X509_free(other);
    EVP_PKEY_free(cak);
    EVP_PKEY_free(mlkem);
    EVP_PKEY_free(other_key);
    printf("1..%d\n", number);
    return failures != 0;
}
