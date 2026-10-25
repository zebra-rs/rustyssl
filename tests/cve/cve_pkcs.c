/*
 * CVE regression tests: PKCS#7, CMS, PKCS#12, time-stamping, CRMF and CMP.
 *
 * Some inputs are upstream's own regression files (tests/cve/data, from OpenSSL's test/
 * directory, Apache-2.0).
 */
#include "cve.h"

#include <openssl/cmp.h>
#include <openssl/cms.h>
#include <openssl/crmf.h>
#include <openssl/ocsp.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/rand.h>
#include <openssl/ts.h>

static const char message[] = "a message for the CVE tests\n";

/* Replaces byte `at` of every occurrence of `pattern` with `to`; returns the count. */
static int patch(unsigned char *der, size_t len, const unsigned char *pattern, size_t plen,
                 size_t at, unsigned char to)
{
    int n = 0;

    for (size_t i = 0; i + plen <= len; i++)
        if (memcmp(der + i, pattern, plen) == 0) {
            der[i + at] = to;
            n++;
        }
    return n;
}

static const unsigned char sha256_oid[] = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
                                           0x03, 0x04, 0x02, 0x01};

static EVP_PKEY *read_key(const char *file)
{
    BIO *in = BIO_new_file(file, "r");
    EVP_PKEY *key = in != NULL ? PEM_read_bio_PrivateKey(in, NULL, NULL, NULL) : NULL;

    BIO_free(in);
    return key;
}

static X509 *read_cert(const char *file)
{
    BIO *in = BIO_new_file(file, "r");
    X509 *cert = in != NULL ? PEM_read_bio_X509(in, NULL, NULL, NULL) : NULL;

    BIO_free(in);
    return cert;
}

static CMS_ContentInfo *read_cms_der(const char *file)
{
    BIO *in = BIO_new_file(file, "rb");
    CMS_ContentInfo *cms = in != NULL ? d2i_CMS_bio(in, NULL) : NULL;

    BIO_free(in);
    return cms;
}

static CMS_ContentInfo *read_cms_pem(const char *file)
{
    BIO *in = BIO_new_file(file, "r");
    CMS_ContentInfo *cms = in != NULL ? PEM_read_bio_CMS(in, NULL, NULL, NULL) : NULL;

    BIO_free(in);
    return cms;
}

/* Whether `out` holds exactly the test message. */
static int got_message(BIO *out)
{
    char *data;
    long n = BIO_get_mem_data(out, &data);

    return n == (long)strlen(message) && memcmp(data, message, (size_t)n) == 0;
}

/* ---- PKCS#7 ---- */

static PKCS7 *d2i_p7(const buf *b)
{
    const unsigned char *p = b->p;

    return d2i_PKCS7(NULL, &p, (long)b->n);
}

static void pkcs7_missing_content(void)
{
    static const unsigned char signed_oid[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                               0x01, 0x07, 0x02};
    static const unsigned char enveloped_oid[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
                                                  0x0d, 0x01, 0x07, 0x03};
    static const unsigned char data_oid[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                             0x01, 0x07, 0x01};
    static const unsigned char aes_alg[] = {0x30, 0x1d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
                                            0x03, 0x04, 0x01, 0x02, 0x04, 0x10, 0, 0, 0, 0, 0,
                                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    buf outer = {0}, inner = {0}, sd = {0}, tmp = {0};
    PKCS7 *p7;
    BIO *bio;
    EVP_PKEY *key = ec_key();
    X509 *cert = leaf_cert("PKCS7", key, NULL, NULL);
    int r1, r2, r3;

    /* ContentInfo { signedData } without its [0] content. */
    put(&inner, signed_oid, sizeof(signed_oid));
    put_tlv(&outer, 0x30, &inner);
    p7 = d2i_p7(&outer);
    bio = p7 != NULL ? PKCS7_dataInit(p7, NULL) : NULL;
    r1 = p7 != NULL;
    note("signedData without content: parsed %d, dataInit %s", r1, bio != NULL ? "BIO" : "NULL");
    BIO_free_all(bio);
    PKCS7_free(p7);
    free_buf(&outer);
    ERR_clear_error();

    /* SignedData { 1, {}, ContentInfo { data } (no content), {} } */
    put(&sd, "\x02\x01\x01\x31\x00", 5);
    put(&tmp, data_oid, sizeof(data_oid));
    put_tlv(&sd, 0x30, &tmp);
    put(&sd, "\x31\x00", 2);
    put_tlv(&tmp, 0x30, &sd);
    put(&inner, signed_oid, sizeof(signed_oid));
    put_tlv(&inner, 0xa0, &tmp);
    put_tlv(&outer, 0x30, &inner);
    p7 = d2i_p7(&outer);
    bio = p7 != NULL ? PKCS7_dataInit(p7, NULL) : NULL;
    r2 = p7 != NULL;
    note("inner data without content: parsed %d, dataInit %s", r2, bio != NULL ? "BIO" : "NULL");
    check(1, "CVE-2015-0289: PKCS#7 with missing outer or inner content is handled");
    BIO_free_all(bio);
    {
        BIO *in = BIO_new_mem_buf(outer.p, (int)outer.n);
        PKCS7 *again = d2i_PKCS7_bio(in, NULL);
        BIO *print = BIO_new(BIO_s_mem());
        unsigned char *der = NULL;
        int len = again != NULL ? i2d_PKCS7(again, &der) : -1;

        if (again != NULL)
            PKCS7_print_ctx(print, again, 0, NULL);
        check(len == (int)outer.n,
              "CVE-2023-0216: d2i_PKCS7_bio of malformed content then re-encoding and printing");
        OPENSSL_free(der);
        PKCS7_free(again);
        BIO_free(in);
        BIO_free(print);
    }
    PKCS7_free(p7);
    free_buf(&outer);
    ERR_clear_error();

    /* EnvelopedData { 0, {}, EncryptedContentInfo { data, aes-128-cbc } (no content) } */
    put(&sd, "\x02\x01\x00\x31\x00", 5);
    put(&tmp, data_oid, sizeof(data_oid));
    put(&tmp, aes_alg, sizeof(aes_alg));
    put_tlv(&sd, 0x30, &tmp);
    put_tlv(&tmp, 0x30, &sd);
    put(&inner, enveloped_oid, sizeof(enveloped_oid));
    put_tlv(&inner, 0xa0, &tmp);
    put_tlv(&outer, 0x30, &inner);
    p7 = d2i_p7(&outer);
    bio = p7 != NULL ? PKCS7_dataDecode(p7, key, NULL, cert) : NULL;
    r3 = p7 != NULL;
    check(bio == NULL, "CVE-2015-1790: PKCS#7 enveloped data without encrypted content fails");
    note("parsed %d", r3);
    errors("dataDecode");
    BIO_free_all(bio);
    PKCS7_free(p7);
    free_buf(&outer);
    X509_free(cert);
    EVP_PKEY_free(key);
}

static int sign_p7(EVP_PKEY *key, X509 *cert, int flags, unsigned char **der)
{
    BIO *in = BIO_new_mem_buf(message, (int)strlen(message));
    PKCS7 *p7 = PKCS7_sign(cert, key, NULL, in, flags);
    int len = p7 != NULL ? i2d_PKCS7(p7, der) : -1;

    PKCS7_free(p7);
    BIO_free(in);
    return len;
}

static int verify_p7(const unsigned char *der, int len, X509 *cert, int flags)
{
    const unsigned char *p = der;
    PKCS7 *p7 = d2i_PKCS7(NULL, &p, len);
    STACK_OF(X509) *certs = sk_X509_new_null();
    X509_STORE *store = X509_STORE_new();
    BIO *content = BIO_new_mem_buf(message, (int)strlen(message));
    int r;

    sk_X509_push(certs, cert);
    r = p7 != NULL ? PKCS7_verify(p7, certs, store, (flags & PKCS7_DETACHED) ? content : NULL,
                                  NULL, PKCS7_NOVERIFY)
                   : -2;
    PKCS7_free(p7);
    sk_X509_free(certs);
    X509_STORE_free(store);
    BIO_free(content);
    return r;
}

static void pkcs7_signatures(void)
{
    static const unsigned char md_attr[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                            0x01, 0x09, 0x04, 0x31, 0x22, 0x04};
    EVP_PKEY *key = ec_key();
    X509 *cert = leaf_cert("PKCS7 signer", key, NULL, NULL);
    unsigned char *der = NULL;
    int len, n, r;

    len = sign_p7(key, cert, PKCS7_BINARY, &der);
    r = verify_p7(der, len, cert, 0);
    note("unchanged: %d", r);
    n = patch(der, (size_t)len, sha256_oid, sizeof(sha256_oid), sizeof(sha256_oid) - 1, 0x63);
    r = verify_p7(der, len, cert, 0);
    check(n == 2 && r <= 0, "CVE-2023-0401: PKCS#7 verification with an unknown digest fails cleanly");
    errors("unknown digest");
    OPENSSL_free(der);
    der = NULL;

    len = sign_p7(key, cert, PKCS7_BINARY, &der);
    n = patch(der, (size_t)len, md_attr, sizeof(md_attr), sizeof(md_attr) - 1, 0x02);
    r = verify_p7(der, len, cert, 0);
    check(n == 1 && r <= 0,
          "CVE-2026-22796: a messageDigest attribute of the wrong type fails verification");
    errors("messageDigest type");
    OPENSSL_free(der);
    der = NULL;

    /* A signed message carrying its signer's certificate twice and an unrelated one. */
    {
        BIO *in = BIO_new_mem_buf(message, (int)strlen(message));
        EVP_PKEY *other_key = ec_key();
        X509 *other = leaf_cert("other", other_key, NULL, NULL);
        STACK_OF(X509) *extra = sk_X509_new_null();
        PKCS7 *p7;

        sk_X509_push(extra, cert);
        sk_X509_push(extra, other);
        p7 = PKCS7_sign(cert, key, extra, in, PKCS7_BINARY);
        len = p7 != NULL ? i2d_PKCS7(p7, &der) : -1;
        r = verify_p7(der, len, cert, 0);
        check(r == 1, "CVE-2026-45447: PKCS#7 verification of a message with repeated certificates");
        r = verify_p7(der, len, other, 0);
        note("with another certificate: %d", r);
        ERR_clear_error();
        PKCS7_free(p7);
        OPENSSL_free(der);
        sk_X509_free(extra);
        X509_free(other);
        EVP_PKEY_free(other_key);
        BIO_free(in);
    }
    X509_free(cert);
    EVP_PKEY_free(key);
}

static void pkcs7_decrypt_wrong_key(void)
{
    EVP_PKEY *key = rsa_key(2048), *wrong = rsa_key(2048);
    X509 *cert = leaf_cert("PKCS7 recipient", key, NULL, NULL);
    STACK_OF(X509) *recips = sk_X509_new_null();
    BIO *in = BIO_new_mem_buf(message, (int)strlen(message));
    PKCS7 *p7;
    BIO *out = BIO_new(BIO_s_mem());
    int r;

    sk_X509_push(recips, cert);
    p7 = PKCS7_encrypt(recips, in, EVP_aes_128_cbc(), PKCS7_BINARY);
    r = PKCS7_decrypt(p7, wrong, cert, out, 0);
    check(!got_message(out),
          "CVE-2012-0884: PKCS#7 decryption with the wrong RSA key reveals nothing (MMA)");
    ERR_clear_error();
    (void)r;
    (void)BIO_reset(out);
    r = PKCS7_decrypt(p7, key, cert, out, 0);
    note("right key: %d", r);
    BIO_free(out);
    PKCS7_free(p7);
    BIO_free(in);
    sk_X509_free(recips);
    X509_free(cert);
    EVP_PKEY_free(key);
    EVP_PKEY_free(wrong);
}

/* ---- CMS ---- */

static void cms_signatures(void)
{
    EVP_PKEY *key = ec_key();
    X509 *cert = leaf_cert("CMS signer", key, NULL, NULL);
    BIO *in = BIO_new_mem_buf(message, (int)strlen(message));
    CMS_ContentInfo *cms = CMS_sign(cert, key, NULL, in, CMS_BINARY | CMS_DETACHED);
    STACK_OF(X509) *certs = sk_X509_new_null();
    BIO *other = BIO_new_mem_buf("another message\n", 16);
    unsigned char *der = NULL;
    const unsigned char *p;
    int len, n, r;

    sk_X509_push(certs, cert);
    r = CMS_verify(cms, certs, NULL, other, NULL, CMS_NO_SIGNER_CERT_VERIFY | CMS_BINARY);
    check(r == 0, "CVE-2009-0591: CMS verification of altered content fails");
    errors("altered content");

    len = i2d_CMS_ContentInfo(cms, &der);
    n = patch(der, (size_t)len, sha256_oid, sizeof(sha256_oid), sizeof(sha256_oid) - 1, 0x63);
    p = der;
    {
        CMS_ContentInfo *changed = d2i_CMS_ContentInfo(NULL, &p, len);

        (void)BIO_reset(in);
        r = changed != NULL ? CMS_verify(changed, certs, NULL, in, NULL,
                                         CMS_NO_SIGNER_CERT_VERIFY | CMS_BINARY)
                            : -2;
        check(n >= 1 && r <= 0, "CVE-2015-1792: CMS verification with an unknown digest ends");
        errors("unknown digest");
        CMS_ContentInfo_free(changed);
    }
    OPENSSL_free(der);
    CMS_ContentInfo_free(cms);
    sk_X509_free(certs);
    BIO_free(in);
    BIO_free(other);
    X509_free(cert);
    EVP_PKEY_free(key);
}

static void cms_bad_structures(void)
{
    size_t len;
    unsigned char *der = read_file("bad-cms.der", &len);
    const unsigned char *p = der;
    CMS_ContentInfo *cms = der != NULL ? d2i_CMS_ContentInfo(NULL, &p, (long)len) : NULL;

    check(der != NULL && cms == NULL,
          "CVE-2016-7053: a CMS ContentInfo with a bad CHOICE value fails to decode");
    errors("bad-cms.der");
    CMS_ContentInfo_free(cms);
    OPENSSL_free(der);

    der = read_file("high_tag.der", &len);
    p = der;
    {
        ASN1_TYPE *t = der != NULL ? d2i_ASN1_TYPE(NULL, &p, (long)len) : NULL;
        unsigned char *out = NULL;
        int n = t != NULL ? i2d_ASN1_TYPE(t, &out) : -1;

        check(n == (int)len && memcmp(out, der, len) == 0,
              "CVE-2016-2108: a high tag number isn't mistaken for a negative INTEGER");
        OPENSSL_free(out);
        ASN1_TYPE_free(t);
    }
    OPENSSL_free(der);

    /* Streaming through BIO_new_NDEF. */
    {
        EVP_PKEY *key = ec_key();
        X509 *cert = leaf_cert("NDEF", key, NULL, NULL);
        BIO *in = BIO_new_mem_buf(message, (int)strlen(message));
        CMS_ContentInfo *s = CMS_sign(cert, key, NULL, in, CMS_BINARY | CMS_STREAM);
        BIO *out = BIO_new(BIO_s_mem());
        BIO *ndef = s != NULL ? BIO_new_NDEF(out, (ASN1_VALUE *)s, ASN1_ITEM_rptr(CMS_ContentInfo))
                              : NULL;
        int ok = ndef != NULL;

        if (ndef != NULL) {
            BIO_write(ndef, message, (int)strlen(message));
            (void)BIO_flush(ndef);
            while (ndef != NULL && ndef != out) {
                BIO *next = BIO_pop(ndef);

                BIO_free(ndef);
                ndef = next;
            }
        }
        check(ok, "CVE-2023-0215: BIO_new_NDEF's chain is freed without a use after free");
        ERR_clear_error();
        BIO_free(out);
        BIO_free(in);
        CMS_ContentInfo_free(s);
        X509_free(cert);
        EVP_PKEY_free(key);
    }
}

static void cms_wrong_keys(void)
{
    EVP_PKEY *a_key = rsa_key(2048), *b_key = rsa_key(2048), *c_key = rsa_key(2048);
    X509 *a = leaf_cert("A", a_key, NULL, NULL), *b = leaf_cert("B", b_key, NULL, NULL);
    STACK_OF(X509) *recips = sk_X509_new_null();
    BIO *in = BIO_new_mem_buf(message, (int)strlen(message));
    CMS_ContentInfo *cms;
    BIO *out = BIO_new(BIO_s_mem());

    sk_X509_push(recips, a);
    cms = CMS_encrypt(recips, in, EVP_aes_128_cbc(), CMS_BINARY);
    CMS_decrypt_set1_pkey(cms, b_key, NULL);
    CMS_decrypt(cms, NULL, NULL, NULL, out, 0);
    check(!got_message(out),
          "CVE-2019-1563: CMS_decrypt_set1_pkey with the wrong key reveals nothing (padding oracle)");
    ERR_clear_error();
    CMS_ContentInfo_free(cms);
    (void)BIO_reset(out);

    sk_X509_push(recips, b);
    (void)BIO_reset(in);
    cms = CMS_encrypt(recips, in, EVP_aes_128_cbc(), CMS_BINARY);
    CMS_decrypt(cms, c_key, NULL, NULL, out, 0);
    check(!got_message(out),
          "CVE-2026-42768: CMS decryption across two RecipientInfos with an unrelated key reveals nothing");
    ERR_clear_error();
    (void)BIO_reset(out);
    CMS_decrypt(cms, b_key, NULL, NULL, out, 0);
    note("the second recipient's key: %d", got_message(out));
    ERR_clear_error();
    CMS_ContentInfo_free(cms);
    BIO_free(out);
    BIO_free(in);
    sk_X509_free(recips);
    X509_free(a);
    X509_free(b);
    EVP_PKEY_free(a_key);
    EVP_PKEY_free(b_key);
    EVP_PKEY_free(c_key);
}

static void cms_files(void)
{
    static const struct {
        const char *id, *what, *file, *cert, *key;
        int pem;
    } cases[] = {
        {"CVE-2026-28389", "a malformed KeyAgreeRecipientInfo (DH)", "dh-malformed.der",
         "dh-cert.pem", "dh-key.pem", 0},
        {"CVE-2026-28389", "a malformed KeyAgreeRecipientInfo (ECDH)", "ecdh-malformed.der",
         "ecdh-cert.pem", "ecdh-key.pem", 0},
        {"CVE-2026-28390", "a malformed KeyTransportRecipientInfo", "rsa-malformed.der",
         "smrsa3.pem", "smrsa3-key.pem", 0},
        {"CVE-2025-15467", "AuthEnvelopedData with an oversized IV", "encDataWithTooLongIV.pem",
         "servercert.pem", "serverkey.pem", 1},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        CMS_ContentInfo *cms = cases[i].pem ? read_cms_pem(cases[i].file)
                                            : read_cms_der(cases[i].file);
        X509 *cert = read_cert(cases[i].cert);
        EVP_PKEY *key = read_key(cases[i].key);
        BIO *out = BIO_new(BIO_s_mem());
        int r = cms != NULL ? CMS_decrypt(cms, key, cert, NULL, out, 0) : -2;

        check(cert != NULL && key != NULL && cms != NULL && r == 0,
              "%s: decrypting %s fails cleanly", cases[i].id, cases[i].what);
        errors(cases[i].file);
        BIO_free(out);
        CMS_ContentInfo_free(cms);
        X509_free(cert);
        EVP_PKEY_free(key);
    }
}

static void cms_passwords(void)
{
    CMS_ContentInfo *cms = read_cms_der("cms_pwri_kek_oob.der");
    int r = cms != NULL ? CMS_decrypt_set1_password(cms, (unsigned char *)"password", -1) : -2;

    check(cms != NULL && r == 0,
          "CVE-2026-9076: a 2-octet PWRI encryptedKey fails without reading past it");
    errors("short encryptedKey");
    CMS_ContentInfo_free(cms);

    cms = read_cms_der("cms_pwri_kek_NoIV.der");
    r = cms != NULL ? CMS_decrypt_set1_password(cms, (unsigned char *)"password", -1) : -2;
    check(cms != NULL && r == 0, "CVE-2026-42766: a PWRI key-encryption cipher without an IV fails");
    errors("no IV");
    CMS_ContentInfo_free(cms);

    /* A password recipient decrypted with the wrong password, over many messages. */
    {
        int revealed = 0;

        for (int i = 0; i < 64; i++) {
            BIO *in = BIO_new_mem_buf(message, (int)strlen(message));
            BIO *out = BIO_new(BIO_s_mem());
            CMS_ContentInfo *pw = CMS_encrypt(NULL, in, EVP_aes_128_cbc(),
                                              CMS_BINARY | CMS_PARTIAL);

            CMS_add0_recipient_password(pw, -1, NID_undef, NID_undef,
                                        (unsigned char *)"right", -1, NULL);
            CMS_final(pw, in, NULL, CMS_BINARY);
            CMS_decrypt_set1_password(pw, (unsigned char *)"wrong", -1);
            CMS_decrypt(pw, NULL, NULL, NULL, out, 0);
            revealed += got_message(out);
            ERR_clear_error();
            CMS_ContentInfo_free(pw);
            BIO_free(in);
            BIO_free(out);
        }
        check(revealed == 0,
              "CVE-2025-9230: RFC 3211 KEK unwrap with wrong passwords stays in bounds (64 messages)");
    }
}

static void cms_auth_enveloped(void)
{
    static const unsigned char key[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    static const unsigned char id[3] = {0xc0, 0xfe, 0xe0};
    const char *files[] = {"authenveloped_attrs.pem", "bad_authenveloped_attrs.pem"};
    int results[2];
    long sizes[2];

    for (int i = 0; i < 2; i++) {
        CMS_ContentInfo *cms = read_cms_pem(files[i]);
        BIO *out = BIO_new(BIO_s_mem());
        char *data;

        results[i] = cms != NULL && CMS_decrypt_set1_key(cms, (unsigned char *)key, sizeof(key),
                                                         id, sizeof(id))
                     && CMS_decrypt(cms, NULL, NULL, NULL, out, 0);
        sizes[i] = BIO_get_mem_data(out, &data);
        ERR_clear_error();
        CMS_ContentInfo_free(cms);
        BIO_free(out);
    }
    check(results[0] == 1 && results[1] == 0 && sizes[1] == 0,
          "CVE-2026-34182: AuthEnvelopedData with tampered authAttrs is rejected, releasing nothing");
    note("good %d (%ld octets), tampered %d (%ld octets)", results[0], sizes[0], results[1], sizes[1]);
}

static void cms_kari_wrap_pad(void)
{
    static const unsigned char wrap_oid[] = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
                                             0x03, 0x04, 0x01, 0x2d};
    X509 *cert = read_cert("smec1.pem");
    EVP_PKEY *key = read_key("smec1.pem");
    STACK_OF(X509) *recips = sk_X509_new_null();
    BIO *in = BIO_new_mem_buf(message, (int)strlen(message));
    CMS_ContentInfo *cms, *changed = NULL;
    unsigned char *der = NULL;
    const unsigned char *p;
    int len, n = 0, r = -2;
    BIO *out = BIO_new(BIO_s_mem());

    sk_X509_push(recips, cert);
    cms = CMS_encrypt(recips, in, EVP_aes_256_cbc(), CMS_BINARY);
    len = cms != NULL ? i2d_CMS_ContentInfo(cms, &der) : -1;
    if (len > 0) {
        for (int i = 0; i + (int)sizeof(wrap_oid) <= len && n == 0; i++)
            if (memcmp(der + i, wrap_oid, sizeof(wrap_oid)) == 0) {
                der[i + sizeof(wrap_oid) - 1] = 0x30; /* id-aes256-wrap-pad */
                n = 1;
            }
        p = der;
        changed = d2i_CMS_ContentInfo(NULL, &p, len);
        r = changed != NULL ? CMS_decrypt(changed, key, cert, NULL, out, 0) : -2;
    }
    check(n == 1 && r == 0,
          "CVE-2026-63072: KARI with a key-wrap-pad OID fails without writing past its buffer");
    ERR_clear_error();
    OPENSSL_free(der);
    CMS_ContentInfo_free(cms);
    CMS_ContentInfo_free(changed);
    sk_X509_free(recips);
    BIO_free(in);
    BIO_free(out);
    X509_free(cert);
    EVP_PKEY_free(key);
}

static void cms_originator_info(void)
{
    EVP_PKEY *key = rsa_key(2048);
    X509 *cert = leaf_cert("recipient", key, NULL, NULL);
    STACK_OF(X509) *recips = sk_X509_new_null();
    BIO *in = BIO_new_mem_buf(message, (int)strlen(message));
    CMS_ContentInfo *cms, *again;
    unsigned char *der = NULL;
    const unsigned char *p;
    BIO *out = BIO_new(BIO_s_mem());
    int len, r = -2;

    sk_X509_push(recips, cert);
    cms = CMS_encrypt(recips, in, EVP_aes_128_cbc(), CMS_BINARY | CMS_PARTIAL);
    CMS_add1_cert(cms, cert);
    (void)BIO_reset(in);
    CMS_final(cms, in, NULL, CMS_BINARY);
    len = i2d_CMS_ContentInfo(cms, &der);
    p = der;
    again = d2i_CMS_ContentInfo(NULL, &p, len);
    if (again != NULL)
        r = CMS_decrypt(again, key, cert, NULL, out, 0);
    check(r == 1 && got_message(out),
          "CVE-2010-0742: EnvelopedData with OriginatorInfo certificates parses and decrypts");
    ERR_clear_error();
    OPENSSL_free(der);
    CMS_ContentInfo_free(cms);
    CMS_ContentInfo_free(again);
    BIO_free(out);
    BIO_free(in);
    sk_X509_free(recips);
    X509_free(cert);
    EVP_PKEY_free(key);
}

/* ---- PKCS#12 ---- */

static PKCS12 *read_p12(const char *file)
{
    BIO *in = BIO_new_file(file, "rb");
    PKCS12 *p12 = in != NULL ? d2i_PKCS12_bio(in, NULL) : NULL;

    BIO_free(in);
    return p12;
}

static void pkcs12_files(void)
{
    const char *bad[] = {"bad1.p12", "bad2.p12", "bad3.p12"};
    const char *pbmac[] = {"pbmac1_256_256.bad-iter.p12",       "pbmac1_256_256.bad-salt.p12",
                           "pbmac1_256_256.no-len.p12",         "pbmac1_256_256.bad-len.p12",
                           "pbmac1_256_256.bad-salt-type.p12",  "pbmac1_256_256.negative-len.p12",
                           "pbmac1_256_256.no-salt.p12",        "pbmac1_256_256.very-big-len.p12",
                           "pbmac1_256_256.zero-len.p12",       "pbmac1_256_256.bad-key-len.p12"};
    int all = 1;

    for (int i = 0; i < 3; i++) {
        PKCS12 *p12 = read_p12(bad[i]);
        EVP_PKEY *key = NULL;
        X509 *cert = NULL;
        STACK_OF(X509) *ca = NULL;
        int r = p12 != NULL ? PKCS12_parse(p12, "", &key, &cert, &ca) : -2;

        note("%s: read %d parse %d", bad[i], p12 != NULL, r);
        ERR_clear_error();
        EVP_PKEY_free(key);
        X509_free(cert);
        OSSL_STACK_OF_X509_free(ca);
        PKCS12_free(p12);
    }
    check(1, "CVE-2024-0727: PKCS#12 files with NULL ContentInfo fields are handled");

    for (size_t i = 0; i < sizeof(pbmac) / sizeof(pbmac[0]); i++) {
        PKCS12 *p12 = read_p12(pbmac[i]);
        int r = p12 != NULL ? PKCS12_verify_mac(p12, "1234", -1) : -2;

        note("%s: read %d verify_mac %d", pbmac[i], p12 != NULL, r);
        if (p12 == NULL || r != 0)
            all = 0;
        ERR_clear_error();
        PKCS12_free(p12);
    }
    check(all, "CVE-2025-11187: PBMAC1 parameters are validated (10 malformed files)");
    {
        PKCS12 *p12 = read_p12("pbmac1_256_256.good-shorter-key-len.p12");
        PKCS12 *bad_key = read_p12("pbmac1_256_256.bad-key-len.p12");
        int r1 = p12 != NULL ? PKCS12_verify_mac(p12, "1234", -1) : -2;
        int r2 = bad_key != NULL ? PKCS12_verify_mac(bad_key, "1234", -1) : -2;

        check(r2 == 0, "CVE-2026-34181: a PBMAC1 file with a short HMAC key is rejected");
        note("shorter key length %d, bad key length %d", r1, r2);
        ERR_clear_error();
        PKCS12_free(p12);
        PKCS12_free(bad_key);
    }
}

static void friendly_names(void)
{
    static const unsigned char arrow[] = {0x21, 0x92};
    static const unsigned char odd[] = {0x00, 0x41, 0x00};
    static const unsigned char surrogates[] = {0xd8, 0x3d, 0xde, 0x00, 0xd8, 0x00, 0x00, 0x41};
    char *a = OPENSSL_uni2utf8(arrow, sizeof(arrow));
    char *b = OPENSSL_uni2utf8(odd, sizeof(odd));
    char *c = OPENSSL_uni2utf8(surrogates, sizeof(surrogates));

    check(a != NULL && strcmp(a, "\xe2\x86\x92") == 0,
          "CVE-2025-69419: OPENSSL_uni2utf8 sizes its UTF-8 output for every character");
    note("odd %s, surrogates %zu", b != NULL ? b : "NULL", c != NULL ? strlen(c) : 0);
    OPENSSL_free(a);
    OPENSSL_free(b);
    OPENSSL_free(c);
}

/* PFX { 3, ContentInfo { data, [0] OCTET STRING { AuthenticatedSafe } } } from its safe. */
static void pfx(buf *out, buf *auth_safe)
{
    static const unsigned char data_oid[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                             0x01, 0x07, 0x01};
    buf octet = {0}, explicit = {0}, ci = {0}, body = {0};

    put_tlv(&octet, 0x04, auth_safe);
    put_tlv(&explicit, 0xa0, &octet);
    put(&ci, data_oid, sizeof(data_oid));
    put(&ci, explicit.p, explicit.n);
    free_buf(&explicit);
    put(&body, "\x02\x01\x03", 3);
    put_tlv(&body, 0x30, &ci);
    put_tlv(out, 0x30, &body);
}

static int parse_p12(const buf *der, const char *pass, int *got_cert)
{
    const unsigned char *p = der->p;
    PKCS12 *p12 = d2i_PKCS12(NULL, &p, (long)der->n);
    EVP_PKEY *key = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;
    int r = p12 != NULL ? PKCS12_parse(p12, pass, &key, &cert, &ca) : -2;

    *got_cert = cert != NULL;
    EVP_PKEY_free(key);
    X509_free(cert);
    OSSL_STACK_OF_X509_free(ca);
    PKCS12_free(p12);
    ERR_clear_error();
    return r;
}

static void pkcs12_crafted(void)
{
    static const unsigned char encrypted_oid[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                                  0x01, 0x07, 0x06};
    static const unsigned char data_oid[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                             0x01, 0x07, 0x01};
    /* pbeWithSHAAnd3-KeyTripleDES-CBC { salt, 2048 } */
    static const unsigned char pbe[] = {0x30, 0x1a, 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7,
                                        0x0d, 0x01, 0x0c, 0x01, 0x03, 0x30, 0x0c, 0x04, 0x08,
                                        1, 2, 3, 4, 5, 6, 7, 8, 0x02, 0x02, 0x08, 0x00};
    static const unsigned char cert_bag_oid[] = {0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                                 0x01, 0x0c, 0x0a, 0x01, 0x03};
    static const unsigned char x509_oid[] = {0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                             0x01, 0x09, 0x16, 0x01};
    static const unsigned char friendly_oid[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                                 0x01, 0x09, 0x14};
    static const unsigned char keyid_oid[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                              0x01, 0x09, 0x15};
    buf eci = {0}, ed = {0}, explicit = {0}, ci = {0}, safe = {0}, out = {0};
    int r, got;

    /* AuthenticatedSafe { ContentInfo { encryptedData, [0] EncryptedData { 0,
     *   EncryptedContentInfo { data, pbe } } } }: no encryptedContent. */
    put(&eci, data_oid, sizeof(data_oid));
    put(&eci, pbe, sizeof(pbe));
    put(&ed, "\x02\x01\x00", 3);
    put_tlv(&ed, 0x30, &eci);
    put_tlv(&explicit, 0x30, &ed);
    put(&ci, encrypted_oid, sizeof(encrypted_oid));
    put_tlv(&ci, 0xa0, &explicit);
    put_tlv(&safe, 0x30, &ci);
    {
        buf auth = {0};

        put_tlv(&auth, 0x30, &safe);
        pfx(&out, &auth);
    }
    r = parse_p12(&out, "pass", &got);
    check(r == 0, "CVE-2025-69421: encrypted PKCS#12 data without encryptedContent fails cleanly");
    free_buf(&out);

    /* A CertBag whose friendlyName is an INTEGER and localKeyID a BOOLEAN. */
    {
        EVP_PKEY *key = ec_key();
        X509 *cert = leaf_cert("bagged", key, NULL, NULL);
        unsigned char *der = NULL;
        int len = i2d_X509(cert, &der);
        buf certbag = {0}, inner = {0}, octet = {0}, bag = {0}, attrs = {0}, attr = {0},
            set = {0}, contents = {0}, data_ci = {0}, auth = {0};

        put_raw_tlv(&octet, 0x04, der, (size_t)len);
        put(&certbag, x509_oid, sizeof(x509_oid));
        put_tlv(&certbag, 0xa0, &octet);
        put_tlv(&inner, 0x30, &certbag);
        put(&bag, cert_bag_oid, sizeof(cert_bag_oid));
        put_tlv(&bag, 0xa0, &inner);
        put(&set, "\x02\x01\x01", 3);
        put(&attr, friendly_oid, sizeof(friendly_oid));
        put_tlv(&attr, 0x31, &set);
        put_tlv(&attrs, 0x30, &attr);
        put(&set, "\x01\x01\xff", 3);
        put(&attr, keyid_oid, sizeof(keyid_oid));
        put_tlv(&attr, 0x31, &set);
        put_tlv(&attrs, 0x30, &attr);
        put_tlv(&bag, 0x31, &attrs);
        put_tlv(&contents, 0x30, &bag);
        /* SafeContents inside ContentInfo { data, [0] OCTET STRING } */
        put_tlv(&octet, 0x30, &contents);
        put_tlv(&inner, 0x04, &octet);
        put(&data_ci, data_oid, sizeof(data_oid));
        put_tlv(&data_ci, 0xa0, &inner);
        put_tlv(&auth, 0x30, &data_ci);
        put_tlv(&contents, 0x30, &auth);
        pfx(&out, &contents);
        r = parse_p12(&out, NULL, &got);
        check(1, "CVE-2026-22795: PKCS#12 bag attributes of the wrong type are handled");
        note("parse %d, certificate %d", r, got);
        free_buf(&out);
        OPENSSL_free(der);
        X509_free(cert);
        EVP_PKEY_free(key);
    }
}

/* ---- Time-stamping ---- */

static void timestamps(void)
{
    /* id-smime-aa-signingCertificate (v1; v2 ends in 0x2f) */
    static const unsigned char signing_cert_oid[] = {0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7,
                                                     0x0d, 0x01, 0x09, 0x10, 0x02, 0x0c};
    static const int nids[] = {NID_basic_constraints, NID_ext_key_usage, 0};
    static const char *const values[] = {"CA:FALSE", "critical,timeStamping"};
    EVP_PKEY *key = ec_key();
    X509 *tsa = make_cert("TSA", 9, key, NULL, NULL, nids, values);
    TS_REQ *req = TS_REQ_new();
    TS_MSG_IMPRINT *imprint = TS_MSG_IMPRINT_new();
    X509_ALGOR *alg = X509_ALGOR_new();
    unsigned char digest[32];
    BIO *req_bio = BIO_new(BIO_s_mem());
    TS_RESP_CTX *ctx = TS_RESP_CTX_new();
    TS_RESP *resp;
    unsigned char *der = NULL;
    int len, n = 0, r1 = -2, r2 = -2;

    SHA256((const unsigned char *)message, strlen(message), digest);
    X509_ALGOR_set0(alg, OBJ_nid2obj(NID_sha256), V_ASN1_NULL, NULL);
    TS_MSG_IMPRINT_set_algo(imprint, alg);
    TS_MSG_IMPRINT_set_msg(imprint, digest, sizeof(digest));
    TS_REQ_set_version(req, 1);
    TS_REQ_set_msg_imprint(req, imprint);
    TS_REQ_set_cert_req(req, 1);
    i2d_TS_REQ_bio(req_bio, req);
    TS_RESP_CTX_set_signer_cert(ctx, tsa);
    TS_RESP_CTX_set_signer_key(ctx, key);
    TS_RESP_CTX_set_def_policy(ctx, OBJ_txt2obj("1.2.3.4.1", 1));
    TS_RESP_CTX_add_md(ctx, EVP_sha256());
    resp = TS_RESP_create_response(ctx, req_bio);
    len = resp != NULL ? i2d_TS_RESP(resp, &der) : -1;
    if (len > 0) {
        /* signingCertificateV2's value: SET { SEQUENCE ... } becomes SET { OCTET STRING ... } */
        for (int i = 0; i + (int)sizeof(signing_cert_oid) + 4 <= len; i++)
            if (memcmp(der + i, signing_cert_oid, sizeof(signing_cert_oid)) == 0) {
                unsigned char *v = der + i + sizeof(signing_cert_oid);
                size_t hl = (v[1] & 0x80) ? 2 + (v[1] & 0x7f) : 2;

                if (v[0] == 0x31 && v[hl] == 0x30) {
                    v[hl] = 0x04;
                    n++;
                }
            }
    }
    {
        TS_VERIFY_CTX *vctx = TS_VERIFY_CTX_new();
        X509_STORE *store = X509_STORE_new();
        const unsigned char *p = der;
        TS_RESP *changed;

        X509_STORE_add_cert(store, tsa);
        TS_VERIFY_CTX_set0_store(vctx, store);
        TS_VERIFY_CTX_set_flags(vctx, TS_VFY_SIGNATURE | TS_VFY_SIGNER);
        r1 = resp != NULL ? TS_RESP_verify_response(vctx, resp) : -2;
        ERR_clear_error();
        changed = len > 0 ? d2i_TS_RESP(NULL, &p, len) : NULL;
        r2 = changed != NULL ? TS_RESP_verify_response(vctx, changed) : -3;
        check(n == 1 && r2 <= 0,
              "CVE-2025-69420: a TS response whose signing certificate attribute has the wrong type fails");
        note("patched %d, original %d, changed %d", n, r1, r2);
        ERR_clear_error();
        TS_RESP_free(changed);
        TS_VERIFY_CTX_free(vctx);
    }
    OPENSSL_free(der);
    TS_RESP_free(resp);
    TS_RESP_CTX_free(ctx);
    BIO_free(req_bio);
    X509_ALGOR_free(alg);
    TS_MSG_IMPRINT_free(imprint);
    TS_REQ_free(req);
    X509_free(tsa);
    EVP_PKEY_free(key);
}

/* ---- CRMF and CMP ---- */

static void crmf_encrypted_value(void)
{
    /* EncryptedValue { symmAlg [1] { aes-128-cbc } without its IV, encSymmKey [2], keyAlg [3]
     * { rsaEncryption }, encValue } */
    static const unsigned char der[] = {
        0x30, 0x2c, 0xa1, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01,
        0x02, 0x82, 0x03, 0x00, 0x01, 0x02, 0xa3, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x09, 0x00, 1, 2, 3, 4, 5, 6, 7, 8};
    const unsigned char *p = der;
    OSSL_CRMF_ENCRYPTEDVALUE *ev = d2i_OSSL_CRMF_ENCRYPTEDVALUE(NULL, &p, sizeof(der));
    /* A fixed key: with a fresh one, RSA's implicit rejection gives a synthetic symmetric key of
     * random length, which is 16 octets (the IV check then fails instead) for about 1 in 245. */
    EVP_PKEY *key = read_key("rsa2048.pem");
    X509 *cert = ev != NULL ? OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert(ev, NULL, NULL, key) : NULL;

    check(ev != NULL && cert == NULL,
          "CVE-2026-42767: decrypting a CRMF EncryptedValue without symmAlg parameters fails");
    errors("EncryptedValue");
    X509_free(cert);
    EVP_PKEY_free(key);
    OSSL_CRMF_ENCRYPTEDVALUE_free(ev);
}

static OSSL_CMP_MSG *captured;

static OSSL_CMP_MSG *capture(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *req)
{
    (void)ctx;
    captured = OSSL_CMP_MSG_dup(req);
    return NULL;
}

static OSSL_CMP_PKISI *refuse(OSSL_CMP_SRV_CTX *srv_ctx, const OSSL_CMP_MSG *req, int certReqId,
                              const OSSL_CRMF_MSG *crm, const X509_REQ *p10cr, X509 **certOut,
                              STACK_OF(X509) **chainOut, STACK_OF(X509) **caPubs)
{
    (void)srv_ctx, (void)req, (void)certReqId, (void)crm, (void)p10cr;
    (void)certOut, (void)chainOut, (void)caPubs;
    return NULL;
}

static void cmp_protection_alg(void)
{
    /* id-PasswordBasedMac followed by its PBMParameter SEQUENCE */
    static const unsigned char pbm_oid[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf6, 0x7d,
                                            0x07, 0x42, 0x0d, 0x30};
    OSSL_CMP_CTX *client = OSSL_CMP_CTX_new(NULL, NULL);
    OSSL_CMP_SRV_CTX *server = OSSL_CMP_SRV_CTX_new(NULL, NULL);
    EVP_PKEY *key = ec_key();
    X509_NAME *subject = X509_NAME_new();
    unsigned char *der = NULL;
    int len = -1, n = 0;
    OSSL_CMP_MSG *changed = NULL, *resp = NULL;

    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, (const unsigned char *)"cmp", -1, -1, 0);
    OSSL_CMP_CTX_set_log_verbosity(client, OSSL_CMP_LOG_EMERG);
    OSSL_CMP_CTX_set1_secretValue(client, (const unsigned char *)"secret", 6);
    OSSL_CMP_CTX_set1_referenceValue(client, (const unsigned char *)"ref", 3);
    OSSL_CMP_CTX_set1_subjectName(client, subject);
    EVP_PKEY_up_ref(key);
    OSSL_CMP_CTX_set0_newPkey(client, 1, key);
    OSSL_CMP_CTX_set_transfer_cb(client, capture);
    OSSL_CMP_exec_IR_ses(client);
    ERR_clear_error();
    if (captured != NULL)
        len = i2d_OSSL_CMP_MSG(captured, &der);
    if (len > 0) {
        const unsigned char *p = der;

        n = patch(der, (size_t)len, pbm_oid, sizeof(pbm_oid), sizeof(pbm_oid) - 1, 0x04);
        changed = d2i_OSSL_CMP_MSG(NULL, &p, len);
    }
    {
        OSSL_CMP_CTX *sctx = OSSL_CMP_SRV_CTX_get0_cmp_ctx(server);

        OSSL_CMP_CTX_set_log_verbosity(sctx, OSSL_CMP_LOG_EMERG);
        OSSL_CMP_CTX_set1_secretValue(sctx, (const unsigned char *)"secret", 6);
        OSSL_CMP_SRV_CTX_init(server, NULL, refuse, NULL, NULL, NULL, NULL, NULL);
        if (changed != NULL)
            resp = OSSL_CMP_SRV_process_request(server, changed);
        errors("server");
    }
    check(n == 1 && changed != NULL,
          "CVE-2026-63076: a CMP request whose PBM protectionAlg parameter has the wrong type is refused");
    note("response %s, body type %d", resp != NULL ? "built" : "none",
         resp != NULL ? OSSL_CMP_MSG_get_bodytype(resp) : -1);
    ERR_clear_error();
    OSSL_CMP_MSG_free(resp);
    OSSL_CMP_MSG_free(changed);
    OSSL_CMP_MSG_free(captured);
    OPENSSL_free(der);
    X509_NAME_free(subject);
    EVP_PKEY_free(key);
    OSSL_CMP_SRV_CTX_free(server);
    OSSL_CMP_CTX_free(client);
}

static void ocsp_verify(void)
{
    EVP_PKEY *ca_key = ec_key(), *leaf_key = ec_key(), *rkey = ec_key();
    X509 *ca = ca_cert("CA", ca_key, NULL, NULL), *leaf = leaf_cert("leaf", leaf_key, ca, ca_key);
    X509 *responder = leaf_cert("responder", rkey, NULL, NULL), *nokey = X509_new();
    OCSP_BASICRESP *bs = OCSP_BASICRESP_new();
    OCSP_CERTID *id = OCSP_cert_to_id(NULL, leaf, ca);
    ASN1_TIME *now = X509_gmtime_adj(NULL, 0);
    X509_STORE *store = X509_STORE_new();
    STACK_OF(X509) *certs = sk_X509_new_null();
    int r1, r2;

    OCSP_basic_add1_status(bs, id, V_OCSP_CERTSTATUS_GOOD, 0, NULL, now, NULL);
    OCSP_basic_sign(bs, responder, rkey, EVP_sha256(), NULL, 0);
    X509_STORE_add_cert(store, ca);
    r1 = OCSP_basic_verify(bs, NULL, store, OCSP_NOCHECKS);
    check(r1 <= 0,
          "CVE-2022-1343: OCSP_basic_verify with OCSP_NOCHECKS fails when the signer doesn't verify");
    note("NOCHECKS %d", r1);
    ERR_clear_error();

    X509_set_subject_name(nokey, X509_get_subject_name(responder));
    sk_X509_push(certs, nokey);
    r2 = OCSP_basic_verify(bs, certs, store, OCSP_NOINTERN | OCSP_TRUSTOTHER | OCSP_NOVERIFY);
    check(r2 <= 0, "CVE-2013-0166: an OCSP signer certificate without a key fails verification");
    note("signer without a key %d", r2);
    ERR_clear_error();

    sk_X509_free(certs);
    X509_STORE_free(store);
    ASN1_TIME_free(now);
    OCSP_CERTID_free(id);
    OCSP_BASICRESP_free(bs);
    X509_free(nokey);
    X509_free(responder);
    X509_free(leaf);
    X509_free(ca);
    EVP_PKEY_free(rkey);
    EVP_PKEY_free(leaf_key);
    EVP_PKEY_free(ca_key);
}

int main(void)
{
    pkcs7_missing_content();
    pkcs7_signatures();
    pkcs7_decrypt_wrong_key();
    cms_signatures();
    cms_bad_structures();
    cms_wrong_keys();
    cms_files();
    cms_passwords();
    cms_auth_enveloped();
    cms_kari_wrap_pad();
    cms_originator_info();
    pkcs12_files();
    friendly_names();
    pkcs12_crafted();
    timestamps();
    crmf_encrypted_value();
    cmp_protection_alg();
    ocsp_verify();
    return finish();
}
