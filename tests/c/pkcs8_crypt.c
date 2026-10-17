/*
 * Conformance test for encrypted PKCS#8 keys (PKCS8_encrypt(3), PKCS8_decrypt(3),
 * PKCS12_pbe_crypt, d2i_PKCS8PrivateKey_bio(3)) and the writers and readers over them, in TAP
 * format: EncryptedPrivateKeyInfos made with fixed salts and IVs (their DER compared) and
 * random ones (decrypted back); each PBE; the right, a wrong, and an empty password; the item
 * encryption and decryption; the PEM and DER key writers encrypting (provided and legacy keys,
 * by cipher and by PBE NID) and the readers and decoders decrypting; the encoder's
 * EncryptedPrivateKeyInfo; and the errors.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

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

static void hex(const char *label, const unsigned char *p, size_t n)
{
    size_t i;

    printf("  %s (%zu):", label, n);
    for (i = 0; i < n; i++)
        printf("%s%02x", i % 32 == 0 && i > 0 ? "\n    " : " ", p[i]);
    printf("\n");
}

static const char KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAMkNIRFUM9yc+f3f\n"
    "4X382GadKojwXpFJiCmuj4GKt16Woi9E5VKTo5rCpZSaj9ZJwz72plEZJP7+hNBX\n"
    "asXyH83dfoKA44g2oIM7kpvAAuj441wdJENZfgRZACjqtl7oAvaswEz1NnvJAhuO\n"
    "GDbqlvdoIcghZI5EK9nyuqWt1w79AgMBAAECgYBgpLYDjXVMlAy7k7XiCPvA/8Wl\n"
    "g94BetZAKxACljqk9kXJ8RVHB386clyDvXRs7pIzHv89tpeJF7GiMJM7ybKtObJf\n"
    "IRBSwRckuVHdlxI4YzTK+xBNGzkjzvj5BpvDtCSsFlfqFM/Uxt/NJzhLOuvpYcwc\n"
    "dypwHmyAEdLyu/HrAQJBAOMaAMxmHnW66UcW86yOTWFMqo2d7JFnuMzDsdcGIA8O\n"
    "onvxVjPs8cWlRd2pc+pBxKi5XaKHAxcl1zjH1mVQYsECQQDiooTpTnxXyQG7J+zA\n"
    "SQgERnZF4fwpdiKn4iJbP+PVrS6ZQ0ND+UN893fY+H9Q+/plEJX13c0nWKqceX0t\n"
    "TEc9AkANlzbJBKt5/C+Ns4/tma6DziS+yN6pbP2gM23nIlS00fljVXQFM37chyGB\n"
    "PGzVbg4o0r8JxO6oaflRSpRIB+GBAkANUhgVznMohbwAUBxuQNyjw7B38wxrM3Je\n"
    "A8CZNGwjxwYSJA30FNaOpcz5h8GT9PuGrS7jQKIqSd/dSpa87trRAkBkyCVNVUoP\n"
    "mf0C/4pEuFF9WmDZ+IBGooNI3YCkePXHU+bcZsXI76kPdHJgtcE0yixVgDlwqBuw\n"
    "v3PX/DuH/TDr\n"
    "-----END PRIVATE KEY-----\n";

static unsigned char SALT[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
static unsigned char IV[16] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
                                0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf };

static int cb_calls = 0;

static int pw_cb(char *buf, int size, int rwflag, void *u)
{
    const char *pw = u == NULL ? "password" : u;
    int n = (int)strlen(pw);

    cb_calls++;
    printf("  callback: size %d rwflag %d\n", size, rwflag);
    if (n > size)
        return -1;
    memcpy(buf, pw, n);
    return n;
}

/* Decrypts the X509_SIG with the password and compares the PrivateKeyInfo's DER. */
static void decrypts(const char *label, const X509_SIG *p8, const char *pass, int passlen,
                     const PKCS8_PRIV_KEY_INFO *orig)
{
    PKCS8_PRIV_KEY_INFO *back = PKCS8_decrypt(p8, pass, passlen);
    unsigned char *a = NULL, *b = NULL;
    int na = i2d_PKCS8_PRIV_KEY_INFO(orig, &a), nb = back == NULL ? -1 : i2d_PKCS8_PRIV_KEY_INFO(back, &b);
    char what[150];

    snprintf(what, sizeof(what), "%s: decrypts to the PrivateKeyInfo", label);
    check(back != NULL && na == nb && memcmp(a, b, na) == 0, what);
    if (back == NULL)
        errors();
    PKCS8_PRIV_KEY_INFO_free(back);
    OPENSSL_free(a);
    OPENSSL_free(b);
}

static void show_sig(const char *label, const X509_SIG *p8, int fixed)
{
    unsigned char *der = NULL;
    int n = p8 == NULL ? -1 : i2d_X509_SIG(p8, &der);

    if (n <= 0) {
        printf("  %s: none\n", label);
        errors();
    } else if (fixed) {
        hex(label, der, (size_t)n);
    } else {
        printf("  %s: %d octets\n", label, n);
    }
    OPENSSL_free(der);
}

static void test_encrypt(EVP_PKEY *k)
{
    PKCS8_PRIV_KEY_INFO *p8inf = EVP_PKEY2PKCS8(k);
    X509_SIG *p8;
    X509_ALGOR *pbe;
    PKCS8_PRIV_KEY_INFO *bad;

    check(p8inf != NULL, "a PrivateKeyInfo");
    /* Fixed: PBES2 with a fixed salt and IV (PKCS8_set0_pbe), PKCS#12 3DES with a fixed salt. */
    pbe = PKCS5_pbe2_set_iv(EVP_aes_256_cbc(), 2048, SALT, 16, IV, NID_hmacWithSHA256);
    p8 = PKCS8_set0_pbe("password", -1, p8inf, pbe);
    show_sig("PBES2 aes-256-cbc fixed", p8, 1);
    decrypts("PBES2 aes-256-cbc fixed", p8, "password", 8, p8inf);
    X509_SIG_free(p8);
    pbe = PKCS5_pbe2_set_iv(EVP_aes_128_cbc(), 10, SALT, 8, IV, -1);
    p8 = PKCS8_set0_pbe_ex("pw", 2, p8inf, pbe, NULL, NULL);
    show_sig("PBES2 aes-128-cbc fixed (_ex)", p8, 1);
    decrypts("PBES2 aes-128-cbc fixed (_ex)", p8, "pw", 2, p8inf);
    X509_SIG_free(p8);
    p8 = PKCS8_encrypt(NID_pbe_WithSHA1And3_Key_TripleDES_CBC, NULL, "password", -1, SALT, 8, 2048, p8inf);
    show_sig("PKCS#12 3DES fixed salt", p8, 1);
    decrypts("PKCS#12 3DES", p8, "password", 8, p8inf);

    /* A wrong and an empty password. */
    bad = PKCS8_decrypt(p8, "wrong", 5);
    check(bad == NULL, "a wrong password fails");
    errors();
    bad = PKCS8_decrypt(p8, "", 0);
    check(bad == NULL, "an empty password fails");
    errors();
    bad = PKCS8_decrypt_ex(p8, NULL, 0, NULL, NULL);
    check(bad == NULL, "no password fails");
    errors();
    X509_SIG_free(p8);

    /* Random IVs: decrypted back. */
    p8 = PKCS8_encrypt(-1, EVP_aes_256_cbc(), "password", -1, NULL, 0, 0, p8inf);
    show_sig("PBES2 aes-256-cbc random", p8, 0);
    decrypts("PBES2 aes-256-cbc random", p8, "password", 8, p8inf);
    X509_SIG_free(p8);
    p8 = PKCS8_encrypt_ex(NID_hmacWithSHA512, EVP_aes_128_cbc(), "pw", 2, SALT, 16, 100, p8inf, NULL, NULL);
    show_sig("PBES2 with a PRF NID", p8, 0);
    decrypts("PBES2 with a PRF NID", p8, "pw", 2, p8inf);
    X509_SIG_free(p8);
    p8 = PKCS8_encrypt(-1, EVP_des_ede3_cbc(), "password", -1, SALT, 8, 10, p8inf);
    decrypts("PBES2 des-ede3-cbc", p8, "password", 8, p8inf);
    X509_SIG_free(p8);

    /* Errors. */
    p8 = PKCS8_encrypt(-1, NULL, "pw", 2, NULL, 0, 0, p8inf);
    check(p8 == NULL, "PBES2 without a cipher fails");
    errors();
    p8 = PKCS8_encrypt(NID_hmacWithSHA256, NULL, "pw", 2, NULL, 0, 0, p8inf);
    check(p8 == NULL, "a PRF NID without a cipher fails");
    errors();
    p8 = PKCS8_encrypt(NID_sha256, NULL, "pw", 2, SALT, 8, 0, p8inf);
    check(p8 == NULL, "an unknown PBE NID fails");
    errors();
    p8 = PKCS8_encrypt(NID_pbeWithMD5AndDES_CBC, NULL, "pw", 2, SALT, 8, 0, p8inf);
    check(p8 == NULL, "PBES1 (legacy) fails");
    errors();
    PKCS8_PRIV_KEY_INFO_free(p8inf);
}

static void test_crypt(void)
{
    X509_ALGOR *pbe = PKCS5_pbe2_set_iv(EVP_aes_128_cbc(), 10, SALT, 16, IV, -1);
    static const unsigned char plain[] = "sixteen octets!!plus more";
    unsigned char *enc = NULL, *dec = NULL, *r;
    int nenc = 0, ndec = 0;
    ASN1_OCTET_STRING *oct;
    PKCS8_PRIV_KEY_INFO *p8inf = PKCS8_PRIV_KEY_INFO_new(), *back;

    r = PKCS12_pbe_crypt(pbe, "pw", 2, plain, sizeof(plain) - 1, &enc, &nenc, 1);
    check(r != NULL && r == enc, "PKCS12_pbe_crypt encrypts");
    hex("ciphertext", enc, (size_t)nenc);
    r = PKCS12_pbe_crypt_ex(pbe, "pw", 2, enc, nenc, &dec, &ndec, 0, NULL, NULL);
    check(r != NULL && ndec == (int)sizeof(plain) - 1 && memcmp(dec, plain, ndec) == 0,
          "PKCS12_pbe_crypt_ex decrypts");
    OPENSSL_free(dec);
    dec = NULL;
    r = PKCS12_pbe_crypt(pbe, "pw", 2, enc, nenc - 1, &dec, &ndec, 0);
    check(r == NULL, "a ciphertext cut short fails");
    errors();
    r = PKCS12_pbe_crypt(pbe, "pw", 2, enc, nenc, NULL, NULL, 0);
    check(r != NULL, "no outputs asked for");
    OPENSSL_free(r);
    OPENSSL_free(enc);

    /* The item functions, over a PrivateKeyInfo with nothing in it. */
    PKCS8_pkey_set0(p8inf, OBJ_nid2obj(NID_rsaEncryption), 0, V_ASN1_NULL, NULL,
                    (unsigned char *)OPENSSL_strdup("abc"), 3);
    oct = PKCS12_item_i2d_encrypt(pbe, ASN1_ITEM_rptr(PKCS8_PRIV_KEY_INFO), "pw", 2, p8inf, 1);
    check(oct != NULL, "PKCS12_item_i2d_encrypt");
    if (oct != NULL)
        hex("encrypted item", oct->data, (size_t)oct->length);
    back = PKCS12_item_decrypt_d2i(pbe, ASN1_ITEM_rptr(PKCS8_PRIV_KEY_INFO), "pw", 2, oct, 1);
    check(back != NULL, "PKCS12_item_decrypt_d2i");
    PKCS8_PRIV_KEY_INFO_free(back);
    back = PKCS12_item_decrypt_d2i_ex(pbe, ASN1_ITEM_rptr(PKCS8_PRIV_KEY_INFO), "no", 2, oct, 1, NULL, NULL);
    check(back == NULL, "the wrong password");
    errors();
    back = PKCS12_item_decrypt_d2i(pbe, ASN1_ITEM_rptr(PKCS8_PRIV_KEY_INFO), "pw", 2, NULL, 1);
    check(back == NULL, "no OCTET STRING");
    errors();
    ASN1_OCTET_STRING_free(oct);
    oct = PKCS12_item_i2d_encrypt_ex(pbe, ASN1_ITEM_rptr(PKCS8_PRIV_KEY_INFO), "pw", 2, p8inf, 0, NULL, NULL);
    check(oct != NULL, "PKCS12_item_i2d_encrypt_ex");
    ASN1_OCTET_STRING_free(oct);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    X509_ALGOR_free(pbe);
}

/* Writes the key encrypted with a writer, then reads it back with the password. */
static void writers(const char *name, EVP_PKEY *k)
{
    BIO *b;
    EVP_PKEY *back;
    FILE *f;
    char what[150];

#define BACK_EQ(label) \
    (snprintf(what, sizeof(what), "%s %s", name, label), check(back != NULL && EVP_PKEY_eq(back, k) == 1, what))
    b = BIO_new(BIO_s_mem());
    check(PEM_write_bio_PKCS8PrivateKey(b, k, EVP_aes_256_cbc(), "password", 8, NULL, NULL), "PEM_write_bio_PKCS8PrivateKey encrypted");
    back = PEM_read_bio_PrivateKey(b, NULL, NULL, "password");
    BACK_EQ("read back with u as the password");
    EVP_PKEY_free(back);
    BIO_free(b);

    b = BIO_new(BIO_s_mem());
    cb_calls = 0;
    check(PEM_write_bio_PKCS8PrivateKey(b, k, EVP_aes_128_cbc(), NULL, 0, pw_cb, NULL), "with a callback's password");
    back = PEM_read_bio_PrivateKey(b, NULL, pw_cb, NULL);
    BACK_EQ("read back with the callback");
    printf("  callback calls %d\n", cb_calls);
    EVP_PKEY_free(back);
    BIO_free(b);

    b = BIO_new(BIO_s_mem());
    check(PEM_write_bio_PKCS8PrivateKey_nid(b, k, NID_pbe_WithSHA1And3_Key_TripleDES_CBC, "password", 8, NULL, NULL),
          "PEM_write_bio_PKCS8PrivateKey_nid");
    back = PEM_read_bio_PrivateKey(b, NULL, NULL, "password");
    BACK_EQ("PKCS#12 3DES read back");
    EVP_PKEY_free(back);
    BIO_free(b);

    b = BIO_new(BIO_s_mem());
    check(PEM_write_bio_PrivateKey(b, k, EVP_aes_256_cbc(), (unsigned char *)"password", 8, NULL, NULL),
          "PEM_write_bio_PrivateKey encrypted");
    {
        char line[64] = "";

        BIO_gets(b, line, sizeof(line));
        printf("  %s", line);
    }
    BIO_free(b);
    b = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(b, k, EVP_aes_256_cbc(), (unsigned char *)"password", 8, NULL, NULL);
    back = PEM_read_bio_PrivateKey(b, NULL, NULL, "password");
    BACK_EQ("PEM_write_bio_PrivateKey read back");
    EVP_PKEY_free(back);
    BIO_free(b);
    b = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(b, k, EVP_aes_256_cbc(), (unsigned char *)"password", 8, NULL, NULL);
    back = PEM_read_bio_PrivateKey(b, NULL, NULL, "wrong");
    snprintf(what, sizeof(what), "%s a wrong password fails", name);
    check(back == NULL, what);
    /*
     * The salt and IV are random, so a wrong key passes the padding check one time in 256 and
     * fails in the decoder instead: which error comes is chance, in OpenSSL too.
     */
    ERR_clear_error();
    BIO_free(b);

    b = BIO_new(BIO_s_mem());
    check(i2d_PKCS8PrivateKey_bio(b, k, EVP_aes_128_cbc(), "pw", 2, NULL, NULL), "i2d_PKCS8PrivateKey_bio encrypted");
    back = d2i_PKCS8PrivateKey_bio(b, NULL, NULL, "pw");
    BACK_EQ("d2i_PKCS8PrivateKey_bio");
    EVP_PKEY_free(back);
    BIO_free(b);
    b = BIO_new(BIO_s_mem());
    i2d_PKCS8PrivateKey_nid_bio(b, k, NID_pbe_WithSHA1And3_Key_TripleDES_CBC, "pw", 2, NULL, NULL);
    cb_calls = 0;
    back = d2i_PKCS8PrivateKey_bio(b, NULL, pw_cb, "pw");
    BACK_EQ("d2i_PKCS8PrivateKey_bio with a callback");
    EVP_PKEY_free(back);
    BIO_free(b);

    if ((f = tmpfile()) != NULL) {
        EVP_PKEY *into = NULL;

        check(i2d_PKCS8PrivateKey_fp(f, k, EVP_aes_128_cbc(), "pw", 2, NULL, NULL), "i2d_PKCS8PrivateKey_fp");
        rewind(f);
        back = d2i_PKCS8PrivateKey_fp(f, &into, NULL, "pw");
        BACK_EQ("d2i_PKCS8PrivateKey_fp");
        check(back == into, "into *x too");
        EVP_PKEY_free(back);
        fclose(f);
    }
    if ((f = tmpfile()) != NULL) {
        check(PEM_write_PKCS8PrivateKey(f, k, EVP_aes_128_cbc(), "pw", 2, NULL, NULL), "PEM_write_PKCS8PrivateKey");
        check(PEM_write_PKCS8PrivateKey_nid(f, k, NID_pbe_WithSHA1And3_Key_TripleDES_CBC, "pw", 2, NULL, NULL),
              "PEM_write_PKCS8PrivateKey_nid");
        check(i2d_PKCS8PrivateKey_nid_fp(f, k, NID_pbe_WithSHA1And3_Key_TripleDES_CBC, "pw", 2, NULL, NULL),
              "i2d_PKCS8PrivateKey_nid_fp");
        rewind(f);
        back = PEM_read_PrivateKey(f, NULL, NULL, "pw");
        BACK_EQ("PEM_read_PrivateKey of the first");
        EVP_PKEY_free(back);
        fclose(f);
    }
#undef BACK_EQ
}

static void test_x509_sig_io(EVP_PKEY *k)
{
    PKCS8_PRIV_KEY_INFO *p8inf = EVP_PKEY2PKCS8(k);
    X509_SIG *p8 = PKCS8_encrypt(NID_pbe_WithSHA1And3_Key_TripleDES_CBC, NULL, "pw", 2, SALT, 8, 10, p8inf);
    BIO *b = BIO_new(BIO_s_mem());
    X509_SIG *back, *into = NULL;
    FILE *f;

    i2d_PKCS8_bio(b, p8);
    back = d2i_PKCS8_bio(b, &into);
    check(back != NULL && back == into, "d2i_PKCS8_bio");
    X509_SIG_free(back);
    if ((f = tmpfile()) != NULL) {
        i2d_PKCS8_fp(f, p8);
        rewind(f);
        back = d2i_PKCS8_fp(f, NULL);
        check(back != NULL, "d2i_PKCS8_fp");
        X509_SIG_free(back);
        fclose(f);
    }
    check(d2i_PKCS8_bio(b, NULL) == NULL, "d2i_PKCS8_bio at the end");
    ERR_clear_error();
    BIO_free(b);
    X509_SIG_free(p8);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
}

/* The encoder's EncryptedPrivateKeyInfo, then the decoder's decryption. */
static void test_codecs(EVP_PKEY *k)
{
    static const char *const outs[] = { "DER", "PEM" };
    size_t i;

    for (i = 0; i < 2; i++) {
        OSSL_ENCODER_CTX *ectx = OSSL_ENCODER_CTX_new_for_pkey(k, EVP_PKEY_KEYPAIR, outs[i],
                                                               "EncryptedPrivateKeyInfo", NULL);
        unsigned char *data = NULL;
        const unsigned char *in;
        size_t len = 0, inlen;
        EVP_PKEY *back = NULL;
        OSSL_DECODER_CTX *dctx;
        char what[100];

        OSSL_ENCODER_CTX_set_cipher(ectx, "AES-256-CBC", NULL);
        OSSL_ENCODER_CTX_set_passphrase(ectx, (const unsigned char *)"pw", 2);
        snprintf(what, sizeof(what), "the encoder's %s EncryptedPrivateKeyInfo", outs[i]);
        check(OSSL_ENCODER_to_data(ectx, &data, &len), what);
        OSSL_ENCODER_CTX_free(ectx);
        in = data;
        inlen = len;
        dctx = OSSL_DECODER_CTX_new_for_pkey(&back, outs[i], NULL, NULL, 0, NULL, NULL);
        OSSL_DECODER_CTX_set_passphrase(dctx, (const unsigned char *)"pw", 2);
        OSSL_DECODER_from_data(dctx, &in, &inlen);
        OSSL_DECODER_CTX_free(dctx);
        snprintf(what, sizeof(what), "the decoders decrypt the %s", outs[i]);
        check(back != NULL && EVP_PKEY_eq(back, k) == 1, what);
        EVP_PKEY_free(back);
        back = NULL;
        in = data;
        inlen = len;
        dctx = OSSL_DECODER_CTX_new_for_pkey(&back, outs[i], NULL, NULL, 0, NULL, NULL);
        OSSL_DECODER_CTX_set_passphrase(dctx, (const unsigned char *)"no", 2);
        snprintf(what, sizeof(what), "the wrong passphrase decodes nothing (%s)", outs[i]);
        check(!OSSL_DECODER_from_data(dctx, &in, &inlen) && back == NULL, what);
        /* The errors depend on the random salt: a wrong key's padding is sometimes valid. */
        ERR_clear_error();
        OSSL_DECODER_CTX_free(dctx);
        OPENSSL_free(data);
    }
}

int main(void)
{
    BIO *in = BIO_new_mem_buf(KEY_PEM, -1);
    EVP_PKEY *k = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL), *legacy = EVP_PKEY_new();

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("TAP version 13\n");
    BIO_free(in);
    check(k != NULL, "the key");
    if (k == NULL) {
        errors();
        return 1;
    }
    check(EVP_PKEY_set1_RSA(legacy, (RSA *)EVP_PKEY_get0_RSA(k)), "a legacy copy");
    test_encrypt(k);
    test_crypt();
    writers("provided", k);
    writers("legacy", legacy);
    test_x509_sig_io(k);
    test_codecs(k);
    EVP_PKEY_free(k);
    EVP_PKEY_free(legacy);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
