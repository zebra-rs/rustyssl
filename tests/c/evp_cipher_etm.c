/*
 * Conformance test for OpenSSL 3.6's AES-CBC-HMAC-SHA1-ETM, -SHA256-ETM, and -SHA512-ETM
 * ciphers (EVP_EncryptInit(3), provider-cipher(7)), in TAP format. The reference offers them
 * only on aarch64 with the AES and SHA instructions; elsewhere both libraries fetch none, and
 * the test says so.
 *
 * Each update is a message of its own: CBC from the IV as set, and HMAC over its ciphertext,
 * the tag to get after an encryption and to check in a decryption.
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}
static void hex(const char *l, const unsigned char *b, size_t n)
{
    printf("%s:", l);
    for (size_t i = 0; i < n; i++)
        printf("%02x", b[i]);
    printf("\n");
}

static void errs(void)
{
    unsigned long e;
    printf("  errors:");
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
}

static unsigned char key[32], iv[16], mk[200], data[256];

static int run(const char *name, const char *md, int enc, size_t mklen, const unsigned char *in,
               size_t inl, unsigned char *out, int split, unsigned char *tag, size_t taglen,
               const unsigned char *exp, size_t explen)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, name, NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    OSSL_PARAM p[3];
    int n = 0, m = 0, r;

    (void)md;
    if (c == NULL) {
        printf("# %s: none\n", name);
        ERR_clear_error();
        return 0;
    }
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_MAC_KEY, mk, mklen);
    p[1] = OSSL_PARAM_construct_end();
    if (exp != NULL) {
        p[1] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_HMAC_PARAM_MAC, (void *)exp, explen);
        p[2] = OSSL_PARAM_construct_end();
    }
    r = EVP_CipherInit_ex2(ctx, c, key, iv, enc, p);
    printf("  init %d flags %lx\n", r, (unsigned long)EVP_CIPHER_get_flags(c));
    if (split) {
        r = EVP_CipherUpdate(ctx, out, &n, in, split);
        printf("  update1 %d %d\n", r, n);
        r = EVP_CipherUpdate(ctx, out + n, &m, in + split, (int)inl - split);
        printf("  update2 %d %d\n", r, m);
    } else {
        r = EVP_CipherUpdate(ctx, out, &n, in, (int)inl);
        printf("  update %d %d\n", r, n);
    }
    r = EVP_CipherFinal_ex(ctx, out + n + m, &m);
    printf("  final %d %d\n", r, m);
    if (tag != NULL) {
        p[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_HMAC_PARAM_MAC, tag, taglen);
        p[1] = OSSL_PARAM_construct_end();
        printf("  get tag %d\n", EVP_CIPHER_CTX_get_params(ctx, p));
    }
    {
        unsigned char u[16];
        EVP_CIPHER_CTX_get_updated_iv(ctx, u, 16);
        hex("  updated iv", u, 16);
    }
    errs();
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
    return 1;
}

static void one(const char *name, const char *aes, const char *md, size_t dlen)
{
    unsigned char ct[96], ct2[96], pt[96], ref[96], tag[64], tag2[64], h[64], h2[64];
    unsigned int hl = 0, hl2 = 0;
    int n = 0;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();

    printf("# %s\n", name);
    memset(tag, 0, sizeof(tag));
    if (!run(name, md, 1, 20, data, 64, ct, 0, tag, dlen, NULL, 0))
        return;
    hex("  ct", ct, 64);
    hex("  tag", tag, dlen);
    EVP_EncryptInit_ex2(c, EVP_get_cipherbyname(aes), key, iv, NULL);
    EVP_CIPHER_CTX_set_padding(c, 0);
    EVP_EncryptUpdate(c, ref, &n, data, 64);
    check(memcmp(ref, ct, 64) == 0, "cbc same");
    HMAC(EVP_get_digestbyname(md), mk, 20, ct, 64, h, &hl);
    check(memcmp(h, tag, dlen) == 0, "hmac(ct) same");
    {
        unsigned char ivct[80];
        memcpy(ivct, iv, 16);
        memcpy(ivct + 16, ct, 64);
        HMAC(EVP_get_digestbyname(md), mk, 20, ivct, 80, h2, &hl2);
        check(memcmp(h2, tag, dlen) != 0, "the tag doesn't cover the IV");
    }
    HMAC(EVP_get_digestbyname(md), mk, 20, data, 64, h2, &hl2);
    check(memcmp(h2, tag, dlen) != 0, "nor the plaintext");
    memset(tag2, 0, sizeof(tag2));
    run(name, md, 1, 20, data, 64, ct2, 16, tag2, dlen, NULL, 0);
    check(memcmp(ct2, ct, 16) == 0 && memcmp(ct2 + 16, ct + 16, 48) != 0,
          "a second update starts from the IV as set again");
    hex("  split tag", tag2, dlen);
    HMAC(EVP_get_digestbyname(md), mk, 20, ct2 + 16, 48, h2, &hl2);
    check(memcmp(h2, tag2, dlen) == 0, "the tag is the last update's");
    /* a long MAC key */
    run(name, md, 1, 150, data, 32, ct2, 0, tag2, dlen, NULL, 0);
    HMAC(EVP_get_digestbyname(md), mk, 150, ct2, 32, h2, &hl2);
    check(memcmp(h2, tag2, dlen) == 0, "long key hmac same");
    /* odd lengths */
    run(name, md, 1, 20, data, 20, ct2, 0, tag2, dlen, NULL, 0);
    run(name, md, 1, 20, data, 0, ct2, 0, tag2, dlen, NULL, 0);
    /* tag sizes */
    run(name, md, 1, 20, data, 32, ct2, 0, tag2, 0, NULL, 0);
    run(name, md, 1, 20, data, 32, ct2, 0, tag2, 65, NULL, 0);
    run(name, md, 1, 20, data, 32, ct2, 0, tag2, 4, NULL, 0);
    hex("  short tag", tag2, 4);
    /* decrypt with the right tag */
    run(name, md, 0, 20, ct, 64, pt, 0, NULL, 0, tag, dlen);
    check(memcmp(pt, data, 64) == 0, "pt same");
    run(name, md, 0, 20, ct, 64, pt, 0, NULL, 0, tag, 8);
    tag[0] ^= 1;
    run(name, md, 0, 20, ct, 64, pt, 0, NULL, 0, tag, dlen);
    tag[0] ^= 1;
    run(name, md, 0, 20, ct, 64, pt, 0, NULL, 0, NULL, 0);
    run(name, md, 0, 20, ct, 64, pt, 16, NULL, 0, tag, dlen);
    /* decrypt get tag */
    run(name, md, 0, 20, ct, 64, pt, 0, tag2, dlen, tag, dlen);
    /* in place */
    memcpy(ct2, ct, 64);
    run(name, md, 0, 20, ct2, 64, ct2, 0, NULL, 0, tag, dlen);
    check(memcmp(ct2, data, 64) == 0, "in place pt same");
    EVP_CIPHER_CTX_free(c);
}

static void main_etm(void)
{
    static const char *names[] = { "AES-128-CBC-HMAC-SHA1-ETM", "AES-192-CBC-HMAC-SHA256-ETM",
                                   "AES-256-CBC-HMAC-SHA512-ETM" };
    static const char *aes[] = { "AES-128-CBC", "AES-192-CBC", "AES-256-CBC" };
    static const char *md[] = { "SHA1", "SHA256", "SHA512" };
    static const size_t dl[] = { 20, 32, 64 };

    for (size_t i = 0; i < sizeof(key); i++)
        key[i] = (unsigned char)(i * 3 + 1);
    for (size_t i = 0; i < sizeof(iv); i++)
        iv[i] = (unsigned char)(i * 5 + 2);
    for (size_t i = 0; i < sizeof(mk); i++)
        mk[i] = (unsigned char)(i * 7 + 3);
    for (size_t i = 0; i < sizeof(data); i++)
        data[i] = (unsigned char)(i * 11 + 4);
    for (int i = 0; i < 3; i++)
        one(names[i], aes[i], md[i], dl[i]);
    {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-CBC-HMAC-SHA256-ETM", NULL);
        const OSSL_PARAM *q;

        if (c == NULL) {
            ERR_clear_error();
            return;
        }
        printf("# lists\n");
        for (q = EVP_CIPHER_gettable_params(c); q && q->key; q++) printf(" g %s/%u", q->key, q->data_type);
        printf("\n");
        for (q = EVP_CIPHER_gettable_ctx_params(c); q && q->key; q++) printf(" gc %s/%u", q->key, q->data_type);
        printf("\n");
        for (q = EVP_CIPHER_settable_ctx_params(c); q && q->key; q++) printf(" sc %s/%u", q->key, q->data_type);
        printf("\n");
        printf("  keylen %d ivlen %d block %d mode %lx nid %d name %s\n", EVP_CIPHER_get_key_length(c),
               EVP_CIPHER_get_iv_length(c), EVP_CIPHER_get_block_size(c),
               (unsigned long)EVP_CIPHER_get_mode(c), EVP_CIPHER_get_nid(c), EVP_CIPHER_get0_name(c));
        EVP_CIPHER_free(c);
    }
}


/* Encrypts `len` octets in one update, with `params` at init (NULL: none) and `later` set
 * after init; returns the tag. */
static void enc(const char *name, size_t len, OSSL_PARAM *params, OSSL_PARAM *later,
                unsigned char *ct, unsigned char *tag, size_t taglen)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, name, NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    OSSL_PARAM p[2];
    int n = 0;

    EVP_EncryptInit_ex2(ctx, c, key, iv, params);
    if (later != NULL)
        printf("  later %d\n", EVP_CIPHER_CTX_set_params(ctx, later));
    printf("  update %d\n", EVP_EncryptUpdate(ctx, ct, &n, data, (int)len));
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_HMAC_PARAM_MAC, tag, taglen);
    p[1] = OSSL_PARAM_construct_end();
    printf("  get %d\n", EVP_CIPHER_CTX_get_params(ctx, p));
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
}

static void raw(void)
{
    unsigned char ct[256], tag[64], h[64], h2[64];
    unsigned int hl;
    OSSL_PARAM p[2];
    SHA_CTX s;
    SHA256_CTX s2;
    SHA512_CTX s5;

    for (size_t i = 0; i < sizeof(key); i++)
        key[i] = (unsigned char)(i * 3 + 1);
    for (size_t i = 0; i < sizeof(iv); i++)
        iv[i] = (unsigned char)(i * 5 + 2);
    for (size_t i = 0; i < sizeof(mk); i++)
        mk[i] = (unsigned char)(i * 7 + 3);
    for (size_t i = 0; i < sizeof(data); i++)
        data[i] = (unsigned char)(i * 11 + 4);

    {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-CBC-HMAC-SHA512-ETM", NULL);

        if (c == NULL) {
            printf("# no ETM ciphers\n");
            ERR_clear_error();
            return;
        }
        EVP_CIPHER_free(c);
    }
    printf("# no MAC key, SHA1\n");
    enc("AES-128-CBC-HMAC-SHA1-ETM", 48, NULL, NULL, ct, tag, 20);
    hex("  tag", tag, 20);
    SHA1(ct, 48, h);
    SHA1(h, 20, h2);
    check(memcmp(h2, tag, 20) != 0, "without a MAC key the tag isn't H(H(ct))");
    SHA1_Init(&s);
    s.Nl = 512;
    SHA1_Update(&s, ct, 48);
    SHA1_Final(h, &s);
    SHA1_Init(&s);
    s.Nl = 512;
    SHA1_Update(&s, h, 20);
    SHA1_Final(h2, &s);
    check(memcmp(h2, tag, 20) == 0, "but continues from the initial state, counting a block");

    printf("# no MAC key, SHA256\n");
    enc("AES-128-CBC-HMAC-SHA256-ETM", 48, NULL, NULL, ct, tag, 32);
    hex("  tag", tag, 32);
    SHA256(ct, 48, h);
    SHA256(h, 32, h2);
    check(memcmp(h2, tag, 32) != 0, "without a MAC key the tag isn't H(H(ct))");
    SHA256_Init(&s2);
    s2.Nl = 512;
    SHA256_Update(&s2, ct, 48);
    SHA256_Final(h, &s2);
    SHA256_Init(&s2);
    s2.Nl = 512;
    SHA256_Update(&s2, h, 32);
    SHA256_Final(h2, &s2);
    check(memcmp(h2, tag, 32) == 0, "but continues from the initial state, counting a block");

    printf("# no MAC key, SHA512\n");
    enc("AES-128-CBC-HMAC-SHA512-ETM", 48, NULL, NULL, ct, tag, 64);
    hex("  tag", tag, 64);
    SHA512(ct, 48, h);
    SHA512(h, 64, h2);
    check(memcmp(h2, tag, 64) != 0, "without a MAC key the tag isn't H(H(ct))");
    SHA512_Init(&s5);
    s5.Nl = 1024;
    SHA512_Update(&s5, ct, 48);
    SHA512_Final(h, &s5);
    SHA512_Init(&s5);
    s5.Nl = 1024;
    SHA512_Update(&s5, h, 64);
    SHA512_Final(h2, &s5);
    check(memcmp(h2, tag, 64) == 0, "but continues from the initial state, counting a block");

    printf("# key after init\n");
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_MAC_KEY, mk, 20);
    p[1] = OSSL_PARAM_construct_end();
    enc("AES-128-CBC-HMAC-SHA256-ETM", 48, NULL, p, ct, tag, 32);
    HMAC(EVP_sha256(), mk, 20, ct, 48, h, &hl);
    check(memcmp(h, tag, 32) == 0, "hmac");
    printf("# a long message, SHA512\n");
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_MAC_KEY, mk, 129);
    enc("AES-256-CBC-HMAC-SHA512-ETM", 256, p, NULL, ct, tag, 64);
    HMAC(EVP_sha512(), mk, 129, ct, 256, h, &hl);
    check(memcmp(h, tag, 64) == 0, "hmac");
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_MAC_KEY, mk, 128);
    enc("AES-256-CBC-HMAC-SHA512-ETM", 256, p, NULL, ct, tag, 64);
    HMAC(EVP_sha512(), mk, 128, ct, 256, h, &hl);
    check(memcmp(h, tag, 64) == 0, "hmac 128");
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_MAC_KEY, mk, 65);
    enc("AES-256-CBC-HMAC-SHA1-ETM", 256, p, NULL, ct, tag, 20);
    HMAC(EVP_sha1(), mk, 65, ct, 256, h, &hl);
    check(memcmp(h, tag, 20) == 0, "hmac sha1 65");
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_MAC_KEY, mk, 0);
    enc("AES-256-CBC-HMAC-SHA1-ETM", 16, p, NULL, ct, tag, 20);
    HMAC(EVP_sha1(), "", 0, ct, 16, h, &hl);
    check(memcmp(h, tag, 20) == 0, "hmac sha1 empty key");
    p[0] = OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_AEAD_MAC_KEY, (int *)mk);
    enc("AES-256-CBC-HMAC-SHA1-ETM", 16, p, NULL, ct, tag, 20);
    {
        unsigned long e;
        while ((e = ERR_get_error()) != 0)
            printf("  error %d/%d\n", ERR_GET_LIB(e), ERR_GET_REASON(e));
    }
    /* keylen */
    {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-CBC-HMAC-SHA1-ETM", NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        unsigned long e;
        EVP_EncryptInit_ex2(ctx, c, NULL, NULL, NULL);
        printf("  keylen 16: %d\n", EVP_CIPHER_CTX_set_key_length(ctx, 16));
        printf("  keylen 32: %d\n", EVP_CIPHER_CTX_set_key_length(ctx, 32));
        printf("  padding: %d\n", EVP_CIPHER_CTX_set_padding(ctx, 0));
        printf("  no key update: %d\n", EVP_EncryptUpdate(ctx, ct, (int *)&hl, data, 16));
        while ((e = ERR_get_error()) != 0)
            printf("  error %d/%d\n", ERR_GET_LIB(e), ERR_GET_REASON(e));
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(c);
    }
}

int main(void)
{
    main_etm();
    raw();
    check(1, "done");
    printf("1..%d\n", number);
    return failures != 0;
}
