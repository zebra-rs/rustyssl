/*
 * CVE regression tests: symmetric ciphers, AEADs and digests through EVP and the low-level
 * modes API.
 */
#include "cve.h"

#include <openssl/aes.h>
#include <openssl/core_names.h>
#include <openssl/modes.h>
#include <openssl/provider.h>

static void hex(const char *what, const unsigned char *p, size_t n)
{
    char line[600] = "";
    size_t used = 0;

    for (size_t i = 0; i < n && used + 3 < sizeof(line); i++)
        used += (size_t)snprintf(line + used, sizeof(line) - used, "%02x", p[i]);
    note("%s: %s", what, line);
}

static void digest_note(const char *what, const unsigned char *p, size_t n)
{
    unsigned char md[32];

    SHA256(p, n, md);
    note("%s: %zu octets", what, n);
    hex("  sha256", md, 8);
}

static const unsigned char key32[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
                                        31, 32};
static const unsigned char iv16[16] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
                                       0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf};

/* Encrypts or decrypts `in` with `name` in pieces of `step`; returns the output length or -1. */
static int run_cipher(const char *name, int enc, const unsigned char *in, int len, int step,
                      unsigned char *out)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, name, NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int total = 0, n;

    if (c == NULL || !EVP_CipherInit_ex2(ctx, c, key32, iv16, enc, NULL)) {
        total = -1;
        goto end;
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    for (int at = 0; at < len; at += step) {
        int piece = len - at < step ? len - at : step;

        if (!EVP_CipherUpdate(ctx, out + total, &n, in + at, piece)) {
            total = -1;
            goto end;
        }
        total += n;
    }
    if (!EVP_CipherFinal_ex(ctx, out + total, &n))
        total = -1;
    else
        total += n;
end:
    ERR_clear_error();
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
    return total;
}

static void round_trips(void)
{
    static unsigned char in[4096], out[4200], back[4200];
    /* XTS lengths of 4 mod 5 blocks; CFB-128 and OCB lengths, in odd pieces. */
    static const int xts_lengths[] = {64, 144, 224, 304, 1104, 4064};
    static const int lengths[] = {1, 15, 16, 17, 63, 64, 65, 255, 1000, 4095};
    int ok;

    for (int i = 0; i < (int)sizeof(in); i++)
        in[i] = (unsigned char)(i * 31 + 7);

    ok = 1;
    for (size_t i = 0; i < sizeof(xts_lengths) / sizeof(xts_lengths[0]); i++) {
        int n = run_cipher("AES-128-XTS", 1, in, xts_lengths[i], xts_lengths[i], out);
        int m = run_cipher("AES-128-XTS", 0, out, n, n, back);

        digest_note("XTS", out, n > 0 ? (size_t)n : 0);
        if (n != xts_lengths[i] || m != n || memcmp(back, in, (size_t)n) != 0)
            ok = 0;
    }
    check(ok, "CVE-2023-1255: AES-XTS decryption of 4 mod 5 blocks reads only its input");

    ok = 1;
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        int n = run_cipher("AES-256-CFB", 1, in, lengths[i], 7, out);
        int m = run_cipher("AES-256-CFB", 0, out, n, 13, back);

        digest_note("CFB-128", out, n > 0 ? (size_t)n : 0);
        if (n != lengths[i] || m != n || memcmp(back, in, (size_t)n) != 0)
            ok = 0;
    }
    check(ok, "CVE-2026-28386: AES-CFB-128 in odd pieces reads only its input");

    ok = 1;
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        int n = run_cipher("AES-256-OCB", 1, in, lengths[i], 5, out);

        digest_note("OCB", out, n > 0 ? (size_t)n : 0);
        if (n != lengths[i])
            ok = 0;
    }
    check(ok, "CVE-2022-2097: AES-OCB encrypts all of its input, in any pieces");
}

/* An AEAD run with explicit IV length, AADs and tag; returns the output length or -1. */
static int aead(const char *name, int enc, int ivlen, const unsigned char *const *aads,
                const int *aadlens, int naad, const unsigned char *in, int len,
                unsigned char *tag, unsigned char *out)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, name, NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n, total = -1;
    int siv = strstr(name, "SIV") != NULL;

    if (c == NULL || !EVP_CipherInit_ex2(ctx, c, NULL, NULL, enc, NULL))
        goto end;
    if (ivlen > 0 && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, ivlen, NULL) <= 0)
        goto end;
    if (!enc && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) <= 0)
        goto end;
    if (!EVP_CipherInit_ex2(ctx, NULL, key32, siv ? NULL : iv16, enc, NULL))
        goto end;
    for (int i = 0; i < naad; i++)
        if (!EVP_CipherUpdate(ctx, NULL, &n, aads[i], aadlens[i]))
            goto end;
    total = 0;
    if (len > 0 || siv) {
        if (!EVP_CipherUpdate(ctx, out, &n, in, len)) {
            total = -1;
            goto end;
        }
        total = n;
    }
    if (!EVP_CipherFinal_ex(ctx, out + total, &n)) {
        total = -1;
        goto end;
    }
    total += n;
    if (enc)
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
end:
    ERR_clear_error();
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
    return total;
}

static void aeads(void)
{
    static const unsigned char msg[] = "sixteen octets!!";
    unsigned char out[64], tag1[16], tag2[16], tag3[16];
    const unsigned char *aad_empty[] = {(const unsigned char *)""};
    const unsigned char *aad_two[] = {(const unsigned char *)"", (const unsigned char *)"x"};
    int empty_len[] = {0}, two_len[] = {0, 1};
    int r12, r13;

    r12 = aead("ChaCha20-Poly1305", 1, 12, NULL, NULL, 0, msg, 16, tag1, out);
    r13 = aead("ChaCha20-Poly1305", 1, 13, NULL, NULL, 0, msg, 16, tag1, out);
    check(r12 == 16 && r13 == -1, "CVE-2019-1543: ChaCha20-Poly1305 refuses nonces over 12 octets");

    aead("AES-128-SIV", 1, 0, NULL, NULL, 0, msg, 16, tag1, out);
    aead("AES-128-SIV", 1, 0, aad_empty, empty_len, 1, msg, 16, tag2, out);
    aead("AES-128-SIV", 1, 0, aad_two, two_len, 2, msg, 16, tag3, out);
    check(memcmp(tag1, tag2, 16) != 0, "CVE-2023-2975: AES-SIV authenticates an empty AAD entry");
    hex("no AAD", tag1, 16);
    hex("one empty AAD", tag2, 16);
    hex("empty and 'x'", tag3, 16);

    {
        const char *names[] = {"AES-128-SIV", "AES-128-GCM-SIV"};
        int all = 1;

        for (int i = 0; i < 2; i++) {
            unsigned char tag[16];
            int e = aead(names[i], 1, 0, NULL, NULL, 0, msg, 0, tag, out), d;

            tag[0] ^= 1;
            d = aead(names[i], 0, 0, NULL, NULL, 0, out, 0, tag, out);
            note("%s: empty encrypt %d, decrypt with a wrong tag %d", names[i], e, d);
            if (d != -1)
                all = 0;
        }
        check(all, "CVE-2026-45446: AES-SIV and AES-GCM-SIV check the tag of an empty message");
    }
}

static void init_params(void)
{
    static const unsigned char pt[32] = "thirty-two octets of plaintext!";
    EVP_CIPHER *gcm = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char out[48], tag[16];
    size_t ivlen = 16;
    OSSL_PARAM params[2];
    int n, f, ok;

    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, &ivlen);
    params[1] = OSSL_PARAM_construct_end();
    ok = EVP_EncryptInit_ex2(ctx, gcm, key32, iv16, params) && EVP_EncryptUpdate(ctx, out, &n, pt, 32)
         && EVP_EncryptFinal_ex(ctx, out + n, &f)
         && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) > 0;
    check(ok && EVP_CIPHER_CTX_get_iv_length(ctx) == 16,
          "CVE-2023-5363: an IV length set in EVP_EncryptInit_ex2's parameters applies to its IV");
    hex("ciphertext", out, 32);
    hex("tag", tag, 16);
    ERR_clear_error();
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(gcm);
}

static void evp_cipher_path(void)
{
    static const unsigned char pt[32] = "thirty-two octets of plaintext!";
    EVP_CIPHER *ocb = EVP_CIPHER_fetch(NULL, "AES-128-OCB", NULL);
    EVP_CIPHER_CTX *a = EVP_CIPHER_CTX_new(), *b = EVP_CIPHER_CTX_new();
    unsigned char o1[48], o2[48];
    int n, r;

    EVP_EncryptInit_ex2(a, ocb, key32, iv16, NULL);
    EVP_EncryptUpdate(a, o1, &n, pt, 32);
    EVP_EncryptInit_ex2(b, ocb, key32, iv16, NULL);
    r = EVP_Cipher(b, o2, pt, 32);
    check(r >= 0 && memcmp(o1, o2, 32) == 0,
          "CVE-2026-45445: AES-OCB through EVP_Cipher uses the IV, as EVP_EncryptUpdate does");
    hex("EVP_Cipher", o2, 32);
    ERR_clear_error();
    EVP_CIPHER_CTX_free(a);
    EVP_CIPHER_CTX_free(b);

    /* An empty ciphertext with a wrong tag, decrypted through EVP_Cipher. */
    {
        const char *names[] = {"ChaCha20-Poly1305", "AES-128-OCB"};
        int all = 1;

        for (int i = 0; i < 2; i++) {
            EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, names[i], NULL);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            unsigned char tag[16] = {0}, out[16];
            int u, fin;

            EVP_DecryptInit_ex2(ctx, c, NULL, NULL, NULL);
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag);
            EVP_DecryptInit_ex2(ctx, NULL, key32, iv16, NULL);
            u = EVP_Cipher(ctx, out, out, 0);
            fin = EVP_Cipher(ctx, NULL, NULL, 0);
            note("%s: EVP_Cipher %d, final %d", names[i], u, fin);
            if (fin >= 0)
                all = 0;
            ERR_clear_error();
            EVP_CIPHER_CTX_free(ctx);
            EVP_CIPHER_free(c);
        }
        check(all, "CVE-2026-75803: an empty ciphertext with a forged tag fails through EVP_Cipher");
    }
    EVP_CIPHER_free(ocb);
}

static void low_level_ocb(void)
{
    AES_KEY enc, dec;
    OCB128_CONTEXT *ocb;
    unsigned char in[37], out[37], tag1[16], tag2[16];
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n, f;

    for (int i = 0; i < 37; i++)
        in[i] = (unsigned char)i;
    AES_set_encrypt_key(key32, 128, &enc);
    AES_set_decrypt_key(key32, 128, &dec);
    ocb = CRYPTO_ocb128_new(&enc, &dec, (block128_f)AES_encrypt, (block128_f)AES_decrypt, NULL);
    CRYPTO_ocb128_setiv(ocb, iv16, 12, 16);
    CRYPTO_ocb128_encrypt(ocb, in, out, sizeof(in));
    CRYPTO_ocb128_tag(ocb, tag1, 16);
    CRYPTO_ocb128_cleanup(ocb);
    OPENSSL_free(ocb);

    EVP_EncryptInit_ex2(ctx, EVP_aes_128_ocb(), key32, iv16, NULL);
    EVP_EncryptUpdate(ctx, out, &n, in, sizeof(in));
    EVP_EncryptFinal_ex(ctx, out + n, &f);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag2);
    check(memcmp(tag1, tag2, 16) == 0,
          "CVE-2025-69418: low-level OCB authenticates and encrypts trailing octets");
    hex("tag", tag1, 16);
    EVP_CIPHER_CTX_free(ctx);
}

static void tls_aead_records(void)
{
    /* A TLS 1.2 record of 10 octets through ChaCha20-Poly1305's TLS mode: shorter than its tag. */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char aad[13] = {0, 0, 0, 0, 0, 0, 0, 1, 0x17, 0x03, 0x03, 0x00, 0x0a};
    unsigned char rec[10] = {0};
    int pad, r = -9;

    EVP_DecryptInit_ex2(ctx, EVP_chacha20_poly1305(), key32, iv16, NULL);
    pad = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD, sizeof(aad), aad);
    if (pad > 0)
        r = EVP_Cipher(ctx, rec, rec, sizeof(rec));
    check(r <= 0, "CVE-2016-7054: a ChaCha20-Poly1305 TLS record shorter than its tag fails");
    note("TLS1_AAD %d, cipher %d", pad, r);
    ERR_clear_error();
    EVP_CIPHER_CTX_free(ctx);
}

static void stitched(void)
{
    OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
    OSSL_PROVIDER *deflt = OSSL_PROVIDER_load(NULL, "default");
    EVP_CIPHER *c;
    unsigned char mackey[20] = {9};

    /* The CBC-HMAC "stitched" ciphers (offered with AES-NI): a record of bad padding and MAC. */
    c = EVP_CIPHER_fetch(NULL, "AES-128-CBC-HMAC-SHA1", NULL);
    ERR_clear_error();
    if (c == NULL) {
        check(1, "CVE-2016-2107: a TLS CBC record with bad padding and MAC fails # skip not offered");
    } else {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        unsigned char rec[64], aad[13] = {0, 0, 0, 0, 0, 0, 0, 1, 0x17, 0x03, 0x03, 0x00, 0x40};
        int r1, r2;

        memset(rec, 0x0f, sizeof(rec));
        EVP_DecryptInit_ex2(ctx, c, key32, iv16, NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_MAC_KEY, (int)sizeof(mackey), mackey);
        r1 = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD, sizeof(aad), aad);
        r2 = EVP_Cipher(ctx, rec, rec, sizeof(rec));
        check(r2 <= 0, "CVE-2016-2107: a TLS CBC record with bad padding and MAC fails");
        note("TLS1_AAD %d, cipher %d", r1, r2);
        ERR_clear_error();
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(c);
    }

    /*
     * RC4-HMAC-MD5 (legacy): a TLS record's MAC is keyed by the MAC key, not by the AAD.
     * Upstream implements it for x86_64; elsewhere the reference fetches it but crashes using
     * it (3.6.5, aarch64 macOS), so it's only exercised on x86_64.
     */
#if defined(__x86_64__)
    c = EVP_CIPHER_fetch(NULL, "RC4-HMAC-MD5", NULL);
#else
    c = NULL;
#endif
    ERR_clear_error();
    if (c == NULL) {
        check(1, "CVE-2022-1434: RC4-HMAC-MD5 keys its MAC from the MAC key # skip not offered");
    } else {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        unsigned char rec[64], aad[13] = {0, 0, 0, 0, 0, 0, 0, 1, 0x17, 0x03, 0x03, 0x00, 0x30};
        int r1, r2;

        for (int i = 0; i < 64; i++)
            rec[i] = (unsigned char)i;
        EVP_EncryptInit_ex2(ctx, c, key32, NULL, NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_MAC_KEY, (int)sizeof(mackey), mackey);
        r1 = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD, sizeof(aad), aad);
        r2 = EVP_Cipher(ctx, rec, rec, sizeof(rec));
        check(r1 == 16 && r2 > 0, "CVE-2022-1434: RC4-HMAC-MD5 keys its MAC from the MAC key");
        hex("record", rec, sizeof(rec));
        ERR_clear_error();
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(c);
    }
    OSSL_PROVIDER_unload(legacy);
    OSSL_PROVIDER_unload(deflt);
}

static int custom_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in,
                         size_t len)
{
    (void)ctx;
    for (size_t i = 0; i < len; i++)
        out[i] = in[i] ^ 0x55;
    return 1;
}

static int custom_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv,
                       int enc)
{
    (void)ctx, (void)key, (void)iv, (void)enc;
    return 1;
}

static void custom_ciphers(void)
{
    EVP_CIPHER *meth = EVP_CIPHER_meth_new(NID_undef, 16, 16);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char out[32];
    int init, n = -1;

    EVP_CIPHER_meth_set_iv_length(meth, 16);
    EVP_CIPHER_meth_set_init(meth, custom_init);
    EVP_CIPHER_meth_set_do_cipher(meth, custom_cipher);
    init = EVP_EncryptInit_ex2(ctx, meth, key32, iv16, NULL);
    if (init)
        EVP_EncryptUpdate(ctx, out, &n, (const unsigned char *)"sixteen octets!!", 16);
    check(!init || (n == 16 && out[0] == ('s' ^ 0x55)),
          "CVE-2022-3358: a custom NID_undef cipher never becomes the NULL cipher");
    note("init %d, update %d", init, n);
    ERR_clear_error();
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_meth_free(meth);
}

static void mdc2(void)
{
    OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
    OSSL_PROVIDER *deflt = OSSL_PROVIDER_load(NULL, "default");
    EVP_MD *md = EVP_MD_fetch(NULL, "MDC2", NULL);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char data[1000], out[16];
    unsigned int len = 0;

    for (int i = 0; i < 1000; i++)
        data[i] = (unsigned char)i;
    if (md == NULL) {
        check(1, "CVE-2016-6303: MDC2 # skip MDC2 isn't offered here");
    } else {
        EVP_DigestInit_ex2(ctx, md, NULL);
        for (int at = 0, step = 1; at < 1000; at += step, step = step % 9 + 1)
            EVP_DigestUpdate(ctx, data + at, (size_t)(1000 - at < step ? 1000 - at : step));
        EVP_DigestFinal_ex(ctx, out, &len);
        check(len == 16, "CVE-2016-6303: MDC2 updates of every small length stay in bounds");
        hex("MDC2", out, len);
    }
    ERR_clear_error();
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    OSSL_PROVIDER_unload(legacy);
    OSSL_PROVIDER_unload(deflt);
}

int main(void)
{
    round_trips();
    aeads();
    init_params();
    evp_cipher_path();
    low_level_ocb();
    tls_aead_records();
    stitched();
    custom_ciphers();
    mdc2();
    return finish();
}
