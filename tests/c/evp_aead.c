/*
 * Conformance test for the AEAD ciphers (EVP_EncryptInit(3)'s "AEAD Interface",
 * EVP_CIPHER-AES(7), EVP_CIPHER-CHACHA(7)), in TAP format, over the default provider's GCM and
 * CCM (AES, ARIA, SM4), AES-OCB, and ChaCha20-Poly1305: their lengths, flags, and parameter
 * lists; encrypting and decrypting with AAD and data in pieces, with every tag length and
 * several IV lengths; tags that don't authenticate (and the output wiped); misuse (AAD after
 * data, CCM without its lengths, finals twice, a tag set when encrypting); the TLS record modes
 * (GCM's fixed and generated IVs, CCM's, ChaCha20-Poly1305's); EVP_Cipher; the IV parameters;
 * and copies mid-message.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>

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
    unsigned long code;

    printf("  errors:");
    while ((code = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
    printf("\n");
}

static void hex(const char *label, const unsigned char *p, int n)
{
    int i;

    printf("  %s:", label);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static unsigned char key[32], iv[128], aad[100], data[300];

static const char *names[] = {
    "AES-256-GCM", "AES-192-GCM", "AES-128-GCM", "ARIA-256-GCM", "ARIA-192-GCM", "ARIA-128-GCM",
    "SM4-GCM", "AES-256-CCM", "AES-192-CCM", "AES-128-CCM", "ARIA-256-CCM", "ARIA-192-CCM",
    "ARIA-128-CCM", "SM4-CCM", "AES-256-OCB", "AES-192-OCB", "AES-128-OCB", "ChaCha20-Poly1305",
    NULL
};

static int is_ccm(const EVP_CIPHER *c)
{
    return EVP_CIPHER_get_mode(c) == EVP_CIPH_CCM_MODE;
}

static void print_list(const char *label, const OSSL_PARAM *p)
{
    printf("  %s:", label);
    for (; p != NULL && p->key != NULL; p++)
        printf(" %s/%u/%zu", p->key, p->data_type, p->data_size);
    printf("\n");
}

/*
 * One message: init (CCM: tag length, then the key, then the message length), AAD in two
 * pieces, data in pieces of `piece`, final, the tag; then decrypting it with the tag.
 */
static void message(EVP_CIPHER *c, int ivlen, int taglen, int aadlen, int len, int piece)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char out[400], back[400], tag[16];
    int n, total = 0, at, step, ok = 1, ccm = is_ccm(c);
    size_t sz = (size_t)ivlen;
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, &sz);
    params[1] = OSSL_PARAM_construct_end();
    ok &= EVP_EncryptInit_ex2(ctx, c, NULL, NULL, ivlen > 0 ? params : NULL);
    if (ccm || EVP_CIPHER_get_mode(c) == EVP_CIPH_OCB_MODE)
        ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, taglen, NULL);
    ok &= EVP_EncryptInit_ex2(ctx, NULL, key, iv, NULL);
    if (ccm)
        ok &= EVP_EncryptUpdate(ctx, NULL, &n, NULL, len);
    if (aadlen > 0 && ccm) {
        /* CCM takes its AAD in one piece: each call starts the MAC again. */
        ok &= EVP_EncryptUpdate(ctx, NULL, &n, aad, aadlen);
    } else if (aadlen > 0) {
        ok &= EVP_EncryptUpdate(ctx, NULL, &n, aad, aadlen / 3);
        ok &= EVP_EncryptUpdate(ctx, NULL, &n, aad + aadlen / 3, aadlen - aadlen / 3);
    }
    for (at = 0; ok && at < len; at += step) {
        step = ccm ? len : (len - at < piece ? len - at : piece);
        ok &= EVP_EncryptUpdate(ctx, out + total, &n, data + at, step);
        total += n;
    }
    ok &= EVP_EncryptFinal_ex(ctx, out + total, &n);
    total += n;
    memset(tag, 0, sizeof(tag));
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, taglen, tag);
    printf("  iv %d tag %d aad %d len %d piece %d: %d %d\n", ivlen, taglen, aadlen, len, piece,
           ok, total);
    if (!ok) {
        errors();
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    hex("out", out, total);
    hex("tag", tag, taglen);
    ok = EVP_DecryptInit_ex2(ctx, c, NULL, NULL, ivlen > 0 ? params : NULL);
    if (ccm || EVP_CIPHER_get_mode(c) == EVP_CIPH_OCB_MODE)
        ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, taglen, NULL);
    ok &= EVP_DecryptInit_ex2(ctx, NULL, key, iv, NULL);
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, taglen, tag);
    if (ccm)
        ok &= EVP_DecryptUpdate(ctx, NULL, &n, NULL, total);
    if (aadlen > 0)
        ok &= EVP_DecryptUpdate(ctx, NULL, &n, aad, aadlen);
    ok &= EVP_DecryptUpdate(ctx, back, &n, out, total);
    at = n;
    ok &= EVP_DecryptFinal_ex(ctx, back + at, &n);
    check(ok && at + n == len && memcmp(back, data, len) == 0, "decrypts back");
    if (!ok)
        errors();
    /* A tag that doesn't authenticate. */
    tag[0] ^= 0x80;
    EVP_DecryptInit_ex2(ctx, c, NULL, NULL, ivlen > 0 ? params : NULL);
    if (ccm || EVP_CIPHER_get_mode(c) == EVP_CIPH_OCB_MODE)
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, taglen, NULL);
    EVP_DecryptInit_ex2(ctx, NULL, key, iv, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, taglen, tag);
    if (ccm)
        EVP_DecryptUpdate(ctx, NULL, &n, NULL, total);
    if (aadlen > 0)
        EVP_DecryptUpdate(ctx, NULL, &n, aad, aadlen);
    memset(back, 0xa5, sizeof(back));
    ok = EVP_DecryptUpdate(ctx, back, &n, out, total);
    printf("  bad tag: update %d", ok);
    ok = EVP_DecryptFinal_ex(ctx, back + (ok ? n : 0), &n);
    printf(" final %d\n", ok);
    hex("output", back, len < 24 ? len : 24);
    errors();
    EVP_CIPHER_CTX_free(ctx);
}

static void each_cipher(void)
{
    const char **n;

    for (n = names; *n != NULL; n++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, *n, NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int ccm, ocb, chacha, t;

        printf("# %s\n", *n);
        check(c != NULL, "fetched");
        if (c == NULL) {
            errors();
            continue;
        }
        ccm = is_ccm(c);
        ocb = EVP_CIPHER_get_mode(c) == EVP_CIPH_OCB_MODE;
        chacha = EVP_CIPHER_get_mode(c) == 0;
        printf("  nid %d type %d block %d key %d iv %d flags %lx mode %d\n", EVP_CIPHER_get_nid(c),
               EVP_CIPHER_get_type(c), EVP_CIPHER_get_block_size(c), EVP_CIPHER_get_key_length(c),
               EVP_CIPHER_get_iv_length(c), EVP_CIPHER_get_flags(c), EVP_CIPHER_get_mode(c));
        print_list("gettable ctx", EVP_CIPHER_gettable_ctx_params(c));
        print_list("settable ctx", EVP_CIPHER_settable_ctx_params(c));
        EVP_EncryptInit_ex2(ctx, c, NULL, NULL, NULL);
        printf("  ctx: iv %d key %d tag %d\n", EVP_CIPHER_CTX_get_iv_length(ctx),
               EVP_CIPHER_CTX_get_key_length(ctx), EVP_CIPHER_CTX_get_tag_length(ctx));
        EVP_CIPHER_CTX_free(ctx);
        message(c, 0, 16, 20, 100, 7);
        message(c, 0, 16, 0, 0, 1);
        message(c, 0, ccm ? 4 : 16, 50, 33, 16);
        if (ccm) {
            message(c, 7, 6, 3, 40, 40);
            message(c, 13, 16, 0, 17, 17);
            message(c, 10, 10, 66, 65, 65);
        } else if (ocb) {
            for (t = 1; t <= 16; t += 5)
                message(c, 12, t, 17, 49, 16);
            message(c, 1, 16, 16, 64, 32);
            message(c, 15, 8, 33, 31, 5);
        } else if (chacha) {
            message(c, 0, 1, 7, 64, 64);
            message(c, 12, 12, 0, 129, 33);
        } else {
            for (t = 1; t <= 16; t += 3)
                message(c, 12, t, 3, 17, 4);
            message(c, 1, 16, 10, 40, 40);
            message(c, 16, 16, 16, 32, 16);
            message(c, 60, 13, 5, 70, 9);
            message(c, 128, 16, 0, 15, 15);
        }
        EVP_CIPHER_free(c);
    }
}

static void misuse(void)
{
    static const char *which[] = { "AES-128-GCM", "AES-128-CCM", "AES-128-OCB", "ChaCha20-Poly1305",
                                   NULL };
    const char **w;

    printf("# misuse\n");
    for (w = which; *w != NULL; w++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, *w, NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        unsigned char out[64], tag[16];
        int n = 0;

        printf("# %s\n", *w);
        /* No key, no IV. */
        printf("  no key: init %d", EVP_EncryptInit_ex2(ctx, c, NULL, NULL, NULL));
        printf(" update %d", EVP_EncryptUpdate(ctx, out, &n, data, 16));
        printf(" final %d\n", EVP_EncryptFinal_ex(ctx, out, &n));
        errors();
        /* A key and no IV: GCM makes one up when encrypting. */
        printf("  no iv: init %d", EVP_EncryptInit_ex2(ctx, c, key, NULL, NULL));
        printf(" update %d %d", EVP_EncryptUpdate(ctx, out, &n, data, 16), n);
        printf(" final %d\n", EVP_EncryptFinal_ex(ctx, out, &n));
        errors();
        /* AAD after data; data after the final; a second final. */
        EVP_EncryptInit_ex2(ctx, c, key, iv, NULL);
        if (is_ccm(c))
            EVP_EncryptUpdate(ctx, NULL, &n, NULL, 16);
        printf("  data %d", EVP_EncryptUpdate(ctx, out, &n, data, 16));
        printf(" aad after %d", EVP_EncryptUpdate(ctx, NULL, &n, aad, 5));
        printf(" final %d", EVP_EncryptFinal_ex(ctx, out, &n));
        printf(" again %d", EVP_EncryptFinal_ex(ctx, out, &n));
        printf(" data after %d\n", EVP_EncryptUpdate(ctx, out, &n, data, 16));
        errors();
        /* Tags: getting one too long, setting one when encrypting, decrypting without one. */
        printf("  tag 17 %d", EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 17, tag));
        printf(" tag 0 %d", EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 0, tag));
        printf(" set when encrypting %d\n", EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag));
        errors();
        EVP_DecryptInit_ex2(ctx, c, key, iv, NULL);
        if (is_ccm(c))
            printf("  ccm aad before length %d", EVP_DecryptUpdate(ctx, NULL, &n, aad, 4));
        printf("  decrypt without a tag: update %d", EVP_DecryptUpdate(ctx, out, &n, data, 16));
        printf(" final %d\n", EVP_DecryptFinal_ex(ctx, out, &n));
        errors();
        printf("  tag lengths:");
        for (n = 0; n <= 18; n += 3)
            printf(" %d", EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, n, NULL));
        printf("\n");
        errors();
        printf("  iv lengths:");
        for (n = 0; n <= 16; n += 2)
            printf(" %d", EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, n, NULL));
        printf(" ccm L 1 %d 9 %d 3 %d\n", EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_L, 1, NULL),
               EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_L, 9, NULL),
               EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_L, 3, NULL));
        printf("  iv length now %d\n", EVP_CIPHER_CTX_get_iv_length(ctx));
        errors();
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(c);
    }
}

static void show_ivs(EVP_CIPHER_CTX *ctx)
{
    unsigned char buf[32];
    int len = EVP_CIPHER_CTX_get_iv_length(ctx), r;

    memset(buf, 0, sizeof(buf));
    r = EVP_CIPHER_CTX_get_original_iv(ctx, buf, len > 0 ? (size_t)len : 0);
    printf("  original iv %d", r);
    hex("", buf, len > 0 && len < 32 ? len : 0);
    memset(buf, 0, sizeof(buf));
    r = EVP_CIPHER_CTX_get_updated_iv(ctx, buf, 16);
    printf("  updated iv %d", r);
    hex("", buf, 16);
    errors();
}

static void ivs(void)
{
    static const char *which[] = { "AES-128-GCM", "AES-128-CCM", "AES-128-OCB", NULL };
    const char **w;

    printf("# IVs\n");
    for (w = which; *w != NULL; w++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, *w, NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        unsigned char out[64];
        int n = 0;
        unsigned int gen = 9;
        OSSL_PARAM params[2];

        printf("# %s\n", *w);
        EVP_EncryptInit_ex2(ctx, c, key, NULL, NULL);
        show_ivs(ctx);
        EVP_EncryptInit_ex2(ctx, NULL, NULL, iv, NULL);
        show_ivs(ctx);
        if (is_ccm(c))
            EVP_EncryptUpdate(ctx, NULL, &n, NULL, 16);
        EVP_EncryptUpdate(ctx, out, &n, data, 16);
        show_ivs(ctx);
        params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_AEAD_IV_GENERATED, &gen);
        params[1] = OSSL_PARAM_construct_end();
        printf("  iv generated %d %u\n", EVP_CIPHER_CTX_get_params(ctx, params), gen);
        errors();
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(c);
    }
}

/* A GCM record as libssl makes it: fixed IV, generated explicit IV, AAD, then in place. */
static void tls_gcm(void)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-GCM", NULL);
    EVP_CIPHER_CTX *enc = EVP_CIPHER_CTX_new(), *dec = EVP_CIPHER_CTX_new();
    unsigned char rec[80], a[13], gen[12];
    int r, i;

    printf("# TLS GCM\n");
    memcpy(a, aad, 13);
    a[11] = 0;
    a[12] = 48; /* the explicit IV and the payload */
    EVP_EncryptInit_ex2(enc, c, key, NULL, NULL);
    printf("  fixed %d", EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_AEAD_SET_IV_FIXED, 4, iv));
    printf(" short %d", EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_AEAD_SET_IV_FIXED, 3, iv));
    printf(" whole %d\n", EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_AEAD_SET_IV_FIXED, -1, iv));
    errors();
    EVP_DecryptInit_ex2(dec, c, key, NULL, NULL);
    printf("  dec fixed %d\n", EVP_CIPHER_CTX_ctrl(dec, EVP_CTRL_AEAD_SET_IV_FIXED, 4, iv));
    for (i = 0; i < 3; i++) {
        memset(rec, 0, sizeof(rec));
        memcpy(rec + 8, data + i, 40);
        printf("  aad pad %d", EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_AEAD_TLS1_AAD, 13, a));
        r = EVP_Cipher(enc, rec, rec, 8 + 40 + 16);
        printf(" encrypt %d\n", r);
        hex("record", rec, 64);
        a[12] = 40 + 8 + 16;
        printf("  dec aad pad %d", EVP_CIPHER_CTX_ctrl(dec, EVP_CTRL_AEAD_TLS1_AAD, 13, a));
        a[12] = 48;
        if (i == 2)
            rec[20] ^= 1;
        r = EVP_Cipher(dec, rec, rec, 8 + 40 + 16);
        /* GCM's EVP_Cipher reports the whole record's length. */
        printf(" decrypt %d\n", r);
        check(r == (i == 2 ? -1 : 64) && (i == 2 || memcmp(rec + 8, data + i, 40) == 0),
              "the record decrypts");
        hex("payload", rec + 8, 8);
    }
    errors();
    printf("  short record: aad %d", EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_AEAD_TLS1_AAD, 13, a));
    printf(" cipher %d\n", EVP_Cipher(enc, rec, rec, 20));
    printf("  short aad %d\n", EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_AEAD_TLS1_AAD, 12, a));
    errors();
    /* The IV generator. */
    EVP_EncryptInit_ex2(enc, c, key, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_AEAD_SET_IV_FIXED, -1, iv);
    for (i = 0; i < 2; i++) {
        memset(gen, 0, sizeof(gen));
        printf("  iv gen %d", EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_GCM_IV_GEN, 8, gen));
        hex("", gen, 12);
    }
    printf("  iv gen all %d", EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_GCM_IV_GEN, -1, gen));
    hex("", gen, 12);
    EVP_DecryptInit_ex2(dec, c, key, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(dec, EVP_CTRL_AEAD_SET_IV_FIXED, 4, iv);
    printf("  iv inv %d\n", EVP_CIPHER_CTX_ctrl(dec, EVP_CTRL_GCM_SET_IV_INV, 8, gen + 4));
    printf("  iv inv when encrypting %d\n",
           EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_GCM_SET_IV_INV, 8, gen + 4));
    errors();
    EVP_CIPHER_CTX_free(enc);
    EVP_CIPHER_CTX_free(dec);
    EVP_CIPHER_free(c);
}

static void tls_ccm(void)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-256-CCM", NULL);
    EVP_CIPHER_CTX *enc = EVP_CIPHER_CTX_new(), *dec = EVP_CIPHER_CTX_new();
    unsigned char rec[80], a[13];
    int r, i;

    printf("# TLS CCM\n");
    memcpy(a, aad, 13);
    a[11] = 0;
    a[12] = 48;
    EVP_EncryptInit_ex2(enc, c, NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);
    EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_AEAD_SET_TAG, 16, NULL);
    EVP_EncryptInit_ex2(enc, NULL, key, NULL, NULL);
    printf("  fixed %d %d\n", EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_AEAD_SET_IV_FIXED, 4, iv),
           EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_AEAD_SET_IV_FIXED, 8, iv));
    EVP_DecryptInit_ex2(dec, c, NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(dec, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);
    EVP_CIPHER_CTX_ctrl(dec, EVP_CTRL_AEAD_SET_TAG, 16, NULL);
    EVP_DecryptInit_ex2(dec, NULL, key, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(dec, EVP_CTRL_AEAD_SET_IV_FIXED, 4, iv);
    errors();
    for (i = 0; i < 2; i++) {
        memset(rec, 0, sizeof(rec));
        memcpy(rec + 8, data + i, 40);
        printf("  aad pad %d", EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_AEAD_TLS1_AAD, 13, a));
        r = EVP_Cipher(enc, rec, rec, 8 + 40 + 16);
        printf(" encrypt %d\n", r);
        hex("record", rec, 64);
        a[12] = 64;
        printf("  dec aad pad %d", EVP_CIPHER_CTX_ctrl(dec, EVP_CTRL_AEAD_TLS1_AAD, 13, a));
        a[12] = 48;
        if (i == 1)
            rec[30] ^= 1;
        r = EVP_Cipher(dec, rec, rec, 8 + 40 + 16);
        printf(" decrypt %d\n", r);
        hex("payload", rec + 8, 8);
    }
    errors();
    EVP_CIPHER_CTX_free(enc);
    EVP_CIPHER_CTX_free(dec);
    EVP_CIPHER_free(c);
}

static void tls_chacha(void)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "ChaCha20-Poly1305", NULL);
    EVP_CIPHER_CTX *enc = EVP_CIPHER_CTX_new(), *dec = EVP_CIPHER_CTX_new();
    unsigned char rec[300], a[13];
    int r, i, plen;

    printf("# TLS ChaCha20-Poly1305\n");
    EVP_EncryptInit_ex2(enc, c, key, NULL, NULL);
    EVP_DecryptInit_ex2(dec, c, key, NULL, NULL);
    printf("  fixed %d %d", EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_AEAD_SET_IV_FIXED, 12, iv),
           EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_AEAD_SET_IV_FIXED, 8, iv));
    printf(" %d\n", EVP_CIPHER_CTX_ctrl(dec, EVP_CTRL_AEAD_SET_IV_FIXED, 12, iv));
    errors();
    for (i = 0; i < 3; i++) {
        plen = i == 0 ? 40 : i == 1 ? 63 : 200;
        memcpy(a, aad + i, 13);
        a[11] = 0;
        a[12] = (unsigned char)plen;
        memcpy(rec, data + i, plen);
        printf("  aad pad %d", EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_AEAD_TLS1_AAD, 13, a));
        r = EVP_Cipher(enc, rec, rec, plen + 16);
        printf(" encrypt %d\n", r);
        hex("record", rec, 24);
        hex("tag", rec + plen, 16);
        a[12] = (unsigned char)(plen + 16);
        printf("  dec aad pad %d", EVP_CIPHER_CTX_ctrl(dec, EVP_CTRL_AEAD_TLS1_AAD, 13, a));
        r = EVP_Cipher(dec, rec, rec, plen + 16);
        printf(" decrypt %d\n", r);
        check(r == plen && memcmp(rec, data + i, plen) == 0, "the record decrypts");
    }
    errors();
    EVP_CIPHER_CTX_free(enc);
    EVP_CIPHER_CTX_free(dec);
    EVP_CIPHER_free(c);
}

static void one_shot(void)
{
    const char **n;

    printf("# EVP_Cipher\n");
    for (n = names; *n != NULL; n++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, *n, NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        unsigned char out[200], tag[16];
        int r;

        if (strstr(*n, "128") == NULL && strstr(*n, "SM4") == NULL && strstr(*n, "ChaCha") == NULL) {
            EVP_CIPHER_CTX_free(ctx);
            EVP_CIPHER_free(c);
            continue;
        }
        memset(out, 0xee, sizeof(out));
        EVP_EncryptInit_ex2(ctx, c, key, iv, NULL);
        if (is_ccm(c))
            printf("  %s length %d", *n, EVP_Cipher(ctx, NULL, NULL, 50));
        /* OCB's EVP_Cipher writes AAD's "output" through NULL in OpenSSL: no AAD for it. */
        if (EVP_CIPHER_get_mode(c) != EVP_CIPH_OCB_MODE)
            printf("  %s aad %d", *n, EVP_Cipher(ctx, NULL, aad, 9));
        r = EVP_Cipher(ctx, out, data, 50);
        printf(" data %d", r);
        printf(" final %d", EVP_Cipher(ctx, out + 50, NULL, 0));
        printf(" tag %d\n", EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, is_ccm(c) ? 12 : 16, tag));
        hex("out", out, 56);
        hex("tag", tag, is_ccm(c) ? 12 : 16);
        errors();
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(c);
    }
}

static void copies(void)
{
    static const char *which[] = { "AES-128-GCM", "AES-128-OCB", "ChaCha20-Poly1305", NULL };
    const char **w;

    printf("# copies\n");
    for (w = which; *w != NULL; w++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, *w, NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(), *cp;
        unsigned char a[80], b[80], ta[16], tb[16];
        int n = 0, m = 0, x = 0, y = 0;

        EVP_EncryptInit_ex2(ctx, c, key, iv, NULL);
        EVP_EncryptUpdate(ctx, NULL, &n, aad, 7);
        EVP_EncryptUpdate(ctx, a, &n, data, 21);
        cp = EVP_CIPHER_CTX_dup(ctx);
        EVP_EncryptUpdate(ctx, a, &n, data + 21, 30);
        EVP_EncryptUpdate(cp, b, &m, data + 21, 30);
        EVP_EncryptFinal_ex(ctx, a + n, &x);
        EVP_EncryptFinal_ex(cp, b + m, &y);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, ta);
        EVP_CIPHER_CTX_ctrl(cp, EVP_CTRL_AEAD_GET_TAG, 16, tb);
        check(n + x == m + y && memcmp(a, b, n + x) == 0 && memcmp(ta, tb, 16) == 0,
              "the copy goes on the same");
        printf("  %s: %d\n", *w, n + x);
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_CTX_free(cp);
        EVP_CIPHER_free(c);
    }
}

/*
 * A CCM context whose key was never set: an init whose IV length EVP refuses before the
 * cipher's init runs leaves the CCM state as allocated, so the tag length it reads (from the
 * nonce's first octet) is 2, whatever the context's own tag length says.
 */
static void ccm_unkeyed(void)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-CCM", NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char tag[16];
    size_t len = 16;
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, &len);
    params[1] = OSSL_PARAM_construct_end();
    check(!EVP_CipherInit_ex2(ctx, c, key, iv, 1, params), "CCM: an IV length of 16 refused");
    errors();
    memset(tag, 0x5a, sizeof(tag));
    check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 12, tag) == 1,
          "a tag set (the init didn't run, so not encrypting)");
    check(EVP_CipherInit_ex2(ctx, NULL, NULL, NULL, 1, NULL) == 1, "encrypting, no key");
    check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL) == 1, "a tag length of 16");
    check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 12, tag) == 0,
          "no 12-octet tag: the unkeyed state's M is 2");
    errors();
    memset(tag, 0x5a, sizeof(tag));
    printf("  2-octet tag: %d\n", EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 2, tag));
    hex("tag", tag, 4);
    errors();
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
}

/*
 * A GCM decryption whose tag check fails leaves the context in use, and GHASH goes on from the
 * tag it computed: a second final fails too. (The stale tag here is the one an empty message's
 * encryption left, which is the encrypted first counter block: a GHASH that restarted from
 * zero would match it.)
 */
static void gcm_final_again(void)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-GCM", NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char out[64];
    int n = -7;

    check(EVP_CipherInit_ex2(ctx, c, key, iv, 1, NULL) == 1
          && EVP_CipherFinal_ex(ctx, out, &n) == 1 && n == 0,
          "GCM: an empty message encrypted");
    check(EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, 0) == 1, "decrypting, no tag set");
    check(EVP_CipherUpdate(ctx, out, &n, data, 10) == 1 && n == 10, "ten octets");
    check(EVP_CipherFinal_ex(ctx, out, &n) == 0, "final: the stale tag doesn't match");
    errors();
    check(EVP_CipherFinal_ex(ctx, out, &n) == 0, "final again: still no match");
    errors();
    check(EVP_CipherUpdate(ctx, out, &n, data, 20) == 1 && n == 20, "more data after it");
    hex("more", out, 20);
    check(EVP_CipherFinal_ex(ctx, out, &n) == 0, "and its final");
    errors();
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
}

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof(key); i++)
        key[i] = (unsigned char)(i * 11 + 5);
    for (i = 0; i < sizeof(iv); i++)
        iv[i] = (unsigned char)(i * 3 + 1);
    for (i = 0; i < sizeof(aad); i++)
        aad[i] = (unsigned char)(i * 13 + 9);
    for (i = 0; i < sizeof(data); i++)
        data[i] = (unsigned char)(i * 7 + 3);
    each_cipher();
    misuse();
    ivs();
    tls_gcm();
    tls_ccm();
    tls_chacha();
    one_shot();
    copies();
    ccm_unkeyed();
    gcm_final_again();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
