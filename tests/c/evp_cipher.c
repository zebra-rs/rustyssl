/*
 * Conformance test for EVP_CIPHER and EVP_CIPHER_CTX (EVP_EncryptInit(3), EVP_CIPHER_fetch(3),
 * EVP_CIPHER_CTX_get_params(3)), in TAP format, over the default provider's block and stream
 * modes (ECB, CBC, OFB, CFB, CFB1, CFB8, CTR of AES, ARIA, Camellia, SM4, and triple DES),
 * ChaCha20, and NULL: each cipher's lengths, flags, and parameter lists; encrypting and
 * decrypting in pieces of several sizes, with and without padding, and through EVP_Cipher;
 * padding errors; IVs, `num`, and re-initializing without a key or IV; key lengths, flags
 * (CFB1 counting bits), ctrls, random keys, copies, application data, and the errors of each
 * entry point.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
/* EVP_CIPHER_CTX_iv() and its kind are deprecated, and tested here. */
#define OPENSSL_SUPPRESS_DEPRECATED

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

static unsigned char key[64], iv[16], data[300];

static const char *names[] = {
    "NULL", "AES-256-ECB", "AES-192-ECB", "AES-128-ECB", "AES-256-CBC", "AES-192-CBC",
    "AES-128-CBC", "AES-256-OFB", "AES-192-OFB", "AES-128-OFB", "AES-256-CFB", "AES-192-CFB",
    "AES-128-CFB", "AES-256-CFB1", "AES-192-CFB1", "AES-128-CFB1", "AES-256-CFB8",
    "AES-192-CFB8", "AES-128-CFB8", "AES-256-CTR", "AES-192-CTR", "AES-128-CTR", "ARIA-256-ECB",
    "ARIA-192-ECB", "ARIA-128-ECB", "ARIA-256-CBC", "ARIA-192-CBC", "ARIA-128-CBC",
    "ARIA-256-OFB", "ARIA-192-OFB", "ARIA-128-OFB", "ARIA-256-CFB", "ARIA-192-CFB",
    "ARIA-128-CFB", "ARIA-256-CFB1", "ARIA-192-CFB1", "ARIA-128-CFB1", "ARIA-256-CFB8",
    "ARIA-192-CFB8", "ARIA-128-CFB8", "ARIA-256-CTR", "ARIA-192-CTR", "ARIA-128-CTR",
    "CAMELLIA-256-ECB", "CAMELLIA-192-ECB", "CAMELLIA-128-ECB", "CAMELLIA-256-CBC",
    "CAMELLIA-192-CBC", "CAMELLIA-128-CBC", "CAMELLIA-256-OFB", "CAMELLIA-192-OFB",
    "CAMELLIA-128-OFB", "CAMELLIA-256-CFB", "CAMELLIA-192-CFB", "CAMELLIA-128-CFB",
    "CAMELLIA-256-CFB1", "CAMELLIA-192-CFB1", "CAMELLIA-128-CFB1", "CAMELLIA-256-CFB8",
    "CAMELLIA-192-CFB8", "CAMELLIA-128-CFB8", "CAMELLIA-256-CTR", "CAMELLIA-192-CTR",
    "CAMELLIA-128-CTR", "DES-EDE3-ECB", "DES-EDE3-CBC", "DES-EDE3-OFB", "DES-EDE3-CFB",
    "DES-EDE3-CFB8", "DES-EDE3-CFB1", "DES-EDE-ECB", "DES-EDE-CBC", "DES-EDE-OFB",
    "DES-EDE-CFB", "SM4-ECB", "SM4-CBC", "SM4-CTR", "SM4-OFB", "SM4-CFB", "ChaCha20", NULL
};

static void print_list(const char *label, const OSSL_PARAM *p)
{
    printf("  %s:", label);
    if (p == NULL)
        printf(" NULL");
    for (; p != NULL && p->key != NULL; p++)
        printf(" %s/%u/%zu/%d", p->key, p->data_type, p->data_size,
               p->return_size == OSSL_PARAM_UNMODIFIED);
    printf("\n");
}

static void describe(EVP_CIPHER *c)
{
    unsigned int mode = 99;
    size_t keylen = 99, ivlen = 99, bs = 99;
    int aead = 9, custom = 9, cts = 9, multi = 9, rk = 9, donly = 9;
    OSSL_PARAM params[11];

    printf("  nid %d type %d block %d key %d iv %d flags %lx mode %d desc %s pipeline %d/%d\n",
           EVP_CIPHER_get_nid(c), EVP_CIPHER_get_type(c), EVP_CIPHER_get_block_size(c),
           EVP_CIPHER_get_key_length(c), EVP_CIPHER_get_iv_length(c), EVP_CIPHER_get_flags(c),
           EVP_CIPHER_get_mode(c), EVP_CIPHER_get0_description(c), EVP_CIPHER_can_pipeline(c, 1),
           EVP_CIPHER_can_pipeline(c, 0));
    params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_MODE, &mode);
    params[1] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN, &keylen);
    params[2] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, &ivlen);
    params[3] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, &bs);
    params[4] = OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_AEAD, &aead);
    params[5] = OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_CUSTOM_IV, &custom);
    params[6] = OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_CTS, &cts);
    params[7] = OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, &multi);
    params[8] = OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, &rk);
    params[9] = OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_DECRYPT_ONLY, &donly);
    params[10] = OSSL_PARAM_construct_end();
    printf("  get_params %d: mode %u key %zu iv %zu block %zu aead %d custom %d cts %d multi %d"
           " randkey %d decrypt-only %d\n",
           EVP_CIPHER_get_params(c, params), mode, keylen, ivlen, bs, aead, custom, cts, multi,
           rk, donly);
    print_list("gettable", EVP_CIPHER_gettable_params(c));
    print_list("gettable ctx", EVP_CIPHER_gettable_ctx_params(c));
    print_list("settable ctx", EVP_CIPHER_settable_ctx_params(c));
}

/* Encrypts `len` octets in pieces of `piece`, then decrypts them in pieces of `back`. */
static void round_trip(EVP_CIPHER *c, int len, int piece, int back, int pad)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char out[400], plain[400];
    int n, total = 0, dtotal = 0, at, ok = 1, step;

    ok &= EVP_EncryptInit_ex2(ctx, c, key, iv, NULL);
    ok &= EVP_CIPHER_CTX_set_padding(ctx, pad);
    for (at = 0; ok && at < len; at += step) {
        step = len - at < piece ? len - at : piece;
        ok &= EVP_EncryptUpdate(ctx, out + total, &n, data + at, step);
        total += n;
    }
    if (ok) {
        ok &= EVP_EncryptFinal_ex(ctx, out + total, &n);
        total += ok ? n : 0;
    }
    printf("  len %d piece %d pad %d: %d %d\n", len, piece, pad, ok, total);
    if (!ok) {
        errors();
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    hex("out", out, total);
    ok &= EVP_DecryptInit_ex2(ctx, c, key, iv, NULL);
    ok &= EVP_CIPHER_CTX_set_padding(ctx, pad);
    for (at = 0; ok && at < total; at += step) {
        step = total - at < back ? total - at : back;
        ok &= EVP_DecryptUpdate(ctx, plain + dtotal, &n, out + at, step);
        dtotal += n;
    }
    if (ok) {
        ok &= EVP_DecryptFinal_ex(ctx, plain + dtotal, &n);
        dtotal += ok ? n : 0;
    }
    check(ok && dtotal == len && memcmp(plain, data, len) == 0, "decrypts back");
    if (!ok)
        errors();
    EVP_CIPHER_CTX_free(ctx);
}

static void one_shot(EVP_CIPHER *c, int len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char out[400];
    int r;

    memset(out, 0xee, sizeof(out));
    EVP_EncryptInit_ex2(ctx, c, key, iv, NULL);
    r = EVP_Cipher(ctx, out, data, (unsigned int)len);
    printf("  EVP_Cipher %d: %d\n", len, r);
    hex("out", out, len + 16);
    EVP_CIPHER_CTX_free(ctx);
    ERR_clear_error();
}

static void each_cipher(void)
{
    const char **n;
    static const int pieces[] = { 1, 5, 16, 33, 300 };

    for (n = names; *n != NULL; n++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, *n, NULL);
        size_t i;
        int len;

        printf("# %s\n", *n);
        check(c != NULL, "fetched");
        if (c == NULL) {
            errors();
            continue;
        }
        describe(c);
        for (i = 0; i < sizeof(pieces) / sizeof(pieces[0]); i++)
            round_trip(c, 100, pieces[i], pieces[(i + 2) % 5], 1);
        for (len = 0; len <= 48; len += 16)
            round_trip(c, len, 7, 16, 0);
        round_trip(c, 17, 4, 3, 0);
        round_trip(c, 0, 1, 1, 1);
        one_shot(c, 48);
        /*
         * A partial block through EVP_Cipher is the platform's in OpenSSL (its ARMv8 assembly
         * encrypts the wrong block in ECB): only the stream ciphers' (docs/DEVIATIONS.md).
         */
        if (EVP_CIPHER_get_block_size(c) == 1)
            one_shot(c, 21);
        EVP_CIPHER_free(c);
    }
}

static void padding_errors(void)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-CBC", NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char ct[64], pt[64], block[16];
    int n = 0, m = 0, last, ok;

    printf("# padding\n");
    for (last = 0; last <= 17; last++) {
        /* A block that decrypts to fifteen 0x10s and then `last`. */
        memset(block, 0x10, sizeof(block));
        block[15] = (unsigned char)last;
        EVP_EncryptInit_ex2(ctx, c, key, iv, NULL);
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        EVP_EncryptUpdate(ctx, ct, &n, block, 16);
        /* The context keeps EVP_CIPH_NO_PADDING across inits: padding back on. */
        EVP_DecryptInit_ex2(ctx, c, key, iv, NULL);
        EVP_CIPHER_CTX_set_padding(ctx, 1);
        EVP_DecryptUpdate(ctx, pt, &n, ct, 16);
        ok = EVP_DecryptFinal_ex(ctx, pt + n, &m);
        printf("  last %d: %d %d %d\n", last, ok, n, m);
        errors();
    }
    /* A wrong pad byte in the middle. */
    memset(block, 4, sizeof(block));
    block[13] = 3;
    EVP_EncryptInit_ex2(ctx, c, key, iv, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, ct, &n, block, 16);
    EVP_DecryptInit_ex2(ctx, c, key, iv, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 1);
    EVP_DecryptUpdate(ctx, pt, &n, ct, 16);
    check(EVP_DecryptFinal_ex(ctx, pt, &m) == 0, "a wrong padding byte fails");
    errors();
    EVP_DecryptInit_ex2(ctx, c, key, iv, NULL);
    EVP_DecryptUpdate(ctx, pt, &n, ct, 10);
    check(EVP_DecryptFinal_ex(ctx, pt, &m) == 0, "a partial block fails");
    errors();
    EVP_EncryptInit_ex2(ctx, c, key, iv, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, ct, &n, data, 10);
    check(EVP_EncryptFinal_ex(ctx, ct, &m) == 0, "no padding and a partial block fails");
    errors();
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
}

static void show_iv(EVP_CIPHER_CTX *ctx, const char *label)
{
    unsigned char buf[16], small[4];
    const unsigned char *o = EVP_CIPHER_CTX_original_iv(ctx), *u = EVP_CIPHER_CTX_iv(ctx);
    int len = EVP_CIPHER_CTX_get_iv_length(ctx);

    printf("  %s: ivlen %d num %d\n", label, len, EVP_CIPHER_CTX_get_num(ctx));
    if (o != NULL && len > 0)
        hex("original", o, len);
    if (u != NULL && len > 0)
        hex("updated", u, len);
    printf("  same pointers: %d %d\n", u == EVP_CIPHER_CTX_iv_noconst(ctx),
           u == EVP_CIPHER_CTX_iv(ctx));
    memset(buf, 0, sizeof(buf));
    printf("  get_updated_iv %d", EVP_CIPHER_CTX_get_updated_iv(ctx, buf, sizeof(buf)));
    hex("", buf, 16);
    printf("  get_original_iv %d", EVP_CIPHER_CTX_get_original_iv(ctx, buf, sizeof(buf)));
    hex("", buf, 16);
    printf("  small: %d\n", EVP_CIPHER_CTX_get_original_iv(ctx, small, sizeof(small)));
    errors();
}

static void ivs(void)
{
    static const char *which[] = { "AES-128-CBC", "AES-128-OFB", "AES-128-CFB", "AES-128-CFB8",
                                   "AES-128-CTR", "AES-128-ECB", "DES-EDE3-CFB", "ChaCha20",
                                   "NULL", NULL };
    const char **w;

    printf("# IVs\n");
    for (w = which; *w != NULL; w++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, *w, NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        unsigned char out[64], again[64];
        int n = 0, m = 0;

        printf("# %s\n", *w);
        show_iv(ctx, "empty");
        EVP_EncryptInit_ex2(ctx, c, key, iv, NULL);
        show_iv(ctx, "set");
        EVP_EncryptUpdate(ctx, out, &n, data, 21);
        show_iv(ctx, "after 21");
        /* No IV: CBC, CFB, and OFB go back to the IV as set; the others keep theirs. */
        EVP_EncryptInit_ex2(ctx, NULL, NULL, NULL, NULL);
        show_iv(ctx, "init without an IV");
        EVP_EncryptUpdate(ctx, again, &m, data, 21);
        printf("  again the same: %d\n", n == m && memcmp(out, again, n) == 0);
        printf("  set_num 0: %d, 1: %d, 3: %d\n", EVP_CIPHER_CTX_set_num(ctx, 0),
               EVP_CIPHER_CTX_set_num(ctx, 1), EVP_CIPHER_CTX_set_num(ctx, 3));
        errors();
        /* The key alone, then the IV alone. */
        EVP_EncryptInit_ex2(ctx, NULL, key, NULL, NULL);
        EVP_EncryptInit_ex2(ctx, NULL, NULL, iv, NULL);
        EVP_EncryptUpdate(ctx, again, &m, data, 21);
        printf("  key then IV the same: %d\n", n == m && memcmp(out, again, n) == 0);
        /* Write the running IV through iv_noconst. */
        if (EVP_CIPHER_CTX_iv_noconst(ctx) != NULL && EVP_CIPHER_CTX_get_iv_length(ctx) > 0) {
            memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv, EVP_CIPHER_CTX_get_iv_length(ctx));
            EVP_EncryptUpdate(ctx, again, &m, data, 16);
            hex("after writing the IV", again, m);
        }
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(c);
    }
}

static void key_lengths(void)
{
    static const char *which[] = { "AES-128-CBC", "ChaCha20", "DES-EDE3-ECB", "NULL", NULL };
    const char **w;

    printf("# key lengths\n");
    for (w = which; *w != NULL; w++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, *w, NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int kl;

        EVP_EncryptInit_ex2(ctx, c, NULL, NULL, NULL);
        kl = EVP_CIPHER_CTX_get_key_length(ctx);
        printf("  %s: key %d same %d other %d now %d\n", *w, kl,
               EVP_CIPHER_CTX_set_key_length(ctx, kl), EVP_CIPHER_CTX_set_key_length(ctx, 24),
               EVP_CIPHER_CTX_get_key_length(ctx));
        errors();
        printf("  ctrl set key length: %d %d\n",
               EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_SET_KEY_LENGTH, kl, NULL),
               EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_SET_KEY_LENGTH, 7, NULL));
        errors();
        print_list("ctx gettable", EVP_CIPHER_CTX_gettable_params(ctx));
        print_list("ctx settable", EVP_CIPHER_CTX_settable_params(ctx));
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(c);
    }
}

static void init_params(void)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-CBC", NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    size_t len = 24;
    unsigned int pad = 0;
    OSSL_PARAM params[3];
    unsigned char out[64];
    int n = 0, m = 0;

    printf("# init parameters\n");
    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN, &len);
    params[1] = OSSL_PARAM_construct_end();
    /* The cipher ignores it, but the context caches it, and the key is then the wrong length. */
    check(EVP_EncryptInit_ex2(ctx, c, key, iv, params) == 0, "a key length the cipher ignores");
    printf("  key length %d\n", EVP_CIPHER_CTX_get_key_length(ctx));
    errors();
    params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_PADDING, &pad);
    check(EVP_EncryptInit_ex2(ctx, c, key, iv, params) == 1, "padding off through init");
    check(EVP_EncryptUpdate(ctx, out, &n, data, 20) && EVP_EncryptFinal_ex(ctx, out + n, &m) == 0,
          "so a partial block fails");
    errors();
    len = 12;
    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN, &len);
    EVP_CIPHER_free(c);
    c = EVP_CIPHER_fetch(NULL, "ChaCha20", NULL);
    check(EVP_EncryptInit_ex2(ctx, c, key, iv, params) == 0, "ChaCha20 refuses a key length");
    errors();
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
}

static void ctrls(void)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-CBC", NULL);
    EVP_CIPHER *d = EVP_CIPHER_fetch(NULL, "DES-EDE3-CBC", NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char buf[32], k[24];
    EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM mb;
    int i, parity = 1;

    printf("# ctrls\n");
    printf("  before init: %d\n", EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_INIT, 0, NULL));
    errors();
    EVP_EncryptInit_ex2(ctx, c, key, iv, NULL);
    printf("  init %d\n", EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_INIT, 0, NULL));
    printf("  unknown %d\n", EVP_CIPHER_CTX_ctrl(ctx, 0x7777, 0, NULL));
    errors();
    printf("  set ivlen %d %d\n", EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL),
           EVP_CIPHER_CTX_get_iv_length(ctx));
    printf("  ccm L %d %d\n", EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_L, 1, NULL),
           EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_L, 4, NULL));
    printf("  get tag %d set tag %d\n", EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, buf),
           EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, buf));
    printf("  tls aad %d\n", EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD, 13, buf));
    printf("  iv fixed %d gen %d inv %d\n",
           EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IV_FIXED, 4, buf),
           EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_IV_GEN, -1, buf),
           EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_INV, 8, buf));
    printf("  rc2 %d", EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GET_RC2_KEY_BITS, 0, NULL));
    fflush(stdout);
    printf(" %d", EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_SET_RC2_KEY_BITS, 40, NULL));
    fflush(stdout);
    printf(" rc5 %d", EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GET_RC5_ROUNDS, 0, NULL));
    fflush(stdout);
    printf(" %d", EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_SET_RC5_ROUNDS, -1, NULL));
    fflush(stdout);
    printf(" speed %d", EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_SET_SPEED, 1, NULL));
    fflush(stdout);
    printf(" mac key %d\n", EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_MAC_KEY, -1, buf));
    printf("  multiblock %d\n",
           EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE, 4096, NULL));
    memset(&mb, 0, sizeof(mb));
    mb.inp = buf;
    mb.len = 13;
    printf("  multiblock aad %d %d\n",
           EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_TLS1_1_MULTIBLOCK_AAD, sizeof(mb), &mb),
           EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_TLS1_1_MULTIBLOCK_AAD, 1, &mb));
    mb.out = buf;
    printf("  multiblock encrypt %d\n",
           EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT, 0, &mb));
    printf("  tag length %d\n", EVP_CIPHER_CTX_get_tag_length(ctx));
    printf("  rand key (AES) %d\n", EVP_CIPHER_CTX_rand_key(ctx, k));
    errors();
    EVP_EncryptInit_ex2(ctx, d, key, iv, NULL);
    memset(k, 0, sizeof(k));
    printf("  rand key (3DES) %d\n", EVP_CIPHER_CTX_rand_key(ctx, k));
    for (i = 0; i < 24; i++) {
        int b, ones = 0;

        for (b = 0; b < 8; b++)
            ones += (k[i] >> b) & 1;
        parity &= ones & 1;
    }
    check(parity, "with odd parity");
    printf("  ctrl rand key %d\n", EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_RAND_KEY, 0, k));
    errors();
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
    EVP_CIPHER_free(d);
}

static void bits(void)
{
    static const char *which[] = { "AES-128-CFB1", "DES-EDE3-CFB1", "AES-128-CFB8", NULL };
    const char **w;

    printf("# CFB1 in bits\n");
    for (w = which; *w != NULL; w++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, *w, NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        /* Room for 13 octets too: a new algorithm context counts octets again. */
        unsigned char out[32], back[32];
        int n = 0, m = 0;

        memset(out, 0xa5, sizeof(out));
        memset(back, 0x5a, sizeof(back));
        EVP_EncryptInit_ex2(ctx, c, key, iv, NULL);
        EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS);
        printf("  %s: test %d\n", *w, EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS));
        printf("  update 13 bits %d", EVP_EncryptUpdate(ctx, out, &n, data, 13));
        printf(" n %d", n);
        hex("", out, 4);
        printf("  update 6 more %d", EVP_EncryptUpdate(ctx, out + 4, &m, data + 2, 6));
        hex("", out + 4, 2);
        EVP_DecryptInit_ex2(ctx, c, key, iv, NULL);
        printf("  decrypt %d %d", EVP_DecryptUpdate(ctx, back, &n, out, 13), n);
        hex("", back, 13);
        EVP_CIPHER_CTX_clear_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS);
        printf("  cleared %d\n", EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS));
        EVP_DecryptInit_ex2(ctx, c, key, iv, NULL);
        printf("  decrypt octets %d", EVP_DecryptUpdate(ctx, back, &n, out, 2));
        hex("", back, 4);
        printf("  EVP_Cipher in bits %d", (EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS),
                                           EVP_Cipher(ctx, back, out, 11)));
        hex("", back, 4);
        errors();
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(c);
    }
}

static void copies(void)
{
    static const char *which[] = { "AES-128-CBC", "AES-128-CTR", "ChaCha20", "DES-EDE3-OFB",
                                   "NULL", NULL };
    const char **w;

    printf("# copies\n");
    for (w = which; *w != NULL; w++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, *w, NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(), *cp = EVP_CIPHER_CTX_new(), *dup;
        unsigned char a[64], b[64], x[64];
        int n = 0, m = 0, k = 0;

        EVP_EncryptInit_ex2(ctx, c, key, iv, NULL);
        EVP_EncryptUpdate(ctx, a, &n, data, 21);
        check(EVP_CIPHER_CTX_copy(cp, ctx) == 1, "copy");
        dup = EVP_CIPHER_CTX_dup(ctx);
        check(dup != NULL, "dup");
        EVP_EncryptUpdate(ctx, a, &n, data + 21, 30);
        EVP_EncryptUpdate(cp, b, &m, data + 21, 30);
        EVP_EncryptUpdate(dup, x, &k, data + 21, 30);
        check(n == m && m == k && memcmp(a, b, n) == 0 && memcmp(a, x, n) == 0,
              "the copies go on the same");
        printf("  %s: %d, same cipher %d\n", *w, n,
               EVP_CIPHER_CTX_get0_cipher(cp) == EVP_CIPHER_CTX_get0_cipher(ctx));
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_CTX_free(cp);
        EVP_CIPHER_CTX_free(dup);
        EVP_CIPHER_free(c);
    }
    {
        EVP_CIPHER_CTX *e = EVP_CIPHER_CTX_new(), *f = EVP_CIPHER_CTX_new();

        check(EVP_CIPHER_CTX_copy(f, e) == 0, "copying an empty context fails");
        check(EVP_CIPHER_CTX_dup(e) == NULL, "and dup");
        errors();
        EVP_CIPHER_CTX_free(e);
        EVP_CIPHER_CTX_free(f);
    }
}

static void accessors(void)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-256-CBC", NULL);
    EVP_CIPHER *o = EVP_CIPHER_fetch(NULL, "AES-128-CTR", NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER *got;
    void *mem = OPENSSL_malloc(8);
    int app = 5;

    printf("# accessors\n");
    printf("  empty: cipher %d nid %d block %d key %d iv %d enc %d app %d data %d\n",
           EVP_CIPHER_CTX_get0_cipher(ctx) == NULL, EVP_CIPHER_CTX_get_nid(ctx),
           EVP_CIPHER_CTX_get_block_size(ctx), EVP_CIPHER_CTX_get_key_length(ctx),
           EVP_CIPHER_CTX_get_iv_length(ctx), EVP_CIPHER_CTX_is_encrypting(ctx),
           EVP_CIPHER_CTX_get_app_data(ctx) == NULL, EVP_CIPHER_CTX_get_cipher_data(ctx) == NULL);
    printf("  empty: get1 %d num %d tag %d params %d buf %d\n",
           EVP_CIPHER_CTX_get1_cipher(ctx) == NULL, EVP_CIPHER_CTX_get_num(ctx),
           EVP_CIPHER_CTX_get_tag_length(ctx), EVP_CIPHER_CTX_get_params(ctx, NULL),
           EVP_CIPHER_CTX_buf_noconst(ctx) != NULL);
    printf("  empty: set params %d padding %d\n", EVP_CIPHER_CTX_set_params(ctx, NULL),
           EVP_CIPHER_CTX_set_padding(ctx, 1));
    errors();
    EVP_CIPHER_CTX_set_app_data(ctx, &app);
    check(EVP_CIPHER_CTX_set_cipher_data(ctx, mem) == NULL, "set cipher data");
    check(EVP_CIPHER_CTX_get_cipher_data(ctx) == mem, "get cipher data");
    EVP_DecryptInit_ex2(ctx, c, key, iv, NULL);
    printf("  init: cipher %d nid %d block %d key %d iv %d enc %d app %d data %d\n",
           EVP_CIPHER_CTX_get0_cipher(ctx) == c, EVP_CIPHER_CTX_get_nid(ctx),
           EVP_CIPHER_CTX_get_block_size(ctx), EVP_CIPHER_CTX_get_key_length(ctx),
           EVP_CIPHER_CTX_get_iv_length(ctx), EVP_CIPHER_CTX_is_encrypting(ctx),
           EVP_CIPHER_CTX_get_app_data(ctx) == &app, EVP_CIPHER_CTX_get_cipher_data(ctx) == mem);
    got = EVP_CIPHER_CTX_get1_cipher(ctx);
    check(got == c && EVP_CIPHER_CTX_cipher(ctx) == c, "get1_cipher");
    EVP_CIPHER_free(got);
    /* A new cipher resets the context, freeing the cipher data and forgetting the app data. */
    EVP_EncryptInit_ex2(ctx, o, key, iv, NULL);
    printf("  new cipher: app %d data %d enc %d\n", EVP_CIPHER_CTX_get_app_data(ctx) == NULL,
           EVP_CIPHER_CTX_get_cipher_data(ctx) == NULL, EVP_CIPHER_CTX_is_encrypting(ctx));
    /* -1 keeps the direction. */
    EVP_CipherInit_ex(ctx, NULL, NULL, NULL, NULL, -1);
    printf("  enc -1: %d\n", EVP_CIPHER_CTX_is_encrypting(ctx));
    EVP_CipherInit_ex2(ctx, NULL, NULL, NULL, 0, NULL);
    printf("  enc 0: %d\n", EVP_CIPHER_CTX_is_encrypting(ctx));
    check(EVP_CIPHER_CTX_reset(ctx) == 1 && EVP_CIPHER_CTX_get0_cipher(ctx) == NULL, "reset");
    check(EVP_CIPHER_CTX_reset(NULL) == 1, "reset NULL");
    /* The cipher data of a context without a cipher is freed with it. */
    EVP_CIPHER_CTX_set_cipher_data(ctx, OPENSSL_malloc(8));
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_CTX_free(NULL);
    EVP_CIPHER_free(c);
    EVP_CIPHER_free(o);
    EVP_CIPHER_free(NULL);
}

static void entry_errors(void)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-CBC", NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char out[64];
    int n = 9;

    printf("# errors\n");
    printf("  update without a cipher %d %d\n", EVP_EncryptUpdate(ctx, out, &n, data, 5), n);
    errors();
    printf("  init without a cipher %d\n", EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv));
    errors();
    printf("  final without a cipher %d\n", EVP_EncryptFinal_ex(ctx, out, &n));
    errors();
    printf("  EVP_Cipher without a cipher %d\n", EVP_Cipher(ctx, out, data, 16));
    EVP_EncryptInit_ex2(ctx, c, NULL, NULL, NULL);
    printf("  update without a key %d\n", EVP_EncryptUpdate(ctx, out, &n, data, 5));
    errors();
    printf("  final without a key %d\n", EVP_EncryptFinal_ex(ctx, out, &n));
    errors();
    printf("  EVP_Cipher without a key %d\n", EVP_Cipher(ctx, out, data, 16));
    errors();
    EVP_EncryptInit_ex2(ctx, c, key, iv, NULL);
    printf("  decrypting an encrypting context %d %d\n", EVP_DecryptUpdate(ctx, out, &n, data, 5),
           EVP_DecryptFinal_ex(ctx, out, &n));
    errors();
    printf("  negative length %d\n", EVP_EncryptUpdate(ctx, out, &n, data, -1));
    printf("  no outl %d %d\n", EVP_EncryptUpdate(ctx, out, NULL, data, 5),
           EVP_EncryptFinal_ex(ctx, out, NULL));
    errors();
    printf("  CipherUpdate %d %d CipherFinal %d %d\n", EVP_CipherUpdate(ctx, out, &n, data, 16), n,
           EVP_CipherFinal(ctx, out, &n), n);
    printf("  EncryptFinal %d\n", EVP_EncryptFinal(ctx, out, &n));
    errors();
    EVP_DecryptInit(ctx, c, key, iv);
    printf("  DecryptFinal of nothing %d %d\n", EVP_DecryptFinal(ctx, out, &n),
           EVP_CipherFinal_ex(ctx, out, &n));
    errors();
    printf("  EncryptInit %d DecryptInit_ex %d\n", EVP_EncryptInit(ctx, c, key, iv),
           EVP_DecryptInit_ex(ctx, c, NULL, key, iv));
    printf("  CipherInit %d\n", EVP_CipherInit(ctx, c, key, iv, 1));
    printf("  wrong key length through params:");
    {
        size_t len = 24;
        OSSL_PARAM p[2];

        p[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, &len);
        p[1] = OSSL_PARAM_construct_end();
        printf(" %d\n", EVP_CIPHER_CTX_set_params(ctx, p));
    }
    errors();
    printf("  fetch nonesuch %d\n", EVP_CIPHER_fetch(NULL, "nonesuch", NULL) == NULL);
    errors();
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
}

static void null_cipher(void)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "NULL", NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char out[64];
    size_t macsize = 4;
    void *mac = NULL;
    OSSL_PARAM params[2];
    int n = 0, r;

    printf("# NULL\n");
    EVP_DecryptInit_ex2(ctx, c, NULL, NULL, NULL);
    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_TLS_MAC_SIZE, &macsize);
    params[1] = OSSL_PARAM_construct_end();
    printf("  mac size %d\n", EVP_CIPHER_CTX_set_params(ctx, params));
    printf("  update %d %d\n", EVP_DecryptUpdate(ctx, out, &n, data, 10), n);
    params[0] = OSSL_PARAM_construct_octet_ptr(OSSL_CIPHER_PARAM_TLS_MAC, &mac, 0);
    r = EVP_CIPHER_CTX_get_params(ctx, params);
    /* Where the pointer isn't set, its value isn't printed (it differs from run to run). */
    printf("  get mac %d", r);
    if (OSSL_PARAM_modified(params) && mac != NULL)
        printf(" at %d size %zu", (int)((unsigned char *)mac - data), params[0].return_size);
    printf("\n");
    printf("  too short %d\n", EVP_DecryptUpdate(ctx, out, &n, data, 3));
    printf("  in place %d %d\n", EVP_DecryptUpdate(ctx, data, &n, data, 10), n);
    errors();
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
}

static void chacha_wrap(void)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "ChaCha20", NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char civ[16], out[200];
    int n = 0, m = 0;

    printf("# ChaCha20 counter\n");
    memset(civ, 0xff, 8);
    memcpy(civ + 8, "nonce!!!", 8);
    EVP_EncryptInit_ex2(ctx, c, key, civ, NULL);
    EVP_EncryptUpdate(ctx, out, &n, data, 70);
    EVP_EncryptUpdate(ctx, out + n, &m, data + 70, 130);
    hex("wrapping", out, n + m);
    civ[0] = 0xfe;
    EVP_EncryptInit_ex2(ctx, c, key, civ, NULL);
    EVP_EncryptUpdate(ctx, out, &n, data, 200);
    hex("wrapping later", out, n);
    /* A new key without an IV starts the partial block again. */
    EVP_EncryptInit_ex2(ctx, c, key, civ, NULL);
    EVP_EncryptUpdate(ctx, out, &n, data, 10);
    EVP_EncryptInit_ex2(ctx, NULL, key + 1, NULL, NULL);
    EVP_EncryptUpdate(ctx, out, &n, data, 20);
    hex("new key", out, n);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
}

static void statics(void)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char out[64];
    int n = 0;

    printf("# static ciphers\n");
    check(EVP_EncryptInit_ex(ctx, EVP_aes_192_ofb(), NULL, key, iv) == 1, "init with a static");
    printf("  cipher %s provided %d\n", EVP_CIPHER_get0_name(EVP_CIPHER_CTX_get0_cipher(ctx)),
           EVP_CIPHER_get0_provider(EVP_CIPHER_CTX_get0_cipher(ctx)) != NULL);
    EVP_EncryptUpdate(ctx, out, &n, data, 20);
    hex("out", out, n);
    check(EVP_EncryptInit_ex(ctx, EVP_des_cbc(), NULL, key, iv) == 0, "DES needs the legacy provider");
    errors();
    check(EVP_EncryptInit_ex(ctx, EVP_enc_null(), NULL, NULL, NULL) == 1, "the NULL cipher");
    EVP_CIPHER_CTX_free(ctx);
}

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof(key); i++)
        key[i] = (unsigned char)(i * 11 + 5);
    for (i = 0; i < sizeof(iv); i++)
        iv[i] = (unsigned char)(i * 3 + 1);
    for (i = 0; i < sizeof(data); i++)
        data[i] = (unsigned char)(i * 7 + 3);
    each_cipher();
    padding_errors();
    ivs();
    key_lengths();
    init_params();
    ctrls();
    bits();
    copies();
    accessors();
    entry_errors();
    null_cipher();
    chacha_wrap();
    statics();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
