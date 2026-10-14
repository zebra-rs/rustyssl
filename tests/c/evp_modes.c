/*
 * Conformance test for the default provider's other cipher modes (EVP_EncryptInit(3),
 * EVP_CIPHER-AES(7), EVP_CIPHER-CAMELLIA(7), EVP_CIPHER-DES(7), EVP_CIPHER-SM4(7)), in TAP
 * format: CBC with ciphertext stealing (CS1, CS2, CS3), XTS (AES's, SM4's in both standards),
 * the AES key wraps with and without padding and their inverses, triple DES's key wrap,
 * AES-SIV and AES-GCM-SIV, and the AES-CBC-HMAC composites where the CPU has them: their
 * lengths, flags, and parameter lists; messages both ways; the lengths each refuses; size
 * queries; tags that don't authenticate; the TLS records of the composites; and copies.
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

static void print_list(const char *label, const OSSL_PARAM *p)
{
    printf("  %s:", label);
    for (; p != NULL && p->key != NULL; p++)
        printf(" %s/%u/%zu", p->key, p->data_type, p->data_size);
    printf("\n");
}

static unsigned char key[64], iv[16], data[600];

static const char *names[] = {
    "AES-128-CBC-CTS", "AES-192-CBC-CTS", "AES-256-CBC-CTS", "CAMELLIA-128-CBC-CTS",
    "CAMELLIA-192-CBC-CTS", "CAMELLIA-256-CBC-CTS", "AES-128-XTS", "AES-256-XTS", "SM4-XTS",
    "AES-128-WRAP", "AES-192-WRAP", "AES-256-WRAP", "AES-128-WRAP-PAD", "AES-192-WRAP-PAD",
    "AES-256-WRAP-PAD", "AES-128-WRAP-INV", "AES-192-WRAP-INV", "AES-256-WRAP-INV",
    "AES-128-WRAP-PAD-INV", "AES-192-WRAP-PAD-INV", "AES-256-WRAP-PAD-INV", "id-aes128-wrap",
    "DES3-WRAP", "id-smime-alg-CMS3DESwrap", "AES-128-SIV", "AES-192-SIV", "AES-256-SIV",
    "AES-128-GCM-SIV", "AES-192-GCM-SIV", "AES-256-GCM-SIV", "AES-128-CBC-HMAC-SHA1",
    "AES-256-CBC-HMAC-SHA1", "AES-128-CBC-HMAC-SHA256", "AES-256-CBC-HMAC-SHA256", NULL
};

/* Each cipher's lengths, flags, mode, and parameter lists. */
static void each_cipher(void)
{
    int i;

    for (i = 0; names[i] != NULL; i++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, names[i], NULL);
        int aead = -1, custom = -1, cts = -1, multi = -1, randkey = -1;
        OSSL_PARAM params[6];

        if (c == NULL) {
            /* The composites, where the CPU lacks AES-NI. */
            printf("  %s: absent\n", names[i]);
            ERR_clear_error();
            check(strstr(names[i], "HMAC") != NULL, "only a composite may be absent");
            continue;
        }
        params[0] = OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_AEAD, &aead);
        params[1] = OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_CUSTOM_IV, &custom);
        params[2] = OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_CTS, &cts);
        params[3] = OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, &multi);
        params[4] = OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, &randkey);
        params[5] = OSSL_PARAM_construct_end();
        check(EVP_CIPHER_get_params(c, params), names[i]);
        printf("  %s nid %d mode %#x flags %#lx key %d iv %d block %d aead %d custom %d cts %d"
               " multi %d randkey %d\n",
               EVP_CIPHER_get0_name(c), EVP_CIPHER_get_nid(c), EVP_CIPHER_get_mode(c),
               EVP_CIPHER_get_flags(c), EVP_CIPHER_get_key_length(c),
               EVP_CIPHER_get_iv_length(c), EVP_CIPHER_get_block_size(c), aead, custom, cts,
               multi, randkey);
        print_list("gettable", EVP_CIPHER_gettable_params(c));
        print_list("gettable ctx", EVP_CIPHER_gettable_ctx_params(c));
        print_list("settable ctx", EVP_CIPHER_settable_ctx_params(c));
        EVP_CIPHER_free(c);
    }
}

/* One pass of `name` (the CTS variant or SM4-XTS standard `variant`, if any) over `len` octets
 * of `in`, printing the result; returns its length or -1. */
static int run(const char *name, const char *variant, int enc, const unsigned char *in, int len,
               unsigned char *out, int with_iv)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, name, NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int a = 0, b = 0, ok;
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

    if (variant != NULL)
        params[0] = OSSL_PARAM_construct_utf8_string(strncmp(name, "SM4", 3) == 0
                                                         ? OSSL_CIPHER_PARAM_XTS_STANDARD
                                                         : OSSL_CIPHER_PARAM_CTS_MODE,
                                                     (char *)variant, 0);
    ok = EVP_CipherInit_ex2(ctx, c, key, with_iv ? iv : NULL, enc, params);
    ok = ok && EVP_CipherUpdate(ctx, out, &a, in, len);
    ok = ok && EVP_CipherFinal_ex(ctx, out + a, &b);
    printf("  %s %s %s %d: %d %d\n", name, variant != NULL ? variant : "-", enc ? "enc" : "dec",
           len, ok, a + b);
    if (ok)
        hex("out", out, a + b);
    else
        errors();
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
    return ok ? a + b : -1;
}

static void round_trip(const char *name, const char *variant, int len)
{
    unsigned char out[700], back[700];
    int n = run(name, variant, 1, data, len, out, 1);

    if (n < 0) {
        check(0, "encrypts");
        return;
    }
    check(run(name, variant, 0, out, n, back, 1) == len && memcmp(back, data, len) == 0,
          "decrypts back");
}

static void cts(void)
{
    static const char *variants[] = { "CS1", "CS2", "CS3", "cs3" };
    static const int lens[] = { 15, 16, 17, 31, 32, 33, 48, 63 };
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-CBC-CTS", NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char out[200];
    char mode[10] = "";
    int v, l, n = -7;
    OSSL_PARAM params[2];

    for (v = 0; v < 4; v++)
        for (l = 0; l < 8; l++)
            if (lens[l] < 16)
                check(run("CAMELLIA-256-CBC-CTS", variants[v], 1, data, lens[l], out, 1) < 0,
                      "less than a block fails");
            else
                round_trip(v % 2 ? "CAMELLIA-128-CBC-CTS" : "AES-256-CBC-CTS", variants[v],
                           lens[l]);

    /* One update a message; a size query doesn't count; final adds nothing. */
    check(EVP_EncryptInit_ex2(ctx, c, key, iv, NULL), "init");
    check(EVP_EncryptUpdate(ctx, NULL, &n, data, 40) && n == 40, "a NULL output gives the size");
    check(EVP_EncryptUpdate(ctx, out, &n, data, 40) && n == 40, "the message");
    check(!EVP_EncryptUpdate(ctx, out, &n, data, 40), "a second update fails");
    errors();
    check(EVP_EncryptFinal_ex(ctx, out, &n) && n == 0, "final adds nothing");
    check(EVP_EncryptFinal_ex(ctx, out, &n) && n == 0, "and again");
    check(!EVP_EncryptUpdate(ctx, out, &n, data, 40), "still no second update");
    check(EVP_EncryptInit_ex2(ctx, NULL, NULL, NULL, NULL), "a new init");
    check(EVP_EncryptUpdate(ctx, out, &n, data, 40) && n == 40, "allows one more");
    hex("again", out, n);
    check(EVP_Cipher(ctx, out, data, 40) > 0, "EVP_Cipher");
    hex("EVP_Cipher", out, 32);

    /* The variant's parameter. */
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE, mode, sizeof(mode));
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_CIPHER_CTX_get_params(ctx, params), "cts_mode");
    printf("  cts_mode %s\n", mode);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE, "CS4", 0);
    check(!EVP_CIPHER_CTX_set_params(ctx, params), "an unknown variant");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE, "cS2", 0);
    check(EVP_CIPHER_CTX_set_params(ctx, params), "without regard to case");
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE, mode, sizeof(mode));
    check(EVP_CIPHER_CTX_get_params(ctx, params), "cts_mode");
    printf("  cts_mode %s\n", mode);
    params[0] = OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_CTS_MODE, &n);
    check(!EVP_CIPHER_CTX_set_params(ctx, params), "not as an integer");
    errors();
    params[0] = OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_CTS_MODE, &n);
    check(!EVP_CIPHER_CTX_get_params(ctx, params), "nor get one");
    errors();
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
}

static void xts(void)
{
    static const int lens[] = { 16, 17, 31, 32, 100, 512 };
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-XTS", NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char out[600], dup[32], *big;
    size_t keylen = 32;
    int l, n = -7;
    OSSL_PARAM params[2];

    for (l = 0; l < 6; l++) {
        round_trip("AES-128-XTS", NULL, lens[l]);
        round_trip("AES-256-XTS", NULL, lens[l]);
        round_trip("SM4-XTS", "GB", lens[l]);
        round_trip("SM4-XTS", "IEEE", lens[l]);
    }
    round_trip("SM4-XTS", NULL, 40);
    round_trip("SM4-XTS", "ieee", 40);
    check(run("SM4-XTS", "ISO", 1, data, 40, out, 1) < 0, "an unknown standard");
    check(run("AES-128-XTS", NULL, 1, data, 15, out, 1) < 0, "less than a block fails");
    check(run("AES-128-XTS", NULL, 1, data, 40, out, 0) < 0, "no IV fails");

    /* Two equal keys: refused to encrypt, allowed to decrypt. */
    memset(dup, 7, sizeof(dup));
    check(!EVP_EncryptInit_ex2(ctx, c, dup, iv, NULL), "equal keys encrypting");
    errors();
    check(EVP_DecryptInit_ex2(ctx, c, dup, iv, NULL), "equal keys decrypting");
    check(EVP_DecryptUpdate(ctx, out, &n, data, 20) && n == 20, "decrypts");
    hex("equal keys", out, n);

    /* The data unit's limit, 2^20 blocks. */
    big = calloc(1, (1 << 24) + 16);
    check(EVP_EncryptInit_ex2(ctx, c, key, iv, NULL), "init");
    check(EVP_EncryptUpdate(ctx, big, &n, big, 1 << 24) && n == 1 << 24, "2^20 blocks");
    check(!EVP_EncryptUpdate(ctx, big, &n, big, (1 << 24) + 16), "one block more");
    errors();
    check(EVP_Cipher(ctx, big, big, (1 << 24) + 16) <= 0, "EVP_Cipher too");
    errors();
    free(big);
    check(EVP_EncryptFinal_ex(ctx, out, &n) && n == 0, "final");

    /* The key length may be set only to what it is; the context reports the IV. */
    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN, &keylen);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_CIPHER_CTX_set_params(ctx, params), "the same key length");
    keylen = 64;
    check(!EVP_CIPHER_CTX_set_params(ctx, params), "another key length");
    errors();
    check(EVP_CIPHER_CTX_get_updated_iv(ctx, out, 16), "the IV");
    hex("iv", out, 16);
    check(EVP_CIPHER_CTX_get_num(ctx) == 0, "num");
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
}

static void wraps(void)
{
    static const char *wrap[] = { "AES-128-WRAP", "AES-192-WRAP-INV", "AES-256-WRAP-PAD",
                                  "AES-128-WRAP-PAD-INV", NULL };
    static const int lens[] = { 1, 7, 8, 9, 15, 16, 17, 24, 40 };
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-WRAP", NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char out[100], back[100];
    unsigned int pad = 9;
    int w, l, n = -7;
    OSSL_PARAM params[2];

    for (w = 0; wrap[w] != NULL; w++)
        for (l = 0; l < 9; l++)
            if (strstr(wrap[w], "PAD") != NULL || (lens[l] % 8 == 0 && lens[l] >= 16))
                round_trip(wrap[w], NULL, lens[l]);
            else
                check(run(wrap[w], NULL, 1, data, lens[l], out, 1) < 0,
                      "not a multiple of 8 from 16");

    /* The inverse cipher's wrap is the normal one's with the cipher's directions swapped. */
    check(run("AES-128-WRAP-INV", NULL, 1, data, 24, out, 0) == 32, "inverse");
    check(run("AES-128-WRAP", NULL, 0, out, 32, back, 0) < 0, "is no normal wrap");

    /* Sizes asked for with no output; the lengths each direction refuses. */
    check(EVP_EncryptInit_ex2(ctx, c, key, NULL, NULL), "init");
    check(EVP_EncryptUpdate(ctx, NULL, &n, data, 24) && n == 32, "the size to wrap");
    check(EVP_EncryptUpdate(ctx, out, &n, data, 0) && n == 0, "nothing");
    check(!EVP_EncryptUpdate(ctx, out, &n, data, 12), "12 octets");
    errors();
    check(!EVP_EncryptUpdate(ctx, out, &n, data, 8), "8 octets");
    errors();
    check(EVP_EncryptUpdate(ctx, out, &n, data, 16) && n == 24, "16 octets");
    hex("wrapped", out, n);
    check(EVP_EncryptFinal_ex(ctx, out, &n) && n == 0, "final");
    check(EVP_DecryptInit_ex2(ctx, NULL, key, NULL, NULL), "decrypting");
    check(EVP_DecryptUpdate(ctx, NULL, &n, data, 24) && n == 16, "the size to unwrap");
    check(!EVP_DecryptUpdate(ctx, out, &n, data, 8), "less than 16");
    errors();
    memset(out, 0x55, sizeof(out));
    check(!EVP_DecryptUpdate(ctx, out, &n, data, 32), "garbage doesn't unwrap");
    errors();
    hex("wiped", out, 32);
    /* No `cipher`: EVP_Cipher runs the update, whose failure is a length of SIZE_MAX. */
    printf("  EVP_Cipher %d\n", EVP_Cipher(ctx, out, data, 32));
    errors();
    params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_PADDING, &pad);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_CIPHER_CTX_get_params(ctx, params), "padding");
    printf("  padding %u\n", pad);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);

    /* The padded wrap's garbage wipes the whole input's length. */
    c = EVP_CIPHER_fetch(NULL, "AES-256-WRAP-PAD", NULL);
    ctx = EVP_CIPHER_CTX_new();
    check(EVP_DecryptInit_ex2(ctx, c, key, NULL, NULL), "padded");
    memset(out, 0x55, sizeof(out));
    check(!EVP_DecryptUpdate(ctx, out, &n, data, 40), "garbage");
    errors();
    hex("wiped", out, 48);
    check(EVP_DecryptUpdate(ctx, NULL, &n, data, 40) && n == 32, "the size to unwrap");
    check(EVP_CIPHER_CTX_get_params(ctx, params), "padding");
    printf("  padding %u\n", pad);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
}

static void tdes_wrap(void)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "DES3-WRAP", NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(), *copy = EVP_CIPHER_CTX_new();
    unsigned char out[100], back[100];
    int n = -7, m = -7;

    check(EVP_EncryptInit_ex2(ctx, c, key, NULL, NULL), "init");
    check(EVP_EncryptUpdate(ctx, NULL, &n, data, 24) && n == 40, "the size to wrap");
    check(EVP_EncryptUpdate(ctx, out, &n, data, 24) && n == 40, "wraps (under a random IV)");
    check(EVP_EncryptFinal_ex(ctx, out + n, &m) && m == 0, "final");
    check(!EVP_EncryptUpdate(ctx, out, &m, data, 12), "not a multiple of 8");
    errors();
    check(EVP_DecryptInit_ex2(ctx, NULL, key, NULL, NULL), "decrypting");
    check(EVP_DecryptUpdate(ctx, NULL, &m, out, 40) && m == 24, "the size to unwrap");
    check(EVP_DecryptUpdate(ctx, back, &m, out, 40) && m == 24 && memcmp(back, data, 24) == 0,
          "unwraps");
    out[20] ^= 1;
    check(!EVP_DecryptUpdate(ctx, back, &m, out, 40), "a changed one doesn't");
    errors();
    hex("wiped", back, 24);
    check(!EVP_DecryptUpdate(ctx, back, &m, out, 16), "less than 24");
    errors();
    check(EVP_Cipher(ctx, back, out, 16) <= 0, "EVP_Cipher too");
    errors();
    check(!EVP_CIPHER_CTX_copy(copy, ctx), "no copies");
    errors();
    check(EVP_CIPHER_CTX_rand_key(ctx, back), "a random key");
    EVP_CIPHER_CTX_free(copy);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
}

static int set_tag(EVP_CIPHER_CTX *ctx, const unsigned char *tag, size_t len)
{
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, (void *)tag, len);
    params[1] = OSSL_PARAM_construct_end();
    return EVP_CIPHER_CTX_set_params(ctx, params);
}

static int get_tag(EVP_CIPHER_CTX *ctx, unsigned char *tag, size_t len)
{
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, len);
    params[1] = OSSL_PARAM_construct_end();
    return EVP_CIPHER_CTX_get_params(ctx, params);
}

static int set_speed(EVP_CIPHER_CTX *ctx, unsigned int speed)
{
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_SPEED, &speed);
    params[1] = OSSL_PARAM_construct_end();
    return EVP_CIPHER_CTX_set_params(ctx, params);
}

/* SIV and GCM-SIV: AAD, one message per key, the tag, `speed`, and final's checks. */
static void sivs(const char *name, int gcm)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, name, NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(), *copy = EVP_CIPHER_CTX_new();
    unsigned char out[100], back[100], tag[16], tag2[16];
    size_t taglen = 0;
    int n = -7, m = -7;
    OSSL_PARAM params[2];

    printf("  %s\n", name);
    check(EVP_EncryptInit_ex2(ctx, c, key, gcm ? iv : NULL, NULL), "init");
    check(!EVP_EncryptFinal_ex(ctx, out, &n) || gcm, "final before a message");
    errors();
    check(EVP_EncryptInit_ex2(ctx, NULL, key, gcm ? iv : NULL, NULL), "init again");
    check(EVP_EncryptUpdate(ctx, NULL, &n, data, 10) && n == 10, "AAD");
    check(EVP_EncryptUpdate(ctx, NULL, &n, data + 10, 7) && n == 7, "more AAD");
    check(EVP_CIPHER_CTX_copy(copy, ctx), "a copy");
    check(EVP_EncryptUpdate(ctx, out, &n, data + 20, 30) && n == 30, "the message");
    hex("out", out, n);
    check(!EVP_EncryptUpdate(ctx, out, &n, data + 20, 30), "one message a key");
    errors();
    check(!EVP_EncryptFinal_ex(ctx, out + 30, &n), "final after the second failed");
    errors();
    check(EVP_EncryptUpdate(copy, back, &n, data + 20, 30) && memcmp(out, back, 30) == 0,
          "the copy encrypts the same");
    check(EVP_EncryptFinal_ex(copy, back, &n) && n == 0, "final");
    check(get_tag(copy, tag, 16), "the tag");
    hex("tag", tag, 16);
    check(!get_tag(copy, tag2, 12), "a short tag");
    errors();
    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, &taglen);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_CIPHER_CTX_get_params(copy, params) && taglen == 16, "the tag's length");
    check(set_tag(copy, tag2, 16), "setting a tag encrypting");
    errors();
    /* Only a length, as evp_test sets it: encrypting, the data isn't read. */
    check(EVP_CIPHER_CTX_ctrl(copy, EVP_CTRL_AEAD_SET_TAG, 16, NULL) == 1,
          "a tag's length alone, encrypting");
    check(set_speed(copy, 1), "speed");
    check(EVP_EncryptUpdate(copy, back, &n, data + 20, 30), "then another message");
    check(EVP_EncryptFinal_ex(copy, back, &n), "and its final");

    /* Decrypting: the tag first; a wrong one fails final (SIV wipes the output). */
    check(EVP_DecryptInit_ex2(ctx, c, key, gcm ? iv : NULL, NULL), "decrypting");
    check(set_tag(ctx, tag, 16), "the tag");
    check(!set_tag(ctx, tag, 15), "a short tag");
    errors();
    check(EVP_DecryptUpdate(ctx, NULL, &n, data, 10) && EVP_DecryptUpdate(ctx, NULL, &n, data + 10, 7),
          "AAD");
    m = EVP_DecryptUpdate(ctx, back, &n, out, 30);
    check(m == 1 && n == 30 && memcmp(back, data + 20, 30) == 0, "decrypts");
    check(EVP_DecryptFinal_ex(ctx, back, &n) && n == 0, "final checks the tag");
    check(!get_tag(ctx, tag2, 16), "no tag to get decrypting");
    errors();
    check(EVP_DecryptInit_ex2(ctx, NULL, NULL, gcm ? iv : NULL, NULL), "again");
    tag[0] ^= 1;
    check(set_tag(ctx, tag, 16), "a changed tag");
    check(set_speed(ctx, 1), "speed");
    memset(back, 0x55, sizeof(back));
    m = EVP_DecryptUpdate(ctx, back, &n, out, 30);
    printf("  update %d\n", m);
    errors();
    hex("back", back, 30);
    check(!EVP_DecryptFinal_ex(ctx, back, &n), "final fails");
    errors();
    EVP_CIPHER_CTX_free(copy);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
}

/* SIV can't be copied before it has a key (its CTR context isn't made). */
static void siv_copy(void)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-SIV", NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(), *copy = EVP_CIPHER_CTX_new();

    check(EVP_EncryptInit_ex2(ctx, c, NULL, NULL, NULL), "no key");
    check(!EVP_CIPHER_CTX_copy(copy, ctx), "no copy");
    errors();
    check(EVP_EncryptInit_ex2(ctx, NULL, key, NULL, NULL), "a key");
    check(EVP_CIPHER_CTX_copy(copy, ctx), "a copy");
    EVP_CIPHER_CTX_free(copy);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
}

static void gcm_siv_more(void)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-GCM-SIV", NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char out[100], tag[16];
    int n = -7;

    /* final makes the tag of an empty message; an empty AAD clears the AAD. */
    check(EVP_EncryptInit_ex2(ctx, c, key, iv, NULL), "init");
    check(EVP_EncryptFinal_ex(ctx, out, &n), "final of nothing");
    check(get_tag(ctx, tag, 16), "its tag");
    hex("empty", tag, 16);
    check(EVP_EncryptInit_ex2(ctx, NULL, NULL, iv, NULL), "again");
    check(EVP_EncryptUpdate(ctx, NULL, &n, data, 20), "AAD");
    check(EVP_EncryptUpdate(ctx, NULL, &n, data, 0), "cleared");
    check(EVP_EncryptFinal_ex(ctx, out, &n) && get_tag(ctx, out, 16)
              && memcmp(out, tag, 16) == 0,
          "the same tag");
    check(!get_tag(ctx, out, 12), "a short tag");
    errors();
    check(EVP_EncryptInit_ex2(ctx, NULL, NULL, iv, NULL), "the AAD stays across inits");
    check(EVP_EncryptUpdate(ctx, NULL, &n, data, 20), "AAD");
    check(EVP_EncryptInit_ex2(ctx, NULL, NULL, iv, NULL), "init");
    check(EVP_EncryptFinal_ex(ctx, out, &n) && get_tag(ctx, out, 16), "final");
    hex("aad kept", out, 16);
    /* The nonce is 12 octets; an IV length isn't a parameter GCM-SIV knows. */
    check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 16, NULL) > 0, "ignored");
    check(EVP_CIPHER_CTX_get_iv_length(ctx) == 12, "the nonce is 12 octets");

    /* Decrypting without a tag: final fails. */
    check(EVP_DecryptInit_ex2(ctx, NULL, key, iv, NULL), "decrypting");
    check(EVP_DecryptUpdate(ctx, out, &n, data, 16), "a message");
    check(!EVP_DecryptFinal_ex(ctx, out, &n), "no tag");
    errors();
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
}

static int set_aad(EVP_CIPHER_CTX *ctx, unsigned char *aad)
{
    return EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD, 13, aad);
}

/* The composites: CBC on whole blocks, then TLS records with their MAC (where present). */
static void composites(void)
{
    static const char *names2[] = { "AES-128-CBC-HMAC-SHA1", "AES-256-CBC-HMAC-SHA256", NULL };
    int i;

    for (i = 0; names2[i] != NULL; i++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, names2[i], NULL);
        EVP_CIPHER_CTX *ctx;
        unsigned char out[300], back[300], rec[300];
        unsigned char aad[13] = { 0, 0, 0, 0, 0, 0, 0, 1, 23, 3, 3, 0, 50 };
        size_t pad = 0, frag = 4096, bufsz = 0;
        unsigned int interleave = 0;
        int n = -7, ret, len;
        OSSL_PARAM params[3];

        if (c == NULL) {
            ERR_clear_error();
            printf("  %s: absent\n", names2[i]);
            continue;
        }
        ctx = EVP_CIPHER_CTX_new();
        check(EVP_EncryptInit_ex2(ctx, c, key, iv, NULL), names2[i]);
        check(EVP_EncryptUpdate(ctx, out, &n, data, 32) && n == 32, "CBC");
        hex("cbc", out, n);
        check(!EVP_EncryptUpdate(ctx, out, &n, data, 20), "whole blocks only");
        errors();
        check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_MAC_KEY, 20, key + 3) > 0, "the MAC key");

        /* A TLS 1.2 record: explicit IV, 50 - 16 octets of payload, the MAC, padding. */
        ret = set_aad(ctx, aad);
        printf("  tls aad %d, length now %d\n", ret, aad[11] << 8 | aad[12]);
        params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, &pad);
        params[1] = OSSL_PARAM_construct_end();
        check(EVP_CIPHER_CTX_get_params(ctx, params), "the padding");
        len = 50 + (int)pad;
        printf("  pad %zu record %d\n", pad, len);
        memcpy(rec, data, 50);
        check(EVP_Cipher(ctx, rec, rec, len) > 0, "encrypts the record");
        hex("record", rec, len);
        check(EVP_Cipher(ctx, out, data, 33) <= 0, "then whole blocks only");
        errors();

        /* Decrypting it, then with its MAC changed. */
        check(EVP_DecryptInit_ex2(ctx, NULL, key, iv, NULL), "decrypting");
        check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_MAC_KEY, 20, key + 3) > 0, "the MAC key");
        aad[11] = 0;
        aad[12] = (unsigned char)len;
        check(set_aad(ctx, aad) > 0, "the AAD");
        check(EVP_CIPHER_CTX_get_params(ctx, params), "the padding");
        printf("  pad %zu\n", pad);
        memset(back, 0x55, sizeof(back));
        ret = EVP_Cipher(ctx, back, rec, len);
        printf("  decrypt %d\n", ret);
        hex("back", back, len);
        check(ret > 0 && memcmp(back + 16, data + 16, 34) == 0, "the payload");
        rec[len - 20] ^= 1;
        check(set_aad(ctx, aad) > 0, "the AAD");
        ret = EVP_Cipher(ctx, back, rec, len);
        printf("  decrypt %d\n", ret);
        errors();
        check(ret <= 0, "a bad MAC fails");

        /* Multi-block's sizes. */
        params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_SEND_FRAGMENT,
                                                &frag);
        params[1] = OSSL_PARAM_construct_end();
        check(EVP_CIPHER_CTX_set_params(ctx, params), "the fragment size");
        params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_BUFSIZE,
                                                &bufsz);
        check(EVP_CIPHER_CTX_get_params(ctx, params), "the buffer size");
        printf("  bufsz %zu\n", bufsz);
        params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE,
                                              &interleave);
        check(EVP_CIPHER_CTX_get_params(ctx, params), "the interleave");
        printf("  interleave %u\n", interleave);
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(c);
    }
}

/*
 * TLS 1.0 records (no explicit IV) through each composite, of `len` octets of payload: sealed,
 * opened, then opened with its last padding octet changed, then with its MAC's.
 */
static void tls10_records(int len)
{
    static const char *names2[] = { "AES-128-CBC-HMAC-SHA1", "AES-256-CBC-HMAC-SHA256", NULL };
    int i;

    for (i = 0; names2[i] != NULL; i++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, names2[i], NULL);
        EVP_CIPHER_CTX *ctx;
        unsigned char rec[600], back[600], work[600];
        unsigned char aad[13] = { 0, 0, 0, 0, 0, 0, 0, 9, 23, 3, 1, 0, 0 };
        size_t pad = 0;
        int ret, total;
        OSSL_PARAM params[2];

        if (c == NULL) {
            ERR_clear_error();
            continue;
        }
        ctx = EVP_CIPHER_CTX_new();
        aad[11] = (unsigned char)(len >> 8);
        aad[12] = (unsigned char)len;
        check(EVP_EncryptInit_ex2(ctx, c, key, iv, NULL), names2[i]);
        check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_MAC_KEY, 70, key) > 0, "a long MAC key");
        check(set_aad(ctx, aad) > 0, "a TLS 1.0 AAD");
        params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, &pad);
        params[1] = OSSL_PARAM_construct_end();
        check(EVP_CIPHER_CTX_get_params(ctx, params), "the padding");
        total = len + (int)pad;
        printf("  %s payload %d record %d\n", names2[i], len, total);
        memcpy(rec, data, len);
        check(EVP_Cipher(ctx, rec, rec, total) > 0, "sealed");
        hex("record", rec, total);
        check(EVP_DecryptInit_ex2(ctx, NULL, key, iv, NULL), "opening");
        check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_MAC_KEY, 70, key) > 0, "the MAC key");
        aad[11] = (unsigned char)(total >> 8);
        aad[12] = (unsigned char)total;
        check(set_aad(ctx, aad) > 0, "the AAD");
        ret = EVP_Cipher(ctx, back, rec, total);
        check(ret > 0 && memcmp(back, data, len) == 0, "opened");
        hex("opened", back, total);
        /* The last padding octet, then the MAC's first, changed (decrypted, so in the block
         * before: flip the ciphertext of the block before it). */
        memcpy(work, rec, total);
        work[total - 17] ^= 1;
        check(EVP_DecryptInit_ex2(ctx, NULL, NULL, iv, NULL) && set_aad(ctx, aad) > 0, "again");
        ret = EVP_Cipher(ctx, back, work, total);
        printf("  bad padding: %d\n", ret);
        errors();
        memcpy(work, rec, total);
        work[len - 16 > 0 ? len - 16 : 0] ^= 0x80;
        check(EVP_DecryptInit_ex2(ctx, NULL, NULL, iv, NULL) && set_aad(ctx, aad) > 0, "again");
        ret = EVP_Cipher(ctx, back, work, total);
        printf("  bad MAC: %d\n", ret);
        errors();
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(c);
    }
}

int main(void)
{
    int i;

    for (i = 0; i < (int)sizeof(key); i++)
        key[i] = (unsigned char)(i * 7 + 3);
    for (i = 0; i < (int)sizeof(iv); i++)
        iv[i] = (unsigned char)(0xa0 + i);
    for (i = 0; i < (int)sizeof(data); i++)
        data[i] = (unsigned char)(i * 13 + 1);
    each_cipher();
    cts();
    xts();
    wraps();
    tdes_wrap();
    sivs("AES-128-SIV", 0);
    sivs("AES-256-SIV", 0);
    sivs("AES-192-GCM-SIV", 1);
    siv_copy();
    gcm_siv_more();
    composites();
    tls10_records(3);
    tls10_records(40);
    tls10_records(400);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
