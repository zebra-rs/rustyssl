/*
 * The Wycheproof runner (TEST_PLAN.md, layer L2), driven by `cargo xtask test-wycheproof`.
 * Reads one test per line on stdin, runs it against whichever libcrypto the dynamic loader
 * picked, and prints what the library computed, one line per test. xtask runs the same input
 * against the reference and rustyssl, requires the same output from both, and checks it
 * against Wycheproof's verdicts. The runner only computes: it knows nothing of verdicts.
 *
 * Fields are hex, `-` for none (a NULL pointer where one is optional) and `_` for empty.
 * Every line starts with the test's id, which is echoed. Commands:
 *
 *   aead <cipher> <taglen> <key> <iv> <aads> <msg> <ct> <tag>
 *       Encrypts msg and decrypts ct with tag. <aads> is `-` or a comma-separated list, each
 *       given to its own update (SIV takes each as an S2V component). The IV length is set
 *       when it isn't the cipher's; CCM gets the tag length and the message length first.
 *       Prints `E:<ct>/<tag>` or `E:fail`, and `D:<msg>` or `D:fail`.
 *   cipher <cipher> <key> <iv> <msg> <ct>
 *       Encrypts msg and decrypts ct, with the cipher's default padding (key wrap allowed).
 *       Prints `E:<ct>` or `E:fail`, and `D:<msg>` or `D:fail`.
 *   mac <name> <params> <key> <msg>
 *       EVP_MAC over msg. <params> is `-` or a comma-separated list of name=value: digest,
 *       cipher (strings), size (size_t), c-rounds and d-rounds (unsigned), iv (hex).
 *       Prints `T:<tag>` or `T:fail`.
 *   hkdf <digest> <ikm> <salt> <info> <size>
 *       The HKDF KDF. Prints `K:<okm>` or `K:fail`.
 *   pbkdf2 <digest> <password> <salt> <iter> <size>
 *       PKCS5_PBKDF2_HMAC. Prints `K:<dk>` or `K:fail`.
 *   pbes2 <digest> <cipher> <password> <salt> <iter> <iv> <msg> <ct>
 *       PBKDF2 for the cipher's key, then as `cipher`. Prints as `cipher`.
 *   rsadec <padding> <digest> <mgf1> <key> <label> <ct>
 *       Decrypts ct with the RSA key (see below), `oaep` (with the digest, MGF1 digest, and
 *       label) or `pkcs1`. Prints `D:<msg>` or `D:fail`; for `pkcs1`, that with implicit
 *       rejection off, then `I:<msg>` or `I:fail` with it on (the default).
 *   rsaver <padding> <digest> <mgf1> <saltlen> <key> <msg> <sig>
 *       EVP_DigestVerify of sig over msg, `pkcs1` or `pss` (with the MGF1 digest and the salt
 *       length). Prints `V:ok` or `V:fail`.
 *   rsasign <digest> <key> <msg>
 *       EVP_DigestSign with PKCS #1 v1.5 padding. Prints `S:<sig>` or `S:fail`.
 *
 * An RSA key is its numbers in hex, comma-separated: n and e (a public key), then d, then
 * optionally the primes, their exponents, and the coefficients, as OpenSSL's parameters
 * rsa-factor1..k, rsa-exponent1..k, rsa-coefficient1..k-1 name them.
 *
 * A failure is printed with the library and reason of the error it left, `fail(<lib>/<r>)`.
 */
/* getline, strdup, strtok_r. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>

struct buf {
    unsigned char *p;
    size_t n;
    int null;
};

static int hexval(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* Decodes `text` (`-` NULL, `_` empty); exits on bad input, which is xtask's mistake. */
static struct buf hex(const char *text)
{
    struct buf b = { NULL, 0, 0 };
    size_t i, len;

    if (strcmp(text, "-") == 0) {
        b.null = 1;
        b.p = malloc(1);
        return b;
    }
    if (strcmp(text, "_") == 0)
        text = "";
    len = strlen(text);
    if (len % 2 != 0) {
        fprintf(stderr, "odd hex: %s\n", text);
        exit(2);
    }
    b.n = len / 2;
    b.p = malloc(b.n + 1);
    for (i = 0; i < b.n; i++) {
        int hi = hexval(text[2 * i]), lo = hexval(text[2 * i + 1]);

        if (hi < 0 || lo < 0) {
            fprintf(stderr, "bad hex: %s\n", text);
            exit(2);
        }
        b.p[i] = (unsigned char)(hi << 4 | lo);
    }
    return b;
}

static void print_hex(const unsigned char *p, size_t n)
{
    size_t i;

    if (n == 0)
        printf("_");
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
}

/* `fail` with the last error's library and reason, which is then cleared. */
static void print_fail(void)
{
    unsigned long e = ERR_peek_last_error();

    printf("fail(%d/%d)", ERR_GET_LIB(e), ERR_GET_REASON(e));
    ERR_clear_error();
}

static void field(const char *what, int ok, const unsigned char *p, size_t n)
{
    printf(" %s:", what);
    if (ok)
        print_hex(p, n);
    else
        print_fail();
}

/* Splits `line` into at most `max` words in place. */
static int split(char *line, char **words, int max)
{
    int n = 0;
    char *s = strtok(line, " \n");

    while (s != NULL && n < max) {
        words[n++] = s;
        s = strtok(NULL, " \n");
    }
    return n;
}

/* The AAD list: `-` none, else comma-separated hex (`_` empty), each its own update. */
static int add_aads(EVP_CIPHER_CTX *ctx, const char *list)
{
    char *copy, *item, *save = NULL;
    int ok = 1, outl;

    if (strcmp(list, "-") == 0)
        return 1;
    copy = strdup(list);
    for (item = strtok_r(copy, ",", &save); ok && item != NULL; item = strtok_r(NULL, ",", &save)) {
        struct buf a = hex(item);

        ok = EVP_CipherUpdate(ctx, NULL, &outl, a.p, (int)a.n) > 0;
        free(a.p);
    }
    free(copy);
    return ok;
}

/* One direction of an AEAD: `in` to `out`, the tag got (enc) or checked (dec). */
static int aead_one(EVP_CIPHER *c, int enc, size_t taglen, struct buf *key, struct buf *iv,
                    const char *aads, struct buf *in, unsigned char *out, int *outn,
                    unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int ccm = EVP_CIPHER_get_mode(c) == EVP_CIPH_CCM_MODE;
    int ok, n = 0, m = 0;

    ok = EVP_CipherInit_ex2(ctx, c, NULL, NULL, enc, NULL) > 0;
    if (ok && !iv->null && iv->n != (size_t)EVP_CIPHER_CTX_get_iv_length(ctx))
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)iv->n, NULL) > 0;
    if (ok && ccm)
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)taglen, enc ? NULL : tag) > 0;
    if (ok)
        ok = EVP_CipherInit_ex2(ctx, NULL, key->p, iv->null ? NULL : iv->p, enc, NULL) > 0;
    if (ok && !enc && !ccm)
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)taglen, tag) > 0;
    if (ok && ccm)
        ok = EVP_CipherUpdate(ctx, NULL, &n, NULL, (int)in->n) > 0;
    if (ok)
        ok = add_aads(ctx, aads);
    if (ok)
        ok = EVP_CipherUpdate(ctx, out, &n, in->p, (int)in->n) > 0;
    if (ok)
        ok = EVP_CipherFinal_ex(ctx, out + n, &m) > 0;
    if (ok && enc)
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)taglen, tag) > 0;
    *outn = n + m;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static void aead(char **w)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, w[0], NULL);
    size_t taglen = (size_t)atoi(w[1]);
    struct buf key = hex(w[2]), iv = hex(w[3]), msg = hex(w[5]), ct = hex(w[6]), tag = hex(w[7]);
    unsigned char *out = malloc(msg.n + ct.n + 64), gottag[64];
    int ok, n = 0;

    if (c == NULL || taglen > sizeof(gottag)) {
        printf(" E:");
        print_fail();
        printf(" D:");
        print_fail();
    } else {
        ok = aead_one(c, 1, taglen, &key, &iv, w[4], &msg, out, &n, gottag);
        printf(" E:");
        if (ok) {
            print_hex(out, (size_t)n);
            printf("/");
            print_hex(gottag, taglen);
        } else {
            print_fail();
        }
        /* A tag of another length than `taglen` can't be checked: the reference reads
         * `taglen` octets of it. */
        memset(gottag, 0, sizeof(gottag));
        memcpy(gottag, tag.p, tag.n < taglen ? tag.n : taglen);
        ok = tag.n == taglen && aead_one(c, 0, taglen, &key, &iv, w[4], &ct, out, &n, gottag);
        printf(" D:");
        if (ok)
            print_hex(out, (size_t)n);
        else if (tag.n != taglen)
            printf("fail(tag)");
        else
            print_fail();
    }
    EVP_CIPHER_free(c);
    free(out);
    free(key.p), free(iv.p), free(msg.p), free(ct.p), free(tag.p);
}

static int cipher_one(EVP_CIPHER *c, int enc, struct buf *key, struct buf *iv, struct buf *in,
                      unsigned char *out, int *outn)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int ok, n = 0, m = 0;

    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    ok = EVP_CipherInit_ex2(ctx, c, key->p, iv->null ? NULL : iv->p, enc, NULL) > 0;
    if (ok)
        ok = EVP_CipherUpdate(ctx, out, &n, in->p, (int)in->n) > 0;
    if (ok)
        ok = EVP_CipherFinal_ex(ctx, out + n, &m) > 0;
    *outn = n + m;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* Encrypts msg and decrypts ct with `c` (consumed), printing both. */
static void cipher_both(EVP_CIPHER *c, struct buf *key, struct buf *iv, struct buf *msg,
                        struct buf *ct)
{
    unsigned char *out = malloc(msg->n + ct->n + 64);
    int ok, n = 0;

    if (c == NULL) {
        printf(" E:");
        print_fail();
        printf(" D:");
        print_fail();
    } else {
        ok = cipher_one(c, 1, key, iv, msg, out, &n);
        field("E", ok, out, (size_t)n);
        ok = cipher_one(c, 0, key, iv, ct, out, &n);
        field("D", ok, out, (size_t)n);
    }
    EVP_CIPHER_free(c);
    free(out);
}

static void cipher(char **w)
{
    struct buf key = hex(w[1]), iv = hex(w[2]), msg = hex(w[3]), ct = hex(w[4]);

    cipher_both(EVP_CIPHER_fetch(NULL, w[0], NULL), &key, &iv, &msg, &ct);
    free(key.p), free(iv.p), free(msg.p), free(ct.p);
}

static void mac(char **w)
{
    EVP_MAC *m = EVP_MAC_fetch(NULL, w[0], NULL);
    EVP_MAC_CTX *ctx = m == NULL ? NULL : EVP_MAC_CTX_new(m);
    struct buf key = hex(w[2]), msg = hex(w[3]), iv = { NULL, 0, 1 };
    OSSL_PARAM params[8];
    size_t size = 0, n = 0, np = 0;
    unsigned int crounds = 0, drounds = 0;
    unsigned char tag[128];
    char *copy = strdup(w[1]), *item, *save = NULL;
    int ok;

    if (strcmp(copy, "-") != 0) {
        for (item = strtok_r(copy, ",", &save); item != NULL; item = strtok_r(NULL, ",", &save)) {
            char *value = strchr(item, '=');

            *value++ = '\0';
            if (strcmp(item, "size") == 0) {
                size = (size_t)atoi(value);
                params[np++] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &size);
            } else if (strcmp(item, "c-rounds") == 0) {
                crounds = (unsigned int)atoi(value);
                params[np++] = OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_C_ROUNDS, &crounds);
            } else if (strcmp(item, "d-rounds") == 0) {
                drounds = (unsigned int)atoi(value);
                params[np++] = OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_D_ROUNDS, &drounds);
            } else if (strcmp(item, "iv") == 0) {
                iv = hex(value);
                params[np++] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_IV, iv.p, iv.n);
            } else {
                params[np++] = OSSL_PARAM_construct_utf8_string(item, value, 0);
            }
        }
    }
    params[np] = OSSL_PARAM_construct_end();
    ok = ctx != NULL && EVP_MAC_init(ctx, key.p, key.n, params) > 0
        && EVP_MAC_update(ctx, msg.p, msg.n) > 0
        && EVP_MAC_final(ctx, tag, &n, sizeof(tag)) > 0;
    field("T", ok, tag, n);
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(m);
    free(copy), free(key.p), free(msg.p), free(iv.p);
}

static void hkdf(char **w)
{
    EVP_KDF *k = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *ctx = k == NULL ? NULL : EVP_KDF_CTX_new(k);
    struct buf ikm = hex(w[1]), salt = hex(w[2]), info = hex(w[3]);
    size_t size = (size_t)atoi(w[4]);
    unsigned char *okm = malloc(size + 1);
    OSSL_PARAM params[5], *p = params;
    int ok;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, w[0], 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm.p, ikm.n);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt.p, salt.n);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info.p, info.n);
    *p = OSSL_PARAM_construct_end();
    ok = ctx != NULL && EVP_KDF_derive(ctx, okm, size, params) > 0;
    field("K", ok, okm, size);
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(k);
    free(okm), free(ikm.p), free(salt.p), free(info.p);
}

static void pbkdf2(char **w)
{
    const EVP_MD *md = EVP_get_digestbyname(w[0]);
    struct buf pass = hex(w[1]), salt = hex(w[2]);
    int size = atoi(w[4]);
    unsigned char *dk = malloc((size_t)size + 1);
    int ok = md != NULL
        && PKCS5_PBKDF2_HMAC((const char *)pass.p, (int)pass.n, salt.p, (int)salt.n,
                             atoi(w[3]), md, size, dk) > 0;

    field("K", ok, dk, (size_t)size);
    free(dk), free(pass.p), free(salt.p);
}

static void pbes2(char **w)
{
    const EVP_MD *md = EVP_get_digestbyname(w[0]);
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, w[1], NULL);
    struct buf pass = hex(w[2]), salt = hex(w[3]), iv = hex(w[5]), msg = hex(w[6]), ct = hex(w[7]);
    struct buf key = { NULL, 0, 0 };
    int ok;

    if (md == NULL || c == NULL) {
        EVP_CIPHER_free(c);
        c = NULL;
    } else {
        key.n = (size_t)EVP_CIPHER_get_key_length(c);
        key.p = malloc(key.n + 1);
        ok = PKCS5_PBKDF2_HMAC((const char *)pass.p, (int)pass.n, salt.p, (int)salt.n,
                               atoi(w[4]), md, (int)key.n, key.p) > 0;
        if (!ok) {
            EVP_CIPHER_free(c);
            c = NULL;
        }
    }
    cipher_both(c, &key, &iv, &msg, &ct);
    free(key.p), free(pass.p), free(salt.p), free(iv.p), free(msg.p), free(ct.p);
}

/* An RSA key from its numbers (see above), or NULL. */
static EVP_PKEY *rsa_key(const char *numbers)
{
    /* The builder keeps the names, so they're static. */
    static const char *const names[3][10] = {
        { "rsa-factor1", "rsa-factor2", "rsa-factor3", "rsa-factor4", "rsa-factor5",
          "rsa-factor6", "rsa-factor7", "rsa-factor8", "rsa-factor9", "rsa-factor10" },
        { "rsa-exponent1", "rsa-exponent2", "rsa-exponent3", "rsa-exponent4", "rsa-exponent5",
          "rsa-exponent6", "rsa-exponent7", "rsa-exponent8", "rsa-exponent9",
          "rsa-exponent10" },
        { "rsa-coefficient1", "rsa-coefficient2", "rsa-coefficient3", "rsa-coefficient4",
          "rsa-coefficient5", "rsa-coefficient6", "rsa-coefficient7", "rsa-coefficient8",
          "rsa-coefficient9", NULL }
    };
    char *copy = strdup(numbers), *item, *save = NULL;
    BIGNUM *nums[32];
    size_t count = 0, i, k;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    EVP_PKEY *pkey = NULL;

    for (item = strtok_r(copy, ",", &save); item != NULL && count < 32;
         item = strtok_r(NULL, ",", &save)) {
        nums[count] = NULL;
        BN_hex2bn(&nums[count], item);
        count++;
    }
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, nums[0]);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, nums[1]);
    if (count > 2)
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, nums[2]);
    /* The primes, then their exponents, then the coefficients: k, k, and k - 1 numbers. */
    k = count > 3 ? (count - 3 + 1) / 3 : 0;
    for (i = 3; i < count && k <= 10; i++) {
        size_t j = i - 3, which = j < k ? 0 : j < 2 * k ? 1 : 2;

        OSSL_PARAM_BLD_push_BN(bld, names[which][j - which * k], nums[i]);
    }
    params = OSSL_PARAM_BLD_to_param(bld);
    if (ctx == NULL || EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, &pkey, count > 2 ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY,
                             params) <= 0)
        pkey = NULL;
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    for (i = 0; i < count; i++)
        BN_free(nums[i]);
    free(copy);
    return pkey;
}

/* One decryption of ct; `implicit` is the PKCS #1 v1.5 implicit-rejection setting. */
static void rsa_decrypt_one(const char *what, EVP_PKEY *key, char **w, struct buf *label,
                            struct buf *ct, int implicit)
{
    EVP_PKEY_CTX *ctx = key == NULL ? NULL : EVP_PKEY_CTX_new(key, NULL);
    unsigned char *out = malloc(ct->n + 1);
    size_t n = ct->n;
    int oaep = strcmp(w[0], "oaep") == 0;
    int ok = ctx != NULL && EVP_PKEY_decrypt_init(ctx) > 0
        && EVP_PKEY_CTX_set_rsa_padding(ctx, oaep ? RSA_PKCS1_OAEP_PADDING
                                                  : RSA_PKCS1_PADDING) > 0;

    if (ok && oaep) {
        ok = EVP_PKEY_CTX_set_rsa_oaep_md_name(ctx, w[1], NULL) > 0
            && EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx, w[2], NULL) > 0;
        /* An empty label is no label (setting a NULL one fails). */
        if (ok && label->n > 0) {
            unsigned char *l = OPENSSL_memdup(label->p, label->n);

            ok = EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, l, (int)label->n) > 0;
            if (!ok)
                OPENSSL_free(l);
        }
    }
    if (ok && !oaep)
        ok = EVP_PKEY_CTX_ctrl_str(ctx, "rsa_pkcs1_implicit_rejection",
                                   implicit ? "1" : "0") > 0;
    ok = ok && EVP_PKEY_decrypt(ctx, out, &n, ct->p, ct->n) > 0;
    field(what, ok, out, n);
    EVP_PKEY_CTX_free(ctx);
    free(out);
}

static void rsa_decrypt(char **w)
{
    EVP_PKEY *key = rsa_key(w[3]);
    struct buf label = hex(w[4]), ct = hex(w[5]);

    rsa_decrypt_one("D", key, w, &label, &ct, 0);
    if (strcmp(w[0], "pkcs1") == 0)
        rsa_decrypt_one("I", key, w, &label, &ct, 1);
    EVP_PKEY_free(key);
    free(label.p), free(ct.p);
}

static void rsa_verify(char **w)
{
    EVP_PKEY *key = rsa_key(w[4]);
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    struct buf msg = hex(w[5]), sig = hex(w[6]);
    int ok = key != NULL && EVP_DigestVerifyInit_ex(md, &pctx, w[1], NULL, NULL, key, NULL) > 0;

    if (ok && strcmp(w[0], "pss") == 0)
        ok = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0
            && EVP_PKEY_CTX_set_rsa_mgf1_md_name(pctx, w[2], NULL) > 0
            && EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, atoi(w[3])) > 0;
    ok = ok && EVP_DigestVerify(md, sig.p, sig.n, msg.p, msg.n) == 1;
    printf(" V:");
    if (ok)
        printf("ok");
    else
        print_fail();
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(key);
    free(msg.p), free(sig.p);
}

static void rsa_sign(char **w)
{
    EVP_PKEY *key = rsa_key(w[1]);
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    struct buf msg = hex(w[2]);
    unsigned char sig[2048];
    size_t n = sizeof(sig);
    int ok = key != NULL && EVP_DigestSignInit_ex(md, NULL, w[0], NULL, NULL, key, NULL) > 0
        && EVP_DigestSign(md, sig, &n, msg.p, msg.n) > 0;

    field("S", ok, sig, n);
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(key);
    free(msg.p);
}

int main(void)
{
    char *line = NULL, *w[16];
    size_t cap = 0;

    while (getline(&line, &cap, stdin) > 0) {
        int n = split(line, w, 16);

        if (n < 2)
            continue;
        printf("%s", w[0]);
        if (strcmp(w[1], "aead") == 0 && n == 10)
            aead(w + 2);
        else if (strcmp(w[1], "cipher") == 0 && n == 7)
            cipher(w + 2);
        else if (strcmp(w[1], "mac") == 0 && n == 6)
            mac(w + 2);
        else if (strcmp(w[1], "hkdf") == 0 && n == 7)
            hkdf(w + 2);
        else if (strcmp(w[1], "pbkdf2") == 0 && n == 7)
            pbkdf2(w + 2);
        else if (strcmp(w[1], "pbes2") == 0 && n == 10)
            pbes2(w + 2);
        else if (strcmp(w[1], "rsadec") == 0 && n == 8)
            rsa_decrypt(w + 2);
        else if (strcmp(w[1], "rsaver") == 0 && n == 9)
            rsa_verify(w + 2);
        else if (strcmp(w[1], "rsasign") == 0 && n == 5)
            rsa_sign(w + 2);
        else {
            fprintf(stderr, "bad command: %s\n", w[1]);
            return 2;
        }
        printf("\n");
        ERR_clear_error();
    }
    free(line);
    return 0;
}
