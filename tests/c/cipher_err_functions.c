/*
 * Conformance test for the functions a cipher mode's errors are raised in (ERR_get_error_all(3)),
 * in TAP format: the AES and triple-DES key wraps, XTS (AES and SM4), and the AES-CBC-HMAC-ETM
 * ciphers, whose update and one-shot functions are their own in the default provider
 * (aes_wrap_cipher_internal, tdes_wrap_update, aes_xts_stream_update, ...), not the generic
 * ones. `openssl enc` and friends print these names.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both, with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/*
 * Prints and clears the error queue (library, reason, and function of each entry), and says
 * whether its functions, in order and separated by spaces, are `want`.
 */
static int functions_are(const char *what, const char *want)
{
    unsigned long e;
    const char *func;
    char got[512] = "";
    size_t n = 0;

    printf("# errors %s:", what);
    while ((e = ERR_get_error_all(NULL, NULL, &func, NULL, NULL)) != 0) {
        if (func == NULL)
            func = "";
        printf(" %d/%d %s", ERR_GET_LIB(e), ERR_GET_REASON(e), func);
        n += (size_t)snprintf(got + n, n < sizeof(got) ? sizeof(got) - n : 0, "%s%s",
                              n == 0 ? "" : " ", func);
    }
    printf("\n");
    return strcmp(got, want) == 0;
}

static const unsigned char key[64] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
};
static const unsigned char iv[16] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
                                      0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf };

/* A context for `name` set up to encrypt (1) or decrypt (0); NULL if the cipher is missing. */
static EVP_CIPHER_CTX *start(const char *name, int enc)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, name, NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int ok;

    if (c == NULL || ctx == NULL) {
        EVP_CIPHER_free(c);
        EVP_CIPHER_CTX_free(ctx);
        ERR_clear_error();
        return NULL;
    }
    ok = EVP_CipherInit_ex2(ctx, c, key, EVP_CIPHER_get_iv_length(c) > 0 ? iv : NULL, enc,
                            NULL);
    EVP_CIPHER_free(c);
    if (!ok) {
        EVP_CIPHER_CTX_free(ctx);
        ERR_clear_error();
        return NULL;
    }
    return ctx;
}

/*
 * EVP_CipherUpdate with `inl` octets of input: it must fail, raising errors in `want`'s
 * functions.
 */
static void update_fails(const char *name, int enc, size_t inl, const char *want)
{
    EVP_CIPHER_CTX *ctx = start(name, enc);
    unsigned char *in = calloc(inl + 1, 1), *out = calloc(inl + 64, 1);
    int outl = 0, r;
    char what[160];

    snprintf(what, sizeof(what), "%s %s update of %zu octets", name,
             enc ? "encrypt" : "decrypt", inl);
    if (ctx == NULL || in == NULL || out == NULL) {
        check(0, what);
    } else {
        r = EVP_CipherUpdate(ctx, out, &outl, in, (int)inl);
        check(r == 0 && functions_are(what, want), what);
    }
    free(in);
    free(out);
    EVP_CIPHER_CTX_free(ctx);
}

/* EVP_Cipher (the one-shot function) likewise: it must fail (not return a length). */
static void cipher_fails(const char *name, int enc, size_t inl, const char *want)
{
    EVP_CIPHER_CTX *ctx = start(name, enc);
    unsigned char *in = calloc(inl + 1, 1), *out = calloc(inl + 64, 1);
    char what[160];

    snprintf(what, sizeof(what), "%s %s EVP_Cipher of %zu octets", name,
             enc ? "encrypt" : "decrypt", inl);
    if (ctx == NULL || in == NULL || out == NULL) {
        check(0, what);
    } else {
        int r = EVP_Cipher(ctx, out, in, (unsigned int)inl);

        printf("# %s: %d\n", what, r);
        check(r <= 0 && functions_are(what, want), what);
    }
    free(in);
    free(out);
    EVP_CIPHER_CTX_free(ctx);
}

/* update_fails for an ETM cipher's decryption of 32 octets, skipped if the CPU lacks it. */
static void etm_update_fails(const char *name, const char *want)
{
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, name, NULL);

    if (c == NULL) {
        ERR_clear_error();
        number++;
        printf("ok %d # skip %s isn't offered on this CPU\n", number, name);
        return;
    }
    EVP_CIPHER_free(c);
    update_fails(name, 0, 32, want);
}

int main(void)
{
    /* The AES key wraps: input checks and the unwrap's integrity check fail inside
     * aes_wrap_cipher_internal, which reports success with a length EVP refuses. */
    update_fails("AES-128-WRAP", 0, 15, "aes_wrap_cipher_internal EVP_DecryptUpdate");
    update_fails("AES-128-WRAP", 1, 12, "aes_wrap_cipher_internal EVP_EncryptUpdate");
    update_fails("AES-256-WRAP", 0, 24, "aes_wrap_cipher_internal EVP_DecryptUpdate");
    update_fails("AES-192-WRAP-PAD", 0, 24, "aes_wrap_cipher_internal EVP_DecryptUpdate");
    update_fails("AES-128-WRAP-INV", 0, 17, "aes_wrap_cipher_internal EVP_DecryptUpdate");

    /* Triple DES's key wrap: the inner function fails silently, its update reports it. */
    update_fails("DES3-WRAP", 0, 7, "tdes_wrap_update");
    update_fails("DES3-WRAP", 0, 32, "tdes_wrap_update");
    cipher_fails("DES3-WRAP", 0, 7, "");

    /* XTS: a data unit shorter than a block fails silently inside; the update reports it. */
    update_fails("AES-128-XTS", 1, 8, "aes_xts_stream_update");
    cipher_fails("AES-128-XTS", 1, 8, "");
    /* A data unit of more than 2^20 blocks: refused inside, then by the update. */
    update_fails("AES-256-XTS", 0, ((size_t)1 << 24) + 16, "aes_xts_cipher aes_xts_stream_update");
    update_fails("SM4-XTS", 0, ((size_t)1 << 24) + 16, "sm4_xts_cipher sm4_xts_stream_update");
    cipher_fails("AES-128-XTS", 1, ((size_t)1 << 24) + 16, "aes_xts_cipher");
    update_fails("SM4-XTS", 1, 8, "sm4_xts_stream_update");

    /* ETM: decrypting without the expected tag fails in the hardware-specific function, then
     * in the generic update. The default provider offers these ciphers only on aarch64 CPUs
     * with the AES and SHA instructions; elsewhere the checks are skipped. */
    etm_update_fails("AES-128-CBC-HMAC-SHA1-ETM",
                     "hwaes_cbc_hmac_sha1_etm ossl_cipher_generic_stream_update");
    etm_update_fails("AES-256-CBC-HMAC-SHA256-ETM",
                     "hwaes_cbc_hmac_sha256_etm ossl_cipher_generic_stream_update");
    etm_update_fails("AES-192-CBC-HMAC-SHA512-ETM",
                     "hwaes_cbc_hmac_sha512_etm ossl_cipher_generic_stream_update");

    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
