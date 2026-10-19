/*
 * Conformance test for OpenSSL 3.6's parameter decoders, in TAP format: a provider function
 * that 3.6 reads through a generated decoder fails a request that gives one of its parameters
 * twice (PROV_R_REPEATED_PARAMETER, "param <key> is repeated") or a list parameter more times
 * than it takes (PROV_R_TOO_MANY_RECORDS); other keys, repeated or not, are ignored, and
 * functions without a decoder (the RSA key manager's) still take the first.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

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
    const char *func = NULL, *data = NULL;
    int flags = 0;

    printf("  errors:");
    while ((e = ERR_get_error_all(NULL, NULL, &func, &data, &flags)) != 0)
        printf(" %d/%d %s \"%s\"", ERR_GET_LIB(e), ERR_GET_REASON(e), func != NULL ? func : "-",
               (flags & ERR_TXT_STRING) != 0 ? data : "");
    printf("\n");
}

static unsigned char salt[] = "salt", key[] = "secret key", info[] = "info";

static void kdfs(void)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM p[8];
    size_t size = 0;
    int i;

    printf("# HKDF\n");
    p[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    p[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, 4);
    p[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, 2);
    p[3] = OSSL_PARAM_construct_end();
    check(EVP_KDF_CTX_set_params(ctx, p) == 0, "a repeated salt fails");
    errors();
    p[2] = OSSL_PARAM_construct_utf8_string("no-such-key", "x", 0);
    p[3] = OSSL_PARAM_construct_utf8_string("no-such-key", "y", 0);
    p[4] = OSSL_PARAM_construct_end();
    check(EVP_KDF_CTX_set_params(ctx, p) == 1, "repeated unknown keys are ignored");
    errors();
    for (i = 0; i < 5; i++)
        p[i] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, 4);
    p[5] = OSSL_PARAM_construct_end();
    check(EVP_KDF_CTX_set_params(ctx, p) == 1, "five infos are taken");
    errors();
    p[5] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, 4);
    p[6] = OSSL_PARAM_construct_end();
    check(EVP_KDF_CTX_set_params(ctx, p) == 0, "six are too many");
    errors();
    p[0] = OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_SIZE, &size);
    p[1] = OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_SIZE, &size);
    p[2] = OSSL_PARAM_construct_end();
    check(EVP_KDF_CTX_get_params(ctx, p) == 0, "a repeated size request fails");
    errors();
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);

    printf("# PBKDF2 and SSKDF\n");
    kdf = EVP_KDF_fetch(NULL, "PBKDF2", NULL);
    ctx = EVP_KDF_CTX_new(kdf);
    check(EVP_KDF_CTX_get_params(ctx, p) == 0, "PBKDF2: a repeated size request fails");
    errors();
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    kdf = EVP_KDF_fetch(NULL, "X963KDF", NULL);
    ctx = EVP_KDF_CTX_new(kdf);
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, key, 4);
    p[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key, 4);
    p[2] = OSSL_PARAM_construct_end();
    check(EVP_KDF_CTX_set_params(ctx, p) == 0, "X963KDF: secret and key are one parameter");
    errors();
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
}

static void macs_and_digests(void)
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    EVP_MD *md = EVP_MD_fetch(NULL, "SHA256", NULL);
    OSSL_PARAM p[4];
    size_t a = 0, b = 0;

    printf("# HMAC and SHA-256\n");
    p[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0);
    p[1] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA1", 0);
    p[2] = OSSL_PARAM_construct_end();
    check(EVP_MAC_CTX_set_params(ctx, p) == 0, "HMAC: a repeated digest fails");
    errors();
    p[0] = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE, &a);
    p[1] = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE, &b);
    p[2] = OSSL_PARAM_construct_end();
    check(EVP_MD_get_params(md, p) == 0, "SHA-256: a repeated size request fails");
    errors();
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    EVP_MD_free(md);
}

static void ciphers(void)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char k[32] = { 0 }, iv[16] = { 0 };
    unsigned int pad = 1;
    size_t ivlen = 12;
    OSSL_PARAM p[4];

    printf("# AES-128-CBC and AES-256-GCM\n");
    EVP_EncryptInit_ex2(ctx, EVP_aes_128_cbc(), k, iv, NULL);
    p[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_PADDING, &pad);
    p[1] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_PADDING, &pad);
    p[2] = OSSL_PARAM_construct_end();
    check(EVP_CIPHER_CTX_set_params(ctx, p) == 0, "CBC: a repeated padding fails");
    errors();
    EVP_EncryptInit_ex2(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    p[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, &ivlen);
    p[1] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, &ivlen);
    p[2] = OSSL_PARAM_construct_end();
    check(EVP_CIPHER_CTX_set_params(ctx, p) == 0, "GCM: a repeated IV length fails");
    errors();
    EVP_CIPHER_CTX_free(ctx);
}

static void keys_and_rand(void)
{
    EVP_PKEY_CTX *pctx;
    EVP_PKEY *pkey = NULL;
    EVP_RAND *rand = EVP_RAND_fetch(NULL, "CTR-DRBG", NULL);
    EVP_RAND_CTX *rctx = EVP_RAND_CTX_new(rand, NULL);
    unsigned char pub[32] = { 9 };
    unsigned int bits = 2048;
    OSSL_PARAM p[4];

    printf("# X25519, RSA, CTR-DRBG\n");
    pctx = EVP_PKEY_CTX_new_from_name(NULL, "X25519", NULL);
    EVP_PKEY_fromdata_init(pctx);
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pub, 32);
    p[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pub, 32);
    p[2] = OSSL_PARAM_construct_end();
    check(EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, p) == 0, "X25519: a repeated public key fails");
    errors();
    EVP_PKEY_CTX_free(pctx);
    pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    EVP_PKEY_keygen_init(pctx);
    p[0] = OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_RSA_BITS, &bits);
    p[1] = OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_RSA_BITS, &bits);
    p[2] = OSSL_PARAM_construct_end();
    check(EVP_PKEY_CTX_set_params(pctx, p) == 1, "RSA key generation (no decoder) takes the first");
    errors();
    EVP_PKEY_CTX_free(pctx);
    p[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, "AES-128-CTR", 0);
    p[1] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, "AES-256-CTR", 0);
    p[2] = OSSL_PARAM_construct_end();
    check(EVP_RAND_CTX_set_params(rctx, p) == 0, "CTR-DRBG: a repeated cipher fails");
    errors();
    EVP_RAND_CTX_free(rctx);
    EVP_RAND_free(rand);
}

/* 3.6: Ed25519ph's and Ed25519ctx's set_ctx_params take only the context string. */
static void eddsa_variants(void)
{
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    static const char *const names[] = { "ED25519", "ED25519ph", "ED25519ctx" };
    unsigned char context[] = "context";
    OSSL_PARAM p[3];
    size_t i;

    printf("# EdDSA instances\n");
    for (i = 0; i < 3; i++) {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
        EVP_SIGNATURE *sig = EVP_SIGNATURE_fetch(NULL, names[i], NULL);

        printf("  %s: init %d", names[i], EVP_PKEY_sign_message_init(ctx, sig, NULL));
        p[0] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_INSTANCE, "Ed25519", 0);
        p[1] = OSSL_PARAM_construct_end();
        printf(", instance %d", EVP_PKEY_CTX_set_params(ctx, p));
        p[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, context, 7);
        p[1] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, context, 7);
        p[2] = OSSL_PARAM_construct_end();
        printf(", repeated context %d\n", EVP_PKEY_CTX_set_params(ctx, p));
        errors();
        EVP_SIGNATURE_free(sig);
        EVP_PKEY_CTX_free(ctx);
    }
    EVP_PKEY_free(key);
}

int main(void)
{
    kdfs();
    macs_and_digests();
    ciphers();
    keys_and_rand();
    eddsa_variants();
    printf("1..%d\n", number);
    return failures != 0;
}
