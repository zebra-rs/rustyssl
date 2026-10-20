/*
 * Conformance test for UTF-8 string parameters made with a size of zero
 * (OSSL_PARAM_utf8_string(key, value, 0)), in TAP format, across the built-in providers' readers:
 * key generation and import (EC, DH, DSA, X25519), KDFs (HKDF, PBKDF2, TLS1-PRF, SSHKDF,
 * X942KDF), MACs (HMAC, CMAC), DRBGs (CTR, HASH, HMAC), ciphers' modes (CTS, XTS), signatures
 * (RSA, ECDSA), key exchange (ECDH), asymmetric ciphers (RSA), and KEMs (RSA). OpenSSL reads such
 * a parameter as a C string where it uses the data directly (the whole value counts), as an empty
 * string where it copies the parameter (OSSL_PARAM_get_utf8_string), and by its size where it
 * looks at the size; each case prints what the call returned and what it raised.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
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

/* The queue's codes, oldest first. */
static void codes(void)
{
    unsigned long code;

    printf("  errors:");
    while ((code = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
    printf("\n");
}

static void hex(const char *what, const unsigned char *b, size_t n)
{
    size_t i;

    printf("  %s:", what);
    for (i = 0; i < n; i++)
        printf("%02x", b[i]);
    printf("\n");
}

/* A UTF-8 string parameter of size zero over a whole C string. */
#define ZERO(key, value) OSSL_PARAM_utf8_string(key, (char *)(value), 0)

/* A key generated from one string parameter; prints the results and returns the key. */
static EVP_PKEY *keygen(const char *alg, const char *what, const OSSL_PARAM *params)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    EVP_PKEY *pkey = NULL;
    int set, gen = -2;

    ERR_clear_error();
    if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0) {
        check(0, what);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    set = EVP_PKEY_CTX_set_params(ctx, params);
    if (set > 0)
        gen = EVP_PKEY_generate(ctx, &pkey);
    printf("# %s %s\n", alg, what);
    printf("  set %d, generate %d, bits %d\n", set, gen, pkey == NULL ? 0 : EVP_PKEY_get_bits(pkey));
    codes();
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* Setting one parameter on a parameter-generation context; prints the result. */
static void paramgen_set(const char *alg, const char *what, const OSSL_PARAM *params)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);

    ERR_clear_error();
    check(ctx != NULL && EVP_PKEY_paramgen_init(ctx) > 0, "a parameter-generation context");
    printf("  %s %s: %d\n", alg, what, EVP_PKEY_CTX_set_params(ctx, params));
    codes();
    EVP_PKEY_CTX_free(ctx);
}

/* Domain parameters imported from one parameter; prints the results. */
static void fromdata(const char *alg, const char *what, OSSL_PARAM *params)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    EVP_PKEY *pkey = NULL;
    char name[64] = "";
    int r;

    ERR_clear_error();
    check(ctx != NULL && EVP_PKEY_fromdata_init(ctx) > 0, "an import context");
    r = EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEY_PARAMETERS, params);
    if (pkey != NULL)
        EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, name, sizeof(name), NULL);
    printf("  %s %s: %d, bits %d, group %s\n", alg, what, r,
           pkey == NULL ? 0 : EVP_PKEY_get_bits(pkey), name);
    codes();
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}

/* A KDF's output from parameters, or its failure. */
static void kdf(const char *alg, const char *what, const OSSL_PARAM *params, size_t n)
{
    EVP_KDF *k = EVP_KDF_fetch(NULL, alg, NULL);
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(k);
    unsigned char out[64];
    int r;

    ERR_clear_error();
    check(ctx != NULL, "a KDF context");
    printf("# %s %s\n", alg, what);
    r = EVP_KDF_derive(ctx, out, n, params);
    printf("  derive: %d\n", r);
    if (r > 0)
        hex("out", out, n);
    codes();
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(k);
}

/* Setting a KDF's parameters only. */
static void kdf_set(const char *alg, const char *what, const OSSL_PARAM *params)
{
    EVP_KDF *k = EVP_KDF_fetch(NULL, alg, NULL);
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(k);

    ERR_clear_error();
    check(ctx != NULL, "a KDF context");
    printf("  %s %s: %d\n", alg, what, EVP_KDF_CTX_set_params(ctx, params));
    codes();
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(k);
}

/* A MAC of "abc" under a 16-octet key, set up from parameters. */
static void mac(const char *alg, const char *what, const OSSL_PARAM *params)
{
    static const unsigned char key[] = "0123456789abcdef";
    EVP_MAC *m = EVP_MAC_fetch(NULL, alg, NULL);
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(m);
    unsigned char out[64];
    size_t n = 0;
    int r;

    ERR_clear_error();
    check(ctx != NULL, "a MAC context");
    printf("# %s %s\n", alg, what);
    r = EVP_MAC_init(ctx, key, 16, params);
    printf("  init: %d\n", r);
    if (r > 0 && EVP_MAC_update(ctx, (const unsigned char *)"abc", 3) > 0
        && EVP_MAC_final(ctx, out, &n, sizeof(out)) > 0)
        hex("mac", out, n);
    codes();
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(m);
}

/* Setting a DRBG's parameters (with a parent, so it can be instantiated later). */
static void drbg(const char *alg, const char *what, const OSSL_PARAM *params)
{
    EVP_RAND *r = EVP_RAND_fetch(NULL, alg, NULL);
    EVP_RAND_CTX *ctx = EVP_RAND_CTX_new(r, NULL);

    ERR_clear_error();
    check(ctx != NULL, "a DRBG context");
    printf("  %s %s: %d\n", alg, what, EVP_RAND_CTX_set_params(ctx, params));
    codes();
    EVP_RAND_CTX_free(ctx);
    EVP_RAND_free(r);
}

/* Setting a cipher context's parameters after its initialisation, then reading one back. */
static void cipher(const char *alg, const char *what, const OSSL_PARAM *params, const char *back)
{
    static const unsigned char iv[16];
    unsigned char key[64];
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, alg, NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    char text[32] = "";
    OSSL_PARAM get[2];
    size_t i;

    for (i = 0; i < sizeof(key); i++)
        key[i] = (unsigned char)i;
    ERR_clear_error();
    check(c != NULL && ctx != NULL && EVP_EncryptInit_ex2(ctx, c, key, iv, NULL) > 0,
          "an initialised cipher context");
    printf("  %s %s: %d", alg, what, EVP_CIPHER_CTX_set_params(ctx, params));
    if (back != NULL) {
        get[0] = OSSL_PARAM_construct_utf8_string(back, text, sizeof(text));
        get[1] = OSSL_PARAM_construct_end();
        if (EVP_CIPHER_CTX_get_params(ctx, get) > 0)
            printf(", %s %s", back, text);
    }
    printf("\n");
    codes();
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
}

enum op { SIGN, DERIVE, DECRYPT, ENCAPSULATE };

/* Setting a public-key operation's parameters. */
static void operation(EVP_PKEY *pkey, enum op op, const char *what, const OSSL_PARAM *params)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    int init = 0;

    ERR_clear_error();
    if (ctx != NULL) {
        switch (op) {
        case SIGN:
            init = EVP_PKEY_sign_init(ctx);
            break;
        case DERIVE:
            init = EVP_PKEY_derive_init(ctx);
            break;
        case DECRYPT:
            init = EVP_PKEY_decrypt_init(ctx);
            break;
        case ENCAPSULATE:
            init = EVP_PKEY_encapsulate_init(ctx, NULL);
            break;
        }
    }
    check(init > 0, "an initialised operation");
    printf("  %s: %d\n", what, EVP_PKEY_CTX_set_params(ctx, params));
    codes();
    EVP_PKEY_CTX_free(ctx);
}

int main(void)
{
    static unsigned char secret[] = "secret-material!", salt[] = "saltsalt";
    char text[64];
    EVP_PKEY *ec, *dh, *x, *rsa;

    printf("# OSSL_PARAM_get_utf8_string and _ptr on a size of zero\n");
    {
        OSSL_PARAM p = ZERO("x", "P-256");
        const char *ptr = NULL;
        char *s = text;

        check(OSSL_PARAM_get_utf8_string_ptr(&p, &ptr) == 1 && strcmp(ptr, "P-256") == 0,
              "the pointer is the whole string");
        check(OSSL_PARAM_get_utf8_string(&p, &s, sizeof(text)) == 1 && text[0] == '\0',
              "the copy is empty");
    }

    printf("# key generation\n");
    {
        OSSL_PARAM a[] = { ZERO(OSSL_PKEY_PARAM_GROUP_NAME, "P-256"), OSSL_PARAM_END };
        OSSL_PARAM b[] = { OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "P-256xyz", 5),
                           OSSL_PARAM_END };
        OSSL_PARAM c[] = { ZERO(OSSL_PKEY_PARAM_GROUP_NAME, "P-384"),
                           ZERO(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, "compressed"),
                           ZERO(OSSL_PKEY_PARAM_EC_ENCODING, "explicit"), OSSL_PARAM_END };
        OSSL_PARAM d[] = { ZERO(OSSL_PKEY_PARAM_GROUP_NAME, "ffdhe2048"), OSSL_PARAM_END };
        OSSL_PARAM e[] = { ZERO(OSSL_PKEY_PARAM_GROUP_NAME, "x25519"), OSSL_PARAM_END };
        OSSL_PARAM f[] = { ZERO(OSSL_PKEY_PARAM_GROUP_NAME, "x448"), OSSL_PARAM_END };
        EVP_PKEY *k;

        ec = keygen("EC", "group P-256", a);
        check(ec != NULL, "an EC key from a size-0 group");
        k = keygen("EC", "group P-256xyz of size 5", b);
        EVP_PKEY_free(k);
        k = keygen("EC", "group P-384, compressed, explicit", c);
        text[0] = '\0';
        if (k != NULL) {
            EVP_PKEY_get_utf8_string_param(k, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, text,
                                           sizeof(text), NULL);
            printf("  format %s", text);
            text[0] = '\0';
            EVP_PKEY_get_utf8_string_param(k, OSSL_PKEY_PARAM_EC_ENCODING, text, sizeof(text),
                                           NULL);
            printf(", encoding %s\n", text);
        }
        EVP_PKEY_free(k);
        dh = keygen("DH", "group ffdhe2048", d);
        check(dh != NULL, "a DH key from a size-0 group");
        x = keygen("X25519", "group x25519", e);
        check(x != NULL, "an X25519 key from a size-0 group");
        k = keygen("X25519", "group x448", f);
        EVP_PKEY_free(k);
    }

    printf("# parameter generation\n");
    {
        OSSL_PARAM a[] = { ZERO(OSSL_PKEY_PARAM_FFC_TYPE, "generator"), OSSL_PARAM_END };
        OSSL_PARAM b[] = { ZERO(OSSL_PKEY_PARAM_FFC_TYPE, "nonsense"), OSSL_PARAM_END };
        OSSL_PARAM c[] = { ZERO(OSSL_PKEY_PARAM_FFC_TYPE, "fips186_4"),
                           ZERO(OSSL_PKEY_PARAM_FFC_DIGEST, "SHA256"),
                           ZERO(OSSL_PKEY_PARAM_FFC_DIGEST_PROPS, "provider=default"),
                           OSSL_PARAM_END };
        OSSL_PARAM d[] = { ZERO(OSSL_PKEY_PARAM_GROUP_NAME, "ffdhe3072"), OSSL_PARAM_END };

        paramgen_set("DH", "type generator", a);
        paramgen_set("DH", "type nonsense", b);
        paramgen_set("DH", "group ffdhe3072", d);
        paramgen_set("DSA", "type fips186_4, digest SHA256", c);
        paramgen_set("DSA", "type nonsense", b);
    }

    printf("# import\n");
    {
        OSSL_PARAM a[] = { ZERO(OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1"), OSSL_PARAM_END };
        OSSL_PARAM b[] = { ZERO(OSSL_PKEY_PARAM_GROUP_NAME, "ffdhe2048"), OSSL_PARAM_END };

        fromdata("EC", "group prime256v1", a);
        fromdata("DH", "group ffdhe2048", b);
    }

    printf("# KDFs\n");
    {
        OSSL_PARAM a[] = { ZERO(OSSL_KDF_PARAM_DIGEST, "SHA256"),
                           ZERO(OSSL_KDF_PARAM_MODE, "EXTRACT_ONLY"),
                           OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, secret, 16),
                           OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, salt, 8),
                           OSSL_PARAM_END };
        OSSL_PARAM b[] = { ZERO(OSSL_KDF_PARAM_DIGEST, "SHA1"),
                           ZERO(OSSL_KDF_PARAM_PROPERTIES, "provider=default"),
                           OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, secret, 16),
                           OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, salt, 8),
                           OSSL_PARAM_END };
        OSSL_PARAM c[] = { ZERO(OSSL_KDF_PARAM_DIGEST, "SHA256"),
                           OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SECRET, secret, 16),
                           OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SEED, salt, 8),
                           OSSL_PARAM_END };
        OSSL_PARAM d[] = { ZERO(OSSL_KDF_PARAM_SSHKDF_TYPE, "A"), OSSL_PARAM_END };
        OSSL_PARAM e[] = { ZERO(OSSL_KDF_PARAM_CEK_ALG, "AES-128-WRAP"), OSSL_PARAM_END };
        OSSL_PARAM f[] = { ZERO(OSSL_KDF_PARAM_DIGEST, "SHA256"),
                           ZERO(OSSL_KDF_PARAM_MAC, "HMAC"),
                           ZERO(OSSL_KDF_PARAM_MODE, "counter"),
                           OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, secret, 16),
                           OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, salt, 8),
                           OSSL_PARAM_END };
        OSSL_PARAM g[] = { ZERO(OSSL_KDF_PARAM_DIGEST, "SHA256"),
                           OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, secret, 16),
                           OSSL_PARAM_END };

        kdf("HKDF", "digest SHA256, mode EXTRACT_ONLY", a, 32);
        kdf("PBKDF2", "digest SHA1, properties", b, 20);
        kdf("TLS1-PRF", "digest SHA256", c, 32);
        kdf("KBKDF", "digest SHA256, mac HMAC, mode counter", f, 32);
        kdf("SSKDF", "digest SHA256", g, 32);
        kdf_set("SSHKDF", "type A", d);
        kdf_set("X942KDF-ASN1", "cekalg AES-128-WRAP", e);
    }

    printf("# MACs\n");
    {
        OSSL_PARAM a[] = { ZERO(OSSL_MAC_PARAM_DIGEST, "SHA256"), OSSL_PARAM_END };
        OSSL_PARAM b[] = { ZERO(OSSL_MAC_PARAM_CIPHER, "AES-128-CBC"),
                           ZERO(OSSL_MAC_PARAM_PROPERTIES, "provider=default"), OSSL_PARAM_END };

        mac("HMAC", "digest SHA256", a);
        mac("CMAC", "cipher AES-128-CBC, properties", b);
    }

    printf("# DRBGs\n");
    {
        OSSL_PARAM a[] = { ZERO(OSSL_DRBG_PARAM_CIPHER, "AES-128-CTR"), OSSL_PARAM_END };
        OSSL_PARAM b[] = { ZERO(OSSL_DRBG_PARAM_DIGEST, "SHA256"), OSSL_PARAM_END };
        OSSL_PARAM c[] = { ZERO(OSSL_DRBG_PARAM_DIGEST, "SHA256"),
                           ZERO(OSSL_DRBG_PARAM_MAC, "HMAC"), OSSL_PARAM_END };

        drbg("CTR-DRBG", "cipher AES-128-CTR", a);
        drbg("HASH-DRBG", "digest SHA256", b);
        drbg("HMAC-DRBG", "digest SHA256, mac HMAC", c);
    }

    printf("# ciphers' modes\n");
    {
        OSSL_PARAM a[] = { ZERO(OSSL_CIPHER_PARAM_CTS_MODE, "CS3"), OSSL_PARAM_END };
        OSSL_PARAM b[] = { ZERO(OSSL_CIPHER_PARAM_XTS_STANDARD, "IEEE1619"), OSSL_PARAM_END };

        cipher("AES-128-CBC-CTS", "cts_mode CS3", a, OSSL_CIPHER_PARAM_CTS_MODE);
        cipher("AES-128-XTS", "xts_standard IEEE1619", b, NULL);
    }

    printf("# operations\n");
    rsa = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)1024);
    check(rsa != NULL, "an RSA key");
    {
        OSSL_PARAM pad[] = { ZERO(OSSL_SIGNATURE_PARAM_PAD_MODE, "pss"), OSSL_PARAM_END };
        OSSL_PARAM md[] = { ZERO(OSSL_SIGNATURE_PARAM_DIGEST, "SHA256"), OSSL_PARAM_END };
        OSSL_PARAM slen[] = { ZERO(OSSL_SIGNATURE_PARAM_PAD_MODE, "pss"),
                              ZERO(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, "digest"), OSSL_PARAM_END };
        OSSL_PARAM kdf_type[] = { ZERO(OSSL_EXCHANGE_PARAM_KDF_TYPE, "X963KDF"), OSSL_PARAM_END };
        OSSL_PARAM dh_kdf[] = { ZERO(OSSL_EXCHANGE_PARAM_KDF_TYPE, "X942KDF-ASN1"), OSSL_PARAM_END };
        OSSL_PARAM kdf_md[] = { ZERO(OSSL_EXCHANGE_PARAM_KDF_DIGEST, "SHA256"), OSSL_PARAM_END };
        OSSL_PARAM enc_pad[] = { ZERO(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, "oaep"), OSSL_PARAM_END };
        OSSL_PARAM oaep_md[] = { ZERO(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, "oaep"),
                                 ZERO(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, "SHA256"),
                                 OSSL_PARAM_END };
        OSSL_PARAM kem[] = { ZERO(OSSL_KEM_PARAM_OPERATION, "RSASVE"), OSSL_PARAM_END };

        operation(rsa, SIGN, "RSA pad-mode pss", pad);
        operation(rsa, SIGN, "RSA digest SHA256", md);
        operation(rsa, SIGN, "RSA pad-mode pss, saltlen digest", slen);
        operation(ec, SIGN, "ECDSA digest SHA256", md);
        operation(ec, DERIVE, "ECDH kdf-type X963KDF", kdf_type);
        operation(ec, DERIVE, "ECDH kdf-digest SHA256", kdf_md);
        operation(dh, DERIVE, "DH kdf-type X942KDF-ASN1", dh_kdf);
        operation(rsa, DECRYPT, "RSA pad-mode oaep", enc_pad);
        operation(rsa, DECRYPT, "RSA pad-mode oaep, oaep-digest SHA256", oaep_md);
        operation(rsa, ENCAPSULATE, "RSA operation RSASVE", kem);
    }

    EVP_PKEY_free(rsa);
    EVP_PKEY_free(x);
    EVP_PKEY_free(dh);
    EVP_PKEY_free(ec);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
