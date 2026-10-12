/*
 * Conformance test for PKCS12KDF (EVP_KDF-PKCS12KDF(7)), KRB5KDF (EVP_KDF-KRB5KDF(7)),
 * HMAC-DRBG-KDF (EVP_KDF-HMAC-DRBG(7)), and ARGON2I/D/ID (EVP_KDF-ARGON2(7)), in TAP format:
 * their names and parameter lists, known vectors (RFC 7292's, RFC 3961's, SP 800-90A's, and
 * RFC 9106's), each KDF's parameters, errors (with their data), and quirks, copies, and resets.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/thread.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* The queue, oldest first, with each entry's data. */
static void errors(void)
{
    unsigned long code;
    const char *data;
    int flags;

    printf("  errors:");
    while ((code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        if ((flags & ERR_TXT_STRING) != 0 && data != NULL && data[0] != '\0')
            printf(" [%s]", data);
    }
    printf("\n");
}

/* The queue's codes only (a failed fetch's data has the name's number, which differs). */
static void codes(void)
{
    unsigned long code;

    printf("  errors:");
    while ((code = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
    printf("\n");
}

static void hex(const char *label, const unsigned char *p, size_t n)
{
    size_t i;

    printf("  %s:", label);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static int unhex(const char *s, unsigned char *out)
{
    int n = 0;
    unsigned int b;

    while (s[0] != '\0' && s[1] != '\0' && sscanf(s, "%2x", &b) == 1) {
        out[n++] = (unsigned char)b;
        s += 2;
    }
    return n;
}

static int same_hex(const unsigned char *p, size_t n, const char *want)
{
    unsigned char w[256];

    return (size_t)unhex(want, w) == n && memcmp(p, w, n) == 0;
}

static void list(const char *label, const OSSL_PARAM *p)
{
    printf("  %s:", label);
    if (p == NULL)
        printf(" NULL");
    for (; p != NULL && p->key != NULL; p++)
        printf(" %s/%u/%zu", p->key, p->data_type, p->data_size);
    printf("\n");
}

static void name_cb(const char *name, void *arg)
{
    (void)arg;
    printf(" %s", name);
}

static EVP_KDF_CTX *context(const char *name)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, name, NULL);
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);

    EVP_KDF_free(kdf);
    return ctx;
}

static OSSL_PARAM octets(const char *key, const char *hexstr, unsigned char *buf)
{
    return OSSL_PARAM_construct_octet_string(key, buf, (size_t)unhex(hexstr, buf));
}

static OSSL_PARAM utf8(const char *key, const char *value)
{
    return OSSL_PARAM_construct_utf8_string(key, (char *)value, 0);
}

static void methods(void)
{
    static const char *names[] = { "PKCS12KDF", "KRB5KDF", "HMAC-DRBG-KDF", "ARGON2I",
                                   "ARGON2D", "ARGON2ID", NULL };
    const char **n;

    for (n = names; *n != NULL; n++) {
        EVP_KDF *kdf = EVP_KDF_fetch(NULL, *n, NULL);
        EVP_KDF_CTX *ctx, *dup;

        check(kdf != NULL, *n);
        if (kdf == NULL)
            continue;
        printf("  %s:", *n);
        EVP_KDF_names_do_all(kdf, name_cb, NULL);
        printf("\n");
        list("gettable ctx", EVP_KDF_gettable_ctx_params(kdf));
        list("settable ctx", EVP_KDF_settable_ctx_params(kdf));
        ctx = EVP_KDF_CTX_new(kdf);
        printf("  size %zu\n", EVP_KDF_CTX_get_kdf_size(ctx));
        dup = EVP_KDF_CTX_dup(ctx);
        printf("  fresh copy %s\n", dup != NULL ? "made" : "refused");
        errors();
        EVP_KDF_CTX_free(dup);
        EVP_KDF_CTX_free(ctx);
        EVP_KDF_free(kdf);
    }
}

/* ---------------------------------------------------------------------------------------- */

static int pkcs12(EVP_KDF_CTX *ctx, const char *md, const char *pass, const char *salt,
                  int id, uint64_t iter, unsigned char *out, size_t n)
{
    unsigned char p[128], s[128];
    OSSL_PARAM params[6], *q = params;

    if (md != NULL)
        *q++ = utf8(OSSL_KDF_PARAM_DIGEST, md);
    if (pass != NULL)
        *q++ = octets(OSSL_KDF_PARAM_PASSWORD, pass, p);
    if (salt != NULL)
        *q++ = octets(OSSL_KDF_PARAM_SALT, salt, s);
    *q++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_PKCS12_ID, &id);
    *q++ = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_ITER, &iter);
    *q = OSSL_PARAM_construct_end();
    return EVP_KDF_derive(ctx, out, n, params);
}

static void pkcs12kdf(void)
{
    unsigned char out[100], again[100];
    EVP_KDF_CTX *ctx = context("PKCS12KDF"), *dup;
    OSSL_PARAM params[3], get[2];
    size_t size = 0;
    int ret;

    /* The password "smeg" as a BMPString with its terminating zeros. */
    check(pkcs12(ctx, "SHA1", "0073006d006500670000", "0a58cf64530d823f", 1, 1, out, 24) == 1
          && same_hex(out, 24, "8aaae6297b6cb04642ab5b077851284eb7128f1a2a7fbca3"),
          "the key of \"smeg\"");
    check(pkcs12(ctx, "SHA1", "0073006d006500670000", "0a58cf64530d823f", 2, 1, out, 8) == 1
          && same_hex(out, 8, "79993dfe048d3b76"),
          "its IV");
    ret = pkcs12(ctx, "SHA1", "0073006d006500670000", "0a58cf64530d823f", 3, 1000, out, 20);
    check(ret == 1, "a MAC key, 1000 iterations");
    hex("mac key", out, 20);
    ret = pkcs12(ctx, "SHA256", "0071007500650065006700000000", "1682c0fc5b3f7ec5", 1, 3, out, 100);
    check(ret == 1, "100 octets over SHA-256 (I updated between blocks)");
    hex("long", out, 100);
    ret = pkcs12(ctx, "SHA512", "61", "", 300, 0, out, 70);
    check(ret == 1, "an empty salt, an id past a byte, no iterations");
    hex("empty salt", out, 70);
    ret = pkcs12(ctx, "SHA256", "", "0102", 1, 1, out, 16);
    check(ret == 1, "an empty password");
    hex("empty password", out, 16);
    ERR_clear_error();
    ret = pkcs12(ctx, "SHA256", "", "", 1, 1, out, 16);
    check(ret == 0, "no password and no salt make no input: a silent failure");
    errors();
    ret = pkcs12(ctx, "SHA256", "6162", "6364", 1, 1, out, 0);
    check(ret == 1, "no output");
    errors();
    ret = pkcs12(ctx, "SHAKE256", "6162", "6364", 1, 1, out, 40);
    printf("  SHAKE256: %d\n", ret);
    if (ret == 1)
        hex("shake", out, 40);
    errors();
    ret = pkcs12(ctx, "SHA3-256", "6162", "6364", 1, 2, out, 40);
    check(ret == 1, "SHA3-256");
    hex("sha3", out, 40);
    ret = pkcs12(ctx, "NO-SUCH-MD", "6162", "6364", 1, 1, out, 16);
    check(ret == 0, "an unknown digest");
    errors();
    EVP_KDF_CTX_free(ctx);

    ctx = context("PKCS12KDF");
    ret = EVP_KDF_derive(ctx, out, 16, NULL);
    check(ret == 0, "nothing set: no password");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, "pw", 2);
    params[1] = OSSL_PARAM_construct_end();
    ret = EVP_KDF_derive(ctx, out, 16, params);
    check(ret == 0, "no salt");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, "saltsalt", 8);
    ret = EVP_KDF_derive(ctx, out, 16, params);
    check(ret == 0, "no digest");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, NULL, 4);
    check(EVP_KDF_CTX_set_params(ctx, params) == 1, "a NULL password with a length clears it");
    ret = EVP_KDF_derive(ctx, out, 16, NULL);
    check(ret == 0, "so it's missing");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, NULL, 0);
    params[1] = utf8(OSSL_KDF_PARAM_DIGEST, "MD5");
    params[2] = OSSL_PARAM_construct_end();
    check(EVP_KDF_CTX_set_params(ctx, params) == 1, "a NULL empty password is an empty one");
    ret = EVP_KDF_derive(ctx, out, 16, NULL);
    check(ret == 1, "which derives");
    hex("md5", out, 16);
    dup = EVP_KDF_CTX_dup(ctx);
    check(dup == NULL, "a copy with an empty password is refused");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, "pw", 2);
    params[1] = OSSL_PARAM_construct_end();
    EVP_KDF_CTX_set_params(ctx, params);
    dup = EVP_KDF_CTX_dup(ctx);
    check(dup != NULL && EVP_KDF_derive(ctx, out, 33, NULL) == 1
          && EVP_KDF_derive(dup, again, 33, NULL) == 1 && memcmp(out, again, 33) == 0,
          "a copy derives the same");
    EVP_KDF_CTX_free(dup);
    get[0] = OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_SIZE, &size);
    get[1] = OSSL_PARAM_construct_end();
    check(EVP_KDF_CTX_get_params(ctx, get) == 1 && size == SIZE_MAX, "any size");
    get[0] = OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_MODE, &size);
    printf("  unknown get: %d\n", EVP_KDF_CTX_get_params(ctx, get));
    params[0] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_PKCS12_ID, (uint64_t *)&size);
    check(EVP_KDF_CTX_set_params(ctx, params) == 0, "an id of the wrong type");
    errors();
    EVP_KDF_CTX_reset(ctx);
    ret = EVP_KDF_derive(ctx, out, 16, NULL);
    check(ret == 0, "reset: no password");
    errors();
    EVP_KDF_CTX_free(ctx);
}

/* ---------------------------------------------------------------------------------------- */

static int krb5(EVP_KDF_CTX *ctx, const char *cipher, const char *key, const char *constant,
                unsigned char *out, size_t n)
{
    unsigned char k[64], c[64];
    OSSL_PARAM params[4], *q = params;

    if (cipher != NULL)
        *q++ = utf8(OSSL_KDF_PARAM_CIPHER, cipher);
    if (key != NULL)
        *q++ = octets(OSSL_KDF_PARAM_KEY, key, k);
    if (constant != NULL)
        *q++ = octets(OSSL_KDF_PARAM_CONSTANT, constant, c);
    *q = OSSL_PARAM_construct_end();
    return EVP_KDF_derive(ctx, out, n, params);
}

static void krb5kdf(void)
{
    unsigned char out[64], again[64];
    EVP_KDF_CTX *ctx = context("KRB5KDF"), *dup;
    OSSL_PARAM params[2];
    int ret;

    check(krb5(ctx, "DES-EDE3-CBC", "dce06b1f64c857a11c3db57c51899b2cc1791008ce973b92",
               "0000000155", out, 24) == 1
          && same_hex(out, 24, "925179d04591a79b5d3192c4a7e9c289b049c71f6ee604cd"),
          "RFC 3961, triple DES");
    check(krb5(ctx, "DES-EDE3-CBC", "5e13d31c70ef765746578531cb51c15bf11ca82c97cee9f2",
               "00000001aa", out, 24) == 1
          && same_hex(out, 24, "9e58e5a146d9942a101c469845d67a20e3c4259ed913f207"),
          "RFC 3961, triple DES again");
    ret = krb5(ctx, NULL, NULL, NULL, out, 21);
    check(ret == 1, "triple DES's 21 random octets, unfixed");
    hex("raw", out, 21);
    check(krb5(ctx, "AES-128-CBC", "42263c6e89f4fc28b8df68ee09799f15", "0000000299", out, 16) == 1
          && same_hex(out, 16, "34280a382bc92769b2da2f9ef066854b"),
          "AES-128");
    check(krb5(ctx, "AES-256-CBC",
               "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161",
               "0000000299", out, 32) == 1
          && same_hex(out, 32, "bfab388bdcb238e9f9c98d6a878304f04d30c82556375ac507a7a852790f4674"),
          "AES-256, two blocks");
    ret = krb5(ctx, "AES-128-ECB", "42263c6e89f4fc28b8df68ee09799f15", "6b65726265726f73", out, 16);
    check(ret == 1, "ECB, \"kerberos\" folded");
    hex("ecb", out, 16);
    ret = krb5(ctx, "CAMELLIA-128-CBC", "42263c6e89f4fc28b8df68ee09799f15", "01", out, 16);
    check(ret == 1, "Camellia, one octet folded");
    hex("camellia", out, 16);
    ret = krb5(ctx, "AES-128-CTR", "42263c6e89f4fc28b8df68ee09799f15", "99", out, 16);
    check(ret == 1, "a stream mode, one octet at a time");
    hex("ctr", out, 16);
    errors();
    ret = krb5(ctx, "AES-128-CTR", NULL, "9999", out, 16);
    check(ret == 0, "a constant longer than its block");
    errors();
    ret = krb5(ctx, "AES-128-CBC", NULL, "000102030405060708090a0b0c0d0e0f10", out, 16);
    check(ret == 0, "a constant longer than AES's block");
    errors();
    ret = krb5(ctx, NULL, NULL, "", out, 16);
    check(ret == 0, "an empty constant");
    errors();
    ret = krb5(ctx, NULL, NULL, "0000000299", out, 32);
    check(ret == 0, "an output of the wrong size");
    errors();
    ret = krb5(ctx, NULL, "42263c6e89f4fc28b8df68ee09799f1516", NULL, out, 17);
    check(ret == 0, "a key of the wrong size");
    errors();
    ret = krb5(ctx, "AES-128-WRAP", "42263c6e89f4fc28b8df68ee09799f15", "0102030405060708", out, 16);
    printf("  wrap: %d\n", ret);
    errors();
    ret = krb5(ctx, "NO-SUCH-CIPHER", NULL, NULL, out, 16);
    check(ret == 0, "an unknown cipher");
    errors();
    EVP_KDF_CTX_free(ctx);

    ctx = context("KRB5KDF");
    printf("  size without a cipher %zu\n", EVP_KDF_CTX_get_kdf_size(ctx));
    check(krb5(ctx, NULL, NULL, NULL, out, 16) == 0, "no cipher");
    errors();
    check(krb5(ctx, "AES-256-CBC", NULL, NULL, out, 16) == 0, "no key");
    errors();
    printf("  size with AES-256 %zu\n", EVP_KDF_CTX_get_kdf_size(ctx));
    check(krb5(ctx, NULL, "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161",
               NULL, out, 32) == 0,
          "no constant");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_CONSTANT, NULL, 3);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_KDF_CTX_set_params(ctx, params) == 0, "a NULL constant is refused");
    errors();
    check(krb5(ctx, NULL, NULL, "aa", out, 32) == 1, "then set");
    hex("aes-256 aa", out, 32);
    dup = EVP_KDF_CTX_dup(ctx);
    check(dup != NULL && EVP_KDF_derive(dup, again, 32, NULL) == 1 && memcmp(out, again, 32) == 0,
          "a copy derives the same");
    EVP_KDF_CTX_free(dup);
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, "", 0);
    EVP_KDF_CTX_set_params(ctx, params);
    dup = EVP_KDF_CTX_dup(ctx);
    check(dup == NULL, "a copy with an empty key is refused");
    ret = EVP_KDF_derive(ctx, out, 0, NULL);
    check(ret == 0, "an empty key");
    errors();
    EVP_KDF_CTX_reset(ctx);
    check(EVP_KDF_derive(ctx, out, 16, NULL) == 0, "reset: no cipher");
    errors();
    EVP_KDF_CTX_free(ctx);
}

/* ---------------------------------------------------------------------------------------- */

static void hmac_drbg(void)
{
    unsigned char e[64], n[64], out[80], again[80];
    EVP_KDF_CTX *ctx = context("HMAC-DRBG-KDF"), *dup;
    OSSL_PARAM params[5], get[3];
    char mac[32], md[32];
    int ret;

    params[0] = utf8(OSSL_KDF_PARAM_DIGEST, "SHA1");
    params[1] = utf8(OSSL_KDF_PARAM_PROPERTIES, "provider=default");
    params[2] = octets(OSSL_KDF_PARAM_HMACDRBG_ENTROPY, "411602cb19a6ccc34494d79d98ef1e7ed5af25f7", e);
    params[3] = octets(OSSL_KDF_PARAM_HMACDRBG_NONCE, "8151325dcdbae9e0ff95f9f9658432dbedfdb209", n);
    params[4] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 20, params) == 1
          && same_hex(out, 20, "7bdb6b0ff756e1bb5d53583ef979082f9ad5bd5b"),
          "SHA-1");
    check(EVP_KDF_derive(ctx, out, 20, NULL) == 1, "a second derivation goes on");
    hex("next", out, 20);
    check(EVP_KDF_derive(ctx, out, 50, NULL) == 1, "longer than a block");
    hex("long", out, 50);
    check(EVP_KDF_derive(ctx, out, 0, NULL) == 1, "nothing");
    check(EVP_KDF_derive(ctx, out, 20, NULL) == 1, "after nothing");
    hex("after", out, 20);
    dup = EVP_KDF_CTX_dup(ctx);
    check(dup != NULL && EVP_KDF_derive(ctx, out, 45, NULL) == 1
          && EVP_KDF_derive(dup, again, 45, NULL) == 1 && memcmp(out, again, 45) == 0,
          "a copy goes on the same");
    EVP_KDF_CTX_free(dup);
    get[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC, mac, sizeof(mac));
    get[1] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, md, sizeof(md));
    get[2] = OSSL_PARAM_construct_end();
    check(EVP_KDF_CTX_get_params(ctx, get) == 1, "its MAC and digest");
    printf("  mac %s digest %s\n", mac, md);
    printf("  size %zu\n", EVP_KDF_CTX_get_kdf_size(ctx));
    params[0] = utf8(OSSL_KDF_PARAM_DIGEST, "SHA256");
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 40, params) == 1, "another digest keeps K and V");
    hex("sha256 after sha1", out, 40);
    params[0] = octets(OSSL_KDF_PARAM_HMACDRBG_NONCE,
                       "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", n);
    params[1] = octets(OSSL_KDF_PARAM_HMACDRBG_ENTROPY,
                       "69c7548c21d0dfea6b9a51c9ead4e27c33d3b3f180316e5bcab92c933f0e4dbc", e);
    params[2] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 32, params) == 1
          && same_hex(out, 32, "1d6ce6dda1c5d37307839cd03ab0a5cbb18e60d800937d67dfb4479aac8dead7"),
          "new entropy starts over (SHA-256)");
    params[0] = utf8(OSSL_KDF_PARAM_DIGEST, "SHAKE128");
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_KDF_CTX_set_params(ctx, params) == 0, "an XOF is refused");
    errors();
    check(EVP_KDF_CTX_get_params(ctx, get) == 1, "but kept");
    printf("  mac %s digest %s\n", mac, md);
    params[0] = utf8(OSSL_KDF_PARAM_DIGEST, "NULL");
    check(EVP_KDF_CTX_set_params(ctx, params) == 0, "a digest of no size is refused");
    errors();
    params[0] = utf8(OSSL_KDF_PARAM_DIGEST, "NO-SUCH-MD");
    check(EVP_KDF_CTX_set_params(ctx, params) == 0, "an unknown digest");
    errors();
    check(EVP_KDF_CTX_get_params(ctx, get) == 0, "then it has none");
    ret = EVP_KDF_derive(ctx, out, 20, NULL);
    printf("  derive after: %d\n", ret);
    errors();
    EVP_KDF_CTX_reset(ctx);
    check(EVP_KDF_CTX_get_params(ctx, get) == 0, "reset: no MAC");
    get[0] = get[1];
    get[1] = get[2];
    check(EVP_KDF_CTX_get_params(ctx, get) == 0, "reset: no digest");
    check(EVP_KDF_derive(ctx, out, 20, NULL) == 0, "reset: nothing to derive from");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_HMACDRBG_ENTROPY, "ee", 2);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_HMACDRBG_NONCE, "nn", 2);
    params[2] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 20, params) == 0, "no digest: no MAC");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_HMACDRBG_NONCE, "", 0);
    params[1] = utf8(OSSL_KDF_PARAM_DIGEST, "SHA512");
    params[2] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 20, params) == 0, "an empty nonce: silently");
    errors();
    dup = EVP_KDF_CTX_dup(ctx);
    check(dup == NULL, "a copy with an empty nonce is refused");
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_HMACDRBG_NONCE, NULL, 2);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_KDF_CTX_set_params(ctx, params) == 0, "a NULL nonce is refused");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_HMACDRBG_NONCE, "nn", 2);
    check(EVP_KDF_derive(ctx, out, 70, params) == 1, "SHA-512");
    hex("sha512", out, 70);
    EVP_KDF_CTX_free(ctx);

    ctx = context("HMAC-DRBG-KDF");
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_HMACDRBG_ENTROPY, "ee", 2);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 20, params) == 0, "no nonce: silently");
    errors();
    EVP_KDF_CTX_free(ctx);
}

/* ---------------------------------------------------------------------------------------- */

struct argon2_args {
    const char *pass, *salt, *secret, *ad;
    int lanes, iter, memcost, threads, version, early_clean;
};

static int argon2(EVP_KDF_CTX *ctx, const struct argon2_args *a, unsigned char *out, size_t n)
{
    unsigned char p[64], s[64], k[64], d[64];
    uint32_t lanes = (uint32_t)a->lanes, iter = (uint32_t)a->iter, mem = (uint32_t)a->memcost;
    uint32_t threads = (uint32_t)a->threads, version = (uint32_t)a->version;
    uint32_t early = (uint32_t)a->early_clean;
    OSSL_PARAM params[11], *q = params;

    if (a->pass != NULL)
        *q++ = octets(OSSL_KDF_PARAM_PASSWORD, a->pass, p);
    if (a->salt != NULL)
        *q++ = octets(OSSL_KDF_PARAM_SALT, a->salt, s);
    if (a->secret != NULL)
        *q++ = octets(OSSL_KDF_PARAM_SECRET, a->secret, k);
    if (a->ad != NULL)
        *q++ = octets(OSSL_KDF_PARAM_ARGON2_AD, a->ad, d);
    if (a->lanes >= 0)
        *q++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes);
    if (a->iter >= 0)
        *q++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iter);
    if (a->memcost >= 0)
        *q++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &mem);
    if (a->threads >= 0)
        *q++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads);
    if (a->version >= 0)
        *q++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_VERSION, &version);
    if (a->early_clean >= 0)
        *q++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_EARLY_CLEAN, &early);
    *q = OSSL_PARAM_construct_end();
    return EVP_KDF_derive(ctx, out, n, params);
}

#define RFC_PASS "0101010101010101010101010101010101010101010101010101010101010101"
#define RFC_SALT "02020202020202020202020202020202"

static void argon2s(void)
{
    static const struct { const char *name, *want; } rfc[] = {
        { "ARGON2D", "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb" },
        { "ARGON2I", "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8" },
        { "ARGON2ID", "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659" },
    };
    struct argon2_args rfc_args = { RFC_PASS, RFC_SALT, "0303030303030303",
                                    "040404040404040404040404", 4, 3, 32, -1, -1, -1 };
    struct argon2_args a;
    unsigned char out[128], again[128];
    EVP_KDF_CTX *ctx, *dup;
    OSSL_PARAM params[2], get[2];
    size_t size = 0, i;
    uint32_t u32;
    int ret;

    for (i = 0; i < sizeof(rfc) / sizeof(rfc[0]); i++) {
        ctx = context(rfc[i].name);
        check(argon2(ctx, &rfc_args, out, 32) == 1 && same_hex(out, 32, rfc[i].want), rfc[i].name);
        check(argon2(ctx, &rfc_args, again, 32) == 1 && memcmp(out, again, 32) == 0,
              "again, the same");
        EVP_KDF_CTX_free(ctx);
    }

    ctx = context("ARGON2D");
    a = rfc_args;
    a.early_clean = 1;
    check(argon2(ctx, &a, out, 32) == 1 && same_hex(out, 32, rfc[0].want), "early clean");
    check(EVP_KDF_derive(ctx, again, 32, NULL) == 1, "then without the password and secret");
    hex("cleaned", again, 32);
    EVP_KDF_CTX_free(ctx);

    ctx = context("ARGON2D");
    a = (struct argon2_args){ "31323334353637383930", "73616c7473616c74", NULL, NULL,
                              -1, -1, -1, -1, -1, -1 };
    check(argon2(ctx, &a, out, 64) == 1
          && same_hex(out, 64, "d16ad773b1c6400d3193bc3e66271603e9de72bace20af3f89c236f5434cdec9"
                               "9072ddfc6b9c77ea9f386c0e8d7cb0c37cec6ec3277a22c92d5be58ef67c7eaa"),
          "the defaults");
    check(EVP_KDF_derive(ctx, out, 100, NULL) == 1, "another length becomes the context's");
    hex("100", out, 100);
    check(EVP_KDF_derive(ctx, out, 3, NULL) == 0, "fewer than 4 octets");
    errors();
    u32 = 16;
    params[0] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SIZE, &u32);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 32, params) == 0, "a size among the parameters that differs");
    errors();
    check(EVP_KDF_derive(ctx, out, 16, params) == 1, "and one that doesn't");
    hex("16", out, 16);
    u32 = 0x10;
    params[0] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_VERSION, &u32);
    check(EVP_KDF_derive(ctx, out, 16, params) == 1, "version 0x10");
    hex("v10", out, 16);
    u32 = 1;
    check(EVP_KDF_CTX_set_params(ctx, params) == 0, "version 1");
    errors();
    params[0] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, (u32 = 0, &u32));
    check(EVP_KDF_CTX_set_params(ctx, params) == 0, "no passes");
    errors();
    params[0] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, (u32 = 7, &u32));
    check(EVP_KDF_CTX_set_params(ctx, params) == 0, "7 blocks");
    errors();
    params[0] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, (u32 = 0, &u32));
    check(EVP_KDF_CTX_set_params(ctx, params) == 0, "no lanes");
    errors();
    params[0] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, (u32 = 0x1000000, &u32));
    check(EVP_KDF_CTX_set_params(ctx, params) == 0, "too many lanes");
    errors();
    params[0] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, (u32 = 0, &u32));
    check(EVP_KDF_CTX_set_params(ctx, params) == 0, "no threads");
    errors();
    params[0] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, (u32 = 0x1000000, &u32));
    check(EVP_KDF_CTX_set_params(ctx, params) == 0, "too many threads");
    errors();
    params[0] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, (u32 = 2, &u32));
    check(EVP_KDF_derive(ctx, out, 16, params) == 0, "two lanes in 8 blocks");
    errors();
    params[0] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, (u32 = 21, &u32));
    check(EVP_KDF_derive(ctx, out, 16, params) == 1, "two lanes in 21 blocks (16 used)");
    hex("21", out, 16);
    params[0] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, (u32 = 2, &u32));
    check(EVP_KDF_derive(ctx, out, 16, params) == 0, "two threads, none available");
    errors();
    check(OSSL_set_max_threads(NULL, 1) == 1, "one thread allowed");
    check(EVP_KDF_derive(ctx, out, 16, NULL) == 0, "still too few");
    errors();
    check(OSSL_set_max_threads(NULL, 4) == 1, "four");
    check(EVP_KDF_derive(ctx, again, 16, NULL) == 1 && memcmp(out, again, 16) == 0,
          "two threads derive what one does");
    params[0] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, (u32 = 3, &u32));
    check(EVP_KDF_derive(ctx, out, 16, params) == 0, "more threads than lanes");
    errors();
    OSSL_set_max_threads(NULL, 0);
    params[0] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, (u32 = 1, &u32));
    check(EVP_KDF_CTX_set_params(ctx, params) == 1, "back to one thread");
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, "short", 5);
    check(EVP_KDF_CTX_set_params(ctx, params) == 0, "a short salt");
    errors();
    check(EVP_KDF_derive(ctx, out, 16, NULL) == 0, "leaves none");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, NULL, 8);
    check(EVP_KDF_CTX_set_params(ctx, params) == 0, "a NULL salt");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, NULL, 0);
    check(EVP_KDF_CTX_set_params(ctx, params) == 0, "a NULL password");
    errors();
    params[0] = utf8(OSSL_KDF_PARAM_PROPERTIES, "provider=nonesuch");
    check(EVP_KDF_CTX_set_params(ctx, params) == 1, "a query that finds nothing");
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, "saltsalt", 8);
    check(EVP_KDF_derive(ctx, out, 16, params) == 0, "fails to fetch");
    codes();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0);
    check(EVP_KDF_derive(ctx, out, 16, params) == 1, "no query fetches again");
    hex("refetched", out, 16);
    get[0] = OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_SIZE, &size);
    get[1] = OSSL_PARAM_construct_end();
    check(EVP_KDF_CTX_get_params(ctx, get) == 1 && size == SIZE_MAX, "any size");
    get[0] = OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_MODE, &size);
    printf("  unknown get: %d\n", EVP_KDF_CTX_get_params(ctx, get));
    dup = EVP_KDF_CTX_dup(ctx);
    check(dup == NULL, "no copies");
    EVP_KDF_CTX_reset(ctx);
    check(EVP_KDF_derive(ctx, out, 16, NULL) == 0, "reset: no salt");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, "saltsalt", 8);
    check(EVP_KDF_derive(ctx, out, 64, params) == 1, "reset: the defaults, no password");
    hex("no password", out, 64);
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, "", 0);
    check(EVP_KDF_derive(ctx, again, 64, params) == 1 && memcmp(out, again, 64) == 0,
          "an empty password is none");
    EVP_KDF_CTX_free(ctx);

    ctx = context("ARGON2ID");
    a = rfc_args;
    a.secret = a.ad = NULL;
    a.iter = 1;
    a.memcost = 64;
    a.lanes = 1;
    ret = argon2(ctx, &a, out, 128);
    check(ret == 1, "a long output");
    hex("128", out, 128);
    params[0] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SIZE, (u32 = 3, &u32));
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_KDF_CTX_set_params(ctx, params) == 0, "a size of 3");
    errors();
    params[0] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_ITER, (uint64_t *)&size);
    size = (size_t)1 << 33;
    check(EVP_KDF_CTX_set_params(ctx, params) == 0, "passes past 32 bits");
    errors();
    EVP_KDF_CTX_free(ctx);
}

int main(void)
{
    methods();
    pkcs12kdf();
    krb5kdf();
    hmac_drbg();
    argon2s();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
