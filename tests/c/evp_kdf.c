/*
 * Conformance test for KDFs (EVP_KDF(3), EVP_KDF-HKDF(7), EVP_KDF-TLS13_KDF(7),
 * EVP_KDF-PBKDF2(7), EVP_KDF-TLS1_PRF(7), EVP_KDF-SS(7), EVP_KDF-X963(7),
 * PKCS5_PBKDF2_HMAC(3)), in TAP format: the methods and their parameter lists, contexts
 * through their lifecycle (parameters, derivation, size, copy, reset), the RFC 5869, 6070,
 * and 8448 vectors, each KDF's errors and quirks, and the NULL arguments the reference takes.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/provider.h>

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

static int seen;

static void provided_cb(EVP_KDF *kdf, void *arg)
{
    (void)arg;
    if (EVP_KDF_is_a(kdf, "HKDF") || EVP_KDF_is_a(kdf, "TLS13-KDF") || EVP_KDF_is_a(kdf, "SSKDF")
        || EVP_KDF_is_a(kdf, "PBKDF2") || EVP_KDF_is_a(kdf, "X963KDF")
        || EVP_KDF_is_a(kdf, "TLS1-PRF"))
        seen++;
}

static EVP_KDF_CTX *context(const char *name)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, name, NULL);
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);

    EVP_KDF_free(kdf);
    return ctx;
}

static void methods(void)
{
    static const char *names[] = { "HKDF", "TLS13-KDF", "SSKDF", "PBKDF2",
                                   "1.2.840.113549.1.5.12", "X963KDF", "X942KDF-CONCAT",
                                   "TLS1-PRF", NULL };
    const char **n;
    EVP_KDF *kdf;

    for (n = names; *n != NULL; n++) {
        kdf = EVP_KDF_fetch(NULL, *n, NULL);
        check(kdf != NULL, *n);
        if (kdf == NULL)
            continue;
        printf("  %s (%s, %s):", *n, EVP_KDF_get0_name(kdf),
               OSSL_PROVIDER_get0_name(EVP_KDF_get0_provider(kdf)));
        EVP_KDF_names_do_all(kdf, name_cb, NULL);
        printf("\n");
        check(EVP_KDF_get0_description(kdf) == NULL, "no description");
        list("gettable", EVP_KDF_gettable_params(kdf));
        list("gettable ctx", EVP_KDF_gettable_ctx_params(kdf));
        list("settable ctx", EVP_KDF_settable_ctx_params(kdf));
        check(EVP_KDF_get_params(kdf, NULL) == 1, "no method parameters");
        check(EVP_KDF_up_ref(kdf) == 1, "up_ref");
        EVP_KDF_free(kdf);
        EVP_KDF_free(kdf);
    }
    kdf = EVP_KDF_fetch(NULL, "NO-SUCH-KDF", NULL);
    check(kdf == NULL, "an unknown KDF");
    errors();
    EVP_KDF_do_all_provided(NULL, provided_cb, NULL);
    check(seen == 6, "do_all_provided");

    /* NULL where the reference takes it. */
    check(EVP_KDF_CTX_new(NULL) == NULL, "no context of NULL");
    check(EVP_KDF_CTX_dup(NULL) == NULL, "no copy of NULL");
    check(EVP_KDF_derive(NULL, NULL, 0, NULL) == 0, "no derivation with NULL");
    check(EVP_KDF_CTX_get_kdf_size(NULL) == 0, "no size of NULL");
    EVP_KDF_CTX_reset(NULL);
    EVP_KDF_CTX_free(NULL);
    EVP_KDF_free(NULL);
    errors();
}

static void hkdf(void)
{
    unsigned char ikm[22], salt[13], info[10], out[82];
    EVP_KDF_CTX *ctx = context("HKDF"), *dup;
    OSSL_PARAM params[6];
    int i, mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY, r;

    memset(ikm, 0x0b, sizeof(ikm));
    for (i = 0; i < 13; i++)
        salt[i] = (unsigned char)i;
    for (i = 0; i < 10; i++)
        info[i] = (unsigned char)(0xf0 + i);
    check(ctx != NULL, "an HKDF context");
    list("ctx gettable", EVP_KDF_CTX_gettable_params(ctx));
    list("ctx settable", EVP_KDF_CTX_settable_params(ctx));
    check(EVP_KDF_CTX_kdf(ctx) != NULL && EVP_KDF_is_a(EVP_KDF_CTX_kdf(ctx), "HKDF"), "its KDF");
    printf("  size %zu\n", EVP_KDF_CTX_get_kdf_size(ctx));
    r = EVP_KDF_derive(ctx, out, 42, NULL);
    check(r == 0, "no digest");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();
    r = EVP_KDF_derive(ctx, out, 42, params);
    check(r == 0, "no key");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm, sizeof(ikm));
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, sizeof(salt));
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, 4);
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info + 4, 6);
    params[4] = OSSL_PARAM_construct_end();
    check(EVP_KDF_CTX_set_params(ctx, params) == 1, "key, salt, and info in two parts");
    r = EVP_KDF_derive(ctx, out, 0, NULL);
    check(r == 0, "no output");
    errors();
    check(EVP_KDF_derive(ctx, out, 42, NULL) == 1
          && same_hex(out, 42, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                               "34007208d5b887185865"), "RFC 5869 case 1");
    {
        unsigned char got[16];

        params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, got, sizeof(got));
        params[1] = OSSL_PARAM_construct_end();
        check(EVP_KDF_CTX_get_params(ctx, params) == 1 && params[0].return_size == 10
              && memcmp(got, info, 10) == 0, "the info back");
    }
    dup = EVP_KDF_CTX_dup(ctx);
    check(dup != NULL, "copy");
    params[0] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_KDF_CTX_set_params(ctx, params) == 1, "extract only");
    printf("  size %zu\n", EVP_KDF_CTX_get_kdf_size(ctx));
    r = EVP_KDF_derive(ctx, out, 31, NULL);
    check(r == 0, "extract into the wrong size");
    errors();
    check(EVP_KDF_derive(ctx, out, 32, NULL) == 1
          && same_hex(out, 32, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
          "the PRK");
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, "expand_only", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, out, 32);
    params[2] = OSSL_PARAM_construct_end();
    check(EVP_KDF_CTX_set_params(ctx, params) == 1, "expand only, from the PRK");
    check(EVP_KDF_derive(ctx, out + 32, 42, NULL) == 1
          && same_hex(out + 32, 42, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4"
                                    "c5bf34007208d5b887185865"), "the same OKM");
    r = EVP_KDF_derive(ctx, out, 255 * 32 + 1, NULL);
    check(r == 0, "more than 255 blocks");
    errors();
    check(EVP_KDF_derive(dup, out, 42, NULL) == 1
          && same_hex(out, 42, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                               "34007208d5b887185865"), "the copy");
    EVP_KDF_CTX_free(dup);

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, "both", 0);
    params[1] = OSSL_PARAM_construct_end();
    r = EVP_KDF_CTX_set_params(ctx, params);
    check(r == 0, "an unknown mode");
    errors();
    mode = 3;
    params[0] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    r = EVP_KDF_CTX_set_params(ctx, params);
    check(r == 0, "mode 3");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHAKE256", 0);
    r = EVP_KDF_CTX_set_params(ctx, params);
    check(r == 0, "an XOF digest");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "NO-SUCH-MD", 0);
    r = EVP_KDF_CTX_set_params(ctx, params);
    check(r == 0, "an unknown digest");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_INFO, "text", 0);
    r = EVP_KDF_CTX_set_params(ctx, params);
    check(r == 0, "info that isn't octets");
    errors();

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, "", 0);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_KDF_CTX_set_params(ctx, params) == 1, "an empty salt");
    dup = EVP_KDF_CTX_dup(ctx);
    check(dup == NULL, "doesn't copy (OPENSSL_memdup of nothing is NULL)");
    EVP_KDF_CTX_free(dup);
    EVP_KDF_CTX_reset(ctx);
    r = EVP_KDF_derive(ctx, out, 42, NULL);
    check(r == 0, "nothing after a reset");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA1", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm, 11);
    params[2] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 82, params) == 1, "SHA-1, no salt or info");
    hex("sha1", out, 82);
    EVP_KDF_CTX_free(ctx);
}

static void tls13(void)
{
    unsigned char out[64], secret[32];
    EVP_KDF_CTX *ctx = context("TLS13-KDF");
    OSSL_PARAM params[7];
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY, r;

    check(ctx != NULL, "a TLS13-KDF context");
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();
    r = EVP_KDF_CTX_set_params(ctx, params);
    check(r == 0, "anything in the default mode");
    errors();
    r = EVP_KDF_derive(ctx, out, 32, NULL);
    check(r == 0, "no derivation in the default mode");
    errors();
    params[0] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    params[2] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 32, params) == 1
          && same_hex(out, 32, "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"),
          "RFC 8448 early secret");
    memcpy(secret, out, 32);
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, secret, 32);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PREFIX, "tls13 ", 6);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_LABEL, "derived", 7);
    params[3] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 32, params) == 1, "the next extract, from the derived salt");
    hex("handshake (no key)", out, 32);
    mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
    params[0] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, secret, 32);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_LABEL, "key", 3);
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_DATA, "", 0);
    params[4] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 16, params) == 1, "HKDF-Expand-Label");
    hex("key", out, 16);
    {
        unsigned char label[300];

        memset(label, 'l', sizeof(label));
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_LABEL, label, 250);
        params[1] = OSSL_PARAM_construct_end();
        r = EVP_KDF_derive(ctx, out, 16, params);
        check(r == 0, "a label too long with the prefix");
        errors();
    }
    EVP_KDF_CTX_free(ctx);

    /* Expand with no key fails without an error. */
    ctx = context("TLS13-KDF");
    params[0] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA384", 0);
    params[2] = OSSL_PARAM_construct_end();
    r = EVP_KDF_derive(ctx, out, 16, params);
    check(r == 0, "expand without a key");
    errors();
    EVP_KDF_CTX_free(ctx);
}

static void pbkdf2(void)
{
    unsigned char out[64];
    EVP_KDF_CTX *ctx = context("PBKDF2"), *dup;
    OSSL_PARAM params[6];
    uint64_t iter = 2;
    int pkcs5 = 0, r;

    check(ctx != NULL, "a PBKDF2 context");
    printf("  size %zu\n", EVP_KDF_CTX_get_kdf_size(ctx));
    r = EVP_KDF_derive(ctx, out, 20, NULL);
    check(r == 0, "no password");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, "password", 8);
    params[1] = OSSL_PARAM_construct_end();
    r = EVP_KDF_derive(ctx, out, 20, params);
    check(r == 0, "no salt");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, "salt", 4);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 20, params) == 1, "SHA-1 and 2048 iterations by default");
    hex("2048", out, 20);
    params[0] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_ITER, &iter);
    check(EVP_KDF_derive(ctx, out, 20, params) == 1
          && same_hex(out, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"), "RFC 6070, 2 iterations");
    dup = EVP_KDF_CTX_dup(ctx);
    iter = 4096;
    check(EVP_KDF_derive(ctx, out, 20, params) == 1
          && same_hex(out, 20, "4b007901b765489abead49d926f721d065a429c1"), "4096 iterations");
    check(dup != NULL && EVP_KDF_derive(dup, out, 25, NULL) == 1, "the copy kept 2");
    hex("copy, 25", out, 25);
    EVP_KDF_CTX_free(dup);
    iter = 0;
    r = EVP_KDF_CTX_set_params(ctx, params);
    check(r == 0, "0 iterations");
    errors();

    /* The lower-bound checks, with pkcs5 0. */
    params[0] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_PKCS5, &pkcs5);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_KDF_CTX_set_params(ctx, params) == 1, "lower-bound checks on");
    r = EVP_KDF_derive(ctx, out, 20, NULL);
    check(r == 0, "a salt too short");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, "salt", 4);
    r = EVP_KDF_CTX_set_params(ctx, params);
    check(r == 0, "setting a salt too short");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, "0123456789abcdef", 16);
    params[1] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_ITER, &iter);
    params[2] = OSSL_PARAM_construct_end();
    iter = 999;
    r = EVP_KDF_CTX_set_params(ctx, params);
    check(r == 0, "999 iterations");
    errors();
    iter = 1000;
    check(EVP_KDF_CTX_set_params(ctx, params) == 1, "1000 iterations");
    r = EVP_KDF_derive(ctx, out, 13, NULL);
    check(r == 0, "a key too short");
    errors();
    check(EVP_KDF_derive(ctx, out, 14, NULL) == 1, "a key of 112 bits");
    hex("bounds", out, 14);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA512", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, NULL, 3);
    params[2] = OSSL_PARAM_construct_end();
    check(EVP_KDF_CTX_set_params(ctx, params) == 1, "a NULL password with a length");
    r = EVP_KDF_derive(ctx, out, 64, NULL);
    check(r == 0, "unsets it");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, "", 0);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 64, params) == 1, "an empty password, SHA-512");
    hex("sha512", out, 64);
    EVP_KDF_CTX_reset(ctx);
    r = EVP_KDF_derive(ctx, out, 20, NULL);
    check(r == 0, "nothing after a reset");
    errors();
    EVP_KDF_CTX_free(ctx);

    check(PKCS5_PBKDF2_HMAC_SHA1("password", -1, (const unsigned char *)"salt", 4, 1, 20, out) == 1
          && same_hex(out, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"),
          "PKCS5_PBKDF2_HMAC_SHA1, RFC 6070 1 iteration");
    check(PKCS5_PBKDF2_HMAC("pass\0word", 9, (const unsigned char *)"sa\0lt", 5, 4096,
                            EVP_sha1(), 16, out) == 1
          && same_hex(out, 16, "56fa6aa75548099dcc37d7f03425e0c3"), "RFC 6070, NUL octets");
    check(PKCS5_PBKDF2_HMAC(NULL, 5, NULL, 0, 3, EVP_sha256(), 10, out) == 1,
          "NULL password and salt");
    hex("NULL", out, 10);
    r = PKCS5_PBKDF2_HMAC("p", 1, (const unsigned char *)"s", 1, 0, EVP_sha256(), 10, out);
    check(r == 0, "0 iterations");
    errors();
}

static void tls1_prf(void)
{
    unsigned char secret[48], out[100];
    EVP_KDF_CTX *ctx = context("TLS1-PRF"), *dup;
    OSSL_PARAM params[6];
    int i, r;

    for (i = 0; i < 48; i++)
        secret[i] = (unsigned char)(i * 3);
    check(ctx != NULL, "a TLS1-PRF context");
    r = EVP_KDF_derive(ctx, out, 48, NULL);
    check(r == 0, "no digest");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();
    r = EVP_KDF_derive(ctx, out, 48, params);
    check(r == 0, "no secret");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, secret, 48);
    params[1] = OSSL_PARAM_construct_end();
    r = EVP_KDF_derive(ctx, out, 48, params);
    check(r == 0, "no seed");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, "master secret", 13);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, "client random", 13);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, NULL, 0);
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, "server random", 13);
    params[4] = OSSL_PARAM_construct_end();
    check(EVP_KDF_CTX_set_params(ctx, params) == 1, "seeds in parts");
    dup = EVP_KDF_CTX_dup(ctx);
    check(EVP_KDF_derive(ctx, out, 100, NULL) == 1, "TLS 1.2, SHA-256");
    hex("sha256", out, 100);
    check(dup != NULL && EVP_KDF_derive(dup, out + 50, 50, NULL) == 1
          && memcmp(out, out + 50, 50) == 0, "the copy, a prefix");
    EVP_KDF_CTX_free(dup);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "md5-sha1", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, secret, 47);
    params[2] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 48, params) == 1, "TLS 1.0, MD5-SHA1, an odd secret");
    hex("md5-sha1", out, 48);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA384", 0);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 1, params) == 1, "SHA-384, one octet");
    hex("sha384", out, 1);
    r = EVP_KDF_derive(ctx, out, 0, NULL);
    check(r == 0, "no output");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHAKE128", 0);
    r = EVP_KDF_CTX_set_params(ctx, params);
    check(r == 0, "an XOF digest");
    errors();
    printf("  size %zu\n", EVP_KDF_CTX_get_kdf_size(ctx));
    EVP_KDF_CTX_free(ctx);
}

static void sskdf(void)
{
    unsigned char z[32], out[100];
    EVP_KDF_CTX *ctx = context("SSKDF"), *dup;
    OSSL_PARAM params[6];
    size_t size = 20;
    int i, r;

    for (i = 0; i < 32; i++)
        z[i] = (unsigned char)(i + 1);
    check(ctx != NULL, "an SSKDF context");
    printf("  size %zu\n", EVP_KDF_CTX_get_kdf_size(ctx));
    errors();
    r = EVP_KDF_derive(ctx, out, 16, NULL);
    check(r == 0, "no secret");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, z, 0);
    params[1] = OSSL_PARAM_construct_end();
    r = EVP_KDF_derive(ctx, out, 16, params);
    check(r == 0, "an empty secret is none");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, z, 32);
    params[1] = OSSL_PARAM_construct_end();
    r = EVP_KDF_derive(ctx, out, 16, params);
    check(r == 0, "a key, but no digest");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA224", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, "other", 5);
    params[2] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 100, params) == 1, "hash SSKDF");
    hex("hash", out, 100);
    printf("  size %zu\n", EVP_KDF_CTX_get_kdf_size(ctx));
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC, "HMAC", 0);
    params[1] = OSSL_PARAM_construct_end();
    r = EVP_KDF_derive(ctx, out, 40, params);
    check(r == 0, "HMAC gets its digest only from the call that names it");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC, "HMAC", 0);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA224", 0);
    params[2] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 40, params) == 1, "HMAC SSKDF, the default salt");
    hex("hmac", out, 40);
    dup = EVP_KDF_CTX_dup(ctx);
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, "saltsalt", 8);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 40, params) == 1, "HMAC SSKDF, a salt");
    hex("hmac salt", out, 40);
    check(dup != NULL && EVP_KDF_derive(dup, out, 40, NULL) == 1, "the copy kept the default");
    hex("copy", out, 40);
    EVP_KDF_CTX_free(dup);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC, "KMAC128", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0);
    params[2] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 50, params) == 1, "KMAC SSKDF, its default salt");
    hex("kmac", out, 50);
    printf("  size %zu\n", EVP_KDF_CTX_get_kdf_size(ctx));
    params[0] = OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_MAC_SIZE, &size);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 50, params) == 1, "KMAC SSKDF of 20-octet blocks");
    hex("kmac 20", out, 50);
    size = 21;
    r = EVP_KDF_derive(ctx, out, 50, params);
    check(r == 0, "a KMAC size of 21");
    errors();
    size = 0;
    r = EVP_KDF_CTX_set_params(ctx, params);
    check(r == 0, "a MAC size of 0");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC, "CMAC", 0);
    params[1] = OSSL_PARAM_construct_end();
    r = EVP_KDF_derive(ctx, out, 16, params);
    check(r == 0, "CMAC isn't a choice");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC, "NO-SUCH-MAC", 0);
    r = EVP_KDF_CTX_set_params(ctx, params);
    check(r == 0, "an unknown MAC");
    errors();
    EVP_KDF_CTX_free(ctx);

    ctx = context("X963KDF");
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, z, 24);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, "shared", 6);
    params[3] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 70, params) == 1, "X9.63");
    hex("x963", out, 70);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC, "HMAC", 0);
    params[1] = OSSL_PARAM_construct_end();
    r = EVP_KDF_derive(ctx, out, 16, params);
    check(r == 0, "X9.63 with a MAC");
    errors();
    EVP_KDF_CTX_free(ctx);
}

int main(void)
{
    methods();
    hkdf();
    tls13();
    pbkdf2();
    tls1_prf();
    sskdf();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
