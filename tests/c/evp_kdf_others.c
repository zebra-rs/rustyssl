/*
 * Conformance test for SCRYPT (EVP_KDF-SCRYPT(7), EVP_PBE_scrypt(3)), SSHKDF
 * (EVP_KDF-SSHKDF(7)), KBKDF (EVP_KDF-KB(7)), and X942KDF-ASN1 (EVP_KDF-X942-ASN1(7)), in TAP
 * format: their names and parameter lists, the RFC 7914 vectors, each KDF's parameters, modes,
 * errors, and quirks, copies, and resets.
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

static EVP_KDF_CTX *context(const char *name)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, name, NULL);
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);

    EVP_KDF_free(kdf);
    return ctx;
}

static void methods(void)
{
    static const char *names[] = { "SCRYPT", "id-scrypt", "SSHKDF", "KBKDF", "X942KDF-ASN1",
                                   "X942KDF", NULL };
    const char **n;

    for (n = names; *n != NULL; n++) {
        EVP_KDF *kdf = EVP_KDF_fetch(NULL, *n, NULL);
        EVP_KDF_CTX *ctx;

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
        errors();
        EVP_KDF_CTX_free(ctx);
        EVP_KDF_free(kdf);
    }
}

static void scrypt(void)
{
    unsigned char out[64];
    EVP_KDF_CTX *ctx = context("SCRYPT"), *dup;
    OSSL_PARAM params[7];
    uint64_t n = 16, r = 1, p = 1, maxmem = 1024;
    int ret;

    check(EVP_PBE_scrypt(NULL, 0, NULL, 0, 16, 1, 1, 0, out, 64) == 1
          && same_hex(out, 64, "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
                               "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"),
          "RFC 7914, the empty password");
    check(EVP_PBE_scrypt("password", 8, (const unsigned char *)"NaCl", 4, 1024, 8, 16, 0, out, 64) == 1
          && same_hex(out, 64, "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162"
                               "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"),
          "RFC 7914, password and NaCl");
    check(EVP_PBE_scrypt("p", 1, (const unsigned char *)"s", 1, 1024, 8, 16, 0, NULL, 64) == 1,
          "parameters only, with no key");
    check(EVP_PBE_scrypt_ex(NULL, 0, NULL, 0, 16, 1, 1, 0, out, 64, NULL, "provider=default") == 1
          && same_hex(out, 64, "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
                               "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"),
          "EVP_PBE_scrypt_ex, with properties");
    ret = EVP_PBE_scrypt_ex("p", 1, (const unsigned char *)"s", 1, 16, 1, 1, 0, out, 16, NULL,
                            "provider=nonesuch");
    check(ret == 0, "EVP_PBE_scrypt_ex, no SCRYPT with those properties");
    errors();
    ret = EVP_PBE_scrypt("p", 1, (const unsigned char *)"s", 1, 1 << 20, 8, 1, 0, NULL, 64);
    check(ret == 0, "more than the default 32 MiB");
    errors();
    ret = EVP_PBE_scrypt("p", 1, (const unsigned char *)"s", 1, 16, (uint64_t)1 << 32, 1, 0, out, 16);
    check(ret == 0, "r past 32 bits");
    errors();
    ret = EVP_PBE_scrypt("p", 1, (const unsigned char *)"s", 1, 1 << 16, 1, 1, 0, out, 16);
    check(ret == 0, "N of 2^16 with r 1");
    errors();

    check(ctx != NULL, "a scrypt context");
    ret = EVP_KDF_derive(ctx, out, 16, NULL);
    check(ret == 0, "no password");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, "pw", 2);
    params[1] = OSSL_PARAM_construct_end();
    ret = EVP_KDF_derive(ctx, out, 16, params);
    check(ret == 0, "no salt");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, "salt", 4);
    params[1] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, &n);
    params[2] = OSSL_PARAM_construct_end();
    check(EVP_KDF_CTX_set_params(ctx, params) == 1, "a salt");
    params[0] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, &n);
    params[1] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_R, &r);
    params[2] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_P, &p);
    params[3] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 40, params) == 1, "N 16, r 1, p 1");
    hex("16-1-1", out, 40);
    dup = EVP_KDF_CTX_dup(ctx);
    check(dup != NULL, "copy");
    params[0] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_MAXMEM, &maxmem);
    params[1] = OSSL_PARAM_construct_end();
    ret = EVP_KDF_derive(ctx, out, 40, params);
    check(ret == 0, "a memory limit of 1024");
    errors();
    check(EVP_KDF_derive(dup, out + 24, 40, NULL) == 1 && memcmp(out + 24, out, 0) == 0,
          "the copy kept its limit");
    hex("copy", out + 24, 40);
    EVP_KDF_CTX_free(dup);
    n = 15;
    params[0] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, &n);
    ret = EVP_KDF_CTX_set_params(ctx, params);
    check(ret == 0, "N not a power of two");
    n = 1;
    ret = EVP_KDF_CTX_set_params(ctx, params);
    check(ret == 0, "N of 1");
    r = 0;
    params[0] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_R, &r);
    ret = EVP_KDF_CTX_set_params(ctx, params);
    check(ret == 0, "r of 0");
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_PROPERTIES, "provider=nonesuch", 0);
    ret = EVP_KDF_CTX_set_params(ctx, params);
    check(ret == 0, "no SHA-256 with those properties");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_PROPERTIES, "provider=default", 0);
    check(EVP_KDF_CTX_set_params(ctx, params) == 1, "SHA-256 from the default provider");
    /*
     * A query that doesn't parse leaves an error where each fetch first meets it, then works as
     * no query: fetching SHA-256 when it's set, and PBKDF2 when deriving (scrypt runs PBKDF2
     * as a fetched KDF); a second derivation finds both fetched.
     */
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_PROPERTIES, "7scrypt", 0);
    maxmem = 1 << 20;
    params[1] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_MAXMEM, &maxmem);
    params[2] = OSSL_PARAM_construct_end();
    check(EVP_KDF_CTX_set_params(ctx, params) == 1, "a query that doesn't parse");
    errors();
    check(EVP_KDF_derive(ctx, out, 16, NULL) == 1, "derives with it");
    errors();
    check(EVP_KDF_derive(ctx, out, 16, NULL) == 1, "and again");
    errors();
    {
        size_t size = 0;

        params[0] = OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_SIZE, &size);
        params[1] = OSSL_PARAM_construct_end();
        check(EVP_KDF_CTX_get_params(ctx, params) == 1 && size == (size_t)-1, "any size");
        params[0] = OSSL_PARAM_construct_end();
        printf("  no size asked: %d\n", EVP_KDF_CTX_get_params(ctx, params));
    }
    EVP_KDF_CTX_reset(ctx);
    ret = EVP_KDF_derive(ctx, out, 16, NULL);
    check(ret == 0, "nothing after a reset");
    errors();
    EVP_KDF_CTX_free(ctx);
}

static void sshkdf(void)
{
    unsigned char key[32], h[32], sid[32], out[100], out2[100];
    EVP_KDF_CTX *ctx = context("SSHKDF"), *dup;
    OSSL_PARAM params[7];
    int i, r;

    for (i = 0; i < 32; i++) {
        key[i] = (unsigned char)i;
        h[i] = (unsigned char)(0x40 + i);
        sid[i] = (unsigned char)(0x80 + i);
    }
    check(ctx != NULL, "an SSHKDF context");
    r = EVP_KDF_derive(ctx, out, 16, NULL);
    check(r == 0, "no digest");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();
    r = EVP_KDF_derive(ctx, out, 16, params);
    check(r == 0, "no key");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key, 32);
    r = EVP_KDF_derive(ctx, out, 16, params);
    check(r == 0, "no exchange hash");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SSHKDF_XCGHASH, h, 32);
    r = EVP_KDF_derive(ctx, out, 16, params);
    check(r == 0, "no session id");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SSHKDF_SESSION_ID, sid, 32);
    r = EVP_KDF_derive(ctx, out, 16, params);
    check(r == 0, "no type");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE, "G", 0);
    r = EVP_KDF_CTX_set_params(ctx, params);
    check(r == 0, "type G");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE, "AB", 0);
    r = EVP_KDF_CTX_set_params(ctx, params);
    check(r == 0, "two octets of type");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE, "C", 0);
    check(EVP_KDF_derive(ctx, out, 100, params) == 1, "type C, 100 octets");
    hex("C", out, 100);
    dup = EVP_KDF_CTX_dup(ctx);
    check(dup != NULL && EVP_KDF_derive(dup, out2, 20, NULL) == 1 && memcmp(out, out2, 20) == 0,
          "the copy, a prefix");
    EVP_KDF_CTX_free(dup);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA1", 0);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE, "F", 0);
    params[2] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 41, params) == 1, "SHA-1, type F, 41 octets");
    hex("F", out, 41);
    check(EVP_KDF_derive(ctx, out, 0, NULL) == 1, "no output");
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0);
    params[1] = OSSL_PARAM_construct_end();
    r = EVP_KDF_CTX_set_params(ctx, params);
    check(r == 0, "a NULL key");
    errors();
    EVP_KDF_CTX_free(ctx);
}

static void kbkdf(void)
{
    unsigned char key[32], out[100], out2[100];
    EVP_KDF_CTX *ctx = context("KBKDF"), *dup;
    OSSL_PARAM params[8];
    int i, r, rbits = 8, use_l = 0, sep = 0;

    for (i = 0; i < 32; i++)
        key[i] = (unsigned char)(i * 5);
    check(ctx != NULL, "a KBKDF context");
    r = EVP_KDF_derive(ctx, out, 16, NULL);
    check(r == 0, "no key");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key, 32);
    params[1] = OSSL_PARAM_construct_end();
    r = EVP_KDF_derive(ctx, out, 16, params);
    check(r == 0, "no MAC");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC, "KMAC128", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, "label", 5);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, "context", 7);
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key, 32);
    params[4] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 50, params) == 1, "KMAC128");
    hex("kmac", out, 50);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC, "HMAC", 0);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key, 32);
    params[3] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 100, params) == 1, "counter mode over HMAC-SHA256");
    hex("counter", out, 100);
    dup = EVP_KDF_CTX_dup(ctx);
    check(dup != NULL && EVP_KDF_derive(dup, out2, 100, NULL) == 1 && memcmp(out, out2, 100) == 0,
          "the copy");
    EVP_KDF_CTX_free(dup);
    params[0] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_KBKDF_R, &rbits);
    params[1] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_KBKDF_USE_L, &use_l);
    params[2] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR, &sep);
    params[3] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 64, params) == 1, "an 8-bit counter, no L, no separator");
    hex("r8", out, 64);
    {
        unsigned char *big = malloc(32 * 256);

        memset(big, 0x55, 32 * 256);
        r = EVP_KDF_derive(ctx, big, 32 * 256, NULL);
        check(r == 0 && big[0] == 0 && big[32 * 256 - 1] == 0,
              "256 blocks with an 8-bit counter fail, wiping the output");
        errors();
        free(big);
    }
    rbits = 12;
    params[0] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_KBKDF_R, &rbits);
    params[1] = OSSL_PARAM_construct_end();
    r = EVP_KDF_CTX_set_params(ctx, params);
    check(r == 0, "r of 12");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, "FEEDBACK", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, key, 31);
    params[2] = OSSL_PARAM_construct_end();
    r = EVP_KDF_derive(ctx, out, 64, params);
    check(r == 0, "feedback with an IV of 31 octets");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, key, 32);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 64, params) == 1, "feedback mode, an IV");
    hex("feedback", out, 64);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, "co", 0);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_KDF_CTX_set_params(ctx, params) == 1, "a mode's prefix names it");
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, "pipeline", 0);
    r = EVP_KDF_CTX_set_params(ctx, params);
    check(r == 0, "an unknown mode");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC, "CMAC", 0);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CIPHER, "AES-128-CBC", 0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key, 16);
    params[3] = OSSL_PARAM_construct_end();
    r = EVP_KDF_derive(ctx, out, 40, params);
    check(r == 0, "over CMAC, the HMAC's IV kept");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, NULL, 0);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 40, params) == 1, "over CMAC, the IV cleared");
    hex("cmac", out, 40);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC, "GMAC", 0);
    params[1] = OSSL_PARAM_construct_end();
    r = EVP_KDF_CTX_set_params(ctx, params);
    check(r == 0, "GMAC isn't a choice");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC, "HMAC", 0);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    params[2] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 16, params) == 1, "a new HMAC, keyed with the key kept");
    hex("hmac again", out, 16);
    EVP_KDF_CTX_free(ctx);
}

static void x942(void)
{
    unsigned char z[20], out[100], out2[100];
    EVP_KDF_CTX *ctx = context("X942KDF-ASN1"), *dup;
    OSSL_PARAM params[7];
    int i, r, keybits = 0;

    for (i = 0; i < 20; i++)
        z[i] = (unsigned char)i;
    check(ctx != NULL, "an X942KDF context");
    r = EVP_KDF_derive(ctx, out, 16, NULL);
    check(r == 0, "no secret");
    errors();
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, z, 20);
    params[1] = OSSL_PARAM_construct_end();
    r = EVP_KDF_derive(ctx, out, 16, params);
    check(r == 0, "no digest");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA1", 0);
    r = EVP_KDF_derive(ctx, out, 16, params);
    check(r == 0, "no CEK algorithm");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CEK_ALG, "AES-128-CBC", 0);
    r = EVP_KDF_CTX_set_params(ctx, params);
    check(r == 0, "a cipher that isn't a key wrap");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CEK_ALG, "AES-128-WRAP", 0);
    check(EVP_KDF_derive(ctx, out, 16, params) == 1, "AES-128-WRAP");
    hex("aes128", out, 16);
    printf("  size %zu\n", EVP_KDF_CTX_get_kdf_size(ctx));
    dup = EVP_KDF_CTX_dup(ctx);
    check(dup != NULL && EVP_KDF_derive(dup, out2, 16, NULL) == 1 && memcmp(out, out2, 16) == 0,
          "the copy");
    EVP_KDF_CTX_free(dup);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CEK_ALG, "DES3-WRAP", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_UKM, "user keying material", 20);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_X942_PARTYVINFO, "v", 1);
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_X942_SUPP_PRIVINFO, "priv", 4);
    params[4] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 100, params) == 1, "DES3-WRAP, ukm, partyV, suppPriv");
    hex("des3", out, 100);
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_X942_SUPP_PUBINFO, "pub", 3);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_KDF_derive(ctx, out, 24, params) == 1, "suppPub turns the key bits off");
    hex("pub", out, 24);
    params[0] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_X942_USE_KEYBITS, &keybits);
    keybits = 1;
    r = EVP_KDF_derive(ctx, out, 24, params);
    check(r == 0, "key bits and suppPub both");
    errors();
    keybits = 0;
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_X942_ACVPINFO, "\x04\x01\x00", 3);
    params[2] = OSSL_PARAM_construct_end();
    r = EVP_KDF_derive(ctx, out, 24, params);
    check(r == 0, "ACVP data with the other fields");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CEK_ALG, "AES-256-WRAP", 0);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_PROPERTIES, "provider=default", 0);
    params[2] = OSSL_PARAM_construct_end();
    r = EVP_KDF_CTX_set_params(ctx, params);
    check(r == 1, "properties make the CEK name the query, which still fetches");
    errors();
    EVP_KDF_CTX_reset(ctx);
    r = EVP_KDF_derive(ctx, out, 16, NULL);
    check(r == 0, "nothing after a reset");
    errors();
    EVP_KDF_CTX_free(ctx);
}

int main(void)
{
    methods();
    scrypt();
    sshkdf();
    kbkdf();
    x942();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
