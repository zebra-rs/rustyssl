/*
 * Conformance test for OpenSSL 3.6's derivations into opaque symmetric keys
 * (EVP_PKEY_derive_SKEY(3), EVP_KDF_derive_SKEY(3), EVP_KDF_CTX_set_SKEY(3),
 * EVP_SKEY_import_SKEYMGMT(3)), in TAP format: a key exchange and KDFs that derive into a key
 * themselves (ECDH, PBKDF1) or through their raw output (HKDF, PBKDF1 into another
 * provider's key), and keys given to KDFs as parameters.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
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
    unsigned long e;

    printf("  errors:");
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
}

static void hex(const char *label, const unsigned char *b, size_t n)
{
    printf("  %s:", label);
    for (size_t i = 0; i < n; i++)
        printf("%02x", b[i]);
    printf("\n");
}

/* The raw secret of `k`, compared with `want` (or printed if NULL). */
static int same_raw(EVP_SKEY *k, const unsigned char *want, size_t n)
{
    const unsigned char *raw = NULL;
    size_t len = 0;

    if (k == NULL || EVP_SKEY_get0_raw_key(k, &raw, &len) != 1)
        return 0;
    printf("  key type %s, %zu octets\n", EVP_SKEY_get0_skeymgmt_name(k), len);
    return want == NULL || (len == n && memcmp(raw, want, n) == 0);
}

static void exchange(const char *alg, const char *key_type, size_t keylen)
{
    EVP_PKEY *a = EVP_PKEY_Q_keygen(NULL, NULL, alg, "P-256");
    EVP_PKEY *b = EVP_PKEY_Q_keygen(NULL, NULL, alg, "P-256");
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, a, NULL);
    unsigned char secret[64];
    size_t n = keylen;
    EVP_SKEY *k;
    char what[100];

    printf("# %s into %s\n", alg, key_type);
    k = EVP_PKEY_derive_SKEY(c, NULL, key_type, NULL, keylen, NULL);
    check(k == NULL, "before an init, nothing");
    errors();
    EVP_PKEY_derive_init(c);
    EVP_PKEY_derive_set_peer(c, b);
    EVP_PKEY_derive(c, secret, &n);
    k = EVP_PKEY_derive_SKEY(c, NULL, key_type, NULL, keylen, NULL);
    snprintf(what, sizeof(what), "%s: the key holds the secret", alg);
    check(same_raw(k, secret, keylen), what);
    errors();
    EVP_SKEY_free(k);
    k = EVP_PKEY_derive_SKEY(c, NULL, key_type, NULL, keylen - 1, NULL);
    /* A shorter secret: AES refuses 31 octets; the generic type takes them. */
    printf("  %zu octets: %s\n", keylen - 1, k == NULL ? "none" : "a key");
    check(strcmp(key_type, "AES") == 0 ? k == NULL : same_raw(k, secret, keylen - 1),
          "a shorter secret is its prefix, if the type takes it");
    EVP_SKEY_free(k);
    errors();
    k = EVP_PKEY_derive_SKEY(c, NULL, NULL, NULL, keylen, NULL);
    check(k == NULL, "no key type fails");
    errors();
    k = EVP_PKEY_derive_SKEY(c, NULL, "NO-SUCH-TYPE", NULL, keylen, NULL);
    check(k == NULL, "an unknown key type fails");
    errors();
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);
}

static void hkdf(void)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *c = EVP_KDF_CTX_new(kdf);
    unsigned char out[32], secret[16] = "a secret key ..";
    OSSL_PARAM p[4], ip[2];
    EVP_SKEY *k, *in;

    printf("# HKDF\n");
    p[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    p[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, "salt", 4);
    p[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, "info", 4);
    p[3] = OSSL_PARAM_construct_end();
    EVP_KDF_CTX_set_params(c, p);
    ip[0] = OSSL_PARAM_construct_octet_string(OSSL_SKEY_PARAM_RAW_BYTES, secret, sizeof(secret));
    ip[1] = OSSL_PARAM_construct_end();
    in = EVP_SKEY_import(NULL, "GENERIC-SECRET", NULL, OSSL_SKEYMGMT_SELECT_SECRET_KEY, ip);
    check(EVP_KDF_CTX_set_SKEY(c, in, NULL) == 1, "the key as `key`");
    check(EVP_KDF_derive(c, out, sizeof(out), NULL) == 1, "derive");
    hex("out", out, sizeof(out));
    k = EVP_KDF_derive_SKEY(c, NULL, "AES", NULL, 16, NULL);
    check(same_raw(k, out, 16), "into an AES key, the same octets");
    EVP_SKEY_free(k);
    k = EVP_KDF_derive_SKEY(c, NULL, "GENERIC-SECRET", "provider=default", 32, NULL);
    check(same_raw(k, out, 32), "into a generic key");
    EVP_SKEY_free(k);
    check(EVP_KDF_derive_SKEY(c, NULL, NULL, NULL, 16, NULL) == NULL, "no key type");
    errors();
    check(EVP_KDF_derive_SKEY(NULL, NULL, "AES", NULL, 16, NULL) == NULL, "no context");
    errors();
    check(EVP_KDF_CTX_set_SKEY(c, in, OSSL_KDF_PARAM_SALT) == 1, "the key as `salt`");
    check(EVP_KDF_derive(c, out, sizeof(out), NULL) == 1, "derive again");
    hex("out", out, sizeof(out));
    {
        EVP_SKEYMGMT *m = EVP_SKEYMGMT_fetch(NULL, "AES", NULL);
        EVP_SKEY *imported = EVP_SKEY_import_SKEYMGMT(NULL, m, OSSL_SKEYMGMT_SELECT_SECRET_KEY, ip);

        check(same_raw(imported, secret, sizeof(secret)), "EVP_SKEY_import_SKEYMGMT");
        EVP_SKEY_free(imported);
        k = EVP_KDF_derive_SKEY(c, m, "ignored", NULL, 16, NULL);
        check(same_raw(k, out, 16), "the given key manager");
        EVP_SKEY_free(k);
        imported = EVP_SKEY_import_SKEYMGMT(NULL, m, OSSL_SKEYMGMT_SELECT_SECRET_KEY, NULL);
        check(imported == NULL, "nothing to import");
        errors();
        EVP_SKEYMGMT_free(m);
    }
    EVP_SKEY_free(in);
    EVP_KDF_CTX_free(c);
    EVP_KDF_free(kdf);
}

static void pbkdf1(void)
{
    OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
    OSSL_PROVIDER *dflt = OSSL_PROVIDER_load(NULL, "default");
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "PBKDF1", NULL);
    EVP_KDF_CTX *c = EVP_KDF_CTX_new(kdf);
    unsigned char out[16];
    OSSL_PARAM p[3], ip[2];
    EVP_SKEY *pass, *k;
    uint64_t iter = 3;

    printf("# PBKDF1\n");
    if (c == NULL) {
        printf("  no legacy provider\n");
        ERR_clear_error();
        return;
    }
    p[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA1", 0);
    p[1] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_ITER, &iter);
    p[2] = OSSL_PARAM_construct_end();
    EVP_KDF_CTX_set_params(c, p);
    ip[0] = OSSL_PARAM_construct_octet_string(OSSL_SKEY_PARAM_RAW_BYTES, "password", 8);
    ip[1] = OSSL_PARAM_construct_end();
    pass = EVP_SKEY_import(NULL, "GENERIC-SECRET", "provider=legacy",
                           OSSL_SKEYMGMT_SELECT_SECRET_KEY, ip);
    check(pass != NULL, "a legacy provider key");
    check(EVP_KDF_CTX_set_SKEY(c, pass, OSSL_KDF_PARAM_PASSWORD) == 1, "the password (its own key)");
    check(EVP_KDF_CTX_set_SKEY(c, pass, OSSL_KDF_PARAM_SALT) == 1, "the salt too");
    check(EVP_KDF_CTX_set_SKEY(c, pass, NULL) == 0, "`key` isn't a PBKDF1 parameter");
    errors();
    check(EVP_KDF_derive(c, out, sizeof(out), NULL) == 1, "derive");
    hex("out", out, sizeof(out));
    k = EVP_KDF_derive_SKEY(c, NULL, "GENERIC-SECRET", "provider=legacy", 16, NULL);
    check(same_raw(k, out, 16), "into its own key");
    EVP_SKEY_free(k);
    k = EVP_KDF_derive_SKEY(c, NULL, "AES", NULL, 16, NULL);
    check(same_raw(k, out, 16), "into another provider's");
    EVP_SKEY_free(k);
    check(EVP_KDF_derive_SKEY(c, NULL, "GENERIC-SECRET", "provider=legacy", 0, NULL) == NULL,
          "nothing to derive");
    errors();
    EVP_SKEY_free(pass);
    EVP_KDF_CTX_free(c);
    EVP_KDF_free(kdf);
    OSSL_PROVIDER_unload(legacy);
    OSSL_PROVIDER_unload(dflt);
}

int main(void)
{
    exchange("EC", "AES", 32);
    exchange("EC", "GENERIC-SECRET", 32);
    hkdf();
    pbkdf1();
    printf("1..%d\n", number);
    return failures != 0;
}
