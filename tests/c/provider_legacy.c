/*
 * Conformance test for the legacy provider (OSSL_PROVIDER-legacy(7)), in TAP format: the module
 * OpenSSL's default build ships in MODULESDIR, loaded into the default library context and into
 * one of the test's own through a configuration file; its parameters; every digest and cipher
 * it offers, run on known inputs, with the lengths and flags the EVP layer reports; a
 * variable-length key, RC2's effective key length and its AlgorithmIdentifier parameters, DES's
 * random keys; RC4-HMAC-MD5 over TLS records (its MAC key and header, a bad MAC, a wrong
 * length); and a search path without the module, where loading fails.
 *
 * `cargo xtask test-c` points each run at its own library's modules (OPENSSL_MODULES). Built once
 * against the vendored headers, then run against the reference OpenSSL and against rustyssl: it
 * must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
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

static void hex(const char *label, const unsigned char *p, size_t n)
{
    size_t i;

    printf("  %s:", label);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

/* The queued errors' codes (their data can hold paths and the loader's messages). */
static void error_codes(void)
{
    unsigned long code;

    printf("  errors:");
    while ((code = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
    printf("\n");
}

static void provider_params(OSSL_PROVIDER *prov)
{
    const char *name = NULL, *version = NULL;
    int status = -1;
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, &name, 0),
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, &version, 0),
        OSSL_PARAM_int(OSSL_PROV_PARAM_STATUS, &status),
        OSSL_PARAM_END,
    };

    check(OSSL_PROVIDER_get_params(prov, params) == 1, "the provider's parameters");
    printf("  name %s, version %s, status %d, provider name %s\n", name, version, status,
           OSSL_PROVIDER_get0_name(prov));
}

static const char *const digests[] = { "MD4", "MDC2", "WHIRLPOOL", "RIPEMD160", "RMD160" };

static void test_digests(OSSL_LIB_CTX *ctx)
{
    static const unsigned char msg[] = "Now is the time for all ";
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int n;
    size_t i;

    for (i = 0; i < sizeof(digests) / sizeof(digests[0]); i++) {
        EVP_MD *md = EVP_MD_fetch(ctx, digests[i], "provider=legacy");

        check(md != NULL, digests[i]);
        if (md == NULL) {
            error_codes();
            continue;
        }
        printf("  %s: size %d, block %d, provider %s\n", EVP_MD_get0_name(md),
               EVP_MD_get_size(md), EVP_MD_get_block_size(md),
               OSSL_PROVIDER_get0_name(EVP_MD_get0_provider(md)));
        n = 0;
        check(EVP_Digest(msg, sizeof(msg) - 1, out, &n, md, NULL) == 1, "digested");
        hex("digest", out, n);
        EVP_MD_free(md);
    }
}

struct cipher_case {
    const char *name;
    int keylen; /* the key given: its default if 0 */
};

static const struct cipher_case ciphers[] = {
    { "CAST5-ECB", 0 }, { "CAST5-CBC", 0 }, { "CAST5-OFB", 0 }, { "CAST5-CFB", 0 },
    { "BF-ECB", 0 }, { "BF-CBC", 0 }, { "BF-CBC", 5 }, { "BF-OFB", 0 }, { "BF-CFB", 0 },
    { "IDEA-ECB", 0 }, { "IDEA-CBC", 0 }, { "IDEA-OFB", 0 }, { "IDEA-CFB", 0 },
    { "SEED-ECB", 0 }, { "SEED-CBC", 0 }, { "SEED-OFB", 0 }, { "SEED-CFB", 0 },
    { "RC2-ECB", 0 }, { "RC2-CBC", 0 }, { "RC2-40-CBC", 0 }, { "RC2-64-CBC", 0 },
    { "RC2-CFB", 0 }, { "RC2-OFB", 0 }, { "RC4", 0 }, { "RC4", 7 }, { "RC4-40", 0 },
    { "DESX-CBC", 0 }, { "DES-ECB", 0 }, { "DES-CBC", 0 }, { "DES-OFB", 0 },
    { "DES-CFB", 0 }, { "DES-CFB1", 0 }, { "DES-CFB8", 0 }, { "RC4-HMAC-MD5", 0 },
};

static void test_ciphers(OSSL_LIB_CTX *ctx)
{
    static const unsigned char msg[] = "The quick brown fox jumps over the lazy dog";
    unsigned char key[64], iv[16], out[128], back[128];
    int i, outl, finl, n;
    size_t c;

    for (i = 0; i < 64; i++)
        key[i] = (unsigned char)(i * 7 + 1);
    for (i = 0; i < 16; i++)
        iv[i] = (unsigned char)(0xf0 - i);
    for (c = 0; c < sizeof(ciphers) / sizeof(ciphers[0]); c++) {
        EVP_CIPHER *cipher = EVP_CIPHER_fetch(ctx, ciphers[c].name, "provider=legacy");
        EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
        int ok;

        printf("# %s%s\n", ciphers[c].name, ciphers[c].keylen ? ", another key length" : "");
        check(cipher != NULL, "fetched");
        if (cipher == NULL) {
            error_codes();
            EVP_CIPHER_CTX_free(cctx);
            continue;
        }
        printf("  key %d, iv %d, block %d, mode %lu, flags %lx\n", EVP_CIPHER_get_key_length(cipher),
               EVP_CIPHER_get_iv_length(cipher), EVP_CIPHER_get_block_size(cipher),
               (unsigned long)EVP_CIPHER_get_mode(cipher),
               (unsigned long)(EVP_CIPHER_get_flags(cipher) & ~EVP_CIPH_MODE));
        ok = EVP_EncryptInit_ex2(cctx, cipher, NULL, NULL, NULL);
        if (ciphers[c].keylen != 0)
            ok = ok && EVP_CIPHER_CTX_set_key_length(cctx, ciphers[c].keylen) == 1;
        ok = ok && EVP_EncryptInit_ex2(cctx, NULL, key, iv, NULL)
             && EVP_EncryptUpdate(cctx, out, &outl, msg, sizeof(msg) - 1)
             && EVP_EncryptFinal_ex(cctx, out + outl, &finl);
        check(ok, "encrypted");
        if (!ok) {
            error_codes();
            EVP_CIPHER_CTX_free(cctx);
            EVP_CIPHER_free(cipher);
            continue;
        }
        n = outl + finl;
        printf("  key length %d\n", EVP_CIPHER_CTX_get_key_length(cctx));
        hex("ciphertext", out, (size_t)n);
        ok = EVP_DecryptInit_ex2(cctx, cipher, NULL, NULL, NULL);
        if (ciphers[c].keylen != 0)
            ok = ok && EVP_CIPHER_CTX_set_key_length(cctx, ciphers[c].keylen) == 1;
        ok = ok && EVP_DecryptInit_ex2(cctx, NULL, key, iv, NULL)
             && EVP_DecryptUpdate(cctx, back, &outl, out, n)
             && EVP_DecryptFinal_ex(cctx, back + outl, &finl);
        check(ok && outl + finl == (int)sizeof(msg) - 1
              && memcmp(back, msg, sizeof(msg) - 1) == 0, "decrypted back");
        EVP_CIPHER_CTX_free(cctx);
        EVP_CIPHER_free(cipher);
    }
}


/* RC4-HMAC-MD5 over a TLS record: the MAC key, the header, then one record each way. */
static void tls_record(EVP_CIPHER *cipher, int enc, unsigned char *buf, int len, int len_in_aad,
                       const char *what)
{
    static const unsigned char key[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    static const unsigned char mackey[16] = { 0x55, 0x66, 0x77 };
    unsigned char aad[13] = { 0, 0, 0, 0, 0, 0, 0, 1, 23, 3, 3, 0, 0 };
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int pad, ok, n;

    aad[11] = (unsigned char)(len_in_aad >> 8);
    aad[12] = (unsigned char)len_in_aad;
    ok = EVP_CipherInit_ex2(ctx, cipher, key, NULL, enc, NULL)
         && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_MAC_KEY, (int)sizeof(mackey),
                                (void *)mackey) > 0;
    pad = ok ? EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD, (int)sizeof(aad), aad) : 0;
    check(ok && pad > 0, what);
    printf("  tls-aad-pad %d, the header's length now %d\n", pad, aad[11] << 8 | aad[12]);
    n = EVP_Cipher(ctx, buf, buf, (unsigned int)len);
    printf("  EVP_Cipher %d\n", n);
    if (n <= 0)
        error_codes();
    EVP_CIPHER_CTX_free(ctx);
}

static void test_rc4_hmac_md5(OSSL_LIB_CTX *ctx)
{
    static const char payload[] = "GET / HTTP/1.0\r\n\r\n";
    unsigned char rec[64];
    int plen = (int)sizeof(payload) - 1;
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(ctx, "RC4-HMAC-MD5", NULL);

    printf("# RC4-HMAC-MD5 over TLS records\n");
    check(cipher != NULL, "fetched");
    if (cipher == NULL) {
        error_codes();
        return;
    }
    printf("  key %d, iv %d, block %d, flags %lx\n", EVP_CIPHER_get_key_length(cipher),
           EVP_CIPHER_get_iv_length(cipher), EVP_CIPHER_get_block_size(cipher),
           (unsigned long)(EVP_CIPHER_get_flags(cipher) & ~EVP_CIPH_MODE));
    memset(rec, 0, sizeof(rec));
    memcpy(rec, payload, (size_t)plen);
    tls_record(cipher, 1, rec, plen + 16, plen, "encrypt with the header");
    hex("record", rec, (size_t)plen + 16);
    tls_record(cipher, 0, rec, plen + 16, plen + 16, "decrypt with the header");
    check(memcmp(rec, payload, (size_t)plen) == 0, "the payload back");
    memcpy(rec, payload, (size_t)plen);
    tls_record(cipher, 1, rec, plen + 16, plen, "encrypt again");
    rec[plen + 3] ^= 1;
    tls_record(cipher, 0, rec, plen + 16, plen + 16, "decrypt a bad MAC");
    tls_record(cipher, 1, rec, plen + 3, plen, "a record of the wrong length");
    EVP_CIPHER_free(cipher);
}

/* RC2: the effective key length, and the AlgorithmIdentifier's parameters both ways. */
static void test_rc2(OSSL_LIB_CTX *ctx)
{
    static const char *const names[] = { "RC2-CBC", "RC2-40-CBC", "RC2-64-CBC" };
    unsigned char key[16] = { 0 }, iv[8] = { 1, 2, 3, 4, 5, 6, 7, 8 }, der[64];
    unsigned char *p;
    size_t i;

    for (i = 0; i < 3; i++) {
        EVP_CIPHER *cipher = EVP_CIPHER_fetch(ctx, names[i], NULL);
        EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new(), *back = EVP_CIPHER_CTX_new();
        ASN1_TYPE *type = ASN1_TYPE_new();
        size_t bits = 0;
        int len;
        OSSL_PARAM get[] = { OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_RC2_KEYBITS, &bits), OSSL_PARAM_END };

        printf("# %s's parameters\n", names[i]);
        check(cipher != NULL && EVP_EncryptInit_ex2(cctx, cipher, key, iv, NULL) == 1, "initialized");
        check(EVP_CIPHER_CTX_get_params(cctx, get) == 1, "rc2-keybits");
        printf("  keybits %zu\n", bits);
        check(EVP_CIPHER_param_to_asn1(cctx, type) > 0, "EVP_CIPHER_param_to_asn1");
        p = der;
        len = i2d_ASN1_TYPE(type, &p);
        hex("parameters", der, len > 0 ? (size_t)len : 0);
        check(EVP_DecryptInit_ex2(back, cipher, NULL, NULL, NULL) == 1
              && EVP_CIPHER_asn1_to_param(back, type) > 0, "EVP_CIPHER_asn1_to_param");
        printf("  key length %d after\n", EVP_CIPHER_CTX_get_key_length(back));
        bits = 0;
        check(EVP_CIPHER_CTX_get_params(back, get) == 1, "rc2-keybits after");
        printf("  keybits %zu after\n", bits);
        ASN1_TYPE_free(type);
        EVP_CIPHER_CTX_free(cctx);
        EVP_CIPHER_CTX_free(back);
        EVP_CIPHER_free(cipher);
    }
}

static int odd_parity(const unsigned char *k, size_t n)
{
    size_t i;
    int bit, ones;

    for (i = 0; i < n; i++) {
        for (ones = 0, bit = 0; bit < 8; bit++)
            ones += (k[i] >> bit) & 1;
        if ((ones & 1) == 0)
            return 0;
    }
    return 1;
}

static void test_des_rand_key(OSSL_LIB_CTX *ctx)
{
    static const char *const names[] = { "DES-CBC", "DESX-CBC" };
    unsigned char key[24];
    size_t i;

    for (i = 0; i < 2; i++) {
        EVP_CIPHER *cipher = EVP_CIPHER_fetch(ctx, names[i], NULL);
        EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
        int n = cipher != NULL ? EVP_CIPHER_get_key_length(cipher) : 0;

        printf("# %s's random key\n", names[i]);
        check(cipher != NULL && EVP_EncryptInit_ex2(cctx, cipher, NULL, NULL, NULL) == 1
              && EVP_CIPHER_CTX_rand_key(cctx, key) == 1, "EVP_CIPHER_CTX_rand_key");
        /* DESX's whitening keys get parity too, as each third of the key does. */
        check(n > 0 && odd_parity(key, (size_t)n), "odd parity");
        EVP_CIPHER_CTX_free(cctx);
        EVP_CIPHER_free(cipher);
    }
}

static void test_config(void)
{
    const char *cnf = "provider_legacy.cnf";
    FILE *f = fopen(cnf, "w");
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    EVP_MD *md;

    printf("# a configuration activating it\n");
    if (f == NULL) {
        check(0, "write the configuration");
        return;
    }
    fputs("openssl_conf = init\n[init]\nproviders = provs\n[provs]\ndefault = dflt\n"
          "legacy = lgcy\n[dflt]\nactivate = 1\n[lgcy]\nactivate = 1\n", f);
    fclose(f);
    check(OSSL_LIB_CTX_load_config(ctx, cnf) == 1, "OSSL_LIB_CTX_load_config");
    check(OSSL_PROVIDER_available(ctx, "legacy") == 1, "legacy is active");
    check(OSSL_PROVIDER_available(ctx, "default") == 1, "default is active");
    md = EVP_MD_fetch(ctx, "MD4", NULL);
    check(md != NULL, "MD4 fetched without a property query");
    EVP_MD_free(md);
    test_rc2(ctx);
    OSSL_LIB_CTX_free(ctx);
    remove(cnf);
}

static void test_missing(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();

    printf("# a search path without the module\n");
    check(OSSL_PROVIDER_set_default_search_path(ctx, "/nonexistent/rustyssl-modules") == 1,
          "set the search path");
    ERR_clear_error();
    check(OSSL_PROVIDER_load(ctx, "legacy") == NULL, "loading fails");
    error_codes();
    check(OSSL_PROVIDER_available(ctx, "legacy") == 0, "not available");
    OSSL_LIB_CTX_free(ctx);
}

int main(void)
{
    OSSL_PROVIDER *legacy, *deflt;

    printf("# the module, from OPENSSL_MODULES\n");
    legacy = OSSL_PROVIDER_load(NULL, "legacy");
    check(legacy != NULL, "OSSL_PROVIDER_load(NULL, \"legacy\")");
    if (legacy == NULL) {
        error_codes();
        printf("1..%d\n", number);
        return 1;
    }
    deflt = OSSL_PROVIDER_load(NULL, "default");
    check(deflt != NULL, "and the default provider");
    provider_params(legacy);
    test_digests(NULL);
    test_ciphers(NULL);
    test_rc2(NULL);
    test_rc4_hmac_md5(NULL);
    test_des_rand_key(NULL);
    check(OSSL_PROVIDER_unload(legacy) == 1, "unload it");
    check(EVP_MD_fetch(NULL, "MD4", "provider=legacy") == NULL, "its algorithms are gone");
    ERR_clear_error();
    OSSL_PROVIDER_unload(deflt);
    test_config();
    test_missing();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
