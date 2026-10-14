/*
 * Conformance test for opaque symmetric keys (EVP_SKEY(3), EVP_SKEYMGMT(3)), in TAP format:
 *   - EVP_SKEYMGMT_fetch of the default provider's two key managers ("AES" and
 *     "GENERIC-SECRET"), by any of their names and in any case, and of names it lacks; their
 *     names, descriptions, providers, settable parameters, references, and
 *     EVP_SKEYMGMT_do_all_provided;
 *   - EVP_SKEY_import_raw_key and EVP_SKEY_import: AES keys of each size and the sizes AES
 *     refuses, unknown key types (which fall back to the generic key manager), empty keys,
 *     selections without the secret, and parameters without the raw bytes;
 *     EVP_SKEY_generate, which the default provider doesn't offer;
 *   - EVP_SKEY_export and EVP_SKEY_get0_raw_key, the names, EVP_SKEY_is_a, references, and
 *     EVP_SKEY_to_provider (to the key's own provider by default);
 *   - EVP_CipherInit_SKEY: with a cipher that takes key objects (AES-CBC) and one that takes
 *     the raw key in their place (AES-GCM), against the same ciphers keyed with raw octets; a
 *     key of the wrong size, a cipher from no provider, and none at all;
 *   - EVP_MAC_init_SKEY, which no default MAC supports;
 *   - a provider of the test's own (OSSL_PROVIDER_add_builtin) whose key manager generates
 *     keys, names them, lists its settable parameters, and exports a key length too, beside
 *     one that lacks a function a key manager needs: fetching and using them, and moving keys
 *     between it and the default provider.
 * Every result is printed, with the error queue, so the outputs are compared line by line.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <string.h>

#include <openssl/core_dispatch.h>
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

    printf("# %s (%zu):", label, n);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

/* Prints and clears the error queue: library and reason of each entry. */
static void errors(const char *what)
{
    unsigned long e;

    printf("# errors after %s:", what);
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
}

static void print_name(const char *name, void *arg)
{
    (void)arg;
    printf(" %s", name);
}

static void print_params(const char *what, const OSSL_PARAM *p)
{
    printf("# %s:", what);
    if (p == NULL)
        printf(" NULL");
    for (; p != NULL && p->key != NULL; p++)
        printf(" %s/%u", p->key, p->data_type);
    printf("\n");
}

static void show_mgmt(EVP_SKEYMGMT *m, void *arg)
{
    const char *only = arg;

    if (only != NULL && !EVP_SKEYMGMT_is_a(m, only))
        return;
    printf("# skeymgmt %s \"%s\" from %s, names:", EVP_SKEYMGMT_get0_name(m),
        EVP_SKEYMGMT_get0_description(m) == NULL ? "no description" : EVP_SKEYMGMT_get0_description(m),
        OSSL_PROVIDER_get0_name(EVP_SKEYMGMT_get0_provider(m)));
    EVP_SKEYMGMT_names_do_all(m, print_name, NULL);
    printf("\n");
}

static int export_count;

static int export_cb(const OSSL_PARAM params[], void *arg)
{
    const OSSL_PARAM *p;

    export_count++;
    printf("# export (%s):", (const char *)arg);
    for (p = params; p->key != NULL; p++) {
        printf(" %s/%u", p->key, p->data_type);
        if (p->data_type == OSSL_PARAM_OCTET_STRING)
            printf(" %zu octets", p->data_size);
    }
    printf("\n");
    return 1;
}

static int refuse_cb(const OSSL_PARAM params[], void *arg)
{
    (void)params;
    (void)arg;
    return 0;
}

static unsigned char key32[32];

static void key_managers(void)
{
    static const char *const names[] = { "AES", "aes", "GENERIC-SECRET", "generic-secret", "HMAC", "", NULL };
    EVP_SKEYMGMT *m;
    size_t i;

    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char label[64];

        m = EVP_SKEYMGMT_fetch(NULL, names[i], NULL);
        snprintf(label, sizeof(label), "fetch %s", names[i] == NULL ? "NULL" : names[i]);
        printf("# %s: %s\n", label, m == NULL ? "NULL" : EVP_SKEYMGMT_get0_name(m));
        if (m != NULL) {
            show_mgmt(m, NULL);
            printf("# is_a AES %d, GENERIC-SECRET %d, aes %d\n", EVP_SKEYMGMT_is_a(m, "AES"),
                EVP_SKEYMGMT_is_a(m, "GENERIC-SECRET"), EVP_SKEYMGMT_is_a(m, "aes"));
            print_params("gen settable", EVP_SKEYMGMT_get0_gen_settable_params(m));
            print_params("imp settable", EVP_SKEYMGMT_get0_imp_settable_params(m));
            check(EVP_SKEYMGMT_up_ref(m) == 1, "EVP_SKEYMGMT_up_ref");
            EVP_SKEYMGMT_free(m);
            EVP_SKEYMGMT_free(m);
        }
        errors(label);
    }
    m = EVP_SKEYMGMT_fetch(NULL, "AES", "provider=base");
    printf("# fetch AES from the base provider: %s\n", m == NULL ? "NULL" : "found");
    EVP_SKEYMGMT_free(m);
    errors("a fetch from the base provider");
    EVP_SKEYMGMT_do_all_provided(NULL, show_mgmt, NULL);
    EVP_SKEYMGMT_free(NULL);
    printf("# NULL: name %s, description %s, provider %s, is_a %d, names_do_all %d\n",
        EVP_SKEYMGMT_get0_name(NULL) == NULL ? "NULL" : "set",
        EVP_SKEYMGMT_get0_description(NULL) == NULL ? "NULL" : "set",
        EVP_SKEYMGMT_get0_provider(NULL) == NULL ? "NULL" : "set", EVP_SKEYMGMT_is_a(NULL, "AES"),
        EVP_SKEYMGMT_names_do_all(NULL, print_name, NULL));
    print_params("NULL gen settable", EVP_SKEYMGMT_get0_gen_settable_params(NULL));
    print_params("NULL imp settable", EVP_SKEYMGMT_get0_imp_settable_params(NULL));
    errors("the key managers");
}

static void show_key(const char *what, EVP_SKEY *k)
{
    const unsigned char *raw = NULL;
    size_t len = 0;
    int r;

    if (k == NULL) {
        printf("# %s: NULL\n", what);
        return;
    }
    r = EVP_SKEY_get0_raw_key(k, &raw, &len);
    printf("# %s: type %s, provider %s, id %s, is_a AES %d GENERIC-SECRET %d, raw %d\n", what,
        EVP_SKEY_get0_skeymgmt_name(k), EVP_SKEY_get0_provider_name(k),
        EVP_SKEY_get0_key_id(k) == NULL ? "NULL" : EVP_SKEY_get0_key_id(k), EVP_SKEY_is_a(k, "AES"),
        EVP_SKEY_is_a(k, "GENERIC-SECRET"), r);
    if (r == 1)
        hex("raw key", raw, len);
}

static void keys(void)
{
    static const size_t sizes[] = { 16, 24, 32, 15, 17, 1, 0 };
    OSSL_PARAM params[3];
    size_t length = 16;
    EVP_SKEY *k, *k2;
    size_t i;
    int r;

    for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        char label[64];

        snprintf(label, sizeof(label), "AES of %zu", sizes[i]);
        k = EVP_SKEY_import_raw_key(NULL, "AES", key32, sizes[i], NULL);
        show_key(label, k);
        EVP_SKEY_free(k);
        errors(label);
        snprintf(label, sizeof(label), "GENERIC-SECRET of %zu", sizes[i]);
        k = EVP_SKEY_import_raw_key(NULL, "GENERIC-SECRET", key32, sizes[i], NULL);
        show_key(label, k);
        EVP_SKEY_free(k);
        errors(label);
    }
    k = EVP_SKEY_import_raw_key(NULL, "NO-SUCH-TYPE", key32, 5, NULL);
    show_key("an unknown type", k);
    EVP_SKEY_free(k);
    errors("an unknown type");
    k = EVP_SKEY_import_raw_key(NULL, "AES", key32, 16, "provider=base");
    show_key("AES from the base provider", k);
    errors("AES from the base provider");

    /* EVP_SKEY_import with selections and parameters. */
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_SKEY_PARAM_RAW_BYTES, key32, 24);
    params[1] = OSSL_PARAM_construct_end();
    k = EVP_SKEY_import(NULL, "AES", NULL, OSSL_SKEYMGMT_SELECT_ALL, params);
    show_key("import of all", k);
    EVP_SKEY_free(k);
    k = EVP_SKEY_import(NULL, "AES", NULL, OSSL_SKEYMGMT_SELECT_PARAMETERS, params);
    show_key("import of the parameters only", k);
    errors("an import without the secret");
    params[0] = OSSL_PARAM_construct_size_t(OSSL_SKEY_PARAM_KEY_LENGTH, &length);
    k = EVP_SKEY_import(NULL, "GENERIC-SECRET", NULL, OSSL_SKEYMGMT_SELECT_ALL, params);
    show_key("import without raw bytes", k);
    k = EVP_SKEY_import(NULL, "GENERIC-SECRET", NULL, OSSL_SKEYMGMT_SELECT_ALL, NULL);
    show_key("import without parameters", k);
    errors("imports without raw bytes");
    k = EVP_SKEY_generate(NULL, "AES", NULL, NULL);
    show_key("generate", k);
    errors("generate");

    /* Export, references, and moving to a provider. */
    k = EVP_SKEY_import_raw_key(NULL, "AES", key32, 32, NULL);
    export_count = 0;
    r = EVP_SKEY_export(k, OSSL_SKEYMGMT_SELECT_SECRET_KEY, export_cb, "secret");
    printf("# export of the secret %d (%d calls)\n", r, export_count);
    r = EVP_SKEY_export(k, OSSL_SKEYMGMT_SELECT_ALL, export_cb, "all");
    printf("# export of all %d\n", r);
    r = EVP_SKEY_export(k, OSSL_SKEYMGMT_SELECT_PARAMETERS, export_cb, "parameters");
    printf("# export of the parameters %d\n", r);
    r = EVP_SKEY_export(k, OSSL_SKEYMGMT_SELECT_SECRET_KEY, refuse_cb, NULL);
    printf("# export to a callback that refuses %d\n", r);
    r = EVP_SKEY_export(NULL, OSSL_SKEYMGMT_SELECT_ALL, export_cb, "NULL");
    printf("# export of NULL %d\n", r);
    errors("the exports");
    check(EVP_SKEY_up_ref(k) == 1, "EVP_SKEY_up_ref");
    EVP_SKEY_free(k);
    k2 = EVP_SKEY_to_provider(k, NULL, NULL, NULL);
    check(k2 == k, "EVP_SKEY_to_provider to the default provider gives the key itself");
    EVP_SKEY_free(k2);
    k2 = EVP_SKEY_to_provider(k, NULL, NULL, "provider=base");
    printf("# to the base provider: %s\n", k2 == NULL ? "NULL" : "a key");
    errors("to the base provider");
    k2 = EVP_SKEY_to_provider(NULL, NULL, NULL, NULL);
    printf("# to_provider of NULL: %s\n", k2 == NULL ? "NULL" : "a key");
    show_key("after", k);
    EVP_SKEY_free(k);
    EVP_SKEY_free(NULL);
    printf("# NULL: type %s, provider %s, id %s, is_a %d\n",
        EVP_SKEY_get0_skeymgmt_name(NULL) == NULL ? "NULL" : "set",
        EVP_SKEY_get0_provider_name(NULL) == NULL ? "NULL" : "set",
        EVP_SKEY_get0_key_id(NULL) == NULL ? "NULL" : "set", EVP_SKEY_is_a(NULL, "AES"));
    {
        const unsigned char *raw = NULL;
        size_t len = 0;

        printf("# raw key of NULL %d\n", EVP_SKEY_get0_raw_key(NULL, &raw, &len));
    }
    errors("the keys");
}

/* Encrypts 40 octets with `cipher`, keyed with `skey` (or the raw `key`). */
static int encrypt_with(const char *what, EVP_CIPHER *cipher, EVP_SKEY *skey, const unsigned char *key,
    unsigned char *out)
{
    static const unsigned char iv[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char in[40];
    int r, n = 0, f = 0;

    memset(in, 'x', sizeof(in));
    if (key == NULL)
        r = EVP_CipherInit_SKEY(ctx, cipher, skey, iv, (size_t)EVP_CIPHER_get_iv_length(cipher), 1, NULL);
    else
        r = EVP_CipherInit_ex2(ctx, cipher, key, iv, 1, NULL);
    printf("# %s: init %d", what, r);
    if (r == 1) {
        r = EVP_EncryptUpdate(ctx, out, &n, in, sizeof(in)) && EVP_EncryptFinal_ex(ctx, out + n, &f);
        printf(", encrypt %d, %d octets", r, n + f);
    }
    printf("\n");
    EVP_CIPHER_CTX_free(ctx);
    return n + f;
}

static void ciphers(void)
{
    EVP_CIPHER *cbc = EVP_CIPHER_fetch(NULL, "AES-128-CBC", NULL);
    EVP_CIPHER *gcm = EVP_CIPHER_fetch(NULL, "AES-128-GCM", NULL);
    EVP_SKEY *aes = EVP_SKEY_import_raw_key(NULL, "AES", key32, 16, NULL);
    EVP_SKEY *generic = EVP_SKEY_import_raw_key(NULL, "GENERIC-SECRET", key32, 16, NULL);
    EVP_SKEY *big = EVP_SKEY_import_raw_key(NULL, "AES", key32, 32, NULL);
    unsigned char a[64], b[64];
    EVP_CIPHER_CTX *ctx;
    int n, m, r;

    n = encrypt_with("CBC with an AES key", cbc, aes, NULL, a);
    m = encrypt_with("CBC with raw octets", cbc, NULL, key32, b);
    check(n == m && n == 48 && memcmp(a, b, (size_t)n) == 0, "EVP_CipherInit_SKEY: AES-CBC");
    n = encrypt_with("CBC with a generic key", cbc, generic, NULL, a);
    check(n == m && memcmp(a, b, (size_t)n) == 0, "EVP_CipherInit_SKEY: a generic key");
    n = encrypt_with("GCM with an AES key", gcm, aes, NULL, a);
    m = encrypt_with("GCM with raw octets", gcm, NULL, key32, b);
    check(n == m && n == 40 && memcmp(a, b, (size_t)n) == 0, "EVP_CipherInit_SKEY: AES-GCM takes the raw key");
    errors("the ciphers");
    n = encrypt_with("CBC with a 32-octet key", cbc, big, NULL, a);
    errors("a key of the wrong size");
    n = encrypt_with("GCM with a 32-octet key", gcm, big, NULL, a);
    errors("a key of the wrong size for GCM");
    ctx = EVP_CIPHER_CTX_new();
    r = EVP_CipherInit_SKEY(ctx, cbc, aes, key32, 12, 1, NULL);
    printf("# CBC with a 12-octet IV: %d\n", r);
    EVP_CIPHER_CTX_free(ctx);
    errors("an IV of the wrong length");
    ctx = EVP_CIPHER_CTX_new();
    r = EVP_CipherInit_SKEY(ctx, (EVP_CIPHER *)EVP_aes_128_cbc(), aes, NULL, 0, 1, NULL);
    printf("# a cipher from no provider: %d\n", r);
    errors("a cipher from no provider");
    r = EVP_CipherInit_SKEY(ctx, NULL, aes, NULL, 0, 1, NULL);
    printf("# no cipher: %d\n", r);
    errors("no cipher");
    /* GCM: a key now, the IV in a second step without one. */
    r = EVP_CipherInit_SKEY(ctx, gcm, aes, NULL, 0, 1, NULL);
    printf("# GCM, the key: %d\n", r);
    r = EVP_CipherInit_SKEY(ctx, NULL, NULL, key32, 12, -1, NULL);
    printf("# GCM, then the IV alone: %d, encrypting %d\n", r, EVP_CIPHER_CTX_is_encrypting(ctx));
    errors("a two-step init");
    EVP_CIPHER_CTX_free(ctx);

    {
        EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
        EVP_MAC_CTX *mctx = EVP_MAC_CTX_new(mac);
        OSSL_PARAM params[2];

        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)"SHA256", 0);
        params[1] = OSSL_PARAM_construct_end();
        r = EVP_MAC_init_SKEY(mctx, generic, params);
        printf("# EVP_MAC_init_SKEY with HMAC: %d\n", r);
        errors("EVP_MAC_init_SKEY");
        EVP_MAC_CTX_free(mctx);
        EVP_MAC_free(mac);
    }
    EVP_SKEY_free(aes);
    EVP_SKEY_free(generic);
    EVP_SKEY_free(big);
    EVP_CIPHER_free(cbc);
    EVP_CIPHER_free(gcm);
}

/*
 * The test's own provider: one key manager under three entries, "TEST-SECRET", its own
 * "GENERIC-SECRET", and "ALIAS-SECRET" (also called "AES", so it shares the AES name's number
 * with the default provider's), and one that lacks a function.
 */
struct test_key {
    unsigned char key[64];
    size_t len;
    char id[32];
};

static void test_free(void *keydata)
{
    OPENSSL_free(keydata);
}

static void *test_import(void *provctx, int selection, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_SKEY_PARAM_RAW_BYTES);
    struct test_key *k;

    (void)provctx;
    if ((selection & OSSL_SKEYMGMT_SELECT_SECRET_KEY) == 0 || p == NULL || p->data_size > 64)
        return NULL;
    k = OPENSSL_zalloc(sizeof(*k));
    if (k == NULL)
        return NULL;
    memcpy(k->key, p->data, p->data_size);
    k->len = p->data_size;
    snprintf(k->id, sizeof(k->id), "test-%zu", k->len);
    return k;
}

static int test_export(void *keydata, int selection, OSSL_CALLBACK *cb, void *cbarg)
{
    struct test_key *k = keydata;
    OSSL_PARAM params[3];
    int n = 0;

    if ((selection & OSSL_SKEYMGMT_SELECT_SECRET_KEY) != 0)
        params[n++] = OSSL_PARAM_construct_octet_string(OSSL_SKEY_PARAM_RAW_BYTES, k->key, k->len);
    if ((selection & OSSL_SKEYMGMT_SELECT_PARAMETERS) != 0)
        params[n++] = OSSL_PARAM_construct_size_t(OSSL_SKEY_PARAM_KEY_LENGTH, &k->len);
    params[n] = OSSL_PARAM_construct_end();
    return cb(params, cbarg);
}

static void *test_generate(void *provctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_SKEY_PARAM_KEY_LENGTH);
    struct test_key *k;
    size_t len = 16;

    (void)provctx;
    if (p != NULL && (!OSSL_PARAM_get_size_t(p, &len) || len > 64))
        return NULL;
    k = OPENSSL_zalloc(sizeof(*k));
    if (k == NULL)
        return NULL;
    memset(k->key, 0x42, len);
    k->len = len;
    strcpy(k->id, "generated");
    return k;
}

static const char *test_key_id(void *keydata)
{
    return ((struct test_key *)keydata)->id;
}

static const OSSL_PARAM test_imp_params[] = {
    OSSL_PARAM_octet_string(OSSL_SKEY_PARAM_RAW_BYTES, NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM test_gen_params[] = {
    OSSL_PARAM_size_t(OSSL_SKEY_PARAM_KEY_LENGTH, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *test_imp_settable(void *provctx)
{
    (void)provctx;
    return test_imp_params;
}

static const OSSL_PARAM *test_gen_settable(void *provctx)
{
    (void)provctx;
    return test_gen_params;
}

static const OSSL_DISPATCH test_skeymgmt[] = {
    { OSSL_FUNC_SKEYMGMT_FREE, (void (*)(void))test_free },
    { OSSL_FUNC_SKEYMGMT_IMPORT, (void (*)(void))test_import },
    { OSSL_FUNC_SKEYMGMT_EXPORT, (void (*)(void))test_export },
    { OSSL_FUNC_SKEYMGMT_GENERATE, (void (*)(void))test_generate },
    { OSSL_FUNC_SKEYMGMT_GET_KEY_ID, (void (*)(void))test_key_id },
    { OSSL_FUNC_SKEYMGMT_IMP_SETTABLE_PARAMS, (void (*)(void))test_imp_settable },
    { OSSL_FUNC_SKEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))test_gen_settable },
    OSSL_DISPATCH_END
};
/* No export: a key manager needs free, import, and export. */
static const OSSL_DISPATCH broken_skeymgmt[] = {
    { OSSL_FUNC_SKEYMGMT_FREE, (void (*)(void))test_free },
    { OSSL_FUNC_SKEYMGMT_IMPORT, (void (*)(void))test_import },
    OSSL_DISPATCH_END
};
static const OSSL_ALGORITHM test_skeymgmts[] = {
    { "TEST-SECRET", "provider=skeytest", test_skeymgmt, "a test secret" },
    { "GENERIC-SECRET", "provider=skeytest", test_skeymgmt, NULL },
    { "ALIAS-SECRET:AES", "provider=skeytest", test_skeymgmt, "an alias of AES" },
    { "BROKEN-SECRET", "provider=skeytest", broken_skeymgmt, NULL },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *test_query(void *provctx, int operation_id, int *no_cache)
{
    (void)provctx;
    *no_cache = 0;
    return operation_id == OSSL_OP_SKEYMGMT ? test_skeymgmts : NULL;
}

static const OSSL_DISPATCH test_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))test_query },
    OSSL_DISPATCH_END
};

static int test_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
    void **provctx)
{
    (void)in;
    *out = test_dispatch;
    *provctx = (void *)handle;
    return 1;
}

static void own_provider(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *deflt, *test;
    EVP_SKEYMGMT *m;
    EVP_SKEY *k, *aes, *moved;
    OSSL_PARAM params[2];
    size_t len = 20;
    int r;

    check(OSSL_PROVIDER_add_builtin(ctx, "skeytest", test_init) == 1, "OSSL_PROVIDER_add_builtin");
    deflt = OSSL_PROVIDER_load(ctx, "default");
    test = OSSL_PROVIDER_load(ctx, "skeytest");
    check(deflt != NULL && test != NULL, "both providers load");
    m = EVP_SKEYMGMT_fetch(ctx, "TEST-SECRET", NULL);
    if (m != NULL) {
        show_mgmt(m, NULL);
        print_params("gen settable", EVP_SKEYMGMT_get0_gen_settable_params(m));
        print_params("imp settable", EVP_SKEYMGMT_get0_imp_settable_params(m));
        EVP_SKEYMGMT_free(m);
    }
    m = EVP_SKEYMGMT_fetch(ctx, "ALIAS-SECRET", "provider=skeytest");
    if (m != NULL) {
        show_mgmt(m, NULL);
        printf("# is_a AES %d\n", EVP_SKEYMGMT_is_a(m, "AES"));
        EVP_SKEYMGMT_free(m);
    }
    m = EVP_SKEYMGMT_fetch(ctx, "BROKEN-SECRET", NULL);
    printf("# fetch BROKEN-SECRET: %s\n", m == NULL ? "NULL" : "found");
    EVP_SKEYMGMT_free(m);
    errors("a key manager without export");
    printf("# all of them:\n");
    EVP_SKEYMGMT_do_all_provided(ctx, show_mgmt, NULL);

    params[0] = OSSL_PARAM_construct_size_t(OSSL_SKEY_PARAM_KEY_LENGTH, &len);
    params[1] = OSSL_PARAM_construct_end();
    k = EVP_SKEY_generate(ctx, "TEST-SECRET", NULL, params);
    show_key("generated", k);
    r = EVP_SKEY_export(k, OSSL_SKEYMGMT_SELECT_ALL, export_cb, "generated");
    printf("# export %d\n", r);
    r = EVP_SKEY_export(k, OSSL_SKEYMGMT_SELECT_PARAMETERS, export_cb, "generated");
    printf("# export of the parameters %d\n", r);
    EVP_SKEY_free(k);
    k = EVP_SKEY_generate(ctx, "TEST-SECRET", NULL, NULL);
    show_key("generated with no parameters", k);
    EVP_SKEY_free(k);
    len = 100;
    k = EVP_SKEY_generate(ctx, "TEST-SECRET", NULL, params);
    show_key("generated too long", k);
    k = EVP_SKEY_import_raw_key(ctx, "TEST-SECRET", key32, 10, NULL);
    show_key("imported", k);
    EVP_SKEY_free(k);
    errors("generating");

    /* The default provider's keys to this one, and back. */
    aes = EVP_SKEY_import_raw_key(ctx, "GENERIC-SECRET", key32, 16, "provider=default");
    show_key("the default provider's generic key", aes);
    moved = EVP_SKEY_to_provider(aes, ctx, test, NULL);
    show_key("moved to the test provider", moved);
    k = EVP_SKEY_to_provider(moved, ctx, deflt, NULL);
    show_key("moved back to the default provider", k);
    errors("moving back");
    EVP_SKEY_free(k);
    k = EVP_SKEY_to_provider(moved, ctx, NULL, "provider=default");
    show_key("moved to the default provider by query", k);
    EVP_SKEY_free(k);
    errors("moving by query");
    EVP_SKEY_free(aes);
    aes = EVP_SKEY_import_raw_key(ctx, "AES", key32, 16, "provider=default");
    show_key("the default provider's AES", aes);
    k = EVP_SKEY_to_provider(aes, ctx, test, NULL);
    show_key("AES moved to the test provider", k);
    EVP_SKEY_free(k);
    k = EVP_SKEY_to_provider(aes, ctx, NULL, "provider=skeytest");
    show_key("AES moved by query", k);
    EVP_SKEY_free(k);
    errors("moving AES");

    /* A key of another provider than the cipher's. */
    {
        EVP_CIPHER *cbc = EVP_CIPHER_fetch(ctx, "AES-128-CBC", NULL);
        EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();

        r = EVP_CipherInit_SKEY(cctx, cbc, moved, NULL, 0, 1, NULL);
        printf("# a cipher with another provider's key: %d\n", r);
        errors("another provider's key");
        r = EVP_CipherInit_SKEY(cctx, cbc, aes, NULL, 0, 1, NULL);
        printf("# the same cipher with its provider's key: %d\n", r);
        EVP_CIPHER_CTX_free(cctx);
        EVP_CIPHER_free(cbc);
    }
    EVP_SKEY_free(moved);
    EVP_SKEY_free(aes);
    OSSL_PROVIDER_unload(test);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(ctx);
    errors("the test provider");
}

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof(key32); i++)
        key32[i] = (unsigned char)(i * 11 + 5);
    key_managers();
    keys();
    ciphers();
    own_provider();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
