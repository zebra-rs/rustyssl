/*
 * Conformance test for what OpenSSL's command-line tools need at start-up, in TAP format:
 *   - OPENSSL_init_ssl with OPENSSL_INIT_ENGINE_ALL_BUILTIN and OPENSSL_INIT_LOAD_CONFIG (as
 *     the tools call it), ENGINE_free and ENGINE_finish of NULL, and the engines for a digest
 *     and a cipher (none);
 *   - the UI methods (UI_create_method(3)): UI_null, UI_OpenSSL, UI_create_method, the setters
 *     and getters (and their NULL method), the method's ex_data, and UI_destroy_method;
 *   - the store loaders an application registers (OSSL_STORE_LOADER_new(3)):
 *     OSSL_STORE_LOADER_new, its setters and getters, OSSL_STORE_register_loader (bad schemes,
 *     missing functions, replacing), OSSL_STORE_unregister_loader, and OSSL_STORE_LOADER_free.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/ssl.h>
#include <openssl/store.h>
#include <openssl/ui.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* Prints and clears the error queue: library, reason, and data of each entry. */
static void errors(const char *what)
{
    unsigned long e;
    const char *data;
    int flags;

    printf("# errors %s:", what);
    while ((e = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
        if ((flags & ERR_TXT_STRING) != 0 && data != NULL && *data != '\0')
            printf(" [%s]", data);
    }
    printf("\n");
}

static int my_open(UI *ui)
{
    (void)ui;
    return 1;
}

static int my_string(UI *ui, UI_STRING *uis)
{
    (void)ui;
    (void)uis;
    return 1;
}

static void *my_dup(UI *ui, void *data)
{
    (void)ui;
    return data;
}

static void my_destroy(UI *ui, void *data)
{
    (void)ui;
    (void)data;
}

static char *my_prompt(UI *ui, const char *desc, const char *name)
{
    (void)ui;
    (void)desc;
    (void)name;
    return NULL;
}

static void test_init(void)
{
    check(OPENSSL_init_ssl(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, NULL)
            == 1,
        "OPENSSL_init_ssl as the tools call it");
    check(OPENSSL_init_ssl(0, NULL) == 1, "OPENSSL_init_ssl again");
    check(OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG | OPENSSL_INIT_LOAD_SSL_STRINGS, NULL) == 1,
        "OPENSSL_init_ssl without the configuration");
    check(ENGINE_free(NULL) == 1 && ENGINE_finish(NULL) == 1, "ENGINE_free and ENGINE_finish of NULL");
    check(ENGINE_get_digest_engine(NID_sha256) == NULL
            && ENGINE_get_cipher_engine(NID_aes_128_cbc) == NULL,
        "no engine implements SHA-256 or AES-128-CBC (as `openssl list` asks)");
    errors("init");
}

static void test_ui(void)
{
    const UI_METHOD *null_ui = UI_null();
    UI_METHOD *console = UI_OpenSSL();
    UI_METHOD *m;
    int idx;

    check(null_ui != NULL && console != NULL && (const UI_METHOD *)console != null_ui,
        "UI_null and UI_OpenSSL");
    check(UI_null() == null_ui && UI_OpenSSL() == console, "the same methods each time");
    printf("# UI_null: opener %d writer %d flusher %d reader %d closer %d prompt %d dup %d destroy %d\n",
        UI_method_get_opener(null_ui) != NULL, UI_method_get_writer(null_ui) != NULL,
        UI_method_get_flusher(null_ui) != NULL, UI_method_get_reader(null_ui) != NULL,
        UI_method_get_closer(null_ui) != NULL, UI_method_get_prompt_constructor(null_ui) != NULL,
        UI_method_get_data_duplicator(null_ui) != NULL,
        UI_method_get_data_destructor(null_ui) != NULL);
    printf("# UI_OpenSSL: opener %d writer %d flusher %d reader %d closer %d prompt %d\n",
        UI_method_get_opener(console) != NULL, UI_method_get_writer(console) != NULL,
        UI_method_get_flusher(console) != NULL, UI_method_get_reader(console) != NULL,
        UI_method_get_closer(console) != NULL, UI_method_get_prompt_constructor(console) != NULL);

    m = UI_create_method("test UI");
    check(m != NULL, "UI_create_method");
    check(UI_method_get_opener(m) == NULL && UI_method_get_reader(m) == NULL, "a new method has no functions");
    check(UI_method_set_opener(m, my_open) == 0 && UI_method_set_writer(m, my_string) == 0
            && UI_method_set_flusher(m, my_open) == 0 && UI_method_set_reader(m, my_string) == 0
            && UI_method_set_closer(m, my_open) == 0
            && UI_method_set_data_duplicator(m, my_dup, my_destroy) == 0
            && UI_method_set_prompt_constructor(m, my_prompt) == 0,
        "the setters return 0");
    check(UI_method_get_opener(m) == my_open && UI_method_get_writer(m) == my_string
            && UI_method_get_flusher(m) == my_open && UI_method_get_reader(m) == my_string
            && UI_method_get_closer(m) == my_open && UI_method_get_data_duplicator(m) == my_dup
            && UI_method_get_data_destructor(m) == my_destroy
            && UI_method_get_prompt_constructor(m) == my_prompt,
        "the getters return what was set");
    check(UI_method_set_opener(NULL, my_open) == -1 && UI_method_set_reader(NULL, my_string) == -1
            && UI_method_set_data_duplicator(NULL, my_dup, my_destroy) == -1
            && UI_method_set_prompt_constructor(NULL, my_prompt) == -1,
        "the setters return -1 for NULL");
    check(UI_method_get_opener(NULL) == NULL && UI_method_get_prompt_constructor(NULL) == NULL,
        "the getters return NULL for NULL");
    idx = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_UI_METHOD, 0, NULL, NULL, NULL, NULL);
    check(idx >= 0, "an ex_data index for UI methods");
    check(UI_method_get_ex_data(m, idx) == NULL, "no ex_data yet");
    check(UI_method_set_ex_data(m, idx, (void *)"data") == 1
            && strcmp(UI_method_get_ex_data(m, idx), "data") == 0,
        "UI_method_set_ex_data and UI_method_get_ex_data");
    UI_destroy_method(m);
    UI_destroy_method(NULL);
    errors("UI");
}

static OSSL_STORE_LOADER_CTX *l_open(const OSSL_STORE_LOADER *l, const char *uri,
    const UI_METHOD *ui, void *data)
{
    (void)l, (void)uri, (void)ui, (void)data;
    return NULL;
}

static OSSL_STORE_LOADER_CTX *l_open_ex(const OSSL_STORE_LOADER *l, const char *uri,
    OSSL_LIB_CTX *libctx, const char *propq, const UI_METHOD *ui, void *data)
{
    (void)l, (void)uri, (void)libctx, (void)propq, (void)ui, (void)data;
    return NULL;
}

static OSSL_STORE_LOADER_CTX *l_attach(const OSSL_STORE_LOADER *l, BIO *bio,
    OSSL_LIB_CTX *libctx, const char *propq, const UI_METHOD *ui, void *data)
{
    (void)l, (void)bio, (void)libctx, (void)propq, (void)ui, (void)data;
    return NULL;
}

static int l_ctrl(OSSL_STORE_LOADER_CTX *ctx, int cmd, va_list args)
{
    (void)ctx, (void)cmd, (void)args;
    return 1;
}

static int l_expect(OSSL_STORE_LOADER_CTX *ctx, int expected)
{
    (void)ctx, (void)expected;
    return 1;
}

static int l_find(OSSL_STORE_LOADER_CTX *ctx, const OSSL_STORE_SEARCH *criteria)
{
    (void)ctx, (void)criteria;
    return 1;
}

static OSSL_STORE_INFO *l_load(OSSL_STORE_LOADER_CTX *ctx, const UI_METHOD *ui, void *data)
{
    (void)ctx, (void)ui, (void)data;
    return NULL;
}

static int l_int(OSSL_STORE_LOADER_CTX *ctx)
{
    (void)ctx;
    return 1;
}

/* A loader with the functions OSSL_STORE_register_loader requires. */
static void complete(OSSL_STORE_LOADER *l)
{
    OSSL_STORE_LOADER_set_open(l, l_open);
    OSSL_STORE_LOADER_set_load(l, l_load);
    OSSL_STORE_LOADER_set_eof(l, l_int);
    OSSL_STORE_LOADER_set_error(l, l_int);
    OSSL_STORE_LOADER_set_close(l, l_int);
}

static void test_store(void)
{
    OSSL_STORE_LOADER *l, *l2, *got;

    check(OSSL_STORE_LOADER_new(NULL, NULL) == NULL, "OSSL_STORE_LOADER_new without a scheme");
    errors("no scheme");
    l = OSSL_STORE_LOADER_new(NULL, "rustyssl-test");
    check(l != NULL, "OSSL_STORE_LOADER_new");
    check(strcmp(OSSL_STORE_LOADER_get0_scheme(l), "rustyssl-test") == 0
            && OSSL_STORE_LOADER_get0_engine(l) == NULL,
        "the scheme and engine");
    check(OSSL_STORE_register_loader(l) == 0, "an incomplete loader isn't registered");
    errors("incomplete");
    check(OSSL_STORE_LOADER_set_open(l, l_open) == 1
            && OSSL_STORE_LOADER_set_open_ex(l, l_open_ex) == 1
            && OSSL_STORE_LOADER_set_attach(l, l_attach) == 1
            && OSSL_STORE_LOADER_set_ctrl(l, l_ctrl) == 1
            && OSSL_STORE_LOADER_set_expect(l, l_expect) == 1
            && OSSL_STORE_LOADER_set_find(l, l_find) == 1
            && OSSL_STORE_LOADER_set_load(l, l_load) == 1
            && OSSL_STORE_LOADER_set_eof(l, l_int) == 1
            && OSSL_STORE_LOADER_set_error(l, l_int) == 1,
        "the setters");
    check(OSSL_STORE_register_loader(l) == 0, "without close, still incomplete");
    errors("no close");
    check(OSSL_STORE_LOADER_set_close(l, l_int) == 1, "set close");
    check(OSSL_STORE_register_loader(l) == 1, "registered");
    l2 = OSSL_STORE_LOADER_new(NULL, "rustyssl-test");
    complete(l2);
    check(OSSL_STORE_register_loader(l2) == 1, "another loader for the same scheme");
    got = OSSL_STORE_unregister_loader("rustyssl-test");
    check(got == l2, "the later one is unregistered");
    check(OSSL_STORE_unregister_loader("rustyssl-test") == NULL, "and then none");
    errors("unregistered");
    OSSL_STORE_LOADER_free(l);
    OSSL_STORE_LOADER_free(l2);
    OSSL_STORE_LOADER_free(NULL);

    {
        static const char *bad[] = { "1abc", "a b", "", "a_b", "-x" }; /* "" passes */
        static const char *good[] = { "x", "a+b-c.d", "Z9" };
        size_t i;

        for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            l = OSSL_STORE_LOADER_new(NULL, bad[i]);
            complete(l);
            printf("# register \"%s\": %d\n", bad[i], OSSL_STORE_register_loader(l));
            errors("bad scheme");
            /* The empty scheme passes OpenSSL's check: unregister before freeing. */
            if (bad[i][0] == '\0')
                printf("# unregister \"\": %d\n", OSSL_STORE_unregister_loader("") == l);
            OSSL_STORE_LOADER_free(l);
        }
        for (i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
            l = OSSL_STORE_LOADER_new(NULL, good[i]);
            complete(l);
            {
                /* Separate statements: C leaves the order of arguments' evaluation open. */
                int reg = OSSL_STORE_register_loader(l);
                int unreg = OSSL_STORE_unregister_loader(good[i]) == l;

                printf("# register \"%s\": %d, unregister %d\n", good[i], reg, unreg);
            }
            errors("good scheme");
            OSSL_STORE_LOADER_free(l);
        }
    }
    check(1, "schemes");
}

int main(void)
{
    test_init();
    test_ui();
    test_store();
    printf("1..%d\n", number);
    return failures != 0;
}
