/*
 * Conformance test for providers (OSSL_PROVIDER(3), provider(7)), in TAP format: the fallback
 * that activates the default provider, loading and unloading the built-in providers (default,
 * base, null) and what each reports (name, version, status, gettable parameters, self-test,
 * context, dispatch table), references and activations across repeated loads, the store's
 * order as OSSL_PROVIDER_do_all sees it (fallbacks kept or not), callbacks that stop or unload,
 * module lookups that fail, the search path, the error-library numbers providers take, and
 * configuration parameters (given to OSSL_PROVIDER_load_ex, added, read, and read as Booleans).
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 *
 * Left out: the legacy provider (a module in OpenSSL's default build; rustyssl loads modules
 * later), the default provider's capabilities (step 3.1d-b), and the build information, which
 * names rustyssl (docs/DEVIATIONS.md). A failed module lookup's error data holds the system
 * loader's message, which on macOS lists DYLD_LIBRARY_PATH, so only the codes are printed.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
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

/* Prints the error codes, and the data of those from the CRYPTO library. */
static void errors(void)
{
    unsigned long code;
    const char *data;
    int flags;

    printf(" errors:");
    while ((code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        if (ERR_GET_LIB(code) == ERR_LIB_CRYPTO && (flags & ERR_TXT_STRING) != 0 && data[0] != '\0')
            printf("[%s]", data);
    }
    printf("\n");
}

static int print_name(OSSL_PROVIDER *prov, void *arg)
{
    (void)arg;
    printf(" %s", OSSL_PROVIDER_get0_name(prov));
    return 1;
}

static void list(const char *what, OSSL_LIB_CTX *ctx)
{
    int r;

    printf("# %s:", what);
    r = OSSL_PROVIDER_do_all(ctx, print_name, NULL);
    printf(" (%d)\n", r);
}

static int library_base;

/* The error-library numbers taken since the test started. */
static int libraries_taken(void)
{
    return ERR_get_next_error_library() - library_base - 1;
}

static void describe(OSSL_PROVIDER *prov)
{
    const char *name = NULL, *version = NULL, *buildinfo = NULL;
    int status = -1, r;
    OSSL_PARAM params[5];
    const OSSL_PARAM *g;
    const OSSL_DISPATCH *d;

    params[0] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_NAME, (char **)&name, 0);
    params[1] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_VERSION, (char **)&version, 0);
    params[2] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, (char **)&buildinfo, 0);
    params[3] = OSSL_PARAM_construct_int(OSSL_PROV_PARAM_STATUS, &status);
    params[4] = OSSL_PARAM_construct_end();
    r = OSSL_PROVIDER_get_params(prov, params);
    printf("# %s: get_params %d name \"%s\" version \"%s\" status %d, build info %s; self-test %d\n",
           OSSL_PROVIDER_get0_name(prov), r, name, version, status,
           buildinfo != NULL && strncmp(buildinfo, version, strlen(version)) == 0 ? "starts with the version"
                                                                                  : "differs",
           OSSL_PROVIDER_self_test(prov));
    printf("#   gettable:");
    for (g = OSSL_PROVIDER_gettable_params(prov); g != NULL && g->key != NULL; g++)
        printf(" %s/%u", g->key, g->data_type);
    printf("\n");
    if (strcmp(OSSL_PROVIDER_get0_name(prov), "default") != 0) {
        printf("#   dispatch:");
        for (d = OSSL_PROVIDER_get0_dispatch(prov); d != NULL && d->function_id != 0; d++)
            printf(" %d", d->function_id);
        printf("\n");
    }
}

static void fallback(void)
{
    OSSL_PROVIDER *d, *d2;

    check(OSSL_PROVIDER_available(NULL, "nosuch") == 0, "an unknown provider isn't available");
    printf("# error libraries taken: %d\n", libraries_taken());
    check(OSSL_PROVIDER_available(NULL, "default") == 1, "the default provider is the fallback");
    list("default context", NULL);
    d = OSSL_PROVIDER_load(NULL, "default");
    d2 = OSSL_PROVIDER_load(NULL, "default");
    check(d != NULL && d == d2, "loading finds the fallback provider");
    describe(d);
    check(OSSL_PROVIDER_get0_provider_ctx(d) != NULL && OSSL_PROVIDER_get0_dispatch(d) != NULL,
          "it has a context and a dispatch table");
    check(OSSL_PROVIDER_unload(d) == 1 && OSSL_PROVIDER_unload(d2) == 1 && OSSL_PROVIDER_available(NULL, "default"),
          "unloading the extra loads leaves the fallback active");
    printf("# error libraries taken: %d\n", libraries_taken());
    errors();
}

static void builtins(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *base, *null, *again;

    base = OSSL_PROVIDER_load(ctx, "base");
    null = OSSL_PROVIDER_load(ctx, "null");
    check(base != NULL && null != NULL, "base and null load");
    describe(base);
    describe(null);
    check(OSSL_PROVIDER_get0_provider_ctx(null) == (void *)null, "null's context is its handle");
    check(OSSL_PROVIDER_available(ctx, "default") == 0, "loading stopped the fallback");
    list("base and null", ctx);
    check(OSSL_PROVIDER_unload(null) == 1 && OSSL_PROVIDER_available(ctx, "null") == 0, "unloading deactivates");
    list("after unloading null", ctx);
    again = OSSL_PROVIDER_load(ctx, "null");
    check(again == null && OSSL_PROVIDER_available(ctx, "null") == 1, "reloading reactivates the same provider");
    list("null again", ctx);
    check(OSSL_PROVIDER_unload(again) == 1 && OSSL_PROVIDER_unload(base) == 1, "unload both");
    check(OSSL_PROVIDER_unload(NULL) == 0, "unloading NULL fails");
    printf("# error libraries taken: %d\n", libraries_taken());
    errors();
    OSSL_LIB_CTX_free(ctx);
}

static void order(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *n, *b, *d;

    n = OSSL_PROVIDER_try_load_ex(ctx, "null", NULL, 1);
    check(n != NULL && OSSL_PROVIDER_available(ctx, "default") == 1, "try_load can keep the fallback");
    list("null, then the fallback", ctx);
    b = OSSL_PROVIDER_try_load(ctx, "base", 1);
    list("then base", ctx);
    d = OSSL_PROVIDER_try_load(ctx, "default", 0);
    check(OSSL_PROVIDER_available(ctx, "default") == 1, "default is there");
    list("then default", ctx);
    OSSL_PROVIDER_unload(n);
    OSSL_PROVIDER_unload(b);
    OSSL_PROVIDER_unload(d);
    list("after unloading", ctx);
    errors();
    OSSL_LIB_CTX_free(ctx);
}

static int calls;

static int stop_at_second(OSSL_PROVIDER *prov, void *arg)
{
    (void)arg;
    printf(" %s", OSSL_PROVIDER_get0_name(prov));
    return ++calls < 2;
}

static int unload_each(OSSL_PROVIDER *prov, void *arg)
{
    (void)arg;
    printf(" %s:%d", OSSL_PROVIDER_get0_name(prov), OSSL_PROVIDER_unload(prov));
    return 1;
}

static void callbacks(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    int r;

    OSSL_PROVIDER_load(ctx, "null");
    OSSL_PROVIDER_load(ctx, "base");
    OSSL_PROVIDER_load(ctx, "default");
    calls = 0;
    printf("# stop at the second:");
    r = OSSL_PROVIDER_do_all(ctx, stop_at_second, NULL);
    printf(" (%d)\n", r);
    printf("# unload each:");
    r = OSSL_PROVIDER_do_all(ctx, unload_each, NULL);
    printf(" (%d)\n", r);
    list("after", ctx);
    check(OSSL_PROVIDER_available(ctx, "base") == 0 && OSSL_PROVIDER_available(ctx, "null") == 0,
          "a callback can unload the providers");
    errors();
    OSSL_LIB_CTX_free(ctx);
}

static void modules(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *p;
    OSSL_PARAM params[2];
    char value[] = "v";

    check(OSSL_PROVIDER_get0_default_search_path(ctx) == NULL, "no search path at first");
    check(OSSL_PROVIDER_set_default_search_path(ctx, "/nonexistent/modules/") == 1
              && strcmp(OSSL_PROVIDER_get0_default_search_path(ctx), "/nonexistent/modules/") == 0,
          "set a search path");
    p = OSSL_PROVIDER_load(ctx, "nosuch");
    printf("# load nosuch: %s", p == NULL ? "NULL" : "loaded");
    errors();
    p = OSSL_PROVIDER_try_load(ctx, "/nonexistent/absolute.so", 1);
    printf("# try_load an absolute path: %s", p == NULL ? "NULL" : "loaded");
    errors();
    params[0] = OSSL_PARAM_construct_utf8_string("key", value, 0);
    params[1] = OSSL_PARAM_construct_end();
    p = OSSL_PROVIDER_load_ex(ctx, "sub/dir", params);
    printf("# load_ex sub/dir: %s", p == NULL ? "NULL" : "loaded");
    errors();
    check(OSSL_PROVIDER_available(ctx, "nosuch") == 0 && OSSL_PROVIDER_available(ctx, "default") == 0,
          "failed loads add nothing, and stop the fallback");
    list("after failed loads", ctx);
    check(OSSL_PROVIDER_set_default_search_path(ctx, NULL) == 1 && OSSL_PROVIDER_get0_default_search_path(ctx) == NULL,
          "clear the search path");
    p = OSSL_PROVIDER_load_ex(ctx, "base", params);
    check(p != NULL && strcmp(OSSL_PROVIDER_get0_name(p), "base") == 0, "load_ex with parameters");
    OSSL_PROVIDER_unload(p);
    printf("# error libraries taken: %d\n", libraries_taken());
    errors();
    OSSL_LIB_CTX_free(ctx);
}

static void show_conf(OSSL_PROVIDER *prov, const char *key)
{
    const char *v = NULL;
    OSSL_PARAM params[2];
    int r;

    params[0] = OSSL_PARAM_construct_utf8_ptr(key, (char **)&v, 0);
    params[1] = OSSL_PARAM_construct_end();
    r = OSSL_PROVIDER_get_conf_parameters(prov, params);
    printf("#   %s: %d %s modified %d\n", key, r, v == NULL ? "(none)" : v, OSSL_PARAM_modified(params));
}

static void conf(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *p, *again;
    OSSL_PARAM params[5], wrong[2];
    char one[] = "one", yes[] = "Yes", two[] = "2";
    int i = 7, r;
    static const char *const words[] = { "1", "0", "yes", "NO", "True", "false", "ON", "off", "2", "", "yess" };
    size_t k;

    params[0] = OSSL_PARAM_construct_utf8_string("a", one, 0);
    params[1] = OSSL_PARAM_construct_int("skipped", &i);
    params[2] = OSSL_PARAM_construct_utf8_string("flag", yes, 0);
    params[3] = OSSL_PARAM_construct_utf8_string("a", two, 0);
    params[4] = OSSL_PARAM_construct_end();
    p = OSSL_PROVIDER_load_ex(ctx, "null", params);
    printf("# configuration of null:\n");
    show_conf(p, "a");
    show_conf(p, "flag");
    show_conf(p, "skipped");
    show_conf(p, "missing");
    check(OSSL_PROVIDER_conf_get_bool(p, "flag", 0) == 1 && OSSL_PROVIDER_conf_get_bool(p, "missing", 5) == 5
              && OSSL_PROVIDER_conf_get_bool(p, "a", 9) == 9,
          "conf_get_bool reads Booleans, else the default");
    for (k = 0; k < sizeof(words) / sizeof(words[0]); k++) {
        char key[16];

        snprintf(key, sizeof(key), "w%zu", k);
        r = OSSL_PROVIDER_add_conf_parameter(p, key, words[k]);
        printf("#   add %s=\"%s\": %d bool %d\n", key, words[k], r, OSSL_PROVIDER_conf_get_bool(p, key, -1));
    }
    check(OSSL_PROVIDER_add_conf_parameter(p, NULL, "x") == 0 && OSSL_PROVIDER_add_conf_parameter(p, "x", NULL) == 0,
          "a NULL name or value is refused");
    OSSL_PROVIDER_add_conf_parameter(p, "a", "three");
    show_conf(p, "a");
    wrong[0] = OSSL_PARAM_construct_int("a", &i);
    wrong[1] = OSSL_PARAM_construct_end();
    r = OSSL_PROVIDER_get_conf_parameters(p, wrong);
    printf("# into an integer: %d", r);
    errors();
    again = OSSL_PROVIDER_load_ex(ctx, "null", params);
    check(again == p, "loading it again with parameters finds it");
    show_conf(again, "w0");
    OSSL_PROVIDER_unload(again);
    OSSL_PROVIDER_unload(p);
    errors();
    OSSL_LIB_CTX_free(ctx);
}

static int show_each(OSSL_PROVIDER *prov, void *arg)
{
    (void)arg;
    printf("# %s:\n", OSSL_PROVIDER_get0_name(prov));
    show_conf(prov, "plain");
    show_conf(prov, "nested.inner");
    return 1;
}

/* A provider the configuration names without activating it: the fallback takes its parameters. */
static void conf_fallback(void)
{
    static const char text[] = "openssl_conf = init\n"
                               "[init]\nproviders = provs\n"
                               "[provs]\ndefault = default_sect\n"
                               "[default_sect]\nplain = 1\nnested = nested_sect\n"
                               "[nested_sect]\ninner = no\n";
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    CONF *cnf = NCONF_new_ex(ctx, NULL);
    BIO *b = BIO_new_mem_buf(text, -1);
    EVP_MD *md;

    check(NCONF_load_bio(cnf, b, NULL) == 1 && CONF_modules_load(cnf, NULL, 0) == 1,
          "a configuration naming default without activating it");
    check(OSSL_PROVIDER_available(ctx, "default") == 1, "default is still available");
    md = EVP_MD_fetch(ctx, "SHA256", NULL);
    check(md != NULL, "a fetch activates the fallback");
    OSSL_PROVIDER_do_all(ctx, show_each, NULL);
    errors();
    EVP_MD_free(md);
    NCONF_free(cnf);
    BIO_free(b);
    OSSL_LIB_CTX_free(ctx);
}

int main(void)
{
    library_base = ERR_get_next_error_library();
    fallback();
    builtins();
    order();
    callbacks();
    modules();
    conf();
    conf_fallback();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
