/*
 * Conformance test for external providers (provider(7), provider-base(7), OSSL_PROVIDER(3)), in
 * TAP format: loading a module from a search path, OSSL_PROVIDER_add_builtin with an init
 * function of the application's, and a module named by a configuration file; the modules that
 * fail (no init function, an init function that fails); and the core's dispatch table as the
 * provider sees it, each upcall made from the provider and its result reported back: the
 * core's parameters, errors with the provider's own reason strings, error marks, the core BIOs
 * and BIO_s_core over them, memory, entropy and nonces, object creation, the provider
 * functions, the self-test and indicator callbacks, thread-stop handlers, and child-provider
 * registration. The provider's digest is fetched and run, and listed among the provided ones.
 *
 * The modules are the C files of tests/c/modules, built by `cargo xtask test-c` into the directory
 * RUSTYSSL_TEST_MODULES names. Built once against the vendored headers, then run against the
 * reference OpenSSL and against rustyssl: it must pass on both with the same output
 * (TEST_PLAN.md, layer L4). A failed module lookup's error data holds the system loader's
 * message, so only the codes are printed for those.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/indicator.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/self_test.h>

#include "modules/test_prov.h"

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static int library_base;

/* The errors: each code relative to the providers' libraries, its strings and its data. */
static void errors(int codes_only)
{
    unsigned long code;
    const char *file, *func, *data;
    int line, flags, lib;

    printf("# errors:");
    while ((code = ERR_get_error_all(&file, &line, &func, &data, &flags)) != 0) {
        lib = ERR_GET_LIB(code);
        if (lib > library_base)
            printf(" [provider lib +%d]/%d", lib - library_base, ERR_GET_REASON(code));
        else
            printf(" %d/%d", lib, ERR_GET_REASON(code));
        if (codes_only)
            continue;
        printf(" \"%s\" \"%s\"", ERR_lib_error_string(code) != NULL ? ERR_lib_error_string(code) : "(null)",
               ERR_reason_error_string(code) != NULL ? ERR_reason_error_string(code) : "(null)");
        if (lib > library_base)
            printf(" at %s:%d %s", file, line, func);
        if ((flags & ERR_TXT_STRING) != 0 && data[0] != '\0')
            printf(" [%s]", data);
    }
    printf("\n");
}

static test_prov_run_fn *run_fn(OSSL_PROVIDER *prov)
{
    const OSSL_DISPATCH *d;

    for (d = OSSL_PROVIDER_get0_dispatch(prov); d != NULL && d->function_id != 0; d++)
        if (d->function_id == TEST_PROV_RUN)
            return (test_prov_run_fn *)d->function;
    return NULL;
}

static char report[2048];

static int run(OSSL_PROVIDER *prov, int which, const char *arg)
{
    test_prov_run_fn *f = run_fn(prov);
    int r;

    if (f == NULL)
        return 0;
    r = f(OSSL_PROVIDER_get0_provider_ctx(prov), which, report, sizeof(report), arg);
    printf("%s", report);
    return r;
}

static int self_test_cb(const OSSL_PARAM params[], void *arg)
{
    const OSSL_PARAM *p;

    printf("#   self-test callback (arg %s):", (const char *)arg);
    for (p = params; p->key != NULL; p++)
        if (p->data_type == OSSL_PARAM_UTF8_STRING)
            printf(" %s=%s", p->key, (const char *)p->data);
    printf("\n");
    return 1;
}

static int indicator_cb(const char *type, const char *desc, const OSSL_PARAM params[])
{
    (void)params;
    printf("#   indicator callback: %s %s\n", type, desc);
    return 1;
}

static void print_digest(EVP_MD *md, void *arg)
{
    (void)arg;
    if (strcmp(OSSL_PROVIDER_get0_name(EVP_MD_get0_provider(md)), "test_prov") == 0)
        printf(" %s (%s)", EVP_MD_get0_name(md), EVP_MD_get0_description(md));
}

static void digest(OSSL_LIB_CTX *ctx, const char *props)
{
    EVP_MD *md = EVP_MD_fetch(ctx, "TEST-SUM", props);
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outl = 0;
    EVP_MD_CTX *c;

    printf("# fetch TEST-SUM (%s): %s", props != NULL ? props : "no query", md != NULL ? "found" : "missing");
    if (md != NULL) {
        printf(" from %s, size %d, block %d, is_a OID %d", OSSL_PROVIDER_get0_name(EVP_MD_get0_provider(md)),
               EVP_MD_get_size(md), EVP_MD_get_block_size(md), EVP_MD_is_a(md, "1.3.6.1.4.1.99999.2.1"));
        if (EVP_Digest("abc", 3, out, &outl, md, NULL))
            printf(", sum of abc %02x%02x%02x%02x (%u octets)", out[0], out[1], out[2], out[3], outl);
        c = EVP_MD_CTX_new();
        if (EVP_DigestInit_ex(c, md, NULL) && EVP_DigestUpdate(c, "xyz", 3)
            && EVP_DigestUpdate(c, "!", 1) && EVP_DigestFinal_ex(c, out, &outl))
            printf(", of xyz! %02x%02x%02x%02x", out[0], out[1], out[2], out[3]);
        EVP_MD_CTX_free(c);
    }
    printf("\n");
    EVP_MD_free(md);
    errors(0);
}

static void scenarios(OSSL_LIB_CTX *ctx, OSSL_PROVIDER *prov, const char *tmp)
{
    int stops = -1;
    OSSL_PARAM params[2];

    check(run(prov, TEST_PROV_RUN_CORE, NULL), "the core's dispatch table and parameters");
    check(run(prov, TEST_PROV_RUN_ERRORS, NULL), "errors from the provider");
    errors(0);
    check(run(prov, TEST_PROV_RUN_MARKS, NULL), "error marks");
    errors(0);
    check(run(prov, TEST_PROV_RUN_BIO, tmp), "the core's BIOs");
    errors(0);
    check(run(prov, TEST_PROV_RUN_MEMORY, NULL), "memory");
    check(run(prov, TEST_PROV_RUN_SEEDS, NULL), "entropy and nonces");
    errors(0);
    check(run(prov, TEST_PROV_RUN_OBJECTS, NULL), "objects");
    printf("# testSig: nid known %d, ln \"%s\", sigid %d\n", OBJ_sn2nid("testSig") != NID_undef,
           OBJ_nid2ln(OBJ_sn2nid("testSig")), OBJ_find_sigid_algs(OBJ_sn2nid("testSig"), NULL, NULL));
    errors(0);
    check(run(prov, TEST_PROV_RUN_PROVIDER, NULL), "the provider functions");
    check(run(prov, TEST_PROV_RUN_CALLBACKS, NULL), "callbacks unset");
    OSSL_SELF_TEST_set_callback(ctx, self_test_cb, "the arg");
    OSSL_INDICATOR_set_callback(ctx, indicator_cb);
    check(run(prov, TEST_PROV_RUN_CALLBACKS, NULL), "callbacks set");
    OSSL_SELF_TEST_set_callback(ctx, NULL, NULL);
    OSSL_INDICATOR_set_callback(ctx, NULL);
    check(run(prov, TEST_PROV_RUN_THREADS, NULL), "a thread-stop handler");
    OPENSSL_thread_stop();
    params[0] = OSSL_PARAM_construct_int(TEST_PROV_PARAM_THREAD_STOPS, &stops);
    params[1] = OSSL_PARAM_construct_end();
    check(OSSL_PROVIDER_get_params(prov, params) == 1 && stops == 1, "it ran at OPENSSL_thread_stop");
    OPENSSL_thread_stop();
    check(OSSL_PROVIDER_get_params(prov, params) == 1 && stops == 1, "once");
    check(run(prov, TEST_PROV_RUN_CHILDREN, NULL), "child-provider callbacks");
    errors(0);
    check(run(prov, TEST_PROV_RUN_CHILD_CTX, NULL), "a child context without the default");
    errors(0);
}

static void from_module(const char *dir, const char *tmp)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *prov, *again, *deflt;

    check(OSSL_PROVIDER_set_default_search_path(ctx, dir) == 1, "search the modules' directory");
    prov = OSSL_PROVIDER_load(ctx, "test_prov");
    check(prov != NULL, "load test_prov");
    errors(0);
    if (prov == NULL) {
        OSSL_LIB_CTX_free(ctx);
        return;
    }
    again = OSSL_PROVIDER_load(ctx, "test_prov");
    check(again == prov && OSSL_PROVIDER_available(ctx, "test_prov"), "loading again finds it");
    OSSL_PROVIDER_unload(again);
    check(OSSL_PROVIDER_available(ctx, "default") == 0, "the fallback is off");
    scenarios(ctx, prov, tmp);
    digest(ctx, NULL);
    digest(ctx, "provider=test_prov");
    digest(ctx, "provider=default");
    deflt = OSSL_PROVIDER_load(ctx, "default");
    printf("# provided digests:");
    EVP_MD_do_all_provided(ctx, print_digest, NULL);
    printf("\n");
    check(EVP_set_default_properties(ctx, "?provider=default") == 1, "default properties in the parent");
    check(run(prov, TEST_PROV_RUN_CHILD_CTX, NULL), "a child context with the default");
    errors(0);
    EVP_set_default_properties(ctx, NULL);
    digest(ctx, "?provider=default");
    check(OSSL_PROVIDER_unload(prov) == 1 && OSSL_PROVIDER_available(ctx, "test_prov") == 0, "unload it");
    digest(ctx, NULL);
    prov = OSSL_PROVIDER_load(ctx, "test_prov");
    check(prov != NULL, "load it again after unloading");
    digest(ctx, NULL);
    OSSL_PROVIDER_unload(prov);
    OSSL_PROVIDER_unload(deflt);
    errors(0);
    OSSL_LIB_CTX_free(ctx);
}

static void failing_modules(const char *dir)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *p;

    OSSL_PROVIDER_set_default_search_path(ctx, dir);
    p = OSSL_PROVIDER_load(ctx, "noinit_prov");
    check(p == NULL, "a module without OSSL_provider_init fails");
    errors(1);
    p = OSSL_PROVIDER_load(ctx, "failinit_prov");
    check(p == NULL, "a module whose init function fails");
    errors(0);
    check(OSSL_PROVIDER_available(ctx, "noinit_prov") == 0 && OSSL_PROVIDER_available(ctx, "failinit_prov") == 0,
          "neither is there");
    errors(0);
    OSSL_LIB_CTX_free(ctx);
}

/* An application's own provider, for OSSL_PROVIDER_add_builtin: its init function takes the
 * core's get_params and reports what it says; it offers no algorithms. */
static OSSL_FUNC_core_get_params_fn *builtin_get_params;
static int builtin_inits;

static void builtin_teardown(void *provctx)
{
    printf("# builtin teardown (context %s)\n", provctx == (void *)&builtin_inits ? "ours" : "another");
}

static const OSSL_DISPATCH builtin_functions[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))builtin_teardown },
    OSSL_DISPATCH_END
};

static int builtin_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                        const OSSL_DISPATCH **out, void **provctx)
{
    char *name = NULL, *file = NULL;
    OSSL_PARAM params[3];

    for (; in->function_id != 0; in++)
        if (in->function_id == OSSL_FUNC_CORE_GET_PARAMS)
            builtin_get_params = OSSL_FUNC_core_get_params(in);
    params[0] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_CORE_PROV_NAME, &name, 0);
    params[1] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_CORE_MODULE_FILENAME, &file, 0);
    params[2] = OSSL_PARAM_construct_end();
    printf("# builtin init %d: get_params %d, name %s, module %s\n", ++builtin_inits,
           builtin_get_params(handle, params), name != NULL ? name : "(none)", file != NULL ? file : "(none)");
    *out = builtin_functions;
    *provctx = &builtin_inits;
    return 1;
}

static void builtin(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *p;

    check(OSSL_PROVIDER_add_builtin(ctx, "app_prov", builtin_init) == 1, "add a built-in");
    p = OSSL_PROVIDER_load(ctx, "app_prov");
    check(p != NULL && builtin_inits == 1, "load it: its init function runs");
    check(OSSL_PROVIDER_get0_provider_ctx(p) == (void *)&builtin_inits, "its context");
    OSSL_PROVIDER_unload(p);
    errors(0);
    OSSL_LIB_CTX_free(ctx);
}

static void from_config(const char *dir, const char *cnf, const char *tmp)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *p;
    FILE *f = fopen(cnf, "w");

    if (f == NULL) {
        check(0, "write the configuration");
        return;
    }
    fprintf(f, "openssl_conf = init\n[init]\nproviders = provs\n[provs]\nconfigured = test_sect\n"
               "default = default_sect\n[test_sect]\nmodule = %s/test_prov%s\nactivate = 1\nextra = from the file\n"
               "[default_sect]\nactivate = 1\n",
            dir,
#ifdef __APPLE__
            ".dylib"
#else
            ".so"
#endif
    );
    fclose(f);
    check(OSSL_LIB_CTX_load_config(ctx, cnf) == 1, "load a configuration naming the module");
    errors(0);
    check(OSSL_PROVIDER_available(ctx, "configured") == 1, "it's active under the configuration's name");
    p = OSSL_PROVIDER_load(ctx, "configured");
    if (p != NULL) {
        run(p, TEST_PROV_RUN_CORE, NULL);
        (void)tmp;
        OSSL_PROVIDER_unload(p);
    }
    digest(ctx, NULL);
    errors(0);
    OSSL_LIB_CTX_free(ctx);
}

int main(void)
{
    const char *dir = getenv("RUSTYSSL_TEST_MODULES");
    char tmp[512], cnf[512];

    if (dir == NULL) {
        printf("Bail out! RUSTYSSL_TEST_MODULES isn't set\n");
        return 1;
    }
    snprintf(tmp, sizeof(tmp), "%s/provider_ext.%ld.txt", dir, (long)getpid());
    snprintf(cnf, sizeof(cnf), "%s/provider_ext.%ld.cnf", dir, (long)getpid());
    library_base = ERR_get_next_error_library();
    failing_modules(dir);
    from_module(dir, tmp);
    builtin();
    from_config(dir, cnf, tmp);
    remove(tmp);
    remove(cnf);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
