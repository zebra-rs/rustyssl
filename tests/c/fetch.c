/*
 * Conformance test for fetching (EVP_MD_fetch(3), provider(7), property(7)), in TAP format,
 * with providers of its own registered by OSSL_PROVIDER_add_builtin: "fetchtest" offers digest
 * algorithms with names, aliases, and properties, and ones that can't be made (missing or
 * failing functions, a bad property definition, conflicting or empty names); "fetchtemp" says
 * its algorithms mustn't be stored. The test fetches by name and property query (with and
 * without default properties), checks which implementation comes back and that repeated
 * fetches return the same method, counts the queries each provider sees (each provider is
 * asked once while it stays active, except one that mustn't be stored), lists the methods with
 * EVP_MD_do_all_provided, unloads and reloads, and prints the errors.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 *
 * Numbers in error data are masked: OpenSSL numbers a context's names after the legacy
 * algorithms' (which rustyssl adds with them, step 3.3), so the numbers differ until then.
 */
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include <openssl/core_dispatch.h>
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

/* Prints the errors, with every run of digits in their data shown as #. */
static void errors(void)
{
    unsigned long code;
    const char *data;
    int flags;

    printf(" errors:");
    while ((code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        if ((flags & ERR_TXT_STRING) != 0 && data[0] != '\0') {
            printf("[");
            for (; *data != '\0'; data++) {
                if (isdigit((unsigned char)*data)) {
                    putchar('#');
                    while (isdigit((unsigned char)data[1]))
                        data++;
                } else {
                    putchar(*data);
                }
            }
            printf("]");
        }
    }
    printf("\n");
}

/* The digest functions: never called but for the parameters. */
static void *t_newctx(void *provctx) { return provctx; }
static void t_freectx(void *ctx) { (void)ctx; }
static int t_init(void *ctx, const OSSL_PARAM params[]) { (void)ctx, (void)params; return 1; }
static int t_update(void *ctx, const unsigned char *in, size_t inl) { (void)ctx, (void)in, (void)inl; return 1; }
static int t_final(void *ctx, unsigned char *out, size_t *outl, size_t outsz)
{
    (void)ctx, (void)out, (void)outsz;
    *outl = 0;
    return 1;
}
static int t_digest(void *provctx, const unsigned char *in, size_t inl, unsigned char *out, size_t *outl,
                    size_t outsz)
{
    (void)provctx, (void)in, (void)inl, (void)out, (void)outsz;
    *outl = 0;
    return 1;
}

static int set_sizes(OSSL_PARAM params[], size_t size, size_t block, int xof, int absent)
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE)) != NULL && !OSSL_PARAM_set_size_t(p, size))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE)) != NULL && !OSSL_PARAM_set_size_t(p, block))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_XOF)) != NULL && !OSSL_PARAM_set_int(p, xof))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_ALGID_ABSENT)) != NULL && !OSSL_PARAM_set_int(p, absent))
        return 0;
    return 1;
}
static int a_get_params(OSSL_PARAM params[]) { return set_sizes(params, 32, 64, 0, 0); }
static int b_get_params(OSSL_PARAM params[]) { return set_sizes(params, 16, 128, 1, 1); }
static int fail_get_params(OSSL_PARAM params[]) { (void)params; return 0; }

static const OSSL_PARAM gettable[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_END
};
static const OSSL_PARAM *t_gettable(void *provctx) { (void)provctx; return gettable; }

#define CTX_FUNCTIONS                                                \
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))t_newctx },           \
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))t_init },               \
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))t_update },           \
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))t_final },             \
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))t_freectx }

static const OSSL_DISPATCH full_a[] = { CTX_FUNCTIONS, { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))a_get_params },
                                        { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))t_gettable }, OSSL_DISPATCH_END };
static const OSSL_DISPATCH full_b[] = { CTX_FUNCTIONS, { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))b_get_params },
                                        OSSL_DISPATCH_END };
static const OSSL_DISPATCH oneshot[] = { { OSSL_FUNC_DIGEST_DIGEST, (void (*)(void))t_digest },
                                         { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))a_get_params }, OSSL_DISPATCH_END };
static const OSSL_DISPATCH incomplete[] = { { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))t_newctx },
                                            { OSSL_FUNC_DIGEST_INIT, (void (*)(void))t_init },
                                            { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))a_get_params },
                                            OSSL_DISPATCH_END };
static const OSSL_DISPATCH noparams[] = { CTX_FUNCTIONS, OSSL_DISPATCH_END };
static const OSSL_DISPATCH failparams[] = { CTX_FUNCTIONS,
                                            { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))fail_get_params },
                                            OSSL_DISPATCH_END };

static const OSSL_ALGORITHM test_digests[] = {
    { "TEST-A:TA:test.alias", "provider=fetchtest,x.speed=1", full_a, "Test digest A" },
    { "TEST-A", "provider=fetchtest,x.speed=2,fips=yes", full_b, "A, the second" },
    { "TEST-B:TB", "provider=fetchtest", full_b, NULL },
    { "TEST-ONE", "provider=fetchtest", oneshot, NULL },
    { "TEST-BAD", "provider=fetchtest", incomplete, NULL },
    { "TEST-NOPARAMS", "provider=fetchtest", noparams, NULL },
    { "TEST-FAILPARAMS", "provider=fetchtest", failparams, NULL },
    { "TEST-BADDEF", "provider=fetchtest,bad name", full_a, NULL },
    { "TB:TEST-C", "provider=fetchtest", full_a, NULL },
    { "TEST-D::TEST-E", "provider=fetchtest", full_a, NULL },
    { NULL, NULL, NULL, NULL }
};
static const OSSL_ALGORITHM temp_digests[] = {
    { "TEST-T", "provider=fetchtemp", full_a, NULL },
    { NULL, NULL, NULL, NULL }
};

static int queries[2], unqueries[2];

static const OSSL_ALGORITHM *test_query(void *provctx, int operation_id, int *no_cache)
{
    (void)provctx;
    *no_cache = 0;
    if (operation_id != OSSL_OP_DIGEST)
        return NULL;
    queries[0]++;
    return test_digests;
}
static void test_unquery(void *provctx, int operation_id, const OSSL_ALGORITHM *algs)
{
    (void)provctx, (void)algs;
    if (operation_id == OSSL_OP_DIGEST)
        unqueries[0]++;
}
static const OSSL_ALGORITHM *temp_query(void *provctx, int operation_id, int *no_cache)
{
    (void)provctx;
    *no_cache = 1;
    if (operation_id != OSSL_OP_DIGEST)
        return NULL;
    queries[1]++;
    return temp_digests;
}
static void temp_unquery(void *provctx, int operation_id, const OSSL_ALGORITHM *algs)
{
    (void)provctx, (void)algs;
    if (operation_id == OSSL_OP_DIGEST)
        unqueries[1]++;
}

static const OSSL_DISPATCH test_dispatch[] = { { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))test_query },
                                               { OSSL_FUNC_PROVIDER_UNQUERY_OPERATION, (void (*)(void))test_unquery },
                                               OSSL_DISPATCH_END };
static const OSSL_DISPATCH temp_dispatch[] = { { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))temp_query },
                                               { OSSL_FUNC_PROVIDER_UNQUERY_OPERATION, (void (*)(void))temp_unquery },
                                               OSSL_DISPATCH_END };

static int test_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
                     void **provctx)
{
    (void)in;
    *out = test_dispatch;
    *provctx = (void *)handle;
    return 1;
}
static int temp_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
                     void **provctx)
{
    (void)in;
    *out = temp_dispatch;
    *provctx = (void *)handle;
    return 1;
}

static void print_name(const char *name, void *data)
{
    (void)data;
    printf(" %s", name);
}

static void describe(const char *what, EVP_MD *md)
{
    int r;

    if (md == NULL) {
        printf("# %s: NULL", what);
        errors();
        return;
    }
    printf("# %s: %s \"%s\" from %s, size %d block %d flags %lx type %d; names:", what, EVP_MD_get0_name(md),
           EVP_MD_get0_description(md), OSSL_PROVIDER_get0_name(EVP_MD_get0_provider(md)), EVP_MD_get_size(md),
           EVP_MD_get_block_size(md), EVP_MD_get_flags(md), EVP_MD_get_type(md));
    r = EVP_MD_names_do_all(md, print_name, NULL);
    printf(" (%d);", r);
    errors();
}

static void print_md(EVP_MD *md, void *arg)
{
    (void)arg;
    printf(" %s/%d", EVP_MD_get0_name(md), EVP_MD_get_size(md));
}

static void show_queries(const char *what)
{
    printf("# queries after %s: fetchtest %d/%d, fetchtemp %d/%d\n", what, queries[0], unqueries[0], queries[1],
           unqueries[1]);
}

static void fetching(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *test, *temp;
    EVP_MD *a, *a2, *second, *opt, *t1, *t2, *md;
    size_t size = 0;
    OSSL_PARAM params[2];
    const OSSL_PARAM *g;
    int no_cache = -1;
    const OSSL_ALGORITHM *algs;

    check(OSSL_PROVIDER_add_builtin(ctx, "fetchtest", test_init) == 1
              && OSSL_PROVIDER_add_builtin(ctx, "fetchtemp", temp_init) == 1,
          "add_builtin");
    test = OSSL_PROVIDER_load(ctx, "fetchtest");
    temp = OSSL_PROVIDER_load(ctx, "fetchtemp");
    check(test != NULL && temp != NULL, "the providers load");
    show_queries("loading");

    a = EVP_MD_fetch(ctx, "TEST-A", NULL);
    describe("TEST-A", a);
    show_queries("the first fetch");
    a2 = EVP_MD_fetch(ctx, "test-a", "");
    check(a2 == a, "a second fetch returns the same method");
    show_queries("the second fetch");
    check(EVP_MD_is_a(a, "TA") && EVP_MD_is_a(a, "TEST.ALIAS") && !EVP_MD_is_a(a, "TEST-B")
              && EVP_MD_get0_provider(a) == test,
          "names and provider");
    second = EVP_MD_fetch(ctx, "TEST-A", "x.speed=2");
    describe("x.speed=2", second);
    check(second != a && second == EVP_MD_fetch(ctx, "ta", "fips=yes"), "properties pick the second");
    EVP_MD_free(second);
    opt = EVP_MD_fetch(ctx, "TEST-A", "?x.speed=3");
    check(opt == a, "an optional property that matches nothing takes the first");
    md = EVP_MD_fetch(ctx, "TEST-A", "?x.speed=2,?fips=yes");
    check(md == second, "the most optional matches win");
    EVP_MD_free(md);
    md = EVP_MD_fetch(ctx, "TEST-A", "?x.speed=2,?fips=no");
    check(md == a, "with as many, the first wins");
    EVP_MD_free(md);
    describe("x.speed=3", EVP_MD_fetch(ctx, "TEST-A", "x.speed=3"));
    describe("NOPE", EVP_MD_fetch(ctx, "NOPE", NULL));
    describe("TEST-BAD", EVP_MD_fetch(ctx, "TEST-BAD", NULL));
    describe("TEST-C", EVP_MD_fetch(ctx, "TEST-C", NULL));
    describe("TEST-ONE", md = EVP_MD_fetch(ctx, "TEST-ONE", "provider=fetchtest"));
    EVP_MD_free(md);
    describe("TB", md = EVP_MD_fetch(ctx, "TB", "bad query,"));
    EVP_MD_free(md);
    describe("NULL name", EVP_MD_fetch(ctx, NULL, NULL));

    check(EVP_set_default_properties(ctx, "x.speed=2") == 1, "default properties");
    md = EVP_MD_fetch(ctx, "TEST-A", NULL);
    check(md == second, "the defaults pick the second");
    EVP_MD_free(md);
    md = EVP_MD_fetch(ctx, "TEST-A", "-x.speed");
    check(md == a, "a query can drop a default");
    EVP_MD_free(md);
    EVP_set_default_properties(ctx, NULL);

    t1 = EVP_MD_fetch(ctx, "TEST-T", NULL);
    t2 = EVP_MD_fetch(ctx, "TEST-T", NULL);
    describe("TEST-T", t1);
    check(t1 != NULL && t2 != NULL && t1 != t2, "a method not stored isn't cached: each fetch makes it");
    EVP_MD_free(t1);
    EVP_MD_free(t2);
    show_queries("the temporary fetches");

    printf("# all:");
    EVP_MD_do_all_provided(ctx, print_md, NULL);
    printf("\n");
    show_queries("do_all_provided");

    params[0] = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE, &size);
    params[1] = OSSL_PARAM_construct_end();
    check(EVP_MD_get_params(a, params) == 1 && size == 32, "get_params");
    printf("# gettable:");
    for (g = EVP_MD_gettable_params(a); g != NULL && g->key != NULL; g++)
        printf(" %s", g->key);
    printf("\n");
    check(EVP_MD_up_ref(a) == 1, "up_ref");
    EVP_MD_free(a);
    EVP_MD_free(a2);
    EVP_MD_free(opt);

    algs = OSSL_PROVIDER_query_operation(test, OSSL_OP_DIGEST, &no_cache);
    check(algs == test_digests && no_cache == 0, "query_operation");
    OSSL_PROVIDER_unquery_operation(test, OSSL_OP_DIGEST, algs);
    show_queries("query_operation");

    check(OSSL_PROVIDER_unload(test) == 1, "unload fetchtest");
    describe("TEST-A after unloading", EVP_MD_fetch(ctx, "TEST-A", NULL));
    test = OSSL_PROVIDER_load(ctx, "fetchtest");
    describe("TEST-A after reloading", md = EVP_MD_fetch(ctx, "TEST-A", NULL));
    EVP_MD_free(md);
    show_queries("reloading");

    check(EVP_MD_get_size(NULL) == -1 && EVP_MD_get_block_size(NULL) == -1 && EVP_MD_get0_name(NULL) == NULL,
          "NULL digests");
    errors();
    EVP_MD_free(NULL);
    OSSL_PROVIDER_unload(test);
    OSSL_PROVIDER_unload(temp);
    OSSL_LIB_CTX_free(ctx);
}

static void first_failure(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *test;

    OSSL_PROVIDER_add_builtin(ctx, "fetchtest", test_init);
    test = OSSL_PROVIDER_load(ctx, "fetchtest");
    describe("TEST-BAD first", EVP_MD_fetch(ctx, "TEST-BAD", NULL));
    describe("TEST-BAD again", EVP_MD_fetch(ctx, "TEST-BAD", NULL));
    OSSL_PROVIDER_unload(test);
    OSSL_LIB_CTX_free(ctx);
}

int main(void)
{
    fetching();
    first_failure();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
