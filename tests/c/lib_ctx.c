/*
 * Conformance test for library contexts (OSSL_LIB_CTX(3), OSSL_set_max_threads(3)), in TAP
 * format: making and freeing contexts, the global default, each thread's default
 * (OSSL_LIB_CTX_set0_default) and what NULL means under it, freeing a default (which does
 * nothing), the configuration diagnostics flag and the thread limit kept per context, and the
 * application-data registry, which is the thread's default context's.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 *
 * Freeing the global default context while another is the thread's default is left out: OpenSSL
 * frees its static object (docs/DEVIATIONS.md).
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
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

static int news, frees;

static void count_new(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
    (void)parent, (void)ptr, (void)ad, (void)argp;
    news++;
    printf("# new callback: index %d argl %ld\n", idx, argl);
}

static void count_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
    (void)parent, (void)ptr, (void)ad, (void)argp;
    frees++;
    printf("# free callback: index %d argl %ld\n", idx, argl);
}

static OSSL_LIB_CTX *seen_by_thread;
static uint64_t thread_limit;
static int thread_diag;

/* Runs on a new thread: its default is the global one, whatever the main thread set. */
static void *other_thread(void *arg)
{
    OSSL_LIB_CTX *mine = arg;

    seen_by_thread = OSSL_LIB_CTX_set0_default(NULL);
    thread_limit = OSSL_get_max_threads(NULL);
    thread_diag = OSSL_LIB_CTX_get_conf_diagnostics(NULL);
    /* A default set here is this thread's only. */
    OSSL_LIB_CTX_set0_default(mine);
    OSSL_set_max_threads(NULL, 9);
    return NULL;
}

static void defaults(void)
{
    OSSL_LIB_CTX *global = OSSL_LIB_CTX_get0_global_default();
    OSSL_LIB_CTX *a = OSSL_LIB_CTX_new(), *b = OSSL_LIB_CTX_new();
    OSSL_LIB_CTX *prev;
    pthread_t thread;

    check(global != NULL && global == OSSL_LIB_CTX_get0_global_default(), "one global default");
    check(a != NULL && b != NULL && a != b && a != global, "new contexts are distinct");
    check(OSSL_LIB_CTX_set0_default(NULL) == global, "the default is the global one at first");

    check(OSSL_get_max_threads(NULL) == 0 && OSSL_get_max_threads(a) == 0, "no thread limit at first");
    check(OSSL_set_max_threads(a, 5) == 1 && OSSL_get_max_threads(a) == 5 && OSSL_get_max_threads(NULL) == 0
              && OSSL_get_max_threads(b) == 0,
          "the thread limit is per context");
    check(OSSL_set_max_threads(NULL, 2) == 1 && OSSL_get_max_threads(global) == 2, "NULL is the global default");
    check(OSSL_LIB_CTX_get_conf_diagnostics(a) == 0 && OSSL_LIB_CTX_get_conf_diagnostics(NULL) == 0,
          "no configuration diagnostics at first");
    OSSL_LIB_CTX_set_conf_diagnostics(a, 7);
    printf("# diagnostics: a %d, b %d, default %d\n", OSSL_LIB_CTX_get_conf_diagnostics(a),
           OSSL_LIB_CTX_get_conf_diagnostics(b), OSSL_LIB_CTX_get_conf_diagnostics(NULL));

    prev = OSSL_LIB_CTX_set0_default(a);
    check(prev == global, "set0_default returns the previous default");
    check(OSSL_LIB_CTX_set0_default(NULL) == a, "set0_default(NULL) only reports it");
    check(OSSL_get_max_threads(NULL) == 5 && OSSL_LIB_CTX_get_conf_diagnostics(NULL) == 7,
          "NULL now means the thread's default");
    OSSL_LIB_CTX_free(a);
    OSSL_LIB_CTX_free(NULL);
    check(OSSL_get_max_threads(a) == 5, "freeing the thread's default does nothing");
    OSSL_set_max_threads(NULL, 6);

    check(pthread_create(&thread, NULL, other_thread, b) == 0 && pthread_join(thread, NULL) == 0, "another thread");
    check(seen_by_thread == global && thread_limit == 2 && thread_diag == 0,
          "another thread's default is the global one");
    check(OSSL_LIB_CTX_set0_default(NULL) == a && OSSL_get_max_threads(b) == 9 && OSSL_get_max_threads(a) == 6,
          "its default was its own");

    prev = OSSL_LIB_CTX_set0_default(b);
    check(prev == a && OSSL_LIB_CTX_set0_default(NULL) == b, "switching defaults");
    prev = OSSL_LIB_CTX_set0_default(global);
    check(prev == b && OSSL_LIB_CTX_set0_default(NULL) == global && OSSL_get_max_threads(NULL) == 2,
          "setting the global default undoes it");
    OSSL_LIB_CTX_free(global);
    check(OSSL_get_max_threads(global) == 2, "freeing the global default while it's the default does nothing");
    OSSL_LIB_CTX_free(a);
    OSSL_LIB_CTX_free(b);
    OSSL_set_max_threads(NULL, 0);
    check(ERR_peek_error() == 0, "no errors");
}

static void ex_data(void)
{
    OSSL_LIB_CTX *global = OSSL_LIB_CTX_get0_global_default();
    OSSL_LIB_CTX *a = OSSL_LIB_CTX_new();
    CRYPTO_EX_DATA ad;
    int ig, ia, ia2;

    ig = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_APP, 100, NULL, count_new, NULL, count_free);
    OSSL_LIB_CTX_set0_default(a);
    ia = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_APP, 200, NULL, count_new, NULL, count_free);
    ia2 = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_APP, 201, NULL, count_new, NULL, count_free);
    printf("# indexes: global %d, a %d %d\n", ig, ia, ia2);
    check(ia == ig, "each context numbers its own indexes");

    news = frees = 0;
    check(CRYPTO_new_ex_data(CRYPTO_EX_INDEX_APP, NULL, &ad) == 1 && news == 2, "new data runs a's callbacks");
    check(ad.ctx == NULL, "the data's context is NULL");
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_APP, NULL, &ad);
    check(frees == 2, "free runs a's callbacks");

    OSSL_LIB_CTX_set0_default(global);
    news = frees = 0;
    check(CRYPTO_new_ex_data(CRYPTO_EX_INDEX_APP, NULL, &ad) == 1 && news == 1, "back on the global default");
    OSSL_LIB_CTX_set0_default(a);
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_APP, NULL, &ad);
    printf("# freed under a: %d callbacks\n", frees);
    check(CRYPTO_free_ex_index(CRYPTO_EX_INDEX_APP, ia2) == 1, "free an index of a");
    OSSL_LIB_CTX_set0_default(global);
    check(CRYPTO_free_ex_index(CRYPTO_EX_INDEX_APP, ia2) == 0, "the global default has no such index");
    CRYPTO_free_ex_index(CRYPTO_EX_INDEX_APP, ig);
    OSSL_LIB_CTX_free(a);
    ERR_clear_error();
}

int main(void)
{
    defaults();
    ex_data();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
