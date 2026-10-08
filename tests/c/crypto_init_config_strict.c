/*
 * Conformance test for OPENSSL_INIT_LOAD_CONFIG with flags that don't ignore a missing file
 * (OPENSSL_init_crypto(3), OPENSSL_INIT_set_config_file_flags), in TAP format: the load fails,
 * and the failure sticks, except that OpenSSL skips later loads on the thread that tried first.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdio.h>

#include <openssl/conf.h>
#include <openssl/crypto.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static int other_thread_result;

static void *load_on_another_thread(void *unused)
{
    (void)unused;
    other_thread_result = OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
    return NULL;
}

int main(void)
{
    pthread_t thread;

    OPENSSL_INIT_SETTINGS *s = OPENSSL_INIT_new();

    OPENSSL_INIT_set_config_filename(s, "/nonexistent/rustyssl-test/openssl.cnf");
    OPENSSL_INIT_set_config_file_flags(s, CONF_MFLAGS_DEFAULT_SECTION);
    check(OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, s) == 0,
          "OPENSSL_INIT_LOAD_CONFIG: a missing file fails without CONF_MFLAGS_IGNORE_MISSING_FILE");
    OPENSSL_INIT_free(s);
    check(OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL) == 1,
          "OPENSSL_INIT_LOAD_CONFIG: skipped on the thread that loaded first");
    check(pthread_create(&thread, NULL, load_on_another_thread, NULL) == 0
          && pthread_join(thread, NULL) == 0 && other_thread_result == 0,
          "OPENSSL_INIT_LOAD_CONFIG: the failure is kept for other threads");
    check(OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL) == 0,
          "OPENSSL_INIT_NO_LOAD_CONFIG: so is the decision");
    check(OPENSSL_init_crypto(OPENSSL_INIT_ATFORK, NULL) == 1,
          "OPENSSL_init_crypto: other subsystems still work");
    printf("1..%d\n", number);
    return failures != 0;
}
