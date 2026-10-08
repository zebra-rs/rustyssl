/*
 * Conformance test for OPENSSL_init_crypto, OPENSSL_atexit, and OPENSSL_cleanup
 * (OPENSSL_init_crypto(3)), in TAP format.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4). It only asks for
 * subsystems rustyssl has; configuration loading is switched off first, so no file is read.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static char ran[16];

static void handler(char c)
{
    size_t n = strlen(ran);

    if (n + 1 < sizeof(ran))
        ran[n] = c;
}

static void first(void) { handler('1'); }
static void second(void) { handler('2'); }
static void third(void) { handler('3'); }

static void settings(void)
{
    OPENSSL_INIT_SETTINGS *s = OPENSSL_INIT_new();

    check(s != NULL, "OPENSSL_INIT_new");
    check(OPENSSL_INIT_set_config_filename(s, "/nonexistent/rustyssl.cnf") == 1
          && OPENSSL_INIT_set_config_filename(s, NULL) == 1,
          "OPENSSL_INIT_set_config_filename: sets and clears");
    check(OPENSSL_INIT_set_config_appname(s, "rustyssl_test") == 1
          && OPENSSL_INIT_set_config_appname(s, NULL) == 1,
          "OPENSSL_INIT_set_config_appname: sets and clears");
    OPENSSL_INIT_set_config_file_flags(s, CONF_MFLAGS_IGNORE_MISSING_FILE);
    OPENSSL_INIT_free(s);
    OPENSSL_INIT_free(NULL);
    check(1, "OPENSSL_INIT_set_config_file_flags and OPENSSL_INIT_free");
}

int main(void)
{
    settings();

    check(OPENSSL_atexit(first) == 1, "OPENSSL_atexit: before any initialization");
    check(OPENSSL_init_crypto(0, NULL) == 1, "OPENSSL_init_crypto(0): nothing to do");
    check(OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT | OPENSSL_INIT_NO_LOAD_CONFIG
                                  | OPENSSL_INIT_NO_ADD_ALL_CIPHERS
                                  | OPENSSL_INIT_NO_ADD_ALL_DIGESTS, NULL) == 1,
          "OPENSSL_init_crypto: no exit handler, configuration, ciphers, or digests");
    check(OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL) == 1,
          "OPENSSL_INIT_LOAD_CONFIG after OPENSSL_INIT_NO_LOAD_CONFIG: already decided");
    check(OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS,
                              NULL) == 1,
          "OPENSSL_INIT_ADD_ALL_* after their NO_ twins: already decided");
    check(OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_LOAD_SSL_STRINGS
                                  | OPENSSL_INIT_ATFORK, NULL) == 1,
          "OPENSSL_init_crypto: error strings and fork handlers");
    check(OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS, NULL) == 1,
          "OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS after loading: already decided");
    check(OPENSSL_atexit(second) == 1 && OPENSSL_atexit(third) == 1,
          "OPENSSL_atexit: after initialization");

    OPENSSL_cleanup();
    check(strcmp(ran, "321") == 0, "OPENSSL_cleanup: runs the handlers, newest first");
    OPENSSL_cleanup();
    check(strcmp(ran, "321") == 0, "OPENSSL_cleanup: only once");
    check(OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL) == 0,
          "OPENSSL_init_crypto: fails after OPENSSL_cleanup");
    check(OPENSSL_init_crypto(0, NULL) == 0, "OPENSSL_init_crypto(0): fails after OPENSSL_cleanup");
    printf("1..%d\n", number);
    return failures != 0;
}
