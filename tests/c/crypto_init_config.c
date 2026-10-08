/*
 * Conformance test for OPENSSL_INIT_LOAD_CONFIG with no configuration file
 * (OPENSSL_init_crypto(3), config(5)), in TAP format: OPENSSL_CONF names a file that doesn't
 * exist, which loads nothing and succeeds. OPENSSL_cleanup then runs at exit, with the handler
 * registered here.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>

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

static void at_exit(void)
{
    printf("# the OPENSSL_atexit handler ran at exit\n");
}

int main(void)
{
    OPENSSL_INIT_SETTINGS *s = OPENSSL_INIT_new();

    setenv("OPENSSL_CONF", "/nonexistent/rustssl-test/openssl.cnf", 1);
    check(OPENSSL_atexit(at_exit) == 1, "OPENSSL_atexit");
    check(OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL) == 1,
          "OPENSSL_INIT_LOAD_CONFIG: a missing $OPENSSL_CONF loads nothing");
    OPENSSL_INIT_set_config_filename(s, "/nonexistent/rustssl-test/other.cnf");
    OPENSSL_INIT_set_config_file_flags(s, CONF_MFLAGS_DEFAULT_SECTION);
    check(OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, s) == 1,
          "OPENSSL_INIT_LOAD_CONFIG: the configuration is only decided once");
    OPENSSL_INIT_free(s);
    printf("1..%d\n", number);
    return failures != 0;
}
