/*
 * Conformance test for when the error strings are loaded (ERR_load_strings(3),
 * OPENSSL_init_crypto(3)), in TAP format.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustssl: it must pass on both with the same output (TEST_PLAN.md, layer L4). The strings are
 * global, so this runs in a process of its own, starting with none loaded. Each library's table
 * is loaded only if its first entry is unknown, so an application's string for that entry keeps
 * the whole table out.
 */
/* The legacy loaders are deprecated. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <string.h>

#include <openssl/bnerr.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rsaerr.h>
#include <openssl/ssl.h>
#include <openssl/sslerr.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static int same(const char *a, const char *b)
{
    return a != NULL && b != NULL && strcmp(a, b) == 0;
}

/* The first entries of OpenSSL's BN and SSL tables. */
static const unsigned long BN_FIRST = ERR_PACK(ERR_LIB_BN, 0, BN_R_ARG2_LT_ARG3);
static const unsigned long BN_SECOND = ERR_PACK(ERR_LIB_BN, 0, BN_R_BAD_RECIPROCAL);
static const unsigned long SSL_FIRST =
    ERR_PACK(ERR_LIB_SSL, 0, SSL_R_APPLICATION_DATA_AFTER_CLOSE_NOTIFY);
static const unsigned long SSL_SECOND = ERR_PACK(ERR_LIB_SSL, 0, SSL_R_APP_DATA_IN_HANDSHAKE);

static ERR_STRING_DATA preload[] = {
    { ERR_PACK(ERR_LIB_BN, 0, BN_R_ARG2_LT_ARG3), "the application's text" },
    { 0, NULL },
};

static ERR_STRING_DATA ssl_entries[] = {
    { ERR_PACK(ERR_LIB_SSL, 0, SSL_R_APPLICATION_DATA_AFTER_CLOSE_NOTIFY), "" },
    { ERR_PACK(ERR_LIB_SSL, 0, SSL_R_APP_DATA_IN_HANDSHAKE), "" },
    { 0, NULL },
};

int main(void)
{
    char buf[256];

    check(ERR_lib_error_string(ERR_PACK(ERR_LIB_BN, 0, 0)) == NULL
          && ERR_reason_error_string(ERR_R_MALLOC_FAILURE) == NULL,
          "no strings at first");
    ERR_error_string_n(ERR_PACK(ERR_LIB_BUF, 0, ERR_R_PASSED_INVALID_ARGUMENT), buf, sizeof(buf));
    check(same(buf, "error:03880106:lib(7)::reason(262)"),
          "ERR_error_string_n: numbers without strings, the reason without its flags");

    check(OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS, NULL) == 1,
          "OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS");
    ERR_raise(ERR_LIB_BN, BN_R_DIV_BY_ZERO);
    check(ERR_get_error() == ERR_PACK(ERR_LIB_BN, 0, BN_R_DIV_BY_ZERO)
          && ERR_lib_error_string(ERR_PACK(ERR_LIB_BN, 0, 0)) == NULL,
          "creating the queue loads nothing after OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS");
    check(ERR_load_crypto_strings() == 1
          && ERR_lib_error_string(ERR_PACK(ERR_LIB_BN, 0, 0)) == NULL,
          "ERR_load_crypto_strings: OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS came first");

    check(ERR_load_strings_const(preload) == 1
          && same(ERR_lib_error_string(ERR_PACK(ERR_LIB_BN, 0, 0)), "bignum routines")
          && same(ERR_reason_error_string(ERR_R_MALLOC_FAILURE), "malloc failure")
          && ERR_reason_error_string(ERR_PACK(ERR_LIB_RSA, 0, RSA_R_BAD_E_VALUE)) == NULL,
          "ERR_load_strings_const: loads the library names and common reasons first");
    check(ERR_load_BN_strings() == 1
          && same(ERR_reason_error_string(BN_FIRST), "the application's text")
          && ERR_reason_error_string(BN_SECOND) == NULL,
          "ERR_load_BN_strings: skips the table when its first entry is known");
    check(ERR_load_RSA_strings() == 1
          && same(ERR_reason_error_string(ERR_PACK(ERR_LIB_RSA, 0, RSA_R_BAD_E_VALUE)),
                  "bad e value"),
          "ERR_load_RSA_strings");
    ERR_unload_strings(0, preload);
    check(ERR_load_BN_strings() == 1 && same(ERR_reason_error_string(BN_FIRST), "arg2 lt arg3")
          && same(ERR_reason_error_string(BN_SECOND), "bad reciprocal"),
          "ERR_load_BN_strings: loads the table once its first entry is unknown");

    check(same(ERR_lib_error_string(SSL_FIRST), "SSL routines")
          && ERR_reason_error_string(SSL_FIRST) == NULL,
          "the SSL library's name, without its reasons");
    check(OPENSSL_init_crypto(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL) == 1
          && same(ERR_reason_error_string(SSL_SECOND), "app data in handshake"),
          "OPENSSL_INIT_LOAD_SSL_STRINGS");
    ERR_unload_strings(0, ssl_entries);
    check(ERR_load_SSL_strings() == 1 && ERR_reason_error_string(SSL_SECOND) == NULL,
          "ERR_load_SSL_strings: loads once, through OPENSSL_INIT_LOAD_SSL_STRINGS");
    printf("1..%d\n", number);
    return failures != 0;
}
