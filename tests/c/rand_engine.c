/*
 * Conformance test for the RAND method an ENGINE gives (RAND_set_rand_engine(3),
 * ENGINE_set_default_RAND(3)), in TAP format: the default RAND engine's method is picked on
 * the first use, as `openssl s_server -engine ossltest` relies on, and kept; setting a method
 * or an engine replaces it, and NULL picks again.
 *
 * Nothing draws random numbers before main's first check, so the first use is the test's.
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/rand.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static int calls = 0;

/* Known octets, as ossltest's method gives. */
static int known_bytes(unsigned char *buf, int num)
{
    unsigned char val = 1;

    calls++;
    while (--num >= 0)
        *buf++ = val++;
    return 1;
}

static int known_status(void)
{
    return 1;
}

static RAND_METHOD known = { NULL, known_bytes, NULL, NULL, known_bytes, known_status };

static int is_known(const unsigned char *b, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        if (b[i] != (unsigned char)(i + 1))
            return 0;
    return 1;
}

int main(void)
{
    ENGINE *e = ENGINE_new(), *bare = ENGINE_new();
    unsigned char buf[16];

    check(ENGINE_set_id(e, "known-rand") == 1 && ENGINE_set_name(e, "known random numbers") == 1
              && ENGINE_set_RAND(e, &known) == 1 && ENGINE_set_default_RAND(e) == 1,
          "an engine with a RAND method, the default before any use");
    check(ENGINE_set_id(bare, "no-rand") == 1 && ENGINE_set_name(bare, "no RAND method") == 1,
          "an engine without one");

    memset(buf, 0, sizeof(buf));
    check(RAND_bytes(buf, sizeof(buf)) == 1 && is_known(buf, sizeof(buf)) && calls == 1,
          "RAND_bytes: the first use picks the default engine's method");
    check(RAND_get_rand_method() == &known, "RAND_get_rand_method: the engine's");
    memset(buf, 0, sizeof(buf));
    check(RAND_priv_bytes_ex(NULL, buf, sizeof(buf), 0) == 1 && is_known(buf, sizeof(buf))
              && calls == 2, "RAND_priv_bytes_ex: the engine's too");

    ENGINE_unregister_RAND(e);
    check(RAND_get_rand_method() == &known, "unregistered: the method picked is kept");
    check(RAND_set_rand_method(NULL) == 1 && RAND_get_rand_method() == RAND_OpenSSL(),
          "RAND_set_rand_method(NULL): picks again, the library's with no default engine");
    memset(buf, 0, sizeof(buf));
    check(RAND_bytes(buf, sizeof(buf)) == 1 && !is_known(buf, sizeof(buf)) && calls == 2,
          "RAND_bytes: the library's generators");

    check(ENGINE_set_default_RAND(e) == 1 && RAND_get_rand_method() == RAND_OpenSSL(),
          "a default engine set after the pick isn't taken");
    check(RAND_set_rand_engine(NULL) == 1 && RAND_get_rand_method() == &known,
          "RAND_set_rand_engine(NULL): picks again, the default engine's");
    ENGINE_unregister_RAND(e);

    check(RAND_set_rand_engine(bare) == 0 && RAND_get_rand_method() == &known,
          "RAND_set_rand_engine: an engine without a RAND method fails, the method kept");
    check(RAND_set_rand_method(RAND_OpenSSL()) == 1 && RAND_set_rand_engine(e) == 1
              && RAND_get_rand_method() == &known, "RAND_set_rand_engine: the engine's method");
    memset(buf, 0, sizeof(buf));
    check(RAND_bytes(buf, 4) == 1 && is_known(buf, 4) && calls == 3, "RAND_bytes through it");
    check(RAND_set_rand_engine(NULL) == 1 && RAND_get_rand_method() == RAND_OpenSSL(),
          "RAND_set_rand_engine(NULL): the library's again, with no default engine");
    while (ERR_peek_error() != 0)
        printf("  error: %s\n", ERR_reason_error_string(ERR_get_error()));

    check(ENGINE_free(bare) == 1 && ENGINE_free(e) == 1, "the engines freed");
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
