/*
 * Conformance test for OSSL_SELF_TEST (OSSL_SELF_TEST_new(3), OSSL_SELF_TEST_set_callback(3)):
 * a library context's self-test callback set and read back, and a reporting object's phases
 * (start, pass, fail, corrupt) delivered to its callback as parameters, the corruption of a
 * byte the callback asks for, and an object without a callback.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/self_test.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static int answer = 1;

static int cb(const OSSL_PARAM params[], void *arg)
{
    const OSSL_PARAM *p;

    printf("  %s:", (const char *)arg);
    for (p = params; p->key != NULL; p++)
        printf(" %s=%.*s(%zu)", p->key, (int)p->data_size, (const char *)p->data, p->data_size);
    printf(" -> %d\n", answer);
    return answer;
}

static int other(const OSSL_PARAM params[], void *arg)
{
    (void)params;
    (void)arg;
    return 1;
}

int main(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    OSSL_CALLBACK *got = other;
    void *arg = &got;
    OSSL_SELF_TEST *st;
    unsigned char byte = 0x10;

    setvbuf(stdout, NULL, _IONBF, 0);

    printf("# the library context's callback\n");
    OSSL_SELF_TEST_get_callback(ctx, &got, &arg);
    check(got == NULL && arg == NULL, "none at first");
    OSSL_SELF_TEST_set_callback(ctx, cb, "ctx");
    OSSL_SELF_TEST_get_callback(ctx, &got, &arg);
    check(got == cb && strcmp(arg, "ctx") == 0, "set");
    OSSL_SELF_TEST_get_callback(ctx, NULL, NULL);
    OSSL_SELF_TEST_get_callback(NULL, &got, NULL);
    check(got == NULL, "not the default context's");
    OSSL_SELF_TEST_set_callback(NULL, other, NULL);
    OSSL_SELF_TEST_get_callback(NULL, &got, &arg);
    check(got == other && arg == NULL, "the default context's");
    OSSL_SELF_TEST_set_callback(NULL, NULL, NULL);
    OSSL_SELF_TEST_set_callback(ctx, NULL, NULL);

    printf("# reporting\n");
    st = OSSL_SELF_TEST_new(cb, "test");
    check(st != NULL, "OSSL_SELF_TEST_new");
    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_KAT_DIGEST, OSSL_SELF_TEST_DESC_MD_SHA2);
    OSSL_SELF_TEST_onend(st, 1);
    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_KAT_CIPHER, OSSL_SELF_TEST_DESC_CIPHER_AES_GCM);
    check(OSSL_SELF_TEST_oncorrupt_byte(st, &byte) == 0 && byte == 0x10, "the callback doesn't ask for corruption");
    answer = 0;
    check(OSSL_SELF_TEST_oncorrupt_byte(st, &byte) == 1 && byte == 0x11, "it does");
    answer = 1;
    OSSL_SELF_TEST_onend(st, 0);
    OSSL_SELF_TEST_onend(st, 2);
    OSSL_SELF_TEST_free(st);

    printf("# no callback\n");
    st = OSSL_SELF_TEST_new(NULL, NULL);
    check(st != NULL, "an object without a callback");
    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_PCT, OSSL_SELF_TEST_DESC_PCT_RSA);
    OSSL_SELF_TEST_onend(st, 1);
    check(OSSL_SELF_TEST_oncorrupt_byte(st, &byte) == 0 && byte == 0x11, "nothing to corrupt");
    OSSL_SELF_TEST_free(st);
    OSSL_SELF_TEST_free(NULL);
    OSSL_SELF_TEST_onbegin(NULL, "t", "d");
    OSSL_SELF_TEST_onend(NULL, 1);
    check(OSSL_SELF_TEST_oncorrupt_byte(NULL, &byte) == 0, "NULL");
    check(ERR_peek_error() == 0, "no errors");
    OSSL_LIB_CTX_free(ctx);

    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
