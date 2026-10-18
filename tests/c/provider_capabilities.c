/*
 * Conformance test for OSSL_PROVIDER_get_capabilities(3) and provider-base(7)'s capabilities:
 * the default provider's TLS-GROUP and TLS-SIGALG parameter sets, printed in full (key, type,
 * value, and size of each parameter), a callback that stops the enumeration, a capability no
 * provider has, and a provider without capabilities.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <string.h>

#include <openssl/core.h>
#include <openssl/core_names.h>
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

static int count;

static int print_set(const OSSL_PARAM params[], void *arg)
{
    const OSSL_PARAM *p;

    count++;
    printf("  %s %d:", (const char *)arg, count);
    for (p = params; p->key != NULL; p++) {
        switch (p->data_type) {
        case OSSL_PARAM_UTF8_STRING:
            printf(" %s=\"%s\"(%zu)", p->key, (const char *)p->data, p->data_size);
            break;
        case OSSL_PARAM_UNSIGNED_INTEGER:
            printf(" %s=%u(%zu)", p->key, *(const unsigned int *)p->data, p->data_size);
            break;
        case OSSL_PARAM_INTEGER:
            printf(" %s=%d(%zu)", p->key, *(const int *)p->data, p->data_size);
            break;
        default:
            printf(" %s=?type%u", p->key, p->data_type);
            break;
        }
        if (p->return_size != OSSL_PARAM_UNMODIFIED)
            printf("[ret %zu]", p->return_size);
    }
    printf("\n");
    return 1;
}

static int stop_after_three(const OSSL_PARAM params[], void *arg)
{
    (void)params;
    (void)arg;
    return ++count < 3;
}

static int never(const OSSL_PARAM params[], void *arg)
{
    (void)params;
    (void)arg;
    count++;
    return 1;
}

int main(void)
{
    OSSL_PROVIDER *dflt = OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER *base = OSSL_PROVIDER_load(NULL, "base");
    OSSL_PROVIDER *null = OSSL_PROVIDER_load(NULL, "null");
    int r;

    setvbuf(stdout, NULL, _IONBF, 0);
    check(dflt != NULL && base != NULL && null != NULL, "the providers load");

    printf("# TLS-GROUP\n");
    count = 0;
    r = OSSL_PROVIDER_get_capabilities(dflt, "TLS-GROUP", print_set, "group");
    check(r == 1, "the default provider's groups");
    printf("  %d groups\n", count);

    printf("# TLS-SIGALG\n");
    count = 0;
    r = OSSL_PROVIDER_get_capabilities(dflt, "TLS-SIGALG", print_set, "sigalg");
    check(r == 1, "the default provider's signature algorithms");
    printf("  %d sigalgs\n", count);

    printf("# names are case-insensitive\n");
    count = 0;
    r = OSSL_PROVIDER_get_capabilities(dflt, "tls-group", never, NULL);
    check(r == 1 && count > 0, "tls-group");
    count = 0;
    r = OSSL_PROVIDER_get_capabilities(dflt, "Tls-SigAlg", never, NULL);
    check(r == 1 && count == 3, "Tls-SigAlg");

    printf("# the callback stops it\n");
    count = 0;
    r = OSSL_PROVIDER_get_capabilities(dflt, "TLS-GROUP", stop_after_three, NULL);
    check(r == 0 && count == 3, "stopped after three");

    printf("# unknown capabilities and other providers\n");
    count = 0;
    r = OSSL_PROVIDER_get_capabilities(dflt, "TLS-NOTHING", never, NULL);
    check(r == 0 && count == 0, "an unknown capability");
    count = 0;
    r = OSSL_PROVIDER_get_capabilities(base, "TLS-GROUP", never, NULL);
    printf("  base: %d (%d sets)\n", r, count);
    check(count == 0, "the base provider has none");
    count = 0;
    r = OSSL_PROVIDER_get_capabilities(null, "TLS-GROUP", never, NULL);
    printf("  null: %d (%d sets)\n", r, count);
    check(count == 0, "the null provider has none");

    OSSL_PROVIDER_unload(dflt);
    OSSL_PROVIDER_unload(base);
    OSSL_PROVIDER_unload(null);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
