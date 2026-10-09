/*
 * Conformance test for default properties (EVP_set_default_properties(3), property(7)), in TAP
 * format: queries of every form set as a context's default and read back in canonical form
 * (which orders names by when the context first saw them), the parser's errors with their data
 * text, clearing, the FIPS switch merged into a default, and whether FIPS is required.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static void errors(void)
{
    unsigned long code;
    const char *data;
    int flags;

    printf(" errors:");
    while ((code = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(code), ERR_GET_REASON(code));
        if ((flags & ERR_TXT_STRING) != 0 && data[0] != '\0')
            printf("[%s]", data);
    }
    printf("\n");
}

/* The default query as text, printed; returns whether it equals `want`. */
static int shows(OSSL_LIB_CTX *ctx, const char *want)
{
    char *s = EVP_get1_default_properties(ctx);
    int ok = s != NULL && strcmp(s, want) == 0;

    printf("#   now \"%s\"", s == NULL ? "(NULL)" : s);
    errors();
    OPENSSL_free(s);
    return ok;
}

/* Sets a default query and prints the result, its errors, and the default after. */
static int set(OSSL_LIB_CTX *ctx, const char *q)
{
    int r = EVP_set_default_properties(ctx, q);

    printf("# set \"%s\": %d fips %d", q == NULL ? "(NULL)" : q, r, EVP_default_properties_is_fips_enabled(ctx));
    errors();
    shows(ctx, "");
    return r;
}

static void queries(void)
{
    static const char *const good[] = {
        "", "   ", "provider=default", " Provider = DEFAULT , fips = yes ", "fips", "?fips", "-fips", "fips=no",
        "fips!=yes", "fips != no", "?fips=yes,-provider", "version=1", "version=+42", "version=-7", "version=0x1F",
        "version=017", "version=0", "provider='Mixed Case'", "provider=\"it's\"",
        "provider='a\"b'", "x.y=1,a.b=2,provider=p", "a.b=3,x.y=4", "my.name.is=x", "under_score.x=y_z",
        "output=der,input=pem,structure=type-specific", "unknown", "unknown=1", "?unknown",
        "provider=default,fips=yes,output=der,input=der,structure=x,version=2",
        "version=9223372036854775807", "version=-9223372036854775807",
    };
    static const char *const bad[] = {
        "fips=", "fips!=", "foo,bar", "fips,fips", "fips,FIPS", "fips=12a", "fips=0x", "fips=0xg", "version=0X1F", "fips=08",
        "fips=078", "fips=+", "fips=-", "fips=+x", "version=9223372036854775808", "version=0x8000000000000000",
        "version=01000000000000000000000", "1fips", "-", "?", "fips=yes,", ",fips", "fips=yes junk",
        "fips='unterminated", "fips=\"x'", "fips=a\x01", "fips=a\x7f", "a..b=1", "a.=1", ".a=1", "fips==yes",
        "fips=!yes", "fips=yes,,fips=no", "fips =", "provider=a,provider=b",
    };
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    size_t i;
    int ok = 1;

    check(shows(ctx, ""), "no default query at first");
    for (i = 0; i < sizeof(good) / sizeof(good[0]); i++)
        ok &= set(ctx, good[i]) == 1;
    check(ok, "valid queries are set");
    ok = 1;
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        ok &= set(ctx, bad[i]) == 0;
    check(ok, "invalid queries are refused");
    OSSL_LIB_CTX_free(ctx);
}

static void lengths(void)
{
    char q[1300];
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    int n;

    for (n = 97; n <= 101; n++) {
        memset(q, 'a', (size_t)n);
        strcpy(q + n, ".b=1");
        printf("# name of %d:", n + 2);
        set(ctx, q);
    }
    for (n = 998; n <= 1001; n++) {
        strcpy(q, "fips=");
        memset(q + 5, 'v', (size_t)n);
        q[5 + n] = '\0';
        printf("# value of %d:", n);
        set(ctx, q);
        strcpy(q, "fips='");
        memset(q + 6, 'v', (size_t)n);
        strcpy(q + 6 + n, "'");
        printf("# quoted value of %d:", n);
        set(ctx, q);
    }
    OSSL_LIB_CTX_free(ctx);
}

static void order(void)
{
    OSSL_LIB_CTX *a = OSSL_LIB_CTX_new(), *b = OSSL_LIB_CTX_new();

    set(a, "z.z=1");
    set(a, "a.a=2,z.z=3");
    check(shows(a, "a.a=2,z.z=3"), "names print from the newest the context saw");
    set(b, "a.a=2,z.z=3");
    check(shows(b, "z.z=3,a.a=2"), "another context numbers them in its own order");
    OSSL_LIB_CTX_free(a);
    OSSL_LIB_CTX_free(b);
}

static void fips(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();

    check(EVP_default_properties_is_fips_enabled(ctx) == 0, "FIPS isn't required at first");
    check(EVP_default_properties_enable_fips(ctx, 1) == 1 && EVP_default_properties_is_fips_enabled(ctx) == 1,
          "enable_fips with no default");
    check(shows(ctx, "fips=yes"), "it's the whole default");
    set(ctx, "provider=default,?output=der,fips=no");
    check(EVP_default_properties_enable_fips(ctx, 7) == 1 && shows(ctx, "?output=der,fips=yes,provider=default"),
          "enable_fips replaces the fips term");
    check(EVP_default_properties_enable_fips(ctx, 0) == 1 && EVP_default_properties_is_fips_enabled(ctx) == 0
              && shows(ctx, "?output=der,-fips,provider=default"),
          "disabling overrides it");
    set(ctx, "fips!=no");
    set(ctx, "fips!=yes");
    set(ctx, "?fips=yes");
    set(ctx, "fips=1");
    set(ctx, "fips='yes'");
    set(ctx, "fips=YES");
    check(set(ctx, NULL) == 1 && shows(ctx, ""), "NULL clears the default");
    OSSL_LIB_CTX_free(ctx);
}

static void default_context(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();

    set(NULL, "provider=default");
    OSSL_LIB_CTX_set0_default(ctx);
    check(shows(NULL, ""), "NULL is the thread's default context");
    set(NULL, "fips=no");
    OSSL_LIB_CTX_set0_default(OSSL_LIB_CTX_get0_global_default());
    check(shows(NULL, "provider=default") && shows(ctx, "fips=no"), "each context has its own");
    set(NULL, NULL);
    OSSL_LIB_CTX_free(ctx);
}

int main(void)
{
    queries();
    lengths();
    order();
    fips();
    default_context();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
