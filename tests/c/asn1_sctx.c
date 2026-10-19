/*
 * Conformance test for the ASN.1 scanner context (ASN1_SCTX_new and its accessors in asn1.h),
 * in TAP format.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both (TEST_PLAN.md, layer L4). OpenSSL 3.5 has no function that
 * scans with the context, so a new one's item, template, and flags stay unset.
 */
#include <stdio.h>

#include <openssl/asn1.h>

static int failures = 0;
static int number = 0;
static int calls = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

static int scan(ASN1_SCTX *ctx)
{
    (void)ctx;
    calls++;
    return 1;
}

int main(void)
{
    ASN1_SCTX *s = ASN1_SCTX_new(scan), *t = ASN1_SCTX_new(NULL);
    int data = 7;

    check(s != NULL && t != NULL, "ASN1_SCTX_new, with and without a callback");
    check(ASN1_SCTX_get_item(s) == NULL, "no item");
    check(ASN1_SCTX_get_template(s) == NULL, "no template");
    check(ASN1_SCTX_get_flags(s) == 0, "no flags");
    check(ASN1_SCTX_get_app_data(s) == NULL, "no application data at first");
    ASN1_SCTX_set_app_data(s, &data);
    check(ASN1_SCTX_get_app_data(s) == &data, "ASN1_SCTX_set_app_data");
    check(ASN1_SCTX_get_app_data(t) == NULL, "each context has its own");
    ASN1_SCTX_set_app_data(s, NULL);
    check(ASN1_SCTX_get_app_data(s) == NULL, "set back to NULL");
    check(calls == 0, "the callback isn't called");
    ASN1_SCTX_free(s);
    ASN1_SCTX_free(t);
    ASN1_SCTX_free(NULL);
    check(1, "ASN1_SCTX_free, also of NULL");
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
