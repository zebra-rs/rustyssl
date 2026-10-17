/*
 * Conformance test for the verification context (X509_STORE_CTX_new(3),
 * X509_STORE_CTX_init(3), X509_STORE_CTX_get_error(3), X509_STORE_CTX_set_verify_cb(3),
 * X509_STORE_CTX_get_by_subject, X509_STORE_CTX_get1_issuer, X509_cmp_timeframe, and
 * X509_verify_cert_error_string(3)), in TAP format: a context's state before and after
 * initialization, with and without a store and its callbacks; each setter and getter; the
 * purpose, trust, and named defaults; searches of the store; issuer lookup in the store and in
 * a trusted list; validity times against the parameters; and every verification error's text.
 * Verifying itself comes with step 5.4b.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

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
    unsigned long e;
    const char *data;
    int flags;

    printf("  errors:");
    while ((e = ERR_get_error_all(NULL, NULL, NULL, &data, &flags)) != 0) {
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
        if ((flags & ERR_TXT_STRING) != 0 && data != NULL && *data != '\0')
            printf(" [%s]", data);
    }
    printf("\n");
}

static const char CA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBXzCCAQSgAwIBAgIBATAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApQdXJwb3Nl\n"
    "IENBMB4XDTI2MTAxNzE0NDYxOVoXDTM2MTAxNDE0NDYxOVowFTETMBEGA1UEAwwK\n"
    "UHVycG9zZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBWjWIRih6WIPZH9\n"
    "yyM92OMGrP0IA1y4D9r8UFgmiVhQ2yk9byExM1oXjHDR9dt6q1lEA9jpqNZ3bnJc\n"
    "62luj0mjRTBDMBIGA1UdEwEB/wQIMAYBAf8CAQIwDgYDVR0PAQH/BAQDAgEGMB0G\n"
    "A1UdDgQWBBQ0lsw8dOxP91kYhXzdnHH3mpLhNTAKBggqhkjOPQQDAgNJADBGAiEA\n"
    "kj2rk1mD4ySwCZoobiJ9MdfoCxdvK6omAzn5TXDujQ8CIQD+Ns1YYa12PfODJ3Fy\n"
    "twUt2FgdVL8c5pnN7he1zcvVCQ==\n"
    "-----END CERTIFICATE-----\n";

static const char SERVER_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBvjCCAWSgAwIBAgIBBzAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApQdXJwb3Nl\n"
    "IENBMB4XDTI2MTAxNzE0NDYxOVoXDTM2MTAxNDE0NDYxOVowETEPMA0GA1UEAwwG\n"
    "c2VydmVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEJmU/wZeX86icApfkgw1\n"
    "Vpwhan4WCwtpPNtvP4/ErxhATPYxrjMQqlv00olStwd324fXxDMKZEuBAO3ucJmK\n"
    "lqOBqDCBpTAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggr\n"
    "BgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFCQZP0LkcWQzli7s4uZl9Y/W6N11\n"
    "MB8GA1UdIwQYMBaAFDSWzDx07E/3WRiFfN2ccfeakuE1MBYGA1UdEQQPMA2CC3d3\n"
    "dy5leGFtcGxlMBEGCWCGSAGG+EIBAQQEAwIGwDAKBggqhkjOPQQDAgNIADBFAiEA\n"
    "xpq7e4/INYzqjxGr0AfLJor5LyrRKl9ea0cR7htWCh4CIECo8YuCNq4t5xl6eRH1\n"
    "xspB6WRZ5yKS6EC7pnA7E+4o\n"
    "-----END CERTIFICATE-----\n";

static const char CRL_PEM[] =
    "-----BEGIN X509 CRL-----\n"
    "MIIBIzCBygIBATAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApQdXJwb3NlIENBFw0y\n"
    "NjEwMTcxNTE1MTFaFw0yNjExMTYxNTE1MTFaMCIwIAIBBxcNMjYxMDE3MTUxNTEx\n"
    "WjAMMAoGA1UdFQQDCgEBoGAwXjAfBgNVHSMEGDAWgBQ0lsw8dOxP91kYhXzdnHH3\n"
    "mpLhNTAvBgNVHRwBAf8EJTAjoB2gG4YZaHR0cDovL2NybC5leGFtcGxlL2NhLmNy\n"
    "bIMCA0gwCgYDVR0UBAMCAREwCgYIKoZIzj0EAwIDSAAwRQIhAI76kr7OV6FMMqpS\n"
    "XIEpew38/kE+CMxyGYwejjVbjhyIAiBH9j8oiP2i3450dKVi0Mivw73uIdPqOT4M\n"
    "1teqCGXpXA==\n"
    "-----END X509 CRL-----\n";

static const char EMPTY_CRL_PEM[] =
    "-----BEGIN X509 CRL-----\n"
    "MIH+MIGmAgEBMAoGCCqGSM49BAMCMBUxEzARBgNVBAMMClB1cnBvc2UgQ0EXDTI2\n"
    "MTAxNzE1MTUxMVoXDTI2MTExNjE1MTUxMVqgYDBeMB8GA1UdIwQYMBaAFDSWzDx0\n"
    "7E/3WRiFfN2ccfeakuE1MC8GA1UdHAEB/wQlMCOgHaAbhhlodHRwOi8vY3JsLmV4\n"
    "YW1wbGUvY2EuY3JsgwIDSDAKBgNVHRQEAwIBEDAKBggqhkjOPQQDAgNHADBEAiA4\n"
    "6lXGdquAsE3ImzQrs5zgAcqjcMl76gREvVZJBZrFxwIgHdUgSR2hJL8mKUlTBA75\n"
    "lcKyjjBI/UsLKszeaJxU73A=\n"
    "-----END X509 CRL-----\n";

static X509 *read_cert(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);

    BIO_free(b);
    return x;
}

static X509_CRL *read_crl(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509_CRL *x = PEM_read_bio_X509_CRL(b, NULL, NULL, NULL);

    BIO_free(b);
    return x;
}

/* A time within the test certificates' validity: 2030-01-01. */
static const time_t WITHIN = 1893456000;

static int my_verify_cb(int ok, X509_STORE_CTX *ctx)
{
    printf("  callback: ok %d, error %d, depth %d\n", ok, X509_STORE_CTX_get_error(ctx),
           X509_STORE_CTX_get_error_depth(ctx));
    return ok;
}

static int my_check_issued(X509_STORE_CTX *ctx, X509 *x, X509 *issuer)
{
    (void)ctx, (void)x, (void)issuer;
    return 0;
}

static int my_cleanup(X509_STORE_CTX *ctx)
{
    (void)ctx;
    printf("  cleanup called\n");
    return 1;
}

static void show_params(const char *label, X509_STORE_CTX *ctx)
{
    X509_VERIFY_PARAM *p = X509_STORE_CTX_get0_param(ctx);

    printf("  %s: flags %#lx, purpose %d, depth %d, level %d, name %s\n", label, X509_VERIFY_PARAM_get_flags(p),
           X509_VERIFY_PARAM_get_purpose(p), X509_VERIFY_PARAM_get_depth(p), X509_VERIFY_PARAM_get_auth_level(p),
           X509_VERIFY_PARAM_get0_name(p) == NULL ? "(none)" : X509_VERIFY_PARAM_get0_name(p));
}

static void show_state(const char *label, X509_STORE_CTX *ctx)
{
    printf("  %s: error %d, depth %d, current %d, issuer %d, crl %d, parent %d, chain %d, untrusted %d,"
           " num_untrusted %d, explicit %d, tree %d, rpk %d\n",
           label, X509_STORE_CTX_get_error(ctx), X509_STORE_CTX_get_error_depth(ctx),
           X509_STORE_CTX_get_current_cert(ctx) != NULL, X509_STORE_CTX_get0_current_issuer(ctx) != NULL,
           X509_STORE_CTX_get0_current_crl(ctx) != NULL, X509_STORE_CTX_get0_parent_ctx(ctx) != NULL,
           X509_STORE_CTX_get0_chain(ctx) != NULL, X509_STORE_CTX_get0_untrusted(ctx) != NULL,
           X509_STORE_CTX_get_num_untrusted(ctx), X509_STORE_CTX_get_explicit_policy(ctx),
           X509_STORE_CTX_get0_policy_tree(ctx) != NULL, X509_STORE_CTX_get0_rpk(ctx) != NULL);
}

static void show_fns(const char *label, X509_STORE_CTX *ctx)
{
    printf("  %s: verify %d, cb %d, get_issuer %d, check_issued %d, revocation %d, get_crl %d, check_crl %d,"
           " cert_crl %d, policy %d, lookup_certs %d, lookup_crls %d, cleanup %d\n",
           label, X509_STORE_CTX_get_verify(ctx) != NULL, X509_STORE_CTX_get_verify_cb(ctx) != NULL,
           X509_STORE_CTX_get_get_issuer(ctx) != NULL, X509_STORE_CTX_get_check_issued(ctx) != NULL,
           X509_STORE_CTX_get_check_revocation(ctx) != NULL, X509_STORE_CTX_get_get_crl(ctx) != NULL,
           X509_STORE_CTX_get_check_crl(ctx) != NULL, X509_STORE_CTX_get_cert_crl(ctx) != NULL,
           X509_STORE_CTX_get_check_policy(ctx) != NULL, X509_STORE_CTX_get_lookup_certs(ctx) != NULL,
           X509_STORE_CTX_get_lookup_crls(ctx) != NULL, X509_STORE_CTX_get_cleanup(ctx) != NULL);
}

static void test_lifecycle(X509 *ca, X509 *server)
{
    X509_STORE_CTX *ctx = X509_STORE_CTX_new(), *ex = X509_STORE_CTX_new_ex(NULL, "provider=default");
    X509_STORE *store = X509_STORE_new();
    STACK_OF(X509) *untrusted = sk_X509_new_null(), *chain, *got;
    int idx = X509_STORE_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    static int marker;

    printf("# lifecycle\n");
    check(ctx != NULL && ex != NULL, "new");
    sk_X509_push(untrusted, ca);
    check(X509_STORE_CTX_init(ctx, NULL, server, untrusted) == 1, "init without a store");
    show_state("no store", ctx);
    show_fns("no store", ctx);
    show_params("no store", ctx);
    check(X509_STORE_CTX_get0_cert(ctx) == server && X509_STORE_CTX_get0_untrusted(ctx) == untrusted
              && X509_STORE_CTX_get0_store(ctx) == NULL,
          "its certificate, untrusted list, and store");
    X509_STORE_set_verify_cb(store, my_verify_cb);
    X509_STORE_set_check_issued(store, my_check_issued);
    X509_STORE_set_cleanup(store, my_cleanup);
    X509_STORE_set_flags(store, X509_V_FLAG_X509_STRICT);
    X509_STORE_set_purpose(store, X509_PURPOSE_SSL_CLIENT);
    X509_STORE_set_depth(store, 3);
    check(X509_STORE_CTX_init(ex, store, server, NULL) == 1, "init with a store");
    show_fns("store", ex);
    show_params("store", ex);
    check(X509_STORE_CTX_get_verify_cb(ex) == my_verify_cb && X509_STORE_CTX_get_check_issued(ex) == my_check_issued
              && X509_STORE_CTX_get_cleanup(ex) == my_cleanup,
          "the store's callbacks");
    check(X509_STORE_CTX_get_ex_data(ex, idx) == NULL, "no data");
    check(X509_STORE_CTX_set_ex_data(ex, idx, &marker) == 1 && X509_STORE_CTX_get_ex_data(ex, idx) == &marker, "data");
    X509_STORE_CTX_cleanup(ex);
    show_fns("cleaned up", ex);
    check(X509_STORE_CTX_get0_param(ex) == NULL, "no parameters after cleanup");
    check(X509_STORE_CTX_init(ex, store, NULL, NULL) == 1, "init again");
    check(X509_STORE_CTX_init_rpk(ex, store, NULL) == 1 && X509_STORE_CTX_get0_rpk(ex) == NULL, "init for a raw public key");
    check(X509_STORE_CTX_init(NULL, store, NULL, NULL) == 0, "init nothing");
    errors();

    printf("# setters\n");
    X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REVOKED);
    X509_STORE_CTX_set_error_depth(ctx, 2);
    X509_STORE_CTX_set_current_cert(ctx, ca);
    X509_STORE_CTX_set_cert(ctx, ca);
    X509_STORE_CTX_set0_untrusted(ctx, NULL);
    X509_STORE_CTX_set0_crls(ctx, NULL);
    X509_STORE_CTX_set_current_reasons(ctx, 3);
    show_state("set", ctx);
    check(X509_STORE_CTX_get0_cert(ctx) == ca, "the certificate");
    chain = sk_X509_new_null();
    X509_up_ref(server);
    X509_up_ref(ca);
    sk_X509_push(chain, server);
    sk_X509_push(chain, ca);
    X509_STORE_CTX_set0_verified_chain(ctx, chain);
    got = X509_STORE_CTX_get1_chain(ctx);
    printf("  chain %d, got %d, first %d\n", sk_X509_num(X509_STORE_CTX_get0_chain(ctx)), sk_X509_num(got),
           sk_X509_value(got, 0) == server);
    OSSL_STACK_OF_X509_free(got);
    X509_STORE_CTX_set_verify_cb(ctx, my_verify_cb);
    X509_STORE_CTX_set_verify(ctx, NULL);
    X509_STORE_CTX_set_get_crl(ctx, NULL);
    show_fns("set", ctx);
    X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_CRL_CHECK);
    X509_STORE_CTX_set_depth(ctx, 7);
    X509_STORE_CTX_set_time(ctx, 0, WITHIN);
    show_params("set", ctx);
    printf("  time %ld\n", (long)X509_VERIFY_PARAM_get_time(X509_STORE_CTX_get0_param(ctx)));
    X509_STORE_CTX_set0_rpk(ctx, NULL);
    X509_STORE_CTX_set0_dane(ctx, NULL);
    X509_STORE_CTX_free(ctx);

    printf("# purpose and trust\n");
    ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, NULL, server, NULL);
    check(X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_SSL_SERVER) == 1, "a purpose");
    show_params("purpose", ctx);
    check(X509_STORE_CTX_set_purpose(ctx, 999) == 0, "an unknown purpose");
    errors();
    check(X509_STORE_CTX_set_trust(ctx, X509_TRUST_EMAIL) == 1, "a trust");
    check(X509_STORE_CTX_set_trust(ctx, 999) == 0, "an unknown trust");
    errors();
    check(X509_STORE_CTX_purpose_inherit(ctx, X509_PURPOSE_ANY, 0, 0) == 1, "inherit any");
    check(X509_STORE_CTX_purpose_inherit(ctx, 0, X509_PURPOSE_ANY, 0) == 1, "any, with its default trust");
    check(X509_STORE_CTX_purpose_inherit(ctx, 998, X509_PURPOSE_ANY, 0) == 0, "an unknown default");
    errors();
    check(X509_STORE_CTX_set_default(ctx, "ssl_client") == 1, "ssl_client defaults");
    show_params("ssl_client", ctx);
    check(X509_STORE_CTX_set_default(ctx, "nope") == 0, "unknown defaults");
    errors();
    X509_STORE_CTX_set0_param(ctx, X509_VERIFY_PARAM_new());
    show_params("new parameters", ctx);
    X509_STORE_CTX_free(ctx);

    X509_STORE_CTX_free(ex);
    X509_STORE_CTX_free(NULL);
    X509_STORE_free(store);
    sk_X509_free(untrusted);
}

static void test_searches(X509 *ca, X509 *server, X509_CRL *crl, X509_CRL *empty)
{
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509_OBJECT *obj = X509_OBJECT_new(), *got;
    STACK_OF(X509) *certs, *trusted = sk_X509_new_null();
    STACK_OF(X509_CRL) *crls;
    X509 *issuer = NULL;
    X509_STORE_CTX_get_issuer_fn get_issuer;
    X509_STORE_CTX_check_issued_fn check_issued;

    printf("# searches\n");
    X509_STORE_add_cert(store, ca);
    X509_STORE_add_crl(store, crl);
    X509_STORE_add_crl(store, empty);
    X509_STORE_CTX_init(ctx, store, server, NULL);
    X509_STORE_CTX_set_time(ctx, 0, WITHIN);
    printf("  CA by subject: %d, %d\n", X509_STORE_CTX_get_by_subject(ctx, X509_LU_X509, X509_get_subject_name(ca), obj),
           X509_OBJECT_get0_X509(obj) == ca);
    printf("  server by subject: %d\n",
           X509_STORE_CTX_get_by_subject(ctx, X509_LU_X509, X509_get_subject_name(server), NULL));
    got = X509_STORE_CTX_get_obj_by_subject(ctx, X509_LU_CRL, X509_get_subject_name(ca));
    printf("  a CRL object: %d\n", got != NULL && X509_OBJECT_get0_X509_CRL(got) != NULL);
    X509_OBJECT_free(got);
    got = X509_STORE_CTX_get_obj_by_subject(ctx, X509_LU_X509, X509_get_subject_name(server));
    printf("  no server object: %d\n", got == NULL);
    certs = X509_STORE_CTX_get1_certs(ctx, X509_get_subject_name(ca));
    printf("  certs named the CA: %d\n", sk_X509_num(certs));
    OSSL_STACK_OF_X509_free(certs);
    certs = X509_STORE_CTX_get1_certs(ctx, X509_get_subject_name(server));
    printf("  certs named the server: %d\n", sk_X509_num(certs));
    OSSL_STACK_OF_X509_free(certs);
    crls = X509_STORE_CTX_get1_crls(ctx, X509_get_subject_name(ca));
    printf("  CRLs of the CA: %d\n", sk_X509_CRL_num(crls));
    sk_X509_CRL_pop_free(crls, X509_CRL_free);
    crls = X509_STORE_CTX_get1_crls(ctx, X509_get_subject_name(server));
    printf("  CRLs of the server: %d\n", sk_X509_CRL_num(crls));
    sk_X509_CRL_pop_free(crls, X509_CRL_free);

    printf("# issuers\n");
    check_issued = X509_STORE_CTX_get_check_issued(ctx);
    printf("  check_issued: CA of server %d, server of CA %d\n", check_issued(ctx, server, ca), check_issued(ctx, ca, server));
    printf("  get1_issuer: %d, the CA %d\n", X509_STORE_CTX_get1_issuer(&issuer, ctx, server), issuer == ca);
    X509_free(issuer);
    issuer = NULL;
    printf("  of the CA: %d, the CA %d\n", X509_STORE_CTX_get1_issuer(&issuer, ctx, ca), issuer == ca);
    X509_free(issuer);
    issuer = NULL;
    get_issuer = X509_STORE_CTX_get_get_issuer(ctx);
    printf("  the default lookup: %d, the CA %d\n", get_issuer(&issuer, ctx, server), issuer == ca);
    X509_free(issuer);
    issuer = NULL;
    X509_STORE_CTX_set_time(ctx, 0, 0);
    printf("  in 1970: %d, the CA %d\n", X509_STORE_CTX_get1_issuer(&issuer, ctx, server), issuer == ca);
    X509_free(issuer);
    issuer = NULL;
    X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_NO_CHECK_TIME);
    sk_X509_push(trusted, ca);
    X509_STORE_CTX_set0_trusted_stack(ctx, trusted);
    get_issuer = X509_STORE_CTX_get_get_issuer(ctx);
    printf("  the trusted list: %d, the CA %d\n", get_issuer(&issuer, ctx, server), issuer == ca);
    X509_free(issuer);
    issuer = NULL;
    certs = X509_STORE_CTX_get_lookup_certs(ctx)(ctx, X509_get_subject_name(ca));
    printf("  the trusted list's certs named the CA: %d\n", sk_X509_num(certs));
    OSSL_STACK_OF_X509_free(certs);
    printf("  none: %d, issuer %d\n", get_issuer(&issuer, ctx, ca) , issuer != NULL);
    X509_free(issuer);
    errors();
    X509_OBJECT_free(obj);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(trusted);
}

static void test_timeframe(X509 *ca)
{
    X509_VERIFY_PARAM *p = X509_VERIFY_PARAM_new();
    const ASN1_TIME *nb = X509_get0_notBefore(ca), *na = X509_get0_notAfter(ca);

    printf("# timeframe\n");
    X509_VERIFY_PARAM_set_time(p, WITHIN);
    printf("  within %d, start only %d, end only %d, none %d\n", X509_cmp_timeframe(p, nb, na),
           X509_cmp_timeframe(p, nb, NULL), X509_cmp_timeframe(p, NULL, na), X509_cmp_timeframe(p, NULL, NULL));
    X509_VERIFY_PARAM_set_time(p, 0);
    printf("  before %d\n", X509_cmp_timeframe(p, nb, na));
    X509_VERIFY_PARAM_set_time(p, (time_t)4102444800);
    printf("  after %d\n", X509_cmp_timeframe(p, nb, na));
    X509_VERIFY_PARAM_clear_flags(p, X509_V_FLAG_USE_CHECK_TIME);
    X509_VERIFY_PARAM_set_flags(p, X509_V_FLAG_NO_CHECK_TIME);
    printf("  no check %d\n", X509_cmp_timeframe(p, nb, na));
    X509_VERIFY_PARAM_free(p);
}

static void test_strings(void)
{
    long n;

    printf("# error strings\n");
    for (n = -2; n <= 100; n++)
        printf("  %ld: %s\n", n, X509_verify_cert_error_string(n));
    printf("  4294967296: %s\n", X509_verify_cert_error_string(4294967296L));
    printf("  4294967298: %s\n", X509_verify_cert_error_string(4294967298L));
}

int main(void)
{
    X509 *ca = read_cert(CA_PEM), *server = read_cert(SERVER_PEM);
    X509_CRL *crl = read_crl(CRL_PEM), *empty = read_crl(EMPTY_CRL_PEM);

    test_lifecycle(ca, server);
    test_searches(ca, server, crl, empty);
    test_timeframe(ca);
    test_strings();
    X509_free(ca);
    X509_free(server);
    X509_CRL_free(crl);
    X509_CRL_free(empty);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
