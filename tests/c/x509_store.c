/*
 * Conformance test for the certificate store and its lookups (X509_STORE_new(3),
 * X509_STORE_add_cert(3), X509_STORE_load_locations(3), X509_STORE_set_default_paths(3),
 * X509_OBJECT_new, X509_LOOKUP_new(3), X509_LOOKUP_meth_new(3), X509_LOOKUP_hash_dir(3),
 * X509_load_cert_file), in TAP format: objects; a store's objects, sorting, and searches; its
 * parameters, callbacks, and application data; an application's lookup method and each of
 * its functions; the built-in methods; files (PEM and DER) and hashed directories loaded;
 * and the default paths from the environment.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

    printf("  errors:");
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
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

static const char *type_name(X509_LOOKUP_TYPE t)
{
    return t == X509_LU_X509 ? "cert" : t == X509_LU_CRL ? "crl" : "none";
}

static void name_of(char *buf, size_t n, X509_OBJECT *o)
{
    X509 *x = X509_OBJECT_get0_X509(o);
    X509_CRL *c = X509_OBJECT_get0_X509_CRL(o);
    const X509_NAME *nm = x != NULL ? X509_get_subject_name(x) : c != NULL ? X509_CRL_get_issuer(c) : NULL;

    if (nm == NULL)
        snprintf(buf, n, "-");
    else
        X509_NAME_oneline(nm, buf, (int)n);
}

static void show_objects(const char *label, STACK_OF(X509_OBJECT) *objs)
{
    int i;
    char buf[128];

    printf("  %s: %d:", label, sk_X509_OBJECT_num(objs));
    for (i = 0; i < sk_X509_OBJECT_num(objs); i++) {
        X509_OBJECT *o = sk_X509_OBJECT_value(objs, i);

        name_of(buf, sizeof(buf), o);
        printf(" [%s %s]", type_name(X509_OBJECT_get_type(o)), buf);
    }
    printf("\n");
}

static void test_objects(X509 *ca, X509_CRL *crl)
{
    X509_OBJECT *o = X509_OBJECT_new();

    printf("# objects\n");
    printf("  new: %s, cert %d, crl %d\n", type_name(X509_OBJECT_get_type(o)), X509_OBJECT_get0_X509(o) != NULL,
           X509_OBJECT_get0_X509_CRL(o) != NULL);
    check(X509_OBJECT_up_ref_count(o) == 1, "no type: up_ref_count is 1");
    check(X509_OBJECT_set1_X509(o, ca) == 1, "set a certificate");
    printf("  %s, cert %d, crl %d\n", type_name(X509_OBJECT_get_type(o)), X509_OBJECT_get0_X509(o) == ca,
           X509_OBJECT_get0_X509_CRL(o) != NULL);
    check(X509_OBJECT_up_ref_count(o) == 1, "up_ref_count");
    X509_free(ca);
    check(X509_OBJECT_set1_X509_CRL(o, crl) == 1, "set a CRL");
    printf("  %s, cert %d, crl %d\n", type_name(X509_OBJECT_get_type(o)), X509_OBJECT_get0_X509(o) != NULL,
           X509_OBJECT_get0_X509_CRL(o) == crl);
    check(X509_OBJECT_set1_X509(NULL, ca) == 0, "set into nothing");
    check(X509_OBJECT_get0_X509(NULL) == NULL && X509_OBJECT_get0_X509_CRL(NULL) == NULL, "NULL objects");
    errors();
    X509_OBJECT_free(o);
    X509_OBJECT_free(NULL);
}

static int verify_fn(X509_STORE_CTX *ctx)
{
    (void)ctx;
    return 1;
}

static int verify_cb(int ok, X509_STORE_CTX *ctx)
{
    (void)ctx;
    return ok;
}

static int get_issuer(X509 **issuer, X509_STORE_CTX *ctx, X509 *x)
{
    (void)issuer, (void)ctx, (void)x;
    return 0;
}

static int check_issued(X509_STORE_CTX *ctx, X509 *x, X509 *issuer)
{
    (void)ctx, (void)x, (void)issuer;
    return 0;
}

static int ctx_only(X509_STORE_CTX *ctx)
{
    (void)ctx;
    return 0;
}

static int get_crl(X509_STORE_CTX *ctx, X509_CRL **crl, X509 *x)
{
    (void)ctx, (void)crl, (void)x;
    return 0;
}

static int check_crl(X509_STORE_CTX *ctx, X509_CRL *crl)
{
    (void)ctx, (void)crl;
    return 0;
}

static int cert_crl(X509_STORE_CTX *ctx, X509_CRL *crl, X509 *x)
{
    (void)ctx, (void)crl, (void)x;
    return 0;
}

static STACK_OF(X509) *lookup_certs(X509_STORE_CTX *ctx, const X509_NAME *nm)
{
    (void)ctx, (void)nm;
    return NULL;
}

static STACK_OF(X509_CRL) *lookup_crls(const X509_STORE_CTX *ctx, const X509_NAME *nm)
{
    (void)ctx, (void)nm;
    return NULL;
}

static void test_callbacks(X509_STORE *s)
{
    int idx = X509_STORE_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    static int marker;

    printf("# callbacks\n");
    printf("  defaults: %d%d%d%d%d%d%d%d%d%d%d%d\n", X509_STORE_get_verify(s) == NULL,
           X509_STORE_get_verify_cb(s) == NULL, X509_STORE_get_get_issuer(s) == NULL,
           X509_STORE_get_check_issued(s) == NULL, X509_STORE_get_check_revocation(s) == NULL,
           X509_STORE_get_get_crl(s) == NULL, X509_STORE_get_check_crl(s) == NULL,
           X509_STORE_get_cert_crl(s) == NULL, X509_STORE_get_check_policy(s) == NULL,
           X509_STORE_get_lookup_certs(s) == NULL, X509_STORE_get_lookup_crls(s) == NULL,
           X509_STORE_get_cleanup(s) == NULL);
    X509_STORE_set_verify(s, verify_fn);
    X509_STORE_set_verify_cb(s, verify_cb);
    X509_STORE_set_get_issuer(s, get_issuer);
    X509_STORE_set_check_issued(s, check_issued);
    X509_STORE_set_check_revocation(s, ctx_only);
    X509_STORE_set_get_crl(s, get_crl);
    X509_STORE_set_check_crl(s, check_crl);
    X509_STORE_set_cert_crl(s, cert_crl);
    X509_STORE_set_check_policy(s, ctx_only);
    X509_STORE_set_lookup_certs(s, lookup_certs);
    X509_STORE_set_lookup_crls(s, lookup_crls);
    X509_STORE_set_cleanup(s, ctx_only);
    printf("  set: %d%d%d%d%d%d%d%d%d%d%d%d\n", X509_STORE_get_verify(s) == verify_fn,
           X509_STORE_get_verify_cb(s) == verify_cb, X509_STORE_get_get_issuer(s) == get_issuer,
           X509_STORE_get_check_issued(s) == check_issued, X509_STORE_get_check_revocation(s) == ctx_only,
           X509_STORE_get_get_crl(s) == get_crl, X509_STORE_get_check_crl(s) == check_crl,
           X509_STORE_get_cert_crl(s) == cert_crl, X509_STORE_get_check_policy(s) == ctx_only,
           X509_STORE_get_lookup_certs(s) == lookup_certs, X509_STORE_get_lookup_crls(s) == lookup_crls,
           X509_STORE_get_cleanup(s) == ctx_only);
    X509_STORE_set_verify_cb(s, NULL);
    printf("  cleared: %d\n", X509_STORE_get_verify_cb(s) == NULL);
    check(idx > 0, "an ex_data index");
    check(X509_STORE_get_ex_data(s, idx) == NULL, "no data yet");
    check(X509_STORE_set_ex_data(s, idx, &marker) == 1, "set data");
    check(X509_STORE_get_ex_data(s, idx) == &marker, "get it");
}

static void test_params(X509_STORE *s)
{
    X509_VERIFY_PARAM *p = X509_VERIFY_PARAM_new();

    printf("# parameters\n");
    check(X509_STORE_set_flags(s, X509_V_FLAG_CRL_CHECK) == 1, "flags");
    check(X509_STORE_set_depth(s, 4) == 1, "depth");
    check(X509_STORE_set_purpose(s, X509_PURPOSE_SSL_SERVER) == 1, "purpose");
    check(X509_STORE_set_purpose(s, 999) == 0, "an unknown purpose");
    errors();
    check(X509_STORE_set_trust(s, X509_TRUST_SSL_SERVER) == 1, "trust");
    X509_VERIFY_PARAM_set_auth_level(p, 3);
    check(X509_STORE_set1_param(s, p) == 1, "set1_param");
    printf("  flags %#lx, depth %d, purpose %d, level %d\n", X509_VERIFY_PARAM_get_flags(X509_STORE_get0_param(s)),
           X509_VERIFY_PARAM_get_depth(X509_STORE_get0_param(s)),
           X509_VERIFY_PARAM_get_purpose(X509_STORE_get0_param(s)),
           X509_VERIFY_PARAM_get_auth_level(X509_STORE_get0_param(s)));
    X509_VERIFY_PARAM_free(p);
}

static void test_store(X509 *ca, X509 *server, X509_CRL *crl, X509_CRL *empty)
{
    X509_STORE *s = X509_STORE_new();
    STACK_OF(X509_OBJECT) *copy;
    STACK_OF(X509) *certs;
    X509_OBJECT *probe = X509_OBJECT_new(), *found;
    char buf[128];

    printf("# store\n");
    check(X509_STORE_up_ref(s) == 1, "up_ref");
    X509_STORE_free(s);
    check(X509_STORE_add_cert(s, server) == 1, "add the server");
    check(X509_STORE_add_cert(s, ca) == 1, "add the CA");
    check(X509_STORE_add_cert(s, ca) == 1, "add the CA again");
    check(X509_STORE_add_crl(s, crl) == 1, "add a CRL");
    check(X509_STORE_add_crl(s, empty) == 1, "add another");
    check(X509_STORE_add_crl(s, crl) == 1, "add the first again");
    check(X509_STORE_add_cert(s, NULL) == 0, "add NULL");
    errors();
    show_objects("objects", X509_STORE_get0_objects(s));
    printf("  CA's index %d\n", X509_OBJECT_idx_by_subject(X509_STORE_get0_objects(s), X509_LU_X509,
                                                            X509_get_subject_name(ca)));
    show_objects("searched", X509_STORE_get0_objects(s));
    printf("  CRL's index %d, none's %d\n",
           X509_OBJECT_idx_by_subject(X509_STORE_get0_objects(s), X509_LU_CRL, X509_get_subject_name(ca)),
           X509_OBJECT_idx_by_subject(X509_STORE_get0_objects(s), X509_LU_NONE, X509_get_subject_name(ca)));
    found = X509_OBJECT_retrieve_by_subject(X509_STORE_get0_objects(s), X509_LU_X509, X509_get_subject_name(server));
    name_of(buf, sizeof(buf), found);
    printf("  by subject: %s\n", found == NULL ? "none" : buf);
    found = X509_OBJECT_retrieve_by_subject(X509_STORE_get0_objects(s), X509_LU_X509, X509_CRL_get_issuer(crl));
    printf("  CA by the CRL's issuer: %d\n", found != NULL && X509_OBJECT_get0_X509(found) == ca);
    X509_OBJECT_set1_X509(probe, ca);
    found = X509_OBJECT_retrieve_match(X509_STORE_get0_objects(s), probe);
    printf("  match of the CA: %d\n", found != NULL && X509_OBJECT_get0_X509(found) == ca);
    X509_OBJECT_set1_X509_CRL(probe, empty);
    found = X509_OBJECT_retrieve_match(X509_STORE_get0_objects(s), probe);
    printf("  match of the empty CRL: %d\n", found != NULL && X509_OBJECT_get0_X509_CRL(found) == empty);
    X509_OBJECT_free(probe);
    copy = X509_STORE_get1_objects(s);
    show_objects("copy", copy);
    sk_X509_OBJECT_pop_free(copy, X509_OBJECT_free);
    certs = X509_STORE_get1_all_certs(s);
    printf("  all certs: %d\n", sk_X509_num(certs));
    OSSL_STACK_OF_X509_free(certs);
    check(X509_STORE_get1_objects(NULL) == NULL && X509_STORE_get1_all_certs(NULL) == NULL, "no store");
    errors();
    check(X509_STORE_lock(s) == 1, "lock");
    printf("  objects while locked: %d\n", sk_X509_OBJECT_num(X509_STORE_get0_objects(s)));
    check(X509_STORE_unlock(s) == 1, "unlock");
    test_callbacks(s);
    test_params(s);
    X509_STORE_free(s);
    X509_STORE_free(NULL);
}

/* An application's lookup method, each function counting its calls. */
static int calls[9];

static int my_new_item(X509_LOOKUP *ctx)
{
    calls[0]++;
    return X509_LOOKUP_set_method_data(ctx, calls);
}

static void my_free(X509_LOOKUP *ctx)
{
    (void)ctx;
    calls[1]++;
}

static int my_init(X509_LOOKUP *ctx)
{
    (void)ctx;
    calls[2]++;
    return 7;
}

static int my_shutdown(X509_LOOKUP *ctx)
{
    (void)ctx;
    calls[3]++;
    return 8;
}

static int my_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc, long argl, char **ret)
{
    (void)ctx, (void)ret;
    calls[4]++;
    printf("  ctrl %d [%s] %ld\n", cmd, argc == NULL ? "-" : argc, argl);
    return 5;
}

static int my_by_subject(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type, const X509_NAME *name, X509_OBJECT *ret)
{
    (void)ctx, (void)name, (void)ret;
    calls[5]++;
    return (int)type + 10;
}

static int my_by_issuer_serial(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type, const X509_NAME *name,
                               const ASN1_INTEGER *serial, X509_OBJECT *ret)
{
    (void)ctx, (void)name, (void)ret;
    calls[6]++;
    return (int)type + (int)ASN1_INTEGER_get(serial);
}

static int my_by_fingerprint(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type, const unsigned char *bytes, int len,
                             X509_OBJECT *ret)
{
    (void)ctx, (void)type, (void)bytes, (void)ret;
    calls[7]++;
    return len;
}

static int my_by_alias(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type, const char *str, int len, X509_OBJECT *ret)
{
    (void)ctx, (void)type, (void)str, (void)ret;
    calls[8]++;
    return len * 2;
}

static void show_method(const char *label, const X509_LOOKUP_METHOD *m)
{
    printf("  %s: %d%d%d%d%d%d%d%d%d\n", label, X509_LOOKUP_meth_get_new_item(m) != NULL,
           X509_LOOKUP_meth_get_free(m) != NULL, X509_LOOKUP_meth_get_init(m) != NULL,
           X509_LOOKUP_meth_get_shutdown(m) != NULL, X509_LOOKUP_meth_get_ctrl(m) != NULL,
           X509_LOOKUP_meth_get_get_by_subject(m) != NULL, X509_LOOKUP_meth_get_get_by_issuer_serial(m) != NULL,
           X509_LOOKUP_meth_get_get_by_fingerprint(m) != NULL, X509_LOOKUP_meth_get_get_by_alias(m) != NULL);
}

static void test_methods(X509 *ca)
{
    X509_LOOKUP_METHOD *m = X509_LOOKUP_meth_new("custom");
    X509_STORE *s = X509_STORE_new();
    X509_LOOKUP *lu, *again, *bare;
    X509_OBJECT *o = X509_OBJECT_new();
    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    int i;

    printf("# methods\n");
    show_method("file", X509_LOOKUP_file());
    show_method("hash_dir", X509_LOOKUP_hash_dir());
    show_method("store", X509_LOOKUP_store());
    show_method("custom", m);
    check(X509_LOOKUP_meth_set_new_item(m, my_new_item) == 1, "set new_item");
    check(X509_LOOKUP_meth_set_free(m, my_free) == 1, "set free");
    check(X509_LOOKUP_meth_set_init(m, my_init) == 1, "set init");
    check(X509_LOOKUP_meth_set_shutdown(m, my_shutdown) == 1, "set shutdown");
    check(X509_LOOKUP_meth_set_ctrl(m, my_ctrl) == 1, "set ctrl");
    check(X509_LOOKUP_meth_set_get_by_subject(m, my_by_subject) == 1, "set get_by_subject");
    check(X509_LOOKUP_meth_set_get_by_issuer_serial(m, my_by_issuer_serial) == 1, "set get_by_issuer_serial");
    check(X509_LOOKUP_meth_set_get_by_fingerprint(m, my_by_fingerprint) == 1, "set get_by_fingerprint");
    check(X509_LOOKUP_meth_set_get_by_alias(m, my_by_alias) == 1, "set get_by_alias");
    show_method("custom", m);
    printf("  same: %d%d%d%d%d%d%d%d%d\n", X509_LOOKUP_meth_get_new_item(m) == my_new_item,
           X509_LOOKUP_meth_get_free(m) == my_free, X509_LOOKUP_meth_get_init(m) == my_init,
           X509_LOOKUP_meth_get_shutdown(m) == my_shutdown, X509_LOOKUP_meth_get_ctrl(m) == my_ctrl,
           X509_LOOKUP_meth_get_get_by_subject(m) == my_by_subject,
           X509_LOOKUP_meth_get_get_by_issuer_serial(m) == my_by_issuer_serial,
           X509_LOOKUP_meth_get_get_by_fingerprint(m) == my_by_fingerprint,
           X509_LOOKUP_meth_get_get_by_alias(m) == my_by_alias);

    lu = X509_STORE_add_lookup(s, m);
    again = X509_STORE_add_lookup(s, m);
    check(lu != NULL && lu == again, "one lookup per method");
    check(X509_LOOKUP_get_store(lu) == s, "its store");
    check(X509_LOOKUP_get_method_data(lu) == calls, "new_item set its data");
    printf("  init %d, shutdown %d, ctrl %d\n", X509_LOOKUP_init(lu), X509_LOOKUP_shutdown(lu),
           X509_LOOKUP_ctrl(lu, 42, "arg", 9, NULL));
    printf("  ctrl_ex %d\n", X509_LOOKUP_ctrl_ex(lu, 43, NULL, -1, NULL, NULL, NULL));
    ASN1_INTEGER_set(serial, 100);
    printf("  by subject %d, ex %d, by issuer and serial %d, by fingerprint %d, by alias %d\n",
           X509_LOOKUP_by_subject(lu, X509_LU_CRL, X509_get_subject_name(ca), o),
           X509_LOOKUP_by_subject_ex(lu, X509_LU_X509, X509_get_subject_name(ca), o, NULL, NULL),
           X509_LOOKUP_by_issuer_serial(lu, X509_LU_X509, X509_get_subject_name(ca), serial, o),
           X509_LOOKUP_by_fingerprint(lu, X509_LU_X509, (const unsigned char *)"abcd", 4, o),
           X509_LOOKUP_by_alias(lu, X509_LU_X509, "alias", 5, o));
    check(X509_LOOKUP_set_method_data(lu, NULL) == 1, "clear its data");
    printf("  built-in lookups: by issuer and serial %d, by fingerprint %d, by alias %d\n",
           X509_LOOKUP_by_issuer_serial(X509_STORE_add_lookup(s, X509_LOOKUP_file()), X509_LU_X509,
                                        X509_get_subject_name(ca), serial, o),
           X509_LOOKUP_by_fingerprint(X509_STORE_add_lookup(s, X509_LOOKUP_file()), X509_LU_X509,
                                      (const unsigned char *)"x", 1, o),
           X509_LOOKUP_by_alias(X509_STORE_add_lookup(s, X509_LOOKUP_file()), X509_LU_X509, "x", 1, o));
    printf("  the file lookup by subject %d, an unknown ctrl %d\n",
           X509_LOOKUP_by_subject(X509_STORE_add_lookup(s, X509_LOOKUP_file()), X509_LU_X509,
                                  X509_get_subject_name(ca), o),
           X509_LOOKUP_ctrl(X509_STORE_add_lookup(s, X509_LOOKUP_file()), 99, NULL, 0, NULL));
    bare = X509_LOOKUP_new(m);
    check(bare != NULL, "a lookup of its own");
    X509_LOOKUP_free(bare);
    X509_LOOKUP_free(NULL);
    X509_STORE_free(s);
    printf("  calls:");
    for (i = 0; i < 9; i++)
        printf(" %d", calls[i]);
    printf("\n");
    X509_LOOKUP_meth_free(m);
    X509_LOOKUP_meth_free(NULL);
    X509_OBJECT_free(o);
    ASN1_INTEGER_free(serial);
    errors();
}

static char dir[256], bundle[300], derfile[300], crlder[300], junk[300];

static void write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");

    fputs(text, f);
    fclose(f);
}

static void write_der(const char *path, const unsigned char *der, int len)
{
    FILE *f = fopen(path, "wb");

    fwrite(der, 1, (size_t)len, f);
    fclose(f);
}

static void hashed(const X509_NAME *name, const char *suffix, const char *text)
{
    char path[400];

    snprintf(path, sizeof(path), "%s/%08lx.%s", dir, X509_NAME_hash_ex(name, NULL, NULL, NULL), suffix);
    write_file(path, text);
}

static void setup(X509 *ca, X509_CRL *crl)
{
    const char *tmp = getenv("TMPDIR");
    char text[8192];
    unsigned char *der = NULL;
    int len;

    snprintf(dir, sizeof(dir), "%s/x509_store.%ld", tmp == NULL || *tmp == '\0' ? "/tmp" : tmp, (long)getpid());
    mkdir(dir, 0700);
    snprintf(bundle, sizeof(bundle), "%s/bundle.pem", dir);
    snprintf(derfile, sizeof(derfile), "%s/ca.der", dir);
    snprintf(crlder, sizeof(crlder), "%s/crl.der", dir);
    snprintf(junk, sizeof(junk), "%s/junk.pem", dir);
    snprintf(text, sizeof(text), "%s%s%s", CA_PEM, SERVER_PEM, CRL_PEM);
    write_file(bundle, text);
    len = i2d_X509(ca, &der);
    write_der(derfile, der, len);
    OPENSSL_free(der);
    der = NULL;
    len = i2d_X509_CRL(crl, &der);
    write_der(crlder, der, len);
    OPENSSL_free(der);
    write_file(junk, "no PEM here\n");
    hashed(X509_get_subject_name(ca), "0", CA_PEM);
    hashed(X509_get_subject_name(ca), "1", SERVER_PEM);
    hashed(X509_get_subject_name(ca), "r0", CRL_PEM);
    hashed(X509_get_subject_name(ca), "r1", EMPTY_CRL_PEM);
}

static void cleanup(X509 *ca)
{
    static const char *const suffixes[] = { "0", "1", "r0", "r1" };
    char path[400];
    size_t i;

    for (i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
        snprintf(path, sizeof(path), "%s/%08lx.%s", dir, X509_NAME_hash_ex(X509_get_subject_name(ca), NULL, NULL, NULL),
                 suffixes[i]);
        remove(path);
    }
    remove(bundle);
    remove(derfile);
    remove(crlder);
    remove(junk);
    rmdir(dir);
}

static void test_files(void)
{
    X509_STORE *s = X509_STORE_new();
    X509_LOOKUP *lu = X509_STORE_add_lookup(s, X509_LOOKUP_file());

    printf("# files\n");
    printf("  PEM certificates: %d\n", X509_load_cert_file(lu, bundle, X509_FILETYPE_PEM));
    errors();
    printf("  a DER certificate: %d\n", X509_load_cert_file_ex(lu, derfile, X509_FILETYPE_ASN1, NULL, NULL));
    printf("  DER, not a certificate: %d\n", X509_load_cert_file(lu, bundle, X509_FILETYPE_ASN1));
    errors();
    printf("  a bad type: %d\n", X509_load_cert_file(lu, bundle, 99));
    errors();
    printf("  no PEM: %d\n", X509_load_cert_file(lu, junk, X509_FILETYPE_PEM));
    errors();
    printf("  no file: %d\n", X509_load_cert_file(lu, "/nonexistent/x.pem", X509_FILETYPE_PEM));
    errors();
    printf("  NULL: %d\n", X509_load_cert_file(lu, NULL, X509_FILETYPE_PEM));
    errors();
    printf("  PEM CRLs: %d\n", X509_load_crl_file(lu, bundle, X509_FILETYPE_PEM));
    errors();
    printf("  a DER CRL: %d\n", X509_load_crl_file(lu, crlder, X509_FILETYPE_ASN1));
    printf("  no CRL: %d\n", X509_load_crl_file(lu, junk, X509_FILETYPE_PEM));
    errors();
    printf("  CRL, bad type: %d, no file %d, NULL %d\n", X509_load_crl_file(lu, crlder, 99),
           X509_load_crl_file(lu, "/nonexistent/x.pem", X509_FILETYPE_PEM),
           X509_load_crl_file(lu, NULL, X509_FILETYPE_PEM));
    errors();
    printf("  both: %d\n", X509_load_cert_crl_file(lu, bundle, X509_FILETYPE_PEM));
    printf("  both, DER: %d\n", X509_load_cert_crl_file_ex(lu, derfile, X509_FILETYPE_ASN1, NULL, NULL));
    printf("  both, none: %d\n", X509_load_cert_crl_file(lu, junk, X509_FILETYPE_PEM));
    errors();
    printf("  both, no file: %d\n", X509_load_cert_crl_file(lu, "/nonexistent/x.pem", X509_FILETYPE_PEM));
    errors();
    show_objects("objects", X509_STORE_get0_objects(s));
    printf("  ctrl: load %d, default type %ld\n", X509_LOOKUP_load_file(lu, bundle, X509_FILETYPE_PEM),
           (long)X509_FILETYPE_DEFAULT);
    X509_STORE_free(s);

    s = X509_STORE_new();
    check(X509_STORE_load_file(s, bundle) == 1, "X509_STORE_load_file");
    check(X509_STORE_load_file_ex(s, junk, NULL, NULL) == 0, "a file without certificates");
    errors();
    check(X509_STORE_load_file(s, NULL) == 0, "no file");
    check(X509_STORE_load_locations(s, NULL, NULL) == 0, "no locations");
    check(X509_STORE_load_locations_ex(s, bundle, NULL, NULL, NULL) == 1, "a file location");
    check(X509_STORE_load_locations(s, "/nonexistent/x.pem", dir) == 0, "a missing file");
    errors();
    show_objects("objects", X509_STORE_get0_objects(s));
    X509_STORE_free(s);
}

static void test_dirs(X509 *ca, X509 *server)
{
    X509_STORE *s = X509_STORE_new();
    X509_LOOKUP *lu = X509_STORE_add_lookup(s, X509_LOOKUP_hash_dir());
    X509_OBJECT *o = X509_OBJECT_new();
    char twice[600];
    int r;

    printf("# hashed directories\n");
    check(X509_STORE_load_path(s, dir) == 1, "add the directory");
    snprintf(twice, sizeof(twice), "%s::%s:/nonexistent", dir, dir);
    check(X509_LOOKUP_add_dir(lu, twice, X509_FILETYPE_PEM) == 1, "add it again, and another");
    check(X509_LOOKUP_add_dir(lu, "", X509_FILETYPE_PEM) == 0, "an empty one");
    errors();
    check(X509_STORE_load_path(s, NULL) == 0, "NULL");
    r = X509_LOOKUP_by_subject(lu, X509_LU_X509, X509_get_subject_name(ca), o);
    printf("  CA's subject: %d, %s, the CA %d\n", r, type_name(X509_OBJECT_get_type(o)), X509_OBJECT_get0_X509(o) != NULL && X509_cmp(X509_OBJECT_get0_X509(o), ca) == 0);
    errors();
    show_objects("objects", X509_STORE_get0_objects(s));
    r = X509_LOOKUP_by_subject(lu, X509_LU_CRL, X509_get_subject_name(ca), o);
    printf("  CA's CRLs: %d, %s\n", r, type_name(X509_OBJECT_get_type(o)));
    show_objects("objects", X509_STORE_get0_objects(s));
    r = X509_LOOKUP_by_subject(lu, X509_LU_CRL, X509_get_subject_name(ca), o);
    printf("  again: %d\n", r);
    r = X509_LOOKUP_by_subject(lu, X509_LU_X509, X509_get_subject_name(server), o);
    printf("  server's subject: %d\n", r);
    r = X509_LOOKUP_by_subject(lu, X509_LU_NONE, X509_get_subject_name(ca), o);
    printf("  no type: %d\n", r);
    errors();
    r = X509_LOOKUP_by_subject(lu, X509_LU_X509, NULL, o);
    printf("  no name: %d\n", r);
    X509_STORE_free(s);
    /* The object borrowed the store's references; it holds none of its own. */
    OPENSSL_free(o);

    s = X509_STORE_new();
    check(X509_STORE_load_locations(s, bundle, dir) == 1, "a file and a directory");
    show_objects("objects", X509_STORE_get0_objects(s));
    X509_STORE_free(s);
}

static void test_defaults(void)
{
    X509_STORE *s = X509_STORE_new();
    X509_LOOKUP *lu;

    printf("# default paths\n");
    setenv(X509_get_default_cert_file_env(), bundle, 1);
    setenv(X509_get_default_cert_dir_env(), dir, 1);
    check(X509_STORE_set_default_paths(s) == 1, "from the environment");
    errors();
    show_objects("objects", X509_STORE_get0_objects(s));
    X509_STORE_free(s);
    s = X509_STORE_new();
    setenv(X509_get_default_cert_file_env(), "/nonexistent/cert.pem", 1);
    setenv(X509_get_default_cert_dir_env(), "/nonexistent/certs", 1);
    check(X509_STORE_set_default_paths_ex(s, NULL, NULL) == 1, "missing ones");
    errors();
    show_objects("objects", X509_STORE_get0_objects(s));
    lu = X509_STORE_add_lookup(s, X509_LOOKUP_file());
    printf("  default file: %d\n", X509_LOOKUP_load_file(lu, NULL, X509_FILETYPE_DEFAULT));
    errors();
    lu = X509_STORE_add_lookup(s, X509_LOOKUP_hash_dir());
    printf("  default directory: %d\n", X509_LOOKUP_add_dir(lu, NULL, X509_FILETYPE_DEFAULT));
    errors();
    lu = X509_STORE_add_lookup(s, X509_LOOKUP_store());
    printf("  store: add none %d, load none %d\n", X509_LOOKUP_add_store(lu, NULL), X509_LOOKUP_load_store(lu, NULL));
    errors();
    check(X509_STORE_load_store(s, NULL) == 0 && X509_STORE_load_store_ex(s, NULL, NULL, NULL) == 0, "no URI");
    printf("  store by subject: %d\n", X509_LOOKUP_by_subject(lu, X509_LU_X509, NULL, NULL));
    errors();
    X509_STORE_free(s);
}

int main(void)
{
    X509 *ca = read_cert(CA_PEM), *server = read_cert(SERVER_PEM);
    X509_CRL *crl = read_crl(CRL_PEM), *empty = read_crl(EMPTY_CRL_PEM);

    X509_up_ref(ca);
    test_objects(ca, crl);
    test_store(ca, server, crl, empty);
    test_methods(ca);
    setup(ca, crl);
    test_files();
    test_dirs(ca, server);
    test_defaults();
    cleanup(ca);
    X509_free(ca);
    X509_free(server);
    X509_CRL_free(crl);
    X509_CRL_free(empty);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
