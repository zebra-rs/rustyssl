/*
 * Conformance test for Certificate Transparency on connections (SSL_CTX_enable_ct(3),
 * SSL_enable_ct(3), SSL_CTX_ct_is_enabled(3), SSL_ct_is_enabled(3),
 * SSL_CTX_set_ct_validation_callback(3), SSL_set_ct_validation_callback(3),
 * SSL_get0_peer_scts(3), SSL_CTX_set_default_ctlog_list_file(3),
 * SSL_CTX_set_ctlog_list_file(3), SSL_CTX_set0_ctlog_store(3), SSL_CTX_get0_ctlog_store(3)):
 * the modes and their errors, what a connection inherits, the log store, and handshakes over a
 * BIO pair with the permissive, strict, and an application callback (the test certificates
 * carry no SCTs).
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

static int failures = 0;
static int number = 0;

static void check(int ok, const char *what)
{
    number++;
    if (!ok)
        failures++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", number, what);
}

/* Prints and clears the error queue: library/reason and any data. */
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
    "MIIBmzCCAUCgAwIBAgIUHfTNPsE5lGD3nT8fR1Nd24C0BsgwCgYIKoZIzj0EAwIw\n"
    "KjEQMA4GA1UECgwHRXhhbXBsZTEWMBQGA1UEAwwNVExTIFRlc3QgUm9vdDAgFw0y\n"
    "NjEwMTgwOTMyNDZaGA8yMTI2MDkyNDA5MzI0NlowKjEQMA4GA1UECgwHRXhhbXBs\n"
    "ZTEWMBQGA1UEAwwNVExTIFRlc3QgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEH\n"
    "A0IABLfBhwdOVIbIOwWlwBUmASMV1CS8SOnPi/viY8J5Ml2EwP5wOJe2mtSxgMlo\n"
    "COh/RepmP8BAKwLO40zMoIv99xOjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P\n"
    "AQH/BAQDAgEGMB0GA1UdDgQWBBQ6zTauzjp1rC8vPBSILXAK3pm9PjAKBggqhkjO\n"
    "PQQDAgNJADBGAiEA8n+eFk52ddsEdBxGgskm6aD0for7v4Ys0o0bN2t9wq8CIQDY\n"
    "V8DuzBptykbkta8E/bbLFVRo0LjIzjF/bGH+iqEMeA==\n"
    "-----END CERTIFICATE-----\n";

static const char SERVER_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBxDCCAWqgAwIBAgICA+kwCgYIKoZIzj0EAwIwKjEQMA4GA1UECgwHRXhhbXBs\n"
    "ZTEWMBQGA1UEAwwNVExTIFRlc3QgUm9vdDAgFw0yNjEwMTgwOTMyNDZaGA8yMTI2\n"
    "MDkyNDA5MzI0NlowGTEXMBUGA1UEAwwOc2VydmVyLmV4YW1wbGUwWTATBgcqhkjO\n"
    "PQIBBggqhkjOPQMBBwNCAARQwBruuNdz4xCD1gvolSn84T4lhmxXimDiZyo55Kdd\n"
    "rfRyA09qPpfiXyudWm0VDT2tdis7qXDPv2njo4sH3xHko4GOMIGLMAkGA1UdEwQC\n"
    "MAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBkGA1UdEQQS\n"
    "MBCCDnNlcnZlci5leGFtcGxlMB0GA1UdDgQWBBTJhnvwTSY1MKJTWPQEV8hTOvQj\n"
    "CzAfBgNVHSMEGDAWgBQ6zTauzjp1rC8vPBSILXAK3pm9PjAKBggqhkjOPQQDAgNI\n"
    "ADBFAiA9HtDZKkG58jRwUNQ4CbP61ozryZRRkz7W3RF94vEpSQIhAKwrnOIS/FEg\n"
    "N7iBJyOB+Buj5UbPic6SYxuj11J3f/PG\n"
    "-----END CERTIFICATE-----\n";

static const char SERVER_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgvhwC7sEHpNUtRIwR\n"
    "1HpSoTfsfnL+ayakODf8YQkvzpKhRANCAARQwBruuNdz4xCD1gvolSn84T4lhmxX\n"
    "imDiZyo55KddrfRyA09qPpfiXyudWm0VDT2tdis7qXDPv2njo4sH3xHk\n"
    "-----END PRIVATE KEY-----\n";

static const char CLIENT_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBxTCCAWqgAwIBAgICA+owCgYIKoZIzj0EAwIwKjEQMA4GA1UECgwHRXhhbXBs\n"
    "ZTEWMBQGA1UEAwwNVExTIFRlc3QgUm9vdDAgFw0yNjEwMTgwOTMyNDZaGA8yMTI2\n"
    "MDkyNDA5MzI0NlowGTEXMBUGA1UEAwwOY2xpZW50LmV4YW1wbGUwWTATBgcqhkjO\n"
    "PQIBBggqhkjOPQMBBwNCAAQkY1a23CWRkXteLW6bqTn8zNIFegH+enHHlYkSz0NQ\n"
    "HN1OZT5KvQfVYZUAdGJWz58N/D47RMQIdgskDOGWB3HCo4GOMIGLMAkGA1UdEwQC\n"
    "MAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMBkGA1UdEQQS\n"
    "MBCCDmNsaWVudC5leGFtcGxlMB0GA1UdDgQWBBTjMHUhUC8v+KLimiFT1omnQGns\n"
    "vTAfBgNVHSMEGDAWgBQ6zTauzjp1rC8vPBSILXAK3pm9PjAKBggqhkjOPQQDAgNJ\n"
    "ADBGAiEA0amLpEP6YJrlZqzbIaA4u9L1vwF+/cwCKlaaH8qUcZwCIQD5EkZ1d/AU\n"
    "XFoMrHkToGeOmh2H2EkbQ7vwwHUiF/tOLg==\n"
    "-----END CERTIFICATE-----\n";

static const char CLIENT_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgK5USrGcEj6G/8tSt\n"
    "fC5Su2QV+Tb1ewfevDb87NnfJvyhRANCAAQkY1a23CWRkXteLW6bqTn8zNIFegH+\n"
    "enHHlYkSz0NQHN1OZT5KvQfVYZUAdGJWz58N/D47RMQIdgskDOGWB3HC\n"
    "-----END PRIVATE KEY-----\n";

static X509 *cert(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);

    BIO_free(b);
    return x;
}

static EVP_PKEY *key(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    EVP_PKEY *k = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);

    BIO_free(b);
    return k;
}

/* A server context with the server's certificate and key. */
static SSL_CTX *server_ctx(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    X509 *x = cert(SERVER_PEM);
    EVP_PKEY *k = key(SERVER_KEY_PEM);

    if (ctx == NULL || x == NULL || k == NULL || SSL_CTX_use_certificate(ctx, x) != 1
        || SSL_CTX_use_PrivateKey(ctx, k) != 1) {
        printf("Bail out! server context\n");
        exit(1);
    }
    X509_free(x);
    EVP_PKEY_free(k);
    return ctx;
}

/* A client context that trusts the test root and checks the server's certificate. */
static SSL_CTX *client_ctx(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    X509 *ca = cert(CA_PEM);

    if (ctx == NULL || ca == NULL || X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), ca) != 1) {
        printf("Bail out! client context\n");
        exit(1);
    }
    X509_free(ca);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    return ctx;
}

/* Lets the server's context trust the test root too, for client certificates. */
static void trust_root(SSL_CTX *ctx)
{
    X509 *ca = cert(CA_PEM);

    X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), ca);
    X509_free(ca);
}

/* Connects a client and a server over an in-memory BIO pair. */
static void pair(SSL *c, SSL *s)
{
    BIO *a = NULL, *b = NULL;

    if (BIO_new_bio_pair(&a, 0, &b, 0) != 1) {
        printf("Bail out! BIO pair\n");
        exit(1);
    }
    SSL_set_bio(c, a, a);
    SSL_set_bio(s, b, b);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
}

/*
 * Runs both ends' handshakes in turn until both finish (0), or one stops for something other
 * than I/O (its SSL_get_error value, after printing which end). Each end's wants are printed
 * when `trace` is set.
 */
static int run(SSL *c, SSL *s, int trace)
{
    int cdone = SSL_is_init_finished(c), sdone = SSL_is_init_finished(s), round;

    for (round = 0; round < 64 && (!cdone || !sdone); round++) {
        int i;

        for (i = 0; i < 2; i++) {
            SSL *x = i == 0 ? c : s;
            int *done = i == 0 ? &cdone : &sdone, r, e;

            if (*done)
                continue;
            r = SSL_do_handshake(x);
            if (r == 1) {
                *done = 1;
                if (trace)
                    printf("  %s: done\n", i == 0 ? "client" : "server");
                continue;
            }
            e = SSL_get_error(x, r);
            if (trace)
                printf("  %s: %d -> %d\n", i == 0 ? "client" : "server", r, e);
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
                printf("  %s stopped: %d\n", i == 0 ? "client" : "server", e);
                return e;
            }
        }
    }
    return cdone && sdone ? 0 : -1;
}

/* A connected client and server from the two contexts. */
static void connect_pair(SSL_CTX *cctx, SSL_CTX *sctx, SSL **c, SSL **s)
{
    *c = SSL_new(cctx);
    *s = SSL_new(sctx);
    if (*c == NULL || *s == NULL) {
        printf("Bail out! SSL_new\n");
        exit(1);
    }
    pair(*c, *s);
}

/* The common name of a certificate's subject, or "(none)". */
static const char *cn(X509 *x, char *buf, int len)
{
    if (x == NULL)
        return "(none)";
    if (X509_NAME_get_text_by_NID(X509_get_subject_name(x), NID_commonName, buf, len) < 0)
        return "(no CN)";
    return buf;
}

static int cb_calls;
static int cb_result;

static int ct_cb(const CT_POLICY_EVAL_CTX *ctx, const STACK_OF(SCT) *scts, void *arg)
{
    cb_calls++;
    printf("  callback: ctx %s, %d SCTs, arg %s\n", ctx != NULL ? "set" : "none", sk_SCT_num(scts),
        arg == (void *)&cb_calls ? "ours" : "other");
    return cb_result;
}

static void test_settings(void)
{
    SSL_CTX *ctx = client_ctx();
    SSL *s;
    const CTLOG_STORE *store;
    CTLOG_STORE *mine;
    FILE *f;
    const char *path = "ssl_ct_logs.cnf";

    printf("# settings\n");
    check(SSL_CTX_ct_is_enabled(ctx) == 0, "off by default");
    check(SSL_CTX_enable_ct(ctx, 7) == 0, "an unknown mode");
    errors();
    check(SSL_CTX_enable_ct(ctx, SSL_CT_VALIDATION_STRICT) == 1 && SSL_CTX_ct_is_enabled(ctx) == 1, "strict");
    s = SSL_new(ctx);
    check(SSL_ct_is_enabled(s) == 1, "the connection inherits it");
    printf("  status type: %ld\n", SSL_get_tlsext_status_type(s));
    check(SSL_enable_ct(s, 9) == 0, "an unknown mode on the connection");
    errors();
    check(SSL_set_ct_validation_callback(s, NULL, NULL) == 1 && SSL_ct_is_enabled(s) == 0, "off again");
    printf("  status type: %ld\n", SSL_get_tlsext_status_type(s));
    check(SSL_enable_ct(s, SSL_CT_VALIDATION_PERMISSIVE) == 1 && SSL_ct_is_enabled(s) == 1, "permissive");
    SSL_free(s);
    check(SSL_CTX_set_ct_validation_callback(ctx, NULL, NULL) == 1 && SSL_CTX_ct_is_enabled(ctx) == 0,
        "the context's off");
    s = SSL_new(ctx);
    printf("  a new connection: enabled %d, status type %ld\n", SSL_ct_is_enabled(s), SSL_get_tlsext_status_type(s));
    printf("  peer SCTs before a handshake: %d\n", sk_SCT_num(SSL_get0_peer_scts(s)));
    SSL_free(s);

    store = SSL_CTX_get0_ctlog_store(ctx);
    check(store != NULL, "a log store");
    printf("  default list: %d\n", SSL_CTX_set_default_ctlog_list_file(ctx));
    ERR_clear_error();
    printf("  missing list: %d\n", SSL_CTX_set_ctlog_list_file(ctx, "/nonexistent/ct_log_list.cnf"));
    errors();
    f = fopen(path, "w");
    fputs("enabled_logs = test\n\n[test]\ndescription = A test log\n"
          "key = MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFUJ6n0cGhGDDKWQq0Pa4lI8bHVRqcpUaOXJkUXwHJhb4Zgn"
          "fOy6EOBSovf3W/Ut+j55eUAUK/nQPeHzQdwRHKA==\n", f);
    fclose(f);
    printf("  a list with one log: %d\n", SSL_CTX_set_ctlog_list_file(ctx, path));
    errors();
    remove(path);
    mine = CTLOG_STORE_new();
    SSL_CTX_set0_ctlog_store(ctx, mine);
    check(SSL_CTX_get0_ctlog_store(ctx) == mine, "set0 replaces the store");
    SSL_CTX_set0_ctlog_store(ctx, NULL);
    printf("  after set0(NULL): %s\n", SSL_CTX_get0_ctlog_store(ctx) == NULL ? "none" : "a store");
    SSL_CTX_free(ctx);
}

/* A handshake with the client's CT setting: the result, and what the client reports. */
static void handshake(const char *what, int mode, int verify)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c, *s;
    const STACK_OF(SCT) *scts;

    printf("# a handshake, %s%s\n", what, verify ? "" : " (SSL_VERIFY_NONE)");
    if (mode >= 0)
        SSL_CTX_enable_ct(cctx, mode);
    else
        SSL_CTX_set_ct_validation_callback(cctx, ct_cb, &cb_calls);
    if (!verify)
        SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);
    cb_calls = 0;
    connect_pair(cctx, sctx, &c, &s);
    printf("  result: %d\n", run(c, s, 0));
    errors();
    printf("  verify result: %ld, callback calls: %d\n", SSL_get_verify_result(c), cb_calls);
    scts = SSL_get0_peer_scts(c);
    printf("  peer SCTs: %s %d\n", scts == NULL ? "none" : "a list", sk_SCT_num(scts));
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

int main(void)
{
    test_settings();
    handshake("permissive", SSL_CT_VALIDATION_PERMISSIVE, 1);
    handshake("strict", SSL_CT_VALIDATION_STRICT, 1);
    cb_result = 1;
    handshake("an accepting callback", -1, 1);
    cb_result = 0;
    handshake("a refusing callback", -1, 1);
    (void)CLIENT_PEM;
    (void)CLIENT_KEY_PEM;
    (void)trust_root;
    (void)cn;
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
