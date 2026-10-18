/*
 * Conformance test for requests on an established connection (SSL_key_update(3),
 * SSL_get_key_update_type(3), SSL_renegotiate(3), SSL_renegotiate_abbreviated(3),
 * SSL_renegotiate_pending(3), SSL_verify_client_post_handshake(3),
 * SSL_export_keying_material(3), SSL_export_keying_material_early(3)): a TLS 1.3 key update in
 * each direction, a TLS 1.2 server-initiated renegotiation, post-handshake authentication, and
 * exported keying material with and without a context, on a client and a server in one process
 * over a BIO pair. Each refusal's error is printed.
 *
 * Only deterministic output is printed (keying material is compared, not shown).
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

/* Reads on `x` until `n` octets arrive (pumping `other` meanwhile): what it read, or -1. */
static int recv_on(SSL *x, SSL *other, char *buf, int n)
{
    int round;

    for (round = 0; round < 32; round++) {
        char tmp[16];
        int r = SSL_read(x, buf, n), e;

        if (r > 0)
            return r;
        e = SSL_get_error(x, r);
        if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
            printf("  read stopped: %d\n", e);
            return -1;
        }
        r = SSL_read(other, tmp, sizeof(tmp));
        if (r > 0) {
            printf("  other end read %d unexpectedly\n", r);
            return -1;
        }
        e = SSL_get_error(other, r);
        if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
            printf("  other end stopped: %d\n", e);
            return -1;
        }
    }
    return -1;
}

/* Sends `msg` from `from` and reads it on `to`; whether it arrived intact. */
static int transfer(SSL *from, SSL *to, const char *msg)
{
    char buf[64];
    int n = (int)strlen(msg), r = SSL_write(from, msg, n);

    if (r != n) {
        printf("  write: %d -> %d\n", r, SSL_get_error(from, r));
        return 0;
    }
    r = recv_on(to, from, buf, sizeof(buf));
    return r == n && memcmp(buf, msg, (size_t)n) == 0;
}

static SSL_CTX *server_ctx_max(int max)
{
    SSL_CTX *ctx = server_ctx();

    SSL_CTX_set_max_proto_version(ctx, max);
    return ctx;
}

static void connected(SSL_CTX *cctx, SSL_CTX *sctx, SSL **c, SSL **s)
{
    connect_pair(cctx, sctx, c, s);
    if (run(*c, *s, 0) != 0) {
        errors();
        printf("Bail out! handshake\n");
        exit(1);
    }
}

static void test_key_update(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx_max(TLS1_3_VERSION);
    SSL *c, *s;

    printf("# key update (TLS 1.3)\n");
    c = SSL_new(cctx);
    check(SSL_get_key_update_type(c) == SSL_KEY_UPDATE_NONE, "no key update before the handshake");
    check(SSL_key_update(c, SSL_KEY_UPDATE_REQUESTED) == 0, "SSL_key_update refused before the handshake");
    errors();
    check(SSL_renegotiate_pending(c) == 0, "no renegotiation pending");
    SSL_free(c);
    check(SSL_key_update(NULL, SSL_KEY_UPDATE_REQUESTED) == 0, "SSL_key_update(NULL)");
    errors();

    connected(cctx, sctx, &c, &s);
    check(SSL_key_update(c, 7) == 0, "an invalid update type");
    errors();
    check(SSL_key_update(c, SSL_KEY_UPDATE_REQUESTED) == 1, "SSL_key_update(REQUESTED)");
    check(SSL_get_key_update_type(c) == SSL_KEY_UPDATE_REQUESTED, "the update type is pending");
    check(SSL_is_init_finished(c) == 0, "the client is back in init");
    check(SSL_key_update(c, SSL_KEY_UPDATE_NOT_REQUESTED) == 0, "a second update while one is pending");
    errors();
    check(SSL_renegotiate(c) == 0, "SSL_renegotiate in TLS 1.3");
    errors();
    check(SSL_renegotiate_abbreviated(c) == 0, "SSL_renegotiate_abbreviated in TLS 1.3");
    errors();
    check(transfer(c, s, "after update"), "data after the client's update");
    check(SSL_get_key_update_type(c) == SSL_KEY_UPDATE_NONE, "the client's update was sent");
    printf("  server's pending update: %d\n", SSL_get_key_update_type(s));
    check(transfer(s, c, "reply"), "the server's reply (with its own update)");
    check(SSL_get_key_update_type(s) == SSL_KEY_UPDATE_NONE, "the server's update was sent");
    check(SSL_key_update(s, SSL_KEY_UPDATE_NOT_REQUESTED) == 1, "the server updates without asking");
    check(transfer(s, c, "again"), "data after the server's update");
    check(transfer(c, s, "and back"), "data back");
    check(SSL_is_init_finished(c) && SSL_is_init_finished(s), "both ends finished");
    errors();

    /*
     * Requested updates in a row, then data: what the server writes while it reads them (a
     * TLS 1.3 KeyUpdate record is 27 octets).
     */
    {
        char buf[16];
        int i, n, r;

        for (n = 1; n <= 5; n++) {
            for (i = 0; i < n; i++) {
                SSL_key_update(c, SSL_KEY_UPDATE_REQUESTED);
                SSL_do_handshake(c);
            }
            SSL_write(c, "x", 1);
            r = SSL_read(s, buf, sizeof(buf));
            printf("  %d requests: the server read %d, wrote %d octets, pending %d\n", n, r,
                   (int)BIO_ctrl_pending(SSL_get_rbio(c)), SSL_get_key_update_type(s));
            {
                char tmp[16];

                printf("  then the server writes %d, and %d octets go out\n", SSL_write(s, "y", 1),
                       (int)BIO_ctrl_pending(SSL_get_rbio(c)));
                check(SSL_read(c, tmp, sizeof(tmp)) == 1, "the client reads it");
            }
            check(transfer(s, c, "after the requests"), "data after the requests");
            check(transfer(c, s, "and back again"), "data back after the requests");
        }
        errors();
    }
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

/*
 * Runs the client's renegotiation handshake while the server reads (it has finished its first
 * handshake, so only reading processes the client's messages): whether both ended in step.
 */
static int renegotiation(SSL *c, SSL *s)
{
    int round;

    for (round = 0; round < 32; round++) {
        char tmp[16];
        int r = SSL_do_handshake(c), e;

        if (r == 1 && SSL_is_init_finished(s))
            return 1;
        if (r != 1 && (e = SSL_get_error(c, r)) != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
            printf("  client stopped: %d\n", e);
            return 0;
        }
        r = SSL_read(s, tmp, sizeof(tmp));
        if (r > 0 || ((e = SSL_get_error(s, r)) != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)) {
            printf("  server read: %d\n", r);
            return 0;
        }
    }
    return 0;
}

static void test_renegotiate(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx_max(TLS1_2_VERSION);
    SSL *c, *s;

    printf("# renegotiation (TLS 1.2)\n");
    connected(cctx, sctx, &c, &s);
    check(SSL_key_update(c, SSL_KEY_UPDATE_REQUESTED) == 0, "SSL_key_update in TLS 1.2");
    errors();
    printf("  renegotiations: %ld %ld\n", SSL_num_renegotiations(s), SSL_total_renegotiations(s));
    check(SSL_renegotiate(s) == 1, "the server asks for a renegotiation");
    check(SSL_renegotiate_pending(s) == 1, "pending");
    check(SSL_is_init_finished(s) == 1, "not started yet");
    check(transfer(s, c, "hello"), "data with the HelloRequest");
    printf("  renegotiations: %ld %ld\n", SSL_num_renegotiations(s), SSL_total_renegotiations(s));
    printf("  client write during the renegotiation: %d\n", SSL_get_error(c, SSL_write(c, "x", 1)));
    check(renegotiation(c, s), "the renegotiation handshake");
    check(transfer(c, s, "world"), "data afterwards");
    check(transfer(s, c, "done"), "and back");
    printf("  pending: %d %d, finished: %d %d\n", SSL_renegotiate_pending(s), SSL_renegotiate_pending(c),
        SSL_is_init_finished(s), SSL_is_init_finished(c));
    printf("  cleared: %ld, then %ld %ld\n", SSL_clear_num_renegotiations(s), SSL_num_renegotiations(s),
        SSL_total_renegotiations(s));
    errors();
    SSL_free(c);
    SSL_free(s);

    /* An option set after the handshake applies to the renegotiation: a client dropping the
     * Extended Master Secret it used is refused (RFC 7627). */
    connected(cctx, sctx, &c, &s);
    printf("  extms: %ld\n", SSL_get_extms_support(c));
    SSL_set_options(c, SSL_OP_NO_EXTENDED_MASTER_SECRET);
    check(SSL_renegotiate(c) == 1, "the client renegotiates without EMS");
    check(!renegotiation(c, s), "the server refuses it");
    errors();
    SSL_free(c);
    SSL_free(s);

    SSL_CTX_set_options(sctx, SSL_OP_NO_RENEGOTIATION);
    connected(cctx, sctx, &c, &s);
    check(SSL_renegotiate(s) == 0, "SSL_OP_NO_RENEGOTIATION refuses");
    errors();
    check(SSL_renegotiate_abbreviated(s) == 0, "abbreviated too");
    errors();
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void test_post_handshake_auth(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx_max(TLS1_3_VERSION);
    X509 *x = cert(CLIENT_PEM);
    EVP_PKEY *k = key(CLIENT_KEY_PEM);
    SSL *c, *s;
    char buf[64];

    printf("# post-handshake authentication\n");
    trust_root(sctx);
    SSL_CTX_use_certificate(cctx, x);
    SSL_CTX_use_PrivateKey(cctx, k);
    X509_free(x);
    EVP_PKEY_free(k);

    connected(cctx, sctx, &c, &s);
    check(SSL_verify_client_post_handshake(c) == 0, "not on the client");
    errors();
    check(SSL_verify_client_post_handshake(s) == 0, "not without the client's extension");
    errors();
    SSL_free(c);
    SSL_free(s);

    c = SSL_new(cctx);
    s = SSL_new(sctx);
    SSL_set_post_handshake_auth(c, 1);
    pair(c, s);
    check(SSL_verify_client_post_handshake(s) == 0, "not before the handshake");
    errors();
    if (run(c, s, 0) != 0) {
        printf("Bail out! handshake\n");
        exit(1);
    }
    X509_free(x = SSL_get1_peer_certificate(s));
    check(x == NULL, "no client certificate yet");
    check(SSL_verify_client_post_handshake(s) == 0, "the verify mode wouldn't ask");
    errors();
    SSL_set_verify(s, SSL_VERIFY_PEER, NULL);
    check(SSL_verify_client_post_handshake(s) == 1, "the server asks");
    check(SSL_verify_client_post_handshake(s) == 0, "asking twice");
    errors();
    check(transfer(s, c, "ask"), "the request goes out with data");
    check(transfer(c, s, "answer"), "the client answers with data");
    x = SSL_get1_peer_certificate(s);
    printf("  client certificate: %s, verify %ld\n", cn(x, buf, sizeof(buf)), SSL_get_verify_result(s));
    X509_free(x);
    printf("  asking again after the answer: %d\n", SSL_verify_client_post_handshake(s));
    errors();
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

/* Both ends' keying material for the label and context: 1 if equal, 0 if not, or what failed. */
static void export_both(SSL *c, SSL *s, const char *label, const char *ctx, int use)
{
    unsigned char a[32], b[32], d[32];
    int rc = SSL_export_keying_material(c, a, sizeof(a), label, strlen(label), (const unsigned char *)ctx,
        ctx == NULL ? 0 : strlen(ctx), use);
    int rs = SSL_export_keying_material(s, b, sizeof(b), label, strlen(label), (const unsigned char *)ctx,
        ctx == NULL ? 0 : strlen(ctx), use);
    int rd = SSL_export_keying_material(c, d, sizeof(d), label, strlen(label), NULL, 0, 0);

    printf("  export %s/%s/%d: %d %d, %s, %s the no-context one\n", label, ctx == NULL ? "-" : ctx, use, rc, rs,
        rc == 1 && rs == 1 && memcmp(a, b, sizeof(a)) == 0 ? "same" : "different",
        rd == 1 && rc == 1 && memcmp(a, d, sizeof(a)) == 0 ? "same as" : "unlike");
    errors();
}

static void test_export(int max)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx_max(max);
    SSL *c, *s;
    unsigned char out[16];

    printf("# keying material (max %#x)\n", max);
    c = SSL_new(cctx);
    check(SSL_export_keying_material(c, out, sizeof(out), "EXPORTER-x", 10, NULL, 0, 0) == -1,
        "no session before the handshake");
    errors();
    SSL_free(c);

    connected(cctx, sctx, &c, &s);
    export_both(c, s, "EXPORTER-test", "context", 1);
    export_both(c, s, "EXPORTER-test", "", 1);
    export_both(c, s, "EXPORTER-test", NULL, 0);
    export_both(c, s, "EXPORTER-other", "context", 1);
    export_both(c, s, "key expansion", NULL, 0);
    export_both(c, s, "master secretX", NULL, 0);
    export_both(c, s, "client finished", NULL, 0);
    printf("  early: %d\n", SSL_export_keying_material_early(c, out, sizeof(out), "EXPORTER-x", 10,
        (const unsigned char *)"", 0));
    errors();
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

int main(void)
{
    test_key_update();
    test_renegotiate();
    test_post_handshake_auth();
    test_export(TLS1_3_VERSION);
    test_export(TLS1_2_VERSION);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
