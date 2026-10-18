/*
 * Conformance test for closing TLS connections (SSL_shutdown(3), SSL_get_shutdown(3),
 * SSL_set_shutdown(3), SSL_set_quiet_shutdown(3), SSL_get_error(3), SSL_clear(3)): close_notify
 * in both directions over a BIO pair, TLS 1.3 and 1.2, with the alerts each end reports;
 * writes after close_notify; application data while waiting for the peer's close_notify;
 * quiet shutdown; SSL_shutdown before and during a handshake; the shutdown flags set by hand;
 * SSL_clear afterwards; and a client reused with SSL_set_connect_state(3), which drops what it
 * buffered and resumes its session.
 *
 * Only deterministic output is printed.
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


static void said(const char *what, SSL *x, int r)
{
    printf("  %s: %d -> %d, shutdown %d\n", what, r, SSL_get_error(x, r), SSL_get_shutdown(x));
    errors();
}

static void connected(int max, SSL_CTX **cctx, SSL_CTX **sctx, SSL **c, SSL **s)
{
    *cctx = client_ctx();
    *sctx = server_ctx();
    SSL_CTX_set_max_proto_version(*cctx, max);
    connect_pair(*cctx, *sctx, c, s);
    if (run(*c, *s, 0) != 0) {
        printf("Bail out! handshake\n");
        exit(1);
    }
}

static void done(SSL_CTX *cctx, SSL_CTX *sctx, SSL *c, SSL *s)
{
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void alert_cb(const SSL *s, int where, int ret)
{
    if ((where & SSL_CB_ALERT) != 0)
        printf("  alert %s %s %s %s\n", SSL_is_server((SSL *)s) ? "server" : "client",
            (where & SSL_CB_READ) != 0 ? "read" : "write", SSL_alert_type_string_long(ret),
            SSL_alert_desc_string_long(ret));
}

static void test_both_ways(int max)
{
    SSL_CTX *cctx, *sctx;
    SSL *c, *s;
    char buf[16];
    int r;

    printf("# a shutdown in both directions, %s\n", max == TLS1_2_VERSION ? "TLS 1.2" : "TLS 1.3");
    connected(max, &cctx, &sctx, &c, &s);
    SSL_set_info_callback(c, alert_cb);
    SSL_set_info_callback(s, alert_cb);
    r = SSL_shutdown(c);
    said("the client's first SSL_shutdown", c, r);
    r = SSL_shutdown(c);
    said("its second, before the server answers", c, r);
    r = SSL_write(c, "x", 1);
    said("a write after close_notify", c, r);
    r = SSL_read(s, buf, sizeof(buf));
    said("the server reads", s, r);
    r = SSL_read(s, buf, sizeof(buf));
    said("and reads again", s, r);
    r = SSL_write(s, "late", 4);
    said("the server can still write", s, r);
    r = SSL_shutdown(s);
    said("the server's SSL_shutdown", s, r);
    r = SSL_read(c, buf, sizeof(buf));
    printf("  the client reads what the server wrote last: %d\n", r);
    r = SSL_shutdown(c);
    said("the client's third SSL_shutdown", c, r);
    r = SSL_shutdown(c);
    said("and its fourth", c, r);
    done(cctx, sctx, c, s);
}

static void test_data_after_close_notify(void)
{
    SSL_CTX *cctx, *sctx;
    SSL *c, *s;
    int r;

    printf("# application data while waiting for close_notify\n");
    connected(TLS1_2_VERSION, &cctx, &sctx, &c, &s);
    r = SSL_shutdown(c);
    said("the client's first SSL_shutdown", c, r);
    SSL_write(s, "data", 4);
    r = SSL_shutdown(c);
    said("the client's second SSL_shutdown", c, r);
    done(cctx, sctx, c, s);
}

static void test_quiet(void)
{
    SSL_CTX *cctx, *sctx;
    SSL *c, *s;
    char buf[16];
    int r;

    printf("# quiet shutdown\n");
    connected(TLS1_3_VERSION, &cctx, &sctx, &c, &s);
    SSL_set_quiet_shutdown(c, 1);
    r = SSL_shutdown(c);
    said("the client's SSL_shutdown", c, r);
    r = SSL_read(s, buf, sizeof(buf));
    said("the server got nothing", s, r);
    r = SSL_read(c, buf, sizeof(buf));
    said("the client reads", c, r);
    r = SSL_write(c, "x", 1);
    said("the client writes", c, r);
    done(cctx, sctx, c, s);
}

static void test_in_init(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c, *s, *u;
    int r;

    printf("# SSL_shutdown before or during a handshake\n");
    u = SSL_new(cctx);
    r = SSL_shutdown(u);
    said("no role yet", u, r);
    SSL_set_connect_state(u);
    r = SSL_shutdown(u);
    said("before the handshake", u, r);
    SSL_set_quiet_shutdown(u, 1);
    r = SSL_shutdown(u);
    said("before the handshake, quiet", u, r);
    SSL_free(u);
    connect_pair(cctx, sctx, &c, &s);
    SSL_do_handshake(c);
    r = SSL_shutdown(c);
    said("during the handshake", c, r);
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void test_set_shutdown(void)
{
    SSL_CTX *cctx, *sctx;
    SSL *c, *s;
    char buf[16];
    int r;

    printf("# SSL_set_shutdown\n");
    connected(TLS1_3_VERSION, &cctx, &sctx, &c, &s);
    SSL_set_shutdown(c, SSL_RECEIVED_SHUTDOWN);
    r = SSL_read(c, buf, sizeof(buf));
    said("a read once RECEIVED is set", c, r);
    SSL_set_shutdown(c, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    r = SSL_shutdown(c);
    said("SSL_shutdown with both set", c, r);
    r = SSL_read(s, buf, sizeof(buf));
    said("the server got nothing", s, r);
    done(cctx, sctx, c, s);
}

static void test_clear(void)
{
    SSL_CTX *cctx, *sctx;
    SSL *c, *s;

    printf("# SSL_clear after a shutdown\n");
    connected(TLS1_3_VERSION, &cctx, &sctx, &c, &s);
    SSL_shutdown(c);
    SSL_read(s, NULL, 0);
    ERR_clear_error();
    SSL_shutdown(s);
    SSL_shutdown(c);
    check(SSL_get_shutdown(c) == (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN), "both flags set");
    check(SSL_clear(c) == 1, "SSL_clear");
    check(SSL_get_shutdown(c) == 0, "the flags are clear");
    check(SSL_in_before(c) && SSL_in_init(c), "the connection is back before its handshake");
    printf("  cipher %s, peer %s\n", SSL_get_current_cipher(c) == NULL ? "none" : "kept",
        SSL_get0_peer_certificate(c) == NULL ? "none" : "kept");
    printf("  version %s, verify %ld\n", SSL_get_version(c), SSL_get_verify_result(c));
    done(cctx, sctx, c, s);
}

/* A client reused after a shutdown: SSL_set_connect_state starts over, resuming. */
static void test_reuse(int max)
{
    SSL_CTX *cctx, *sctx;
    SSL *c, *s;
    char buf[16];
    int n;

    printf("# a client reused with SSL_set_connect_state, %s\n",
           max == TLS1_3_VERSION ? "TLS 1.3" : "TLS 1.2");
    connected(max, &cctx, &sctx, &c, &s);
    check(SSL_write(s, "Hello World", 11) == 11, "the server writes");
    check(SSL_read(c, buf, 5) == 5, "the client reads part of it");
    SSL_shutdown(c);
    SSL_shutdown(s);
    SSL_free(s);
    s = SSL_new(sctx);
    /* SSL_set_connect_state on the used client, SSL_set_accept_state on the new server. */
    pair(c, s);
    check(SSL_in_init(c) && SSL_get_shutdown(c) == 0, "the client is back in its handshake");
    check(run(c, s, 0) == 0, "the second handshake");
    check(SSL_session_reused(c) == 1, "the session is resumed");
    check(SSL_write(s, "abc", 3) == 3, "the server writes again");
    n = SSL_read(c, buf, sizeof(buf));
    printf("  the client reads %d octet(s): %.*s\n", n, n > 0 ? n : 0, buf);
    done(cctx, sctx, c, s);
}

/*
 * The client sends its close_notify, then the peer closes with none (its end of the pair is
 * shut for writing): the second SSL_shutdown, with and without SSL_OP_IGNORE_UNEXPECTED_EOF.
 */
static void test_unclean(int max, int ignore)
{
    SSL_CTX *cctx, *sctx;
    SSL *c, *s;

    printf("# an unclean close after our close_notify, %s, %s\n",
           max == TLS1_3_VERSION ? "TLS 1.3" : "TLS 1.2",
           ignore ? "unexpected EOF ignored" : "unexpected EOF an error");
    connected(max, &cctx, &sctx, &c, &s);
    if (ignore)
        SSL_set_options(c, SSL_OP_IGNORE_UNEXPECTED_EOF);
    said("first SSL_shutdown", c, SSL_shutdown(c));
    BIO_shutdown_wr(SSL_get_wbio(s));
    said("second SSL_shutdown", c, SSL_shutdown(c));
    said("third SSL_shutdown", c, SSL_shutdown(c));
    done(cctx, sctx, c, s);
}

/*
 * The client sends its close_notify, and the peer answers with a fatal alert instead (here
 * bad_record_mac, for a record it can't decrypt): the second SSL_shutdown.
 */
static void test_peer_alert(int max)
{
    static const unsigned char junk[37] = { 0x17, 0x03, 0x03, 0x00, 0x20 };
    SSL_CTX *cctx, *sctx;
    SSL *c, *s;
    char buf[16];

    printf("# a fatal alert from the peer after our close_notify, %s\n",
           max == TLS1_3_VERSION ? "TLS 1.3" : "TLS 1.2");
    connected(max, &cctx, &sctx, &c, &s);
    SSL_set_info_callback(c, alert_cb);
    (void)BIO_write(SSL_get_wbio(c), junk, sizeof(junk));
    said("the server reads a record it can't decrypt", s, SSL_read(s, buf, sizeof(buf)));
    said("first SSL_shutdown", c, SSL_shutdown(c));
    said("second SSL_shutdown", c, SSL_shutdown(c));
    said("third SSL_shutdown", c, SSL_shutdown(c));
    done(cctx, sctx, c, s);
}

int main(void)
{
    test_both_ways(TLS1_3_VERSION);
    test_both_ways(TLS1_2_VERSION);
    test_data_after_close_notify();
    test_quiet();
    test_in_init();
    test_set_shutdown();
    test_clear();
    test_reuse(TLS1_3_VERSION);
    test_reuse(TLS1_2_VERSION);
    test_unclean(TLS1_3_VERSION, 1);
    test_unclean(TLS1_2_VERSION, 1);
    test_unclean(TLS1_2_VERSION, 0);
    test_peer_alert(TLS1_3_VERSION);
    test_peer_alert(TLS1_2_VERSION);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
