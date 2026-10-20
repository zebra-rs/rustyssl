/*
 * Conformance test for the SSL filter BIO (BIO_f_ssl(3), BIO_new_ssl(3), BIO_new_ssl_connect(3),
 * BIO_new_buffer_ssl_connect(3), BIO_ssl_copy_session_id(3), BIO_ssl_shutdown(3),
 * SSL_get_rpoll_descriptor(3)): a client and a server SSL BIO over a BIO pair, pushed onto
 * their transports, with the handshake through BIO_do_handshake, data through BIO_read and
 * BIO_write, the retry flags, the ctrls (BIO_get_ssl, BIO_set_ssl_mode, the renegotiation
 * settings, pending, flush, close flag), and the chains the constructors build.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

/* The retry state of a BIO, as flags. */
static void flags(const char *what, BIO *b)
{
    printf("  %s: retry %d read %d write %d special %d reason %d\n", what, BIO_should_retry(b) != 0,
        BIO_should_read(b) != 0, BIO_should_write(b) != 0, BIO_should_io_special(b) != 0,
        BIO_get_retry_reason(b));
}

/* Runs both SSL BIOs' handshakes until both finish: whether they did. */
static int handshake(BIO *c, BIO *s)
{
    int round, cdone = 0, sdone = 0;

    for (round = 0; round < 32 && !(cdone && sdone); round++) {
        if (!cdone) {
            long r = BIO_do_handshake(c);

            if (r == 1)
                cdone = 1;
            else if (!BIO_should_retry(c))
                return 0;
            if (round == 0)
                flags("client after its first try", c);
        }
        if (!sdone) {
            long r = BIO_do_handshake(s);

            if (r == 1)
                sdone = 1;
            else if (!BIO_should_retry(s))
                return 0;
        }
    }
    return cdone && sdone;
}

static void test_pair(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    BIO *a = NULL, *b = NULL, *c, *s, *top;
    SSL *cs = NULL, *ss = NULL;
    char buf[64];
    int n;

    printf("# SSL BIOs over a BIO pair\n");
    check(BIO_new_ssl(NULL, 0) == NULL, "no SSL BIO without a context");
    errors();
    check(BIO_new_bio_pair(&a, 0, &b, 0) == 1, "a BIO pair");
    c = BIO_new_ssl(cctx, 1);
    s = BIO_new_ssl(sctx, 0);
    check(c != NULL && s != NULL, "BIO_new_ssl");
    check(BIO_method_type(c) == BIO_TYPE_SSL, "the SSL BIO type");
    printf("  name: %s\n", BIO_method_name(c));
    check(BIO_get_ssl(c, &cs) == 1 && cs != NULL, "BIO_get_ssl");
    check(SSL_is_server(cs) == 0, "a client");
    BIO_get_ssl(s, &ss);
    check(SSL_is_server(ss) == 1, "a server");
    check(BIO_get_close(c) == BIO_CLOSE, "the BIO owns its connection");
    printf("  before push: rbio %s\n", SSL_get_rbio(cs) == NULL ? "none" : "set");
    top = BIO_push(c, a);
    check(top == c && BIO_next(c) == a, "the client pushed onto its transport");
    check(SSL_get_rbio(cs) == a && SSL_get_wbio(cs) == a, "the push gives the connection its BIOs");
    BIO_push(s, b);
    printf("  info ctrl: %ld\n", BIO_ctrl(c, BIO_CTRL_INFO, 0, NULL));
    printf("  renegotiate bytes: %ld then %ld\n", BIO_set_ssl_renegotiate_bytes(c, 100),
        BIO_set_ssl_renegotiate_bytes(c, 4096));
    printf("  renegotiate timeout: %ld then %ld\n", BIO_set_ssl_renegotiate_timeout(c, 10),
        BIO_set_ssl_renegotiate_timeout(c, 0));
    printf("  renegotiates: %ld\n", BIO_get_num_renegotiates(c));

    n = BIO_read(c, buf, sizeof(buf));
    printf("  a read before the handshake: %d\n", n);
    flags("client", c);
    check(handshake(c, s), "BIO_do_handshake on both");
    errors();
    check(SSL_is_init_finished(cs) && SSL_is_init_finished(ss), "both finished");
    check(BIO_write(c, "hello", 5) == 5, "BIO_write");
    flags("client after the write", c);
    printf("  pending on the server: %ld, wpending on the client: %ld\n", (long)BIO_ctrl_pending(s),
        (long)BIO_ctrl_wpending(c));
    n = BIO_read(s, buf, sizeof(buf));
    check(n == 5 && memcmp(buf, "hello", 5) == 0, "BIO_read");
    n = BIO_read(s, buf, sizeof(buf));
    printf("  an empty read: %d\n", n);
    flags("server", s);
    check(BIO_puts(s, "a line\n") == 7, "BIO_puts");
    n = BIO_gets(c, buf, sizeof(buf));
    printf("  BIO_gets: %d\n", n);
    errors();
    n = BIO_read(c, buf, sizeof(buf));
    check(n == 7 && memcmp(buf, "a line\n", 7) == 0, "the line arrives");
    printf("  flush: %d\n", BIO_flush(c));
    printf("  set close: %d, get close: %d\n", BIO_set_close(c, BIO_CLOSE), BIO_get_close(c));

    BIO_ssl_shutdown(c);
    check((SSL_get_shutdown(cs) & SSL_SENT_SHUTDOWN) != 0, "BIO_ssl_shutdown sent close_notify");
    n = BIO_read(s, buf, sizeof(buf));
    printf("  the server reads: %d, shutdown %d\n", n, SSL_get_shutdown(ss));
    flags("server", s);
    check(BIO_ssl_copy_session_id(NULL, s) == 0, "copy with no SSL BIO");
    check(BIO_ssl_copy_session_id(a, s) == 0, "copy from a chain without one");
    BIO_ssl_shutdown(NULL);
    errors();
    BIO_free_all(c);
    BIO_free_all(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void test_set_ssl(void)
{
    SSL_CTX *ctx = client_ctx();
    BIO *b = BIO_new(BIO_f_ssl()), *m = BIO_new(BIO_s_mem());
    SSL *s = SSL_new(ctx), *got = NULL;
    BIO_POLL_DESCRIPTOR d;

    printf("# BIO_set_ssl\n");
    check(BIO_get_ssl(b, &got) == 0 && got == NULL, "no connection yet");
    printf("  ctrls without one: %ld %ld\n", BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL), (long)BIO_pending(b));
    SSL_set_bio(s, m, m);
    check(BIO_set_ssl(b, s, BIO_NOCLOSE) == 1, "BIO_set_ssl");
    check(BIO_next(b) == m, "the read BIO follows");
    check(BIO_get_close(b) == BIO_NOCLOSE, "not owned");
    check(BIO_get_ssl(b, &got) == 1 && got == s, "BIO_get_ssl");
    check(BIO_set_ssl_mode(b, 1) == 1 && SSL_is_server(s) == 0, "client mode");
    check(BIO_set_ssl_mode(b, 0) == 1 && SSL_is_server(s) == 1, "server mode");
    BIO_set_ssl_mode(b, 1);
    printf("  read poll descriptor: %d\n", SSL_get_rpoll_descriptor(s, &d));
    printf("  write poll descriptor: %d\n", SSL_get_wpoll_descriptor(s, &d));
    printf("  pending (the memory BIO's): %ld\n", (long)BIO_pending(b));
    BIO_write(m, "x", 1);
    printf("  pending after a write to it: %ld\n", (long)BIO_pending(b));
    printf("  handshake: %ld\n", BIO_do_handshake(b));
    flags("BIO", b);
    errors();
    printf("  reset: %d\n", BIO_reset(b));
    errors();
    BIO_pop(b);
    check(SSL_get_rbio(s) == NULL, "the pop takes the connection's BIOs");
    BIO_free(b);
    SSL_free(s);
    SSL_CTX_free(ctx);
}

static void test_constructors(void)
{
    SSL_CTX *ctx = client_ctx();
    BIO *b = BIO_new_ssl_connect(ctx), *n;
    SSL *s = NULL;

    printf("# BIO_new_ssl_connect, BIO_new_buffer_ssl_connect\n");
    check(b != NULL && BIO_method_type(b) == BIO_TYPE_SSL, "an SSL BIO first");
    n = BIO_next(b);
    check(n != NULL && BIO_method_type(n) == BIO_TYPE_CONNECT, "then a connect BIO");
    BIO_get_ssl(b, &s);
    check(s != NULL && SSL_get_rbio(s) == n, "the connection reads from it");
    check(BIO_set_conn_hostname(b, "localhost:0") == 1, "ctrls reach the connect BIO");
    printf("  hostname: %s\n", BIO_get_conn_hostname(n));
    BIO_free_all(b);
    b = BIO_new_buffer_ssl_connect(ctx);
    check(b != NULL && BIO_method_type(b) == BIO_TYPE_BUFFER, "a buffer first");
    n = BIO_next(b);
    check(n != NULL && BIO_method_type(n) == BIO_TYPE_SSL, "then an SSL BIO");
    check(BIO_method_type(BIO_next(n)) == BIO_TYPE_CONNECT, "then a connect BIO");
    BIO_free_all(b);
    check(BIO_new_ssl_connect(NULL) == NULL, "no context");
    errors();
    SSL_CTX_free(ctx);
}

/* The lengths of the application data records an end writes, as text. */
static char app_records[256];

static void count_app_records(int write_p, int version, int content_type, const void *buf,
                              size_t len, SSL *ssl, void *arg)
{
    const unsigned char *h = buf;
    size_t at = strlen(app_records);

    (void)version;
    (void)ssl;
    (void)arg;
    if (write_p && content_type == SSL3_RT_HEADER && len >= 5 && h[0] == SSL3_RT_APPLICATION_DATA
        && at + 8 < sizeof(app_records))
        snprintf(app_records + at, sizeof(app_records) - at, " %u", (unsigned)(h[3] << 8 | h[4]));
}

/*
 * A line read as s_server -www reads its request (BIO_gets through a BIO_f_buffer over a
 * BIO_f_ssl), with the line split over records: TLS 1.0 CBC with the first octet alone in its
 * record (the 1/n-1 split tlslite and browsers make), and the same over TLS 1.2.
 */
static void test_split_line(void)
{
    static const struct {
        const char *name;
        int version;
    } cases[] = { { "TLS 1.0", TLS1_VERSION }, { "TLS 1.2", TLS1_2_VERSION } };
    size_t k;

    for (k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
        SSL *c, *s;
        BIO *io, *sb;
        char buf[128], what[160];
        int n, tries;

        SSL_CTX_set_min_proto_version(cctx, cases[k].version);
        SSL_CTX_set_max_proto_version(cctx, cases[k].version);
        SSL_CTX_set_cipher_list(cctx, "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:AES128-SHA:@SECLEVEL=0");
        SSL_CTX_set_cipher_list(sctx, "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:AES128-SHA:@SECLEVEL=0");
        SSL_CTX_set_min_proto_version(sctx, cases[k].version);
        /* No empty fragment before each record: the client's writes are its records. */
        SSL_CTX_set_options(cctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
        connect_pair(cctx, sctx, &c, &s);
        /* Set before the handshake: a record layer takes the callback when it's made. */
        SSL_set_msg_callback(s, count_app_records);
        snprintf(what, sizeof(what), "%s: the handshake", cases[k].name);
        check(run(c, s, 0) == 0, what);
        snprintf(what, sizeof(what), "%s: two records written", cases[k].name);
        check(SSL_write(c, "G", 1) == 1 && SSL_write(c, "ET / HTTP/1.0\r\n", 15) == 15, what);
        io = BIO_new(BIO_f_buffer());
        sb = BIO_new(BIO_f_ssl());
        BIO_set_ssl(sb, s, BIO_NOCLOSE);
        BIO_push(io, sb);
        n = -1;
        for (tries = 0; tries < 8 && n < 0; tries++)
            n = BIO_gets(io, buf, sizeof(buf));
        printf("  %s: BIO_gets %d \"%.*s\"\n", cases[k].name, n, n > 2 ? n - 2 : 0, buf);
        snprintf(what, sizeof(what), "%s: BIO_gets returns the whole line", cases[k].name);
        check(n == 16 && memcmp(buf, "GET / HTTP/1.0\r\n", 16) == 0, what);
        /*
         * The answer, as s_server -www writes it: lines through the buffer, a flush, then
         * close_notify. In TLS 1.0 CBC each write is an empty fragment and then the data.
         */
        BIO_puts(io, "HTTP/1.0 200 ok\r\n");
        BIO_puts(io, "\r\n<pre>\n");
        app_records[0] = '\0';
        snprintf(what, sizeof(what), "%s: the answer flushed", cases[k].name);
        check(BIO_flush(io) == 1, what);
        /* TLS 1.0 CBC: an empty fragment (only its MAC and padding) before the data. */
        printf("  %s: the server's application data records:%s\n", cases[k].name, app_records);
        snprintf(what, sizeof(what), "%s: the server's close_notify", cases[k].name);
        check(SSL_shutdown(s) == 0, what);
        {
            char got[256];
            int total = 0, r;

            while ((r = SSL_read(c, got + total, (int)sizeof(got) - 1 - total)) > 0)
                total += r;
            got[total] = '\0';
            printf("  %s: the client read %d octets, then %d (SSL_get_error %d)\n",
                   cases[k].name, total, r, SSL_get_error(c, r));
            snprintf(what, sizeof(what), "%s: the client reads the whole answer, then EOF",
                     cases[k].name);
            check(total == 25 && strcmp(got, "HTTP/1.0 200 ok\r\n\r\n<pre>\n") == 0
                      && SSL_get_error(c, r) == SSL_ERROR_ZERO_RETURN,
                  what);
        }
        BIO_free_all(io);
        SSL_set_shutdown(c, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        SSL_set_shutdown(s, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        SSL_free(c);
        SSL_free(s);
        SSL_CTX_free(cctx);
        SSL_CTX_free(sctx);
        errors();
    }
}

/*
 * Both ends write through a buffering BIO (BIO_f_buffer over the pair): the handshake goes on
 * only because the library flushes the write BIO after each flight (statem_flush), as it
 * does; nothing reaches the pair before a flush.
 */
static void test_buffered_wbio(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c = SSL_new(cctx), *s = SSL_new(sctx);
    BIO *a = NULL, *b = NULL, *ca, *sb;
    int r;

    printf("# a buffering write BIO on both ends\n");
    BIO_new_bio_pair(&a, 0, &b, 0);
    ca = BIO_push(BIO_new(BIO_f_buffer()), a);
    sb = BIO_push(BIO_new(BIO_f_buffer()), b);
    BIO_up_ref(a);
    BIO_up_ref(b);
    SSL_set_bio(c, a, ca);
    SSL_set_bio(s, b, sb);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    r = run(c, s, 0);
    printf("  handshake %s, %s\n", r == 0 ? "done" : "failed", SSL_get_version(c));
    check(r == 0, "the handshake through buffering write BIOs");
    errors();
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

/*
 * A TLS 1.3 client that closes its socket as soon as its handshake is done, before reading the
 * server's NewSessionTickets: the server's ticket write fails (EPIPE or ECONNRESET), which
 * OpenSSL ignores, so SSL_accept still succeeds.
 */
static void test_closed_before_tickets(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c = SSL_new(cctx), *s = SSL_new(sctx);
    int fds[2], round, cr = 0, sr = 0;

    printf("# a TLS 1.3 client closes before the server's tickets\n");
    signal(SIGPIPE, SIG_IGN);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        printf("Bail out! socketpair\n");
        exit(1);
    }
    fcntl(fds[0], F_SETFL, O_NONBLOCK);
    fcntl(fds[1], F_SETFL, O_NONBLOCK);
    SSL_set_fd(c, fds[0]);
    SSL_set_fd(s, fds[1]);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    /* The client's flight, the server's, then the client's Finished: the client is done. */
    for (round = 0; round < 16 && cr != 1; round++) {
        cr = SSL_do_handshake(c);
        if (cr != 1)
            SSL_do_handshake(s);
    }
    printf("  client: %d, %s\n", cr, SSL_get_version(c));
    SSL_free(c);
    close(fds[0]);
    for (round = 0; round < 16 && sr != 1; round++) {
        sr = SSL_do_handshake(s);
        if (sr != 1 && SSL_get_error(s, sr) != SSL_ERROR_WANT_READ)
            break;
    }
    printf("  server: %d, SSL_get_error %d\n", sr, sr == 1 ? 0 : SSL_get_error(s, sr));
    check(sr == 1, "the server's handshake succeeds without sending its tickets");
    errors();
    SSL_free(s);
    close(fds[1]);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

/*
 * A write the peer hasn't made room for waits for SSL_write's retry: meanwhile SSL_read reads
 * (WANT_READ), it doesn't try that write again (WANT_WRITE), so two ends that each read before
 * writing more don't wait for each other (ssl_old_test's BIO pairs).
 */
static void test_read_with_write_pending(void)
{
    SSL_CTX *sctx = server_ctx(), *cctx = client_ctx();
    SSL *c = SSL_new(cctx), *s = SSL_new(sctx);
    BIO *a = NULL, *b = NULL;
    static char data[4000], buf[8192];
    int r, total = 0, rounds;

    printf("# a read while a write waits\n");
    BIO_new_bio_pair(&a, 1024, &b, 1024);
    SSL_set_bio(c, a, a);
    SSL_set_bio(s, b, b);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    check(run(c, s, 0) == 0, "the handshake");
    r = SSL_read(c, buf, sizeof(buf));
    printf("  the client reads the tickets: %d -> %d\n", r, SSL_get_error(c, r));
    memset(data, 'x', sizeof(data));
    r = SSL_write(c, data, sizeof(data));
    printf("  the client writes more than fits: %d -> %d\n", r, SSL_get_error(c, r));
    r = SSL_read(c, buf, sizeof(buf));
    printf("  then reads: %d -> %d\n", r, SSL_get_error(c, r));
    check(SSL_get_error(c, r) == SSL_ERROR_WANT_READ, "the read waits for input, not for the write");
    for (rounds = 0; rounds < 32 && total < (int)sizeof(data); rounds++) {
        r = SSL_read(s, buf, sizeof(buf));
        if (r > 0)
            total += r;
        r = SSL_write(c, data, sizeof(data));
        if (r > 0)
            printf("  the retried write: %d\n", r);
    }
    check(total == (int)sizeof(data), "the server read it all");
    errors();
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

int main(void)
{
    test_buffered_wbio();
    test_read_with_write_pending();
    test_closed_before_tickets();
    test_pair();
    test_set_ssl();
    test_constructors();
    test_split_line();
    (void)CLIENT_PEM;
    (void)CLIENT_KEY_PEM;
    (void)trust_root;
    (void)cn;
    (void)run;
    (void)pair;
    (void)connect_pair;
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
