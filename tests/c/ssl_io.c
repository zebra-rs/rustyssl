/*
 * Conformance test for application data over TLS (SSL_read(3), SSL_read_ex(3), SSL_peek(3),
 * SSL_peek_ex(3), SSL_write(3), SSL_write_ex(3), SSL_pending(3), SSL_has_pending(3),
 * SSL_get_error(3), SSL_CTX_set_mode(3)): reads and writes in both directions over a BIO pair,
 * TLS 1.3 and 1.2, peeking and partial reads, empty and negative lengths, I/O that runs the
 * handshake, writes larger than the BIO takes (retries with the same buffer, a different one,
 * SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER, SSL_MODE_ENABLE_PARTIAL_WRITE), and a non-blocking
 * socketpair whose peer goes away without close_notify (with and without
 * SSL_OP_IGNORE_UNEXPECTED_EOF).
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


#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

/* Prints what an I/O call returned and what SSL_get_error says, then the error queue. */
static void said(const char *what, SSL *x, int r)
{
    printf("  %s: %d -> %d\n", what, r, SSL_get_error(x, r));
    errors();
}

/* A connected pair, handshake done, the client's version capped at `max`. */
static void connected(int max, long smode, SSL_CTX **cctx, SSL_CTX **sctx, SSL **c, SSL **s)
{
    *cctx = client_ctx();
    *sctx = server_ctx();
    SSL_CTX_set_max_proto_version(*cctx, max);
    SSL_CTX_set_mode(*cctx, smode);
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

static void test_basic(int max)
{
    SSL_CTX *cctx, *sctx;
    SSL *c, *s;
    char buf[64];
    size_t n = 0;
    int r;

    printf("# reading and writing, %s\n", max == TLS1_2_VERSION ? "TLS 1.2" : "TLS 1.3");
    connected(max, 0, &cctx, &sctx, &c, &s);
    check(SSL_pending(s) == 0 && !SSL_has_pending(s), "nothing pending at first");
    r = SSL_read(s, buf, sizeof(buf));
    said("server reads with nothing sent", s, r);
    r = SSL_read(c, buf, sizeof(buf));
    said("client reads with nothing sent", c, r);
    check(SSL_write(c, "hello", 5) == 5, "the client writes 5 octets");
    check(SSL_pending(s) == 0, "nothing pending before the server reads");
    r = SSL_peek(s, buf, 3);
    check(r == 3 && memcmp(buf, "hel", 3) == 0, "SSL_peek gets the first 3");
    printf("  pending %d, has_pending %d\n", SSL_pending(s), SSL_has_pending(s));
    r = SSL_peek(s, buf, sizeof(buf));
    check(r == 5 && memcmp(buf, "hello", 5) == 0, "SSL_peek again gets all 5");
    r = SSL_read(s, buf, 2);
    check(r == 2 && memcmp(buf, "he", 2) == 0, "SSL_read takes 2");
    printf("  pending %d, has_pending %d\n", SSL_pending(s), SSL_has_pending(s));
    check(SSL_read_ex(s, buf, sizeof(buf), &n) == 1 && n == 3 && memcmp(buf, "llo", 3) == 0,
        "SSL_read_ex takes the other 3");
    printf("  pending %d, has_pending %d\n", SSL_pending(s), SSL_has_pending(s));
    r = SSL_read(s, buf, sizeof(buf));
    said("server reads again", s, r);
    n = 0;
    check(SSL_write_ex(s, "world!", 6, &n) == 1 && n == 6, "SSL_write_ex from the server");
    n = 0;
    check(SSL_peek_ex(c, buf, 4, &n) == 1 && n == 4 && memcmp(buf, "worl", 4) == 0, "SSL_peek_ex");
    r = SSL_read(c, buf, 0);
    said("a read of 0 octets", c, r);
    r = SSL_read(c, buf, sizeof(buf));
    check(r == 6 && memcmp(buf, "world!", 6) == 0, "the client reads 6");
    r = SSL_write(c, "x", 0);
    said("a write of 0 octets", c, r);
    r = SSL_write(c, "x", -1);
    said("a write of -1 octets", c, r);
    r = SSL_read(c, buf, -1);
    said("a read of -1 octets", c, r);
    r = SSL_peek(c, buf, -1);
    said("a peek of -1 octets", c, r);
    /* Two records read in one call: SSL_read returns one record at a time. */
    SSL_write(c, "ab", 2);
    SSL_write(c, "cd", 2);
    r = SSL_read(s, buf, sizeof(buf));
    printf("  two records: first read %d\n", r);
    r = SSL_read(s, buf, sizeof(buf));
    printf("  two records: second read %d\n", r);
    done(cctx, sctx, c, s);
}

static void test_write_starts_handshake(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c, *s;
    char buf[16];
    int r, i;

    printf("# I/O before the handshake runs it\n");
    connect_pair(cctx, sctx, &c, &s);
    r = SSL_write(c, "early", 5);
    said("the client writes first", c, r);
    r = SSL_read(s, buf, sizeof(buf));
    said("the server reads first", s, r);
    check(SSL_in_init(s), "the server is in its handshake");
    for (i = 0, r = -1; i < 8 && r != 5; i++) {
        r = SSL_write(c, "early", 5);
        if (r != 5)
            SSL_read(s, buf, sizeof(buf));
    }
    check(r == 5, "the client's write goes through once the handshake is done");
    r = SSL_read(s, buf, sizeof(buf));
    check(r == 5 && memcmp(buf, "early", 5) == 0, "and the server reads it");
    errors();
    done(cctx, sctx, c, s);
}

/* Reads everything the server has, returning how much. */
static size_t drain(SSL *s)
{
    char buf[4096];
    size_t total = 0;
    int r;

    while ((r = SSL_read(s, buf, sizeof(buf))) > 0)
        total += (size_t)r;
    ERR_clear_error();
    return total;
}

static void test_big_writes(void)
{
    SSL_CTX *cctx, *sctx;
    SSL *c, *s;
    static unsigned char big[100000], copy[100000];
    size_t got = 0;
    int r, i;

    memset(big, 'b', sizeof(big));
    memcpy(copy, big, sizeof(big));

    printf("# a write larger than the BIO's buffer\n");
    connected(TLS1_3_VERSION, 0, &cctx, &sctx, &c, &s);
    r = SSL_write(c, big, sizeof(big));
    said("the first try", c, r);
    for (i = 0; i < 32 && r <= 0; i++) {
        got += drain(s);
        r = SSL_write(c, big, sizeof(big));
    }
    check(r == (int)sizeof(big), "retried with the same buffer, the whole write completes");
    got += drain(s);
    check(got == sizeof(big), "the server reads all of it");
    done(cctx, sctx, c, s);

    printf("# a retry with a different buffer\n");
    connected(TLS1_3_VERSION, 0, &cctx, &sctx, &c, &s);
    r = SSL_write(c, big, sizeof(big));
    said("the first try", c, r);
    drain(s);
    r = SSL_write(c, copy, sizeof(copy));
    said("a retry from another buffer", c, r);
    r = SSL_write(c, big, 10);
    said("a retry with fewer octets", c, r);
    done(cctx, sctx, c, s);

    printf("# SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER\n");
    connected(TLS1_3_VERSION, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER, &cctx, &sctx, &c, &s);
    r = SSL_write(c, big, sizeof(big));
    said("the first try", c, r);
    got = 0;
    for (i = 0; i < 32 && r <= 0; i++) {
        got += drain(s);
        r = SSL_write(c, i % 2 ? big : copy, sizeof(big));
    }
    check(r == (int)sizeof(big), "a moved buffer is accepted");
    got += drain(s);
    check(got == sizeof(big), "the server reads all of it");
    done(cctx, sctx, c, s);

    printf("# SSL_MODE_ENABLE_PARTIAL_WRITE\n");
    connected(TLS1_3_VERSION, SSL_MODE_ENABLE_PARTIAL_WRITE, &cctx, &sctx, &c, &s);
    check(SSL_get_mode(c) & SSL_MODE_ENABLE_PARTIAL_WRITE, "the mode is set");
    r = SSL_write(c, big, sizeof(big));
    printf("  the first write: %d\n", r);
    got = drain(s);
    printf("  the server read %zu\n", got);
    r = SSL_write(c, big, sizeof(big));
    printf("  the second write: %d\n", r);
    done(cctx, sctx, c, s);
}

static void nonblocking(int fd)
{
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
}

static void test_socketpair(long options)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c, *s;
    int fds[2], r, i;
    char buf[64];

    printf("# over a socketpair%s\n", options ? ", ignoring an unexpected EOF" : "");
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        printf("Bail out! socketpair\n");
        exit(1);
    }
    nonblocking(fds[0]);
    nonblocking(fds[1]);
    SSL_CTX_set_options(cctx, options);
    c = SSL_new(cctx);
    s = SSL_new(sctx);
    check(SSL_set_fd(c, fds[0]) == 1 && SSL_set_fd(s, fds[1]) == 1, "SSL_set_fd");
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    check(run(c, s, 1) == 0, "handshake");
    for (i = 0; i < 3; i++) {
        check(SSL_write(c, "ping", 4) == 4, "the client writes");
        r = SSL_read(s, buf, sizeof(buf));
        check(r == 4 && memcmp(buf, "ping", 4) == 0, "the server reads");
    }
    r = SSL_read(c, buf, sizeof(buf));
    said("the client reads with nothing sent", c, r);
    /* The server goes away without close_notify. */
    SSL_free(s);
    close(fds[1]);
    r = SSL_read(c, buf, sizeof(buf));
    said("the client reads after the peer closed", c, r);
    printf("  shutdown state %d\n", SSL_get_shutdown(c));
    r = SSL_read(c, buf, sizeof(buf));
    said("and reads again", c, r);
    r = SSL_write(c, "x", 1);
    printf("  a write after that: %s\n", r > 0 ? "succeeds" : "fails");
    ERR_clear_error();
    SSL_free(c);
    close(fds[0]);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

int main(void)
{
    /* A write to the closed socket must fail, not kill the test. */
    signal(SIGPIPE, SIG_IGN);
    test_basic(TLS1_3_VERSION);
    test_basic(TLS1_2_VERSION);
    test_write_starts_handshake();
    test_big_writes();
    test_socketpair(0);
    test_socketpair(SSL_OP_IGNORE_UNEXPECTED_EOF);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
