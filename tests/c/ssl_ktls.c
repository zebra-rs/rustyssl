/*
 * Conformance test for kernel TLS in the default build, which leaves it out (OPENSSL_NO_KTLS):
 * BIO_get_ktls_send(3) and BIO_get_ktls_recv(3), both as the header's macros and as the
 * BIO_ctrl(3) commands a kTLS-enabled header expands them to, on memory, pair, socket and SSL
 * BIOs; SSL_OP_ENABLE_KTLS (and its sendfile zerocopy companion) kept in the options yet
 * changing nothing in a handshake over sockets; and SSL_sendfile(3)'s failures.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
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

/* A server context with the server's certificate and key. */
static SSL_CTX *server_ctx(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    BIO *b = BIO_new_mem_buf(SERVER_PEM, -1), *k = BIO_new_mem_buf(SERVER_KEY_PEM, -1);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);
    EVP_PKEY *pk = PEM_read_bio_PrivateKey(k, NULL, NULL, NULL);

    if (ctx == NULL || x == NULL || pk == NULL || SSL_CTX_use_certificate(ctx, x) != 1
        || SSL_CTX_use_PrivateKey(ctx, pk) != 1) {
        printf("Bail out! server context\n");
        exit(1);
    }
    X509_free(x);
    EVP_PKEY_free(pk);
    BIO_free(b);
    BIO_free(k);
    return ctx;
}

/* Both kTLS queries on a BIO: the macros, and the controls a kTLS header would send. */
static void ktls_of(const char *what, BIO *b)
{
    printf("  %s: macros %d %d, controls %ld %ld\n", what, BIO_get_ktls_send(b) ? 1 : 0,
        BIO_get_ktls_recv(b) ? 1 : 0, BIO_ctrl(b, BIO_CTRL_GET_KTLS_SEND, 0, NULL),
        BIO_ctrl(b, BIO_CTRL_GET_KTLS_RECV, 0, NULL));
}

/* Runs both ends' handshakes in turn until both finish. */
static int run(SSL *c, SSL *s)
{
    int cdone = 0, sdone = 0, round;

    for (round = 0; round < 1000 && (!cdone || !sdone); round++) {
        int i;

        for (i = 0; i < 2; i++) {
            SSL *x = i == 0 ? c : s;
            int *done = i == 0 ? &cdone : &sdone, r, e;

            if (*done)
                continue;
            r = SSL_do_handshake(x);
            if (r == 1) {
                *done = 1;
                continue;
            }
            e = SSL_get_error(x, r);
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
                printf("  %s stopped: %d\n", i == 0 ? "client" : "server", e);
                errors();
                return 0;
            }
        }
    }
    return cdone && sdone;
}

/* Reads what's there, retrying while the socket has nothing yet. */
static int read_some(SSL *s, char *buf, int len)
{
    int i, r = -1;

    for (i = 0; i < 100000; i++) {
        r = SSL_read(s, buf, len);
        if (r > 0 || SSL_get_error(s, r) != SSL_ERROR_WANT_READ)
            break;
    }
    return r;
}

/* A client and a server over a nonblocking socket pair with socket BIOs. */
static void handshake(SSL_CTX *cctx, SSL_CTX *sctx, const char *version, int max)
{
    int fds[2];
    SSL *c, *s;
    char buf[64];
    int r;
    long n;

    printf("# a %s handshake over sockets, kTLS asked for\n", version);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0
        || fcntl(fds[0], F_SETFL, O_NONBLOCK) != 0 || fcntl(fds[1], F_SETFL, O_NONBLOCK) != 0) {
        printf("Bail out! socketpair\n");
        exit(1);
    }
    c = SSL_new(cctx);
    s = SSL_new(sctx);
    if (c == NULL || s == NULL) {
        printf("Bail out! SSL_new\n");
        exit(1);
    }
    SSL_set_max_proto_version(c, max);
    check(SSL_set_fd(c, fds[0]) == 1 && SSL_set_fd(s, fds[1]) == 1, "the sockets attach");
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    SSL_set_options(c, SSL_OP_ENABLE_KTLS);
    check((SSL_get_options(c) & SSL_OP_ENABLE_KTLS) != 0, "SSL_set_options keeps SSL_OP_ENABLE_KTLS");
    check(run(c, s), "the handshake completes");
    printf("  version %s, cipher %s\n", SSL_get_version(c), SSL_get_cipher_name(c));
    ktls_of("client wbio", SSL_get_wbio(c));
    ktls_of("client rbio", SSL_get_rbio(c));
    ktls_of("server wbio", SSL_get_wbio(s));
    ktls_of("server rbio", SSL_get_rbio(s));
    check(SSL_write(c, "ping", 4) == 4, "the client writes through the record layer");
    r = read_some(s, buf, sizeof(buf));
    check(r == 4 && memcmp(buf, "ping", 4) == 0, "the server reads it");
    errors();

    n = SSL_sendfile(c, fds[0], 0, 4, 0);
    printf("  SSL_sendfile after the handshake: %ld, error %d\n", n, SSL_get_error(c, (int)n));
    errors();
    n = SSL_sendfile(c, -1, 0, 0, 0);
    printf("  SSL_sendfile, no file: %ld\n", n);
    errors();
    SSL_shutdown(c);
    n = SSL_sendfile(c, fds[0], 0, 4, 0);
    printf("  SSL_sendfile after close_notify: %ld, error %d\n", n, SSL_get_error(c, (int)n));
    errors();
    SSL_free(c);
    SSL_free(s);
    close(fds[0]);
    close(fds[1]);
}

int main(void)
{
    SSL_CTX *cctx = SSL_CTX_new(TLS_client_method()), *sctx = server_ctx();
    BIO *mem = BIO_new(BIO_s_mem()), *a = NULL, *b = NULL, *sock, *sslb;
    SSL *fresh;
    int fds[2];
    uint64_t opts;
    long n;

    if (cctx == NULL || mem == NULL || BIO_new_bio_pair(&a, 0, &b, 0) != 1
        || socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        printf("Bail out! setup\n");
        return 1;
    }

    printf("# BIOs without kTLS\n");
    ktls_of("memory", mem);
    ktls_of("pair", a);
    sock = BIO_new_socket(fds[0], BIO_NOCLOSE);
    ktls_of("socket", sock);
    sslb = BIO_new_ssl(cctx, 1);
    ktls_of("ssl", sslb);
    BIO_push(sslb, sock);
    ktls_of("ssl over a socket", sslb);
    errors();
    BIO_free_all(sslb);
    BIO_free(mem);
    BIO_free(a);
    BIO_free(b);
    close(fds[0]);
    close(fds[1]);

    printf("# the options\n");
    opts = SSL_CTX_set_options(cctx, SSL_OP_ENABLE_KTLS | SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE);
    check((opts & SSL_OP_ENABLE_KTLS) != 0 && (opts & SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE) != 0,
        "SSL_CTX_set_options keeps both kTLS options");
    opts = SSL_CTX_clear_options(cctx, SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE);
    check((opts & SSL_OP_ENABLE_KTLS) != 0 && (opts & SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE) == 0,
        "SSL_CTX_clear_options drops one");
    SSL_CTX_set_options(sctx, SSL_OP_ENABLE_KTLS);

    printf("# SSL_sendfile without a handshake\n");
    n = SSL_sendfile(NULL, 0, 0, 0, 0);
    printf("  NULL: %ld\n", n);
    errors();
    fresh = SSL_new(cctx);
    n = SSL_sendfile(fresh, 0, 0, 0, 0);
    printf("  no role: %ld\n", n);
    errors();
    SSL_set_connect_state(fresh);
    n = SSL_sendfile(fresh, 0, 0, 0, 0);
    printf("  a client before its handshake: %ld\n", n);
    errors();
    SSL_set_shutdown(fresh, SSL_SENT_SHUTDOWN);
    n = SSL_sendfile(fresh, 0, 0, 0, 0);
    printf("  a client marked shut down: %ld\n", n);
    errors();
    SSL_free(fresh);
    fresh = SSL_new(cctx);
    SSL_set_shutdown(fresh, SSL_SENT_SHUTDOWN);
    n = SSL_sendfile(fresh, 0, 0, 0, 0);
    printf("  no role, marked shut down: %ld\n", n);
    errors();
    SSL_free(fresh);

    handshake(cctx, sctx, "TLS 1.3", TLS1_3_VERSION);
    handshake(cctx, sctx, "TLS 1.2", TLS1_2_VERSION);

    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
