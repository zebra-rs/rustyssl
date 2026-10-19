/*
 * Conformance test for what a TLS 1.2 server's renegotiation reads (SSL_renegotiate(3)): the
 * settings changed on the connection since its first handshake (SSL_set_cipher_list(3),
 * SSL_set_options(3)) apply when the client starts a renegotiation, as they do when the server
 * asks for one.
 *
 * The key and certificate are made at run time; only deterministic output is printed.
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

/* Prints and clears the error queue: library/reason. */
static void errors(const char *who)
{
    unsigned long e;

    printf("  %s errors:", who);
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
}

static void bail(const char *what)
{
    printf("Bail out! %s\n", what);
    exit(1);
}

static X509 *self_signed(EVP_PKEY *k)
{
    X509 *x = X509_new();
    X509_NAME *n = X509_NAME_new();

    if (x == NULL || n == NULL || X509_set_version(x, X509_VERSION_3) != 1
        || ASN1_INTEGER_set(X509_get_serialNumber(x), 1) != 1
        || X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)"server", -1,
                                      -1, 0) != 1
        || X509_set_subject_name(x, n) != 1 || X509_set_issuer_name(x, n) != 1
        || X509_gmtime_adj(X509_getm_notBefore(x), -3600) == NULL
        || X509_gmtime_adj(X509_getm_notAfter(x), 86400) == NULL || X509_set_pubkey(x, k) != 1
        || X509_sign(x, k, EVP_sha256()) <= 0)
        bail("certificate");
    X509_NAME_free(n);
    return x;
}

/* Runs both ends' handshakes in turn until both finish (0) or one fails (its error). */
static int run(SSL *c, SSL *s)
{
    int cdone = 0, sdone = 0, round;

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
                continue;
            }
            e = SSL_get_error(x, r);
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
                printf("  %s stopped: %d\n", i == 0 ? "client" : "server", e);
                errors(i == 0 ? "client" : "server");
                return e;
            }
        }
    }
    return cdone && sdone ? 0 : -1;
}

/*
 * Runs the renegotiation the client started: the client's handshake, the server reading
 * (which takes the client's new ClientHello), in turn until the client is done or one fails.
 */
static void pump(SSL *c, SSL *s)
{
    unsigned char buf[16];
    int round;

    for (round = 0; round < 32; round++) {
        int r = SSL_do_handshake(c), e;

        if (r == 1 && !SSL_renegotiate_pending(c))
            break;
        if (r <= 0 && (e = SSL_get_error(c, r)) != SSL_ERROR_WANT_READ) {
            printf("  client handshake: %d\n", e);
            errors("client");
            break;
        }
        r = SSL_read(s, buf, sizeof(buf));
        if (r <= 0 && (e = SSL_get_error(s, r)) != SSL_ERROR_WANT_READ) {
            printf("  server read: %d\n", e);
            errors("server");
            break;
        }
    }
}

static void test(const char *name, EVP_PKEY *k, X509 *x, const char *cipher, long options)
{
    SSL_CTX *cctx = SSL_CTX_new(TLS_client_method()), *sctx = SSL_CTX_new(TLS_server_method());
    SSL *c, *s;
    BIO *a = NULL, *b = NULL;

    printf("# %s\n", name);
    if (cctx == NULL || sctx == NULL)
        bail("contexts");
    if (SSL_CTX_use_certificate(sctx, x) != 1 || SSL_CTX_use_PrivateKey(sctx, k) != 1)
        bail("server key");
    SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION);
    SSL_CTX_set_options(cctx, SSL_OP_NO_TICKET);
    /* OpenSSL 3's servers refuse a client's renegotiation unless allowed. */
    SSL_CTX_set_options(sctx, SSL_OP_NO_TICKET | SSL_OP_ALLOW_CLIENT_RENEGOTIATION);
    if (SSL_CTX_set_cipher_list(cctx, "AES128-GCM-SHA256:AES256-GCM-SHA384") != 1
        || SSL_CTX_set_cipher_list(sctx, "AES128-GCM-SHA256:AES256-GCM-SHA384") != 1)
        bail("ciphers");
    c = SSL_new(cctx);
    s = SSL_new(sctx);
    if (c == NULL || s == NULL || BIO_new_bio_pair(&a, 0, &b, 0) != 1)
        bail("connection");
    SSL_set_bio(c, a, a);
    SSL_set_bio(s, b, b);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    check(run(c, s) == 0, "the first handshake");
    printf("  %s %s\n", SSL_get_version(c), SSL_CIPHER_get_name(SSL_get_current_cipher(c)));
    /* The server's settings change; then the client renegotiates. */
    if (cipher != NULL && SSL_set_cipher_list(s, cipher) != 1)
        bail("server cipher");
    if (options != 0)
        SSL_set_options(s, options);
    check(SSL_renegotiate(c) == 1, "renegotiation requested");
    pump(c, s);
    printf("  after: %s, client pending %d, renegotiations %ld/%ld\n",
           SSL_CIPHER_get_name(SSL_get_current_cipher(c)), SSL_renegotiate_pending(c),
           SSL_num_renegotiations(c), SSL_num_renegotiations(s));
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

/*
 * A renegotiation the server asks for with a HelloRequest: the client's read starts it, and
 * both ends count it (SSL_num_renegotiations, SSL_total_renegotiations).
 */
static void test_hello_request(EVP_PKEY *k, X509 *x, int version)
{
    SSL_CTX *cctx = SSL_CTX_new(TLS_client_method()), *sctx = SSL_CTX_new(TLS_server_method());
    SSL *c, *s;
    BIO *a = NULL, *b = NULL;
    unsigned char buf[16];
    int round, r, e;

    printf("# the server asks with a HelloRequest, %s\n",
           version == TLS1_VERSION ? "TLS 1.0" : "TLS 1.2");
    if (cctx == NULL || sctx == NULL || SSL_CTX_use_certificate(sctx, x) != 1
        || SSL_CTX_use_PrivateKey(sctx, k) != 1)
        bail("contexts");
    /* The server caps the version: the client's hellos still offer TLS 1.2 (and 1.3). */
    if (version == TLS1_VERSION)
        SSL_CTX_set_max_proto_version(sctx, version);
    else
        SSL_CTX_set_max_proto_version(cctx, version);
    SSL_CTX_set_options(cctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_options(sctx, SSL_OP_NO_TICKET);
    /* TLS 1.0 needs security level 0; its renegotiation sends no signature_algorithms. */
    if (version == TLS1_VERSION
        && (SSL_CTX_set_cipher_list(cctx, "DEFAULT:@SECLEVEL=0") != 1
            || SSL_CTX_set_cipher_list(sctx, "DEFAULT:@SECLEVEL=0") != 1
            || SSL_CTX_set_min_proto_version(cctx, TLS1_VERSION) != 1
            || SSL_CTX_set_min_proto_version(sctx, TLS1_VERSION) != 1))
        bail("TLS 1.0");
    c = SSL_new(cctx);
    s = SSL_new(sctx);
    if (c == NULL || s == NULL || BIO_new_bio_pair(&a, 0, &b, 0) != 1)
        bail("connection");
    SSL_set_bio(c, a, a);
    SSL_set_bio(s, b, b);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    check(run(c, s) == 0, "the first handshake");
    check(SSL_renegotiate(s) == 1, "renegotiation requested");
    printf("  requested: client %ld/%ld, server %ld/%ld\n", SSL_num_renegotiations(c),
           SSL_total_renegotiations(c), SSL_num_renegotiations(s), SSL_total_renegotiations(s));
    for (round = 0; round < 32; round++) {
        r = SSL_do_handshake(s);
        if (r == 1 && !SSL_renegotiate_pending(s))
            break;
        if (r <= 0 && (e = SSL_get_error(s, r)) != SSL_ERROR_WANT_READ) {
            printf("  server handshake: %d\n", e);
            errors("server");
            break;
        }
        r = SSL_read(c, buf, sizeof(buf));
        if (r <= 0 && (e = SSL_get_error(c, r)) != SSL_ERROR_WANT_READ) {
            printf("  client read: %d\n", e);
            errors("client");
            break;
        }
    }
    printf("  after: client %ld/%ld, server %ld/%ld, pending %d/%d\n", SSL_num_renegotiations(c),
           SSL_total_renegotiations(c), SSL_num_renegotiations(s), SSL_total_renegotiations(s),
           SSL_renegotiate_pending(c), SSL_renegotiate_pending(s));
    printf("  cleared: %ld, then %ld/%ld\n", SSL_clear_num_renegotiations(c),
           SSL_num_renegotiations(c), SSL_total_renegotiations(c));
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

int main(void)
{
    EVP_PKEY *k = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    X509 *x;

    if (k == NULL)
        bail("key");
    x = self_signed(k);
    test("nothing changed", k, x, NULL, 0);
    test("the server's cipher list changed", k, x, "AES256-GCM-SHA384", 0);
    test("the server turned renegotiation off", k, x, NULL, SSL_OP_NO_RENEGOTIATION);
    test_hello_request(k, x, TLS1_2_VERSION);
    test_hello_request(k, x, TLS1_VERSION);
    X509_free(x);
    EVP_PKEY_free(k);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
