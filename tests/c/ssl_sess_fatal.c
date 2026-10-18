/*
 * Conformance test for which failures take the session out of the server's cache: a fatal
 * alert sent removes it (ssl3_send_alert), except once the server has sent close_notify, when
 * the alert isn't sent and the session stays, so the client can resume it.
 *
 * Found by tlsfuzzer (test-extended-master-secret-extension-with-client-cert.py: its client
 * answers close_notify with an alert of level 0, which the server rejects after its own
 * close_notify, and then resumes). Here a corrupted record does the same after SSL_shutdown,
 * and before it.
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

static void bail(const char *what)
{
    printf("Bail out! %s\n", what);
    exit(1);
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

static EVP_PKEY *key;
static X509 *cert;

static void make_cert(void)
{
    X509_NAME *n = X509_NAME_new();

    key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    cert = X509_new();
    if (key == NULL || cert == NULL || n == NULL
        || X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)"server", -1,
                                      -1, 0) != 1
        || X509_set_version(cert, X509_VERSION_3) != 1
        || ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) != 1
        || X509_set_subject_name(cert, n) != 1 || X509_set_issuer_name(cert, n) != 1
        || X509_gmtime_adj(X509_getm_notBefore(cert), -3600) == NULL
        || X509_gmtime_adj(X509_getm_notAfter(cert), 86400) == NULL
        || X509_set_pubkey(cert, key) != 1 || X509_sign(cert, key, EVP_sha256()) <= 0)
        bail("certificate");
    X509_NAME_free(n);
}

struct link {
    SSL *c, *s;
    BIO *c_in, *c_out, *s_in, *s_out;
};

static BIO *mem(void)
{
    BIO *b = BIO_new(BIO_s_mem());

    BIO_set_mem_eof_return(b, -1);
    return b;
}

static void link_up(struct link *l, SSL_CTX *cctx, SSL_CTX *sctx, SSL_SESSION *resume)
{
    l->c = SSL_new(cctx);
    l->s = SSL_new(sctx);
    l->c_in = mem();
    l->c_out = mem();
    l->s_in = mem();
    l->s_out = mem();
    if (l->c == NULL || l->s == NULL)
        bail("connections");
    SSL_set_bio(l->c, l->c_in, l->c_out);
    SSL_set_bio(l->s, l->s_in, l->s_out);
    SSL_set_connect_state(l->c);
    SSL_set_accept_state(l->s);
    if (resume != NULL)
        SSL_set_session(l->c, resume);
}

/* Moves what one side wrote to the other, flipping a byte of it when `flip`. */
static void relay(BIO *from, BIO *to, int flip)
{
    unsigned char buf[65536];
    int len = BIO_read(from, buf, sizeof(buf));

    if (len <= 0)
        return;
    if (flip)
        buf[len - 1] ^= 1;
    BIO_write(to, buf, len);
}

static int handshake(struct link *l)
{
    int round, cdone = 0, sdone = 0;

    for (round = 0; round < 32 && (!cdone || !sdone); round++) {
        if (!cdone)
            cdone = SSL_do_handshake(l->c) == 1;
        relay(l->c_out, l->s_in, 0);
        if (!sdone)
            sdone = SSL_do_handshake(l->s) == 1;
        relay(l->s_out, l->c_in, 0);
    }
    ERR_clear_error();
    return cdone && sdone;
}

/* A full handshake, then a corrupted client record the server reads after its own close_notify
 * (`shutdown_first`) or instead; then whether the client's session resumes. */
static void scenario(const char *name, int shutdown_first)
{
    SSL_CTX *cctx = SSL_CTX_new(TLS_client_method()), *sctx = SSL_CTX_new(TLS_server_method());
    struct link l;
    SSL_SESSION *sess;
    unsigned char buf[16];
    int r;

    printf("# %s\n", name);
    if (cctx == NULL || sctx == NULL || SSL_CTX_use_certificate(sctx, cert) != 1
        || SSL_CTX_use_PrivateKey(sctx, key) != 1)
        bail("contexts");
    SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION);
    SSL_CTX_set_options(sctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_options(cctx, SSL_OP_NO_TICKET);
    link_up(&l, cctx, sctx, NULL);
    check(handshake(&l), "full handshake");
    printf("  cached: %ld\n", SSL_CTX_sess_number(sctx));
    if (shutdown_first) {
        r = SSL_shutdown(l.s);
        printf("  server SSL_shutdown: %d\n", r);
    }
    if (SSL_write(l.c, "hello", 5) != 5)
        bail("write");
    relay(l.c_out, l.s_in, 1);
    r = shutdown_first ? SSL_shutdown(l.s) : SSL_read(l.s, buf, sizeof(buf));
    printf("  server %s: %d, SSL_get_error %d\n", shutdown_first ? "SSL_shutdown" : "SSL_read", r,
           SSL_get_error(l.s, r));
    errors("server");
    printf("  cached: %ld\n", SSL_CTX_sess_number(sctx));
    sess = SSL_get1_session(l.c);
    /* A client freed without its close_notify gives up its session (ssl_clear_bad_session). */
    SSL_shutdown(l.c);
    SSL_free(l.c);
    SSL_free(l.s);
    printf("  cached after SSL_free: %ld, client session resumable %d\n",
           SSL_CTX_sess_number(sctx), SSL_SESSION_is_resumable(sess));
    link_up(&l, cctx, sctx, sess);
    check(handshake(&l), "second handshake");
    printf("  resumed: %d\n", SSL_session_reused(l.c));
    SSL_SESSION_free(sess);
    SSL_free(l.c);
    SSL_free(l.s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

int main(void)
{
    make_cert();
    scenario("a bad record after the server's close_notify", 1);
    scenario("a bad record before any close_notify", 0);
    X509_free(cert);
    EVP_PKEY_free(key);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
