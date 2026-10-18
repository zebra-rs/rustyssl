/*
 * Conformance test for session tickets' callbacks and extra tickets
 * (SSL_CTX_set_session_ticket_cb(3), SSL_SESSION_set1_ticket_appdata(3),
 * SSL_SESSION_get0_ticket_appdata(3), SSL_new_session_ticket(3)): the server's generate
 * callback putting application data in its tickets and the decrypt callback's verdicts
 * (use, renew, ignore, abort) on resumption in TLS 1.3 and 1.2, and extra TLS 1.3 tickets
 * asked for after the handshake, over a BIO pair.
 *
 * Only deterministic output is printed.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
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

static int new_sessions = 0;
static SSL_SESSION *last_session = NULL;

static int new_session_cb(SSL *s, SSL_SESSION *sess)
{
    (void)s;
    new_sessions++;
    SSL_SESSION_free(last_session);
    last_session = sess;
    return 1;
}

static int gen_result = 1, dec_result = SSL_TICKET_RETURN_USE, gen_calls = 0;

static int gen_cb(SSL *s, void *arg)
{
    char data[32];
    SSL_SESSION *sess = SSL_get_session(s);

    gen_calls++;
    snprintf(data, sizeof(data), "appdata-%d", gen_calls);
    printf("  generate (%s, session %s)\n", (const char *)arg, sess != NULL ? "set" : "NULL");
    if (sess != NULL)
        SSL_SESSION_set1_ticket_appdata(sess, data, strlen(data));
    return gen_result;
}

static SSL_TICKET_RETURN dec_cb(SSL *s, SSL_SESSION *sess, const unsigned char *keyname,
                                size_t keyname_len, SSL_TICKET_STATUS status, void *arg)
{
    void *data = NULL;
    size_t len = 0;

    (void)s;
    (void)keyname;
    if (sess != NULL)
        SSL_SESSION_get0_ticket_appdata(sess, &data, &len);
    printf("  decrypt (%s): status %d, keyname %zu octets, session %s, appdata \"%.*s\"\n",
           (const char *)arg, status, keyname_len, sess != NULL ? "set" : "NULL", (int)len,
           data != NULL ? (const char *)data : "");
    return dec_result;
}

/* A connection pair over a BIO pair, run to the end of both handshakes: 0, or the error. */
static int connect_pair(SSL_CTX *cctx, SSL_CTX *sctx, SSL **pc, SSL **ps, SSL_SESSION *sess,
                        int version)
{
    SSL *c = SSL_new(cctx), *s = SSL_new(sctx);
    BIO *a = NULL, *b = NULL;
    int cdone = 0, sdone = 0, round;

    BIO_new_bio_pair(&a, 0, &b, 0);
    SSL_set_bio(c, a, a);
    SSL_set_bio(s, b, b);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    SSL_set_max_proto_version(c, version);
    if (sess != NULL)
        SSL_set_session(c, sess);
    *pc = c;
    *ps = s;
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
                return e;
            }
        }
    }
    return cdone && sdone ? 0 : -1;
}

/* The client reads what the server sent after the handshake (tickets). */
static void drain(SSL *c)
{
    char buf[8];
    size_t n;

    SSL_read_ex(c, buf, sizeof(buf), &n);
    ERR_clear_error();
}

/* Frees both ends after close_notify (a session isn't spoiled by an unclean end). */
static void done(SSL *c, SSL *s)
{
    SSL_shutdown(c);
    SSL_shutdown(s);
    ERR_clear_error();
    SSL_free(c);
    SSL_free(s);
}

static SSL_SESSION *full(SSL_CTX *cctx, SSL_CTX *sctx, int version)
{
    SSL *c, *s;
    SSL_SESSION *sess;

    new_sessions = 0;
    dec_result = SSL_TICKET_RETURN_IGNORE_RENEW;
    check(connect_pair(cctx, sctx, &c, &s, NULL, version) == 0, "a full handshake");
    drain(c);
    printf("  new sessions %d, reused %d\n", new_sessions, SSL_session_reused(c));
    sess = last_session;
    SSL_SESSION_up_ref(sess);
    done(c, s);
    return sess;
}

static void resume(SSL_CTX *cctx, SSL_CTX *sctx, SSL_SESSION *sess, int version, int ret)
{
    SSL *c, *s;
    int r;

    dec_result = ret;
    new_sessions = 0;
    r = connect_pair(cctx, sctx, &c, &s, sess, version);
    printf("  verdict %d: handshake %d, reused %d %d\n", ret, r, SSL_session_reused(c),
           SSL_session_reused(s));
    if (r == 0) {
        void *data = NULL;
        size_t len = 0;

        drain(c);
        SSL_SESSION_get0_ticket_appdata(SSL_get_session(s), &data, &len);
        printf("  new sessions %d, server session appdata \"%.*s\"\n", new_sessions, (int)len,
               data != NULL ? (const char *)data : "");
    }
    errors();
    done(c, s);
}

static void test_callbacks(int version)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL_SESSION *sess;

    printf("# ticket callbacks, version %x\n", version);
    SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_new_cb(cctx, new_session_cb);
    SSL_CTX_set_session_ticket_cb(sctx, gen_cb, dec_cb, "arg");
    gen_calls = 0;
    sess = full(cctx, sctx, version);
    printf("  generate calls %d\n", gen_calls);
    resume(cctx, sctx, sess, version, SSL_TICKET_RETURN_USE);
    resume(cctx, sctx, sess, version, SSL_TICKET_RETURN_USE_RENEW);
    resume(cctx, sctx, sess, version, SSL_TICKET_RETURN_IGNORE);
    resume(cctx, sctx, sess, version, SSL_TICKET_RETURN_IGNORE_RENEW);
    resume(cctx, sctx, sess, version, SSL_TICKET_RETURN_ABORT);
    resume(cctx, sctx, sess, version, 99);
    printf("# the generate callback fails\n");
    gen_result = 0;
    {
        SSL *c, *s;

        printf("  handshake %d\n", connect_pair(cctx, sctx, &c, &s, NULL, version));
        drain(c);
        errors();
        done(c, s);
    }
    gen_result = 1;
    SSL_SESSION_free(sess);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void test_new_session_ticket(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c, *s;

    printf("# SSL_new_session_ticket\n");
    SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_new_cb(cctx, new_session_cb);
    printf("  NULL: %d\n", SSL_new_session_ticket(NULL));
    c = SSL_new(cctx);
    s = SSL_new(sctx);
    printf("  before a handshake: %d\n", SSL_new_session_ticket(s));
    done(c, s);
    new_sessions = 0;
    check(connect_pair(cctx, sctx, &c, &s, NULL, TLS1_3_VERSION) == 0, "a handshake");
    printf("  client: %d\n", SSL_new_session_ticket(c));
    printf("  server: %d, again: %d, in init %d\n", SSL_new_session_ticket(s),
           SSL_new_session_ticket(s), SSL_in_init(s));
    drain(c);
    printf("  new sessions after the handshake's: %d\n", new_sessions);
    check(SSL_do_handshake(s) == 1, "the server sends them");
    drain(c);
    printf("  new sessions: %d, server in init %d\n", new_sessions, SSL_in_init(s));
    check(SSL_new_session_ticket(s) == 1, "one more");
    check(SSL_write(s, "x", 1) == 1, "sent with a write");
    {
        char buf[4];

        printf("  client read %d\n", SSL_read(c, buf, sizeof(buf)));
    }
    printf("  new sessions: %d\n", new_sessions);
    errors();
    done(c, s);
    printf("# TLS 1.2\n");
    check(connect_pair(cctx, sctx, &c, &s, NULL, TLS1_2_VERSION) == 0, "a handshake");
    printf("  server: %d\n", SSL_new_session_ticket(s));
    errors();
    done(c, s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

int main(void)
{
    test_callbacks(TLS1_3_VERSION);
    test_callbacks(TLS1_2_VERSION);
    test_new_session_ticket();
    SSL_SESSION_free(last_session);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
