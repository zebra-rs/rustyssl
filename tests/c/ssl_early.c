/*
 * Conformance test for TLS 1.3 early data (SSL_write_early_data(3), SSL_read_early_data(3),
 * SSL_get_early_data_status(3), SSL_CTX_set_max_early_data(3),
 * SSL_CTX_set_recv_max_early_data(3), SSL_CTX_set_allow_early_data_cb(3), SSL_write_ex2(3)):
 * resumed handshakes over a BIO pair with early data accepted, rejected by the callback,
 * skipped by a server that doesn't read it, rejected with a HelloRetryRequest, and over the
 * limits; the server writing before the client's Finished; and the calls in the wrong state.
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

/* A TLS 1.3 server context with the server's certificate and key, allowing early data. */
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
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_early_data(ctx, 1024);
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

/* Runs both ends' handshakes in turn until both finish (0), or one fails (its error). */
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
                return e;
            }
        }
    }
    return cdone && sdone ? 0 : -1;
}

/* A full handshake: the session the client got (with its tickets read). */
static SSL_SESSION *first_session(SSL_CTX *cctx, SSL_CTX *sctx)
{
    SSL *c = SSL_new(cctx), *s = SSL_new(sctx);
    SSL_SESSION *sess;
    char buf[8];
    size_t n;

    pair(c, s);
    if (run(c, s) != 0) {
        printf("Bail out! first handshake\n");
        exit(1);
    }
    /* The tickets arrive after the handshake. */
    if (SSL_read_ex(c, buf, sizeof(buf), &n) != 0) {
        printf("Bail out! unexpected data\n");
        exit(1);
    }
    ERR_clear_error();
    sess = SSL_get1_session(c);
    SSL_shutdown(c);
    SSL_shutdown(s);
    SSL_free(c);
    SSL_free(s);
    return sess;
}

static const char *read_ret(int r)
{
    switch (r) {
    case SSL_READ_EARLY_DATA_ERROR:
        return "ERROR";
    case SSL_READ_EARLY_DATA_SUCCESS:
        return "SUCCESS";
    case SSL_READ_EARLY_DATA_FINISH:
        return "FINISH";
    }
    return "?";
}

/* SSL_read_early_data once: its result, what it read, and the error. */
static int read_early(SSL *s, const char *what)
{
    char buf[64];
    size_t n = 99;
    int r = SSL_read_early_data(s, buf, sizeof(buf), &n);

    if (r == SSL_READ_EARLY_DATA_SUCCESS)
        printf("  %s: %s \"%.*s\"\n", what, read_ret(r), (int)n, buf);
    else if (r == SSL_READ_EARLY_DATA_FINISH)
        printf("  %s: %s (%zu)\n", what, read_ret(r), n);
    else
        printf("  %s: %s, error %d\n", what, read_ret(r), SSL_get_error(s, 0));
    return r;
}

/* Reads `want` octets on `x` and checks them. */
static void expect_data(SSL *x, const char *want, const char *what)
{
    char buf[64];
    size_t n = 0;
    int r = SSL_read_ex(x, buf, sizeof(buf), &n);

    check(r == 1 && n == strlen(want) && memcmp(buf, want, n) == 0, what);
}

static int allow_answer = 1;
static int allow_calls = 0;

static int allow_cb(SSL *s, void *arg)
{
    (void)s;
    (void)arg;
    allow_calls++;
    return allow_answer;
}

static void test_accepted(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL_SESSION *sess = first_session(cctx, sctx);
    SSL *c = SSL_new(cctx), *s = SSL_new(sctx);
    size_t w = 0;
    int r;

    printf("# accepted early data\n");
    printf("  session max_early_data %u\n", (unsigned)SSL_SESSION_get_max_early_data(sess));
    printf("  status before: client %d, server %d\n", SSL_get_early_data_status(c),
           SSL_get_early_data_status(s));
    pair(c, s);
    SSL_set_session(c, sess);
    r = SSL_write_early_data(c, "early", 5, &w);
    check(r == 1 && w == 5, "the client writes early data");
    printf("  in init %d, finished %d, state %s\n", SSL_in_init(c), SSL_is_init_finished(c),
           SSL_state_string(c));
    check(read_early(s, "server reads") == SSL_READ_EARLY_DATA_SUCCESS, "the server reads it");
    read_early(s, "server reads again");
    printf("  server state %s, in init %d\n", SSL_state_string(s), SSL_in_init(s));
    r = SSL_write_early_data(s, "srv", 3, &w);
    check(r == 1 && w == 3, "the server writes before the client's Finished");
    r = SSL_write_early_data(c, "more", 4, &w);
    check(r == 1 && w == 4, "the client writes more");
    check(read_early(s, "server reads more") == SSL_READ_EARLY_DATA_SUCCESS, "it arrives");
    /* The client finishes: EndOfEarlyData and Finished. */
    r = SSL_do_handshake(c);
    printf("  client handshake: %d (%d)\n", r, SSL_get_error(c, r));
    check(read_early(s, "server reads at the end") == SSL_READ_EARLY_DATA_FINISH, "the end");
    read_early(s, "and after");
    errors();
    check(run(c, s) == 0, "both finish");
    printf("  status: client %d, server %d, reused %d %d\n", SSL_get_early_data_status(c),
           SSL_get_early_data_status(s), SSL_session_reused(c), SSL_session_reused(s));
    expect_data(c, "srv", "the client reads the server's early write");
    check(SSL_write(c, "after", 5) == 5, "a normal write");
    expect_data(s, "after", "the server reads it");
    r = SSL_write_early_data(c, "late", 4, &w);
    printf("  early write after the handshake: %d\n", r);
    errors();
    printf("  early read after the handshake: %s\n", read_ret(SSL_read_early_data(s, NULL, 0, &w)));
    errors();
    SSL_SESSION_free(sess);
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void test_write_then_plain(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL_SESSION *sess = first_session(cctx, sctx);
    SSL *c = SSL_new(cctx), *s = SSL_new(sctx);
    size_t w = 0;

    printf("# early data, then SSL_write and SSL_read\n");
    pair(c, s);
    SSL_set_session(c, sess);
    check(SSL_write_early_data(c, "one", 3, &w) == 1, "an early write");
    check(read_early(s, "server") == SSL_READ_EARLY_DATA_SUCCESS, "read");
    /* A plain write ends the early data: it runs the handshake first. */
    printf("  plain write: %d (%d)\n", SSL_write(c, "two", 3), SSL_get_error(c, -1));
    check(read_early(s, "server") == SSL_READ_EARLY_DATA_FINISH, "the end of early data");
    check(run(c, s) == 0, "both finish");
    printf("  status: client %d, server %d\n", SSL_get_early_data_status(c),
           SSL_get_early_data_status(s));
    {
        int r = SSL_write(c, "two", 3);

        printf("  write: %d\n", r);
    }
    expect_data(s, "two", "the server reads the plain write");
    ERR_clear_error();
    SSL_SESSION_free(sess);
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void test_rejected_by_callback(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL_SESSION *sess = first_session(cctx, sctx);
    SSL *c = SSL_new(cctx), *s = SSL_new(sctx);
    size_t w = 0;

    printf("# rejected by the callback\n");
    SSL_CTX_set_allow_early_data_cb(sctx, allow_cb, NULL);
    allow_answer = 0;
    allow_calls = 0;
    s = (SSL_free(s), SSL_new(sctx));
    pair(c, s);
    SSL_set_session(c, sess);
    check(SSL_write_early_data(c, "early", 5, &w) == 1, "the client writes early data");
    check(read_early(s, "server") == SSL_READ_EARLY_DATA_FINISH, "nothing to read");
    printf("  callback called %d times\n", allow_calls);
    check(SSL_write_early_data(c, "more", 4, &w) == 1, "the client writes more");
    check(run(c, s) == 0, "both finish");
    printf("  status: client %d, server %d, reused %d %d\n", SSL_get_early_data_status(c),
           SSL_get_early_data_status(s), SSL_session_reused(c), SSL_session_reused(s));
    check(SSL_write(c, "data", 4) == 4, "a write");
    expect_data(s, "data", "only the normal data arrives");
    errors();
    SSL_SESSION_free(sess);
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void test_server_not_reading(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL_SESSION *sess = first_session(cctx, sctx);
    SSL *c = SSL_new(cctx), *s = SSL_new(sctx);
    size_t w = 0;

    printf("# a server that doesn't read early data\n");
    pair(c, s);
    SSL_set_session(c, sess);
    check(SSL_write_early_data(c, "early", 5, &w) == 1, "the client writes early data");
    check(run(c, s) == 0, "both finish");
    printf("  status: client %d, server %d\n", SSL_get_early_data_status(c),
           SSL_get_early_data_status(s));
    check(SSL_write(c, "data", 4) == 4, "a write");
    expect_data(s, "data", "the early data was skipped");
    errors();
    SSL_SESSION_free(sess);
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void test_hrr(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL_SESSION *sess = first_session(cctx, sctx);
    SSL *c = SSL_new(cctx), *s = SSL_new(sctx);
    size_t w = 0;

    printf("# rejected with a HelloRetryRequest\n");
    SSL_set1_groups_list(s, "P-256");
    pair(c, s);
    SSL_set_session(c, sess);
    check(SSL_write_early_data(c, "early", 5, &w) == 1, "the client writes early data");
    read_early(s, "server");
    check(SSL_write_early_data(c, "more", 4, &w) == 1, "the client writes more");
    printf("  server: %s\n", read_ret(read_early(s, "server")));
    check(run(c, s) == 0, "both finish");
    printf("  status: client %d, server %d, reused %d %d\n", SSL_get_early_data_status(c),
           SSL_get_early_data_status(s), SSL_session_reused(c), SSL_session_reused(s));
    check(SSL_write(c, "data", 4) == 4, "a write");
    expect_data(s, "data", "only the normal data arrives");
    errors();
    SSL_SESSION_free(sess);
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void test_limits(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL_SESSION *sess = first_session(cctx, sctx), *small;
    SSL *c, *s;
    size_t w = 0;
    char big[40];

    memset(big, 'x', sizeof(big));
    printf("# limits\n");

    /* The client's limit is the session's. */
    small = SSL_SESSION_dup(sess);
    SSL_SESSION_set_max_early_data(small, 10);
    c = SSL_new(cctx);
    s = SSL_new(sctx);
    pair(c, s);
    SSL_set_session(c, small);
    printf("  10 of 10: %d\n", SSL_write_early_data(c, big, 10, &w));
    printf("  1 more: %d (%d)\n", SSL_write_early_data(c, big, 1, &w), SSL_get_error(c, 0));
    errors();
    SSL_free(c);
    SSL_free(s);
    SSL_SESSION_free(small);

    /* The server's limit. */
    SSL_CTX_set_recv_max_early_data(sctx, 16);
    c = SSL_new(cctx);
    s = SSL_new(sctx);
    pair(c, s);
    SSL_set_session(c, sess);
    printf("  client writes 40: %d\n", SSL_write_early_data(c, big, sizeof(big), &w));
    read_early(s, "server");
    errors();
    SSL_free(c);
    SSL_free(s);

    /* Rejected early data is skipped up to the server's limit too. */
    c = SSL_new(cctx);
    s = SSL_new(sctx);
    SSL_set_max_early_data(s, 0);
    pair(c, s);
    SSL_set_session(c, sess);
    printf("  client writes 40: %d\n", SSL_write_early_data(c, big, sizeof(big), &w));
    printf("  handshake: %d\n", run(c, s));
    errors();
    SSL_free(c);
    SSL_free(s);
    SSL_SESSION_free(sess);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void test_misuse(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c = SSL_new(cctx), *s = SSL_new(sctx);
    char buf[8];
    size_t n = 7;

    printf("# misuse\n");
    printf("  NULL: write %d, read %s\n", SSL_write_early_data(NULL, "x", 1, &n),
           read_ret(SSL_read_early_data(NULL, buf, sizeof(buf), &n)));
    errors();
    printf("  client without a session: %d\n", SSL_write_early_data(c, "x", 1, &n));
    errors();
    pair(c, s);
    printf("  server writing: %d\n", SSL_write_early_data(s, "x", 1, &n));
    errors();
    printf("  client reading: %s\n", read_ret(SSL_read_early_data(c, buf, sizeof(buf), &n)));
    errors();
    check(run(c, s) == 0, "a handshake");
    printf("  status: client %d, server %d\n", SSL_get_early_data_status(c),
           SSL_get_early_data_status(s));
    printf("  NULL status: %d\n", SSL_get_early_data_status(NULL));

    printf("# SSL_write_ex2\n");
    n = 0;
    check(SSL_write_ex2(c, "abc", 3, 0, &n) == 1 && n == 3, "no flags");
    expect_data(s, "abc", "arrives");
    n = 9;
    printf("  empty: SSL_write_ex %d (%zu), SSL_write %d\n", SSL_write_ex(c, "", 0, &n), n,
           SSL_write(c, "", 0));
    errors();
    n = 9;
    printf("  CONCLUDE: %d (%zu)\n", SSL_write_ex2(c, "abc", 3, SSL_WRITE_FLAG_CONCLUDE, &n), n);
    errors();
    SSL_shutdown(c);
    printf("  after shutdown: %d\n", SSL_write_ex2(c, "abc", 3, SSL_WRITE_FLAG_CONCLUDE, &n));
    errors();
    SSL_free(c);
    SSL_free(s);
    c = SSL_new(cctx);
    printf("  no role: %d\n", SSL_write_ex2(c, "abc", 3, 0, &n));
    errors();
    SSL_free(c);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

int main(void)
{
    test_accepted();
    test_write_then_plain();
    test_rejected_by_callback();
    test_server_not_reading();
    test_hrr();
    test_limits();
    test_misuse();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
