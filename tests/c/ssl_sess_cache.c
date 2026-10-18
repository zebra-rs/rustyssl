/*
 * Conformance test for the session cache and resumption (SSL_CTX_add_session(3),
 * SSL_CTX_set_session_cache_mode(3), SSL_CTX_sess_number(3), SSL_CTX_sess_set_new_cb(3),
 * SSL_CTX_flush_sessions(3), SSL_get_session(3), SSL_set_session(3), SSL_session_reused(3),
 * SSL_has_matching_session_id(3), SSL_copy_session_id(3)): the cache's API on its own
 * (adding, replacing, removing, evicting, expiry order, flushing), then real handshakes over a
 * BIO pair that resume TLS 1.2 sessions by ID and by ticket and TLS 1.3 sessions by ticket,
 * with the callbacks, the statistics, timeouts, an external cache, encoded sessions, and the
 * removal of sessions that weren't shut down.
 *
 * Only deterministic output is printed (no keys, IDs or tickets).
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

/* Prints and clears the error queue: library/reason only. */
static void errors(void)
{
    unsigned long e;

    printf("  errors:");
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
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

/* The first octet of a session's ID, its label in this test. */
static int label(SSL_SESSION *s)
{
    unsigned int n;
    const unsigned char *id = SSL_SESSION_get_id(s, &n);

    return n == 1 ? id[0] : n == 0 ? -1 : 99;
}

static int quiet_remove = 0;

static void remove_cb(SSL_CTX *ctx, SSL_SESSION *s)
{
    (void)ctx;
    if (quiet_remove)
        return;
    printf("  remove_cb: session %d, resumable %d\n", label(s), SSL_SESSION_is_resumable(s));
}

/* A session with a one-octet ID, made at `t` with a 304-second timeout. */
static SSL_SESSION *made(unsigned char id, time_t t)
{
    SSL_SESSION *s = SSL_SESSION_new();

    SSL_SESSION_set_protocol_version(s, TLS1_2_VERSION);
    SSL_SESSION_set1_id(s, &id, 1);
    SSL_SESSION_set_time_ex(s, t);
    return s;
}

static void stats(const char *who, SSL_CTX *ctx)
{
    printf("  %s: number %ld connect %ld/%ld/%ld accept %ld/%ld/%ld hits %ld cb_hits %ld misses %ld"
           " timeouts %ld cache_full %ld\n",
        who, SSL_CTX_sess_number(ctx), SSL_CTX_sess_connect(ctx), SSL_CTX_sess_connect_good(ctx),
        SSL_CTX_sess_connect_renegotiate(ctx), SSL_CTX_sess_accept(ctx),
        SSL_CTX_sess_accept_good(ctx), SSL_CTX_sess_accept_renegotiate(ctx),
        SSL_CTX_sess_hits(ctx), SSL_CTX_sess_cb_hits(ctx), SSL_CTX_sess_misses(ctx),
        SSL_CTX_sess_timeouts(ctx), SSL_CTX_sess_cache_full(ctx));
}

static void test_cache_api(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    SSL_SESSION *s1 = made(1, 1000000), *s2 = made(2, 2000000), *s3 = made(3, 3000000);
    SSL_SESSION *s4 = made(4, 4000000), *s5 = made(3, 5000000);

    printf("# the cache's API\n");
    SSL_CTX_sess_set_remove_cb(ctx, remove_cb);
    check(SSL_CTX_sess_get_remove_cb(ctx) == remove_cb, "SSL_CTX_sess_get_remove_cb");
    check(SSL_CTX_add_session(ctx, s1) == 1, "add session 1");
    check(SSL_CTX_add_session(ctx, s1) == 0, "add it again");
    check(SSL_CTX_add_session(ctx, s2) == 1 && SSL_CTX_add_session(ctx, s3) == 1,
        "add sessions 2 and 3");
    check(SSL_CTX_sess_number(ctx) == 3, "three sessions");
    check(OPENSSL_LH_num_items((OPENSSL_LHASH *)SSL_CTX_sessions(ctx)) == 3, "three in SSL_CTX_sessions");
    check(SSL_CTX_remove_session(ctx, s2) == 1, "remove session 2");
    check(SSL_CTX_remove_session(ctx, s2) == 0, "remove it again");
    check(SSL_SESSION_is_resumable(s2) == 0, "a removed session isn't resumable");
    check(SSL_CTX_add_session(ctx, s2) == 1, "add it back");
    SSL_CTX_sess_set_cache_size(ctx, 3);
    check(SSL_CTX_add_session(ctx, s4) == 1, "add session 4 to a full cache of 3");
    /* The new session counts before the eviction: two go. */
    check(SSL_CTX_sess_number(ctx) == 2, "two left");
    stats("cache", ctx);
    /* Session 4 now expires last: session 3 is next to go. */
    SSL_SESSION_set_time_ex(s4, 9000000);
    SSL_CTX_sess_set_cache_size(ctx, 0);
    check(SSL_CTX_add_session(ctx, s5) == 1, "add another session 3");
    check(SSL_CTX_sess_number(ctx) == 2, "it replaced the first");
    printf("  flush at 5000400\n");
    SSL_CTX_flush_sessions_ex(ctx, 5000400);
    check(SSL_CTX_sess_number(ctx) == 1, "one left");
    SSL_SESSION_set_timeout(s4, 1);
    printf("  flush at 9000002\n");
    SSL_CTX_flush_sessions_ex(ctx, 9000002);
    check(SSL_CTX_sess_number(ctx) == 0, "none left");
    check(SSL_CTX_add_session(ctx, s1) == 1, "add session 1 back");
    check(SSL_CTX_add_session(ctx, s2) == 1, "and session 2");
    printf("  flush all\n");
    SSL_CTX_flush_sessions(ctx, 0);
    check(SSL_CTX_sess_number(ctx) == 0, "none left");
    check(SSL_CTX_add_session(ctx, s1) == 1, "add session 1 back");
    printf("  free the context\n");
    SSL_CTX_free(ctx);
    check(SSL_SESSION_is_resumable(s1) == 0, "flushed with the context");
    errors();
    SSL_SESSION_free(s1);
    SSL_SESSION_free(s2);
    SSL_SESSION_free(s3);
    SSL_SESSION_free(s4);
    SSL_SESSION_free(s5);
}

/* The sessions the callbacks saw. */
static SSL_SESSION *client_last = NULL;
static int client_new = 0;
static SSL_SESSION *server_last = NULL;
static int server_new = 0;
static int server_keeps = 0;

static int client_new_cb(SSL *ssl, SSL_SESSION *s)
{
    (void)ssl;
    client_new++;
    SSL_SESSION_free(client_last);
    client_last = s;
    return 1;
}

static int server_new_cb(SSL *ssl, SSL_SESSION *s)
{
    (void)ssl;
    server_new++;
    if (server_keeps) {
        SSL_SESSION_free(server_last);
        server_last = s;
        return 1;
    }
    server_last = s;
    return 0;
}

static int get_calls = 0;

static SSL_SESSION *get_cb(SSL *ssl, const unsigned char *id, int len, int *copy)
{
    unsigned int n;
    const unsigned char *have;

    (void)ssl;
    get_calls++;
    if (server_last == NULL)
        return NULL;
    have = SSL_SESSION_get_id(server_last, &n);
    if ((int)n != len || memcmp(have, id, n) != 0)
        return NULL;
    *copy = 1;
    return server_last;
}

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
    SSL_CTX_set_session_id_context(ctx, (const unsigned char *)"test", 4);
    SSL_CTX_sess_set_new_cb(ctx, server_new_cb);
    SSL_CTX_sess_set_remove_cb(ctx, remove_cb);
    return ctx;
}

static SSL_CTX *client_ctx(int max)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    X509 *ca = cert(CA_PEM);

    if (ctx == NULL || ca == NULL || X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), ca) != 1) {
        printf("Bail out! client context\n");
        exit(1);
    }
    X509_free(ca);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_max_proto_version(ctx, max);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_new_cb(ctx, client_new_cb);
    return ctx;
}

/* Runs both ends' handshakes in turn until both finish (0) or one fails (-1). */
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
                return -1;
            }
        }
    }
    return cdone && sdone ? 0 : -1;
}

/* A client and a server over a BIO pair, the client offering `offer`. */
static void connect_pair(SSL_CTX *cctx, SSL_CTX *sctx, SSL_SESSION *offer, SSL **c, SSL **s)
{
    BIO *a = NULL, *b = NULL;

    *c = SSL_new(cctx);
    *s = SSL_new(sctx);
    if (*c == NULL || *s == NULL || BIO_new_bio_pair(&a, 0, &b, 0) != 1) {
        printf("Bail out! connection\n");
        exit(1);
    }
    SSL_set_bio(*c, a, a);
    SSL_set_bio(*s, b, b);
    SSL_set_connect_state(*c);
    SSL_set_accept_state(*s);
    SSL_set_tlsext_host_name(*c, "server.example");
    if (offer != NULL)
        check(SSL_set_session(*c, offer) == 1, "SSL_set_session");
}

/* Lets each end read what the other sent after the handshake (TLS 1.3 tickets). */
static void drain(SSL *c, SSL *s)
{
    char buf[16];
    int i;

    for (i = 0; i < 2; i++) {
        (void)SSL_read(c, buf, sizeof(buf));
        (void)SSL_read(s, buf, sizeof(buf));
    }
    ERR_clear_error();
}

/* Shuts both ends down (each sends close_notify), so their sessions stay cached, and frees. */
static void close_pair(SSL *c, SSL *s)
{
    (void)SSL_shutdown(c);
    (void)SSL_shutdown(s);
    (void)SSL_shutdown(c);
    SSL_free(c);
    SSL_free(s);
    ERR_clear_error();
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

/* What's deterministic about a handshake's session. */
static void describe(SSL_SESSION *s)
{
    unsigned int n;
    char name[64];
    const SSL_CIPHER *c = SSL_SESSION_get0_cipher(s);
    const unsigned char *p;
    size_t len;

    (void)SSL_SESSION_get_id(s, &n);
    printf("  session: protocol %#x cipher %s id %u ticket %d resumable %d master key %zu\n",
        SSL_SESSION_get_protocol_version(s), c == NULL ? "(none)" : SSL_CIPHER_get_name(c), n,
        SSL_SESSION_has_ticket(s), SSL_SESSION_is_resumable(s),
        SSL_SESSION_get_master_key(s, NULL, 0));
    p = SSL_SESSION_get0_id_context(s, &n);
    printf("  id context %.*s, host %s, peer %s, timeout %ld\n", (int)n, (const char *)p,
        SSL_SESSION_get0_hostname(s) == NULL ? "(none)" : SSL_SESSION_get0_hostname(s),
        cn(SSL_SESSION_get0_peer(s), name, sizeof(name)), SSL_SESSION_get_timeout(s));
    SSL_SESSION_get0_ticket(s, &p, &len);
    printf("  ticket %s, lifetime hint %lu, max early data %u\n", p == NULL ? "none" : "some",
        SSL_SESSION_get_ticket_lifetime_hint(s), SSL_SESSION_get_max_early_data(s));
}

/*
 * One handshake: the client offers `offer` (or nothing); prints whether each end resumed.
 * Returns the client's session (a reference).
 */
static SSL_SESSION *handshake(SSL_CTX *cctx, SSL_CTX *sctx, SSL_SESSION *offer, int expect)
{
    SSL *c, *s;
    SSL_SESSION *got;

    connect_pair(cctx, sctx, offer, &c, &s);
    check(run(c, s) == 0, "the handshake");
    drain(c, s);
    printf("  reused: client %d server %d\n", SSL_session_reused(c), SSL_session_reused(s));
    check(SSL_session_reused(c) == expect && SSL_session_reused(s) == expect,
        expect ? "resumed" : "a full handshake");
    check(SSL_get0_session(s) != NULL, "the server has a session");
    got = SSL_get1_session(c);
    check(got != NULL && got == SSL_get_session(c), "SSL_get1_session");
    if (offer != NULL && expect)
        printf("  the client's session is %s\n",
            got == offer ? "the one it offered" : "another");
    close_pair(c, s);
    return got;
}

static void test_tls12_id(void)
{
    SSL_CTX *sctx = server_ctx(), *cctx = client_ctx(TLS1_2_VERSION);
    SSL_SESSION *first, *second, *third;
    SSL *c, *s;

    printf("# TLS 1.2, resumed by session ID\n");
    SSL_CTX_set_options(sctx, SSL_OP_NO_TICKET);
    server_new = client_new = 0;
    first = handshake(cctx, sctx, NULL, 0);
    describe(first);
    printf("  new sessions: client %d server %d\n", client_new, server_new);
    second = handshake(cctx, sctx, first, 1);
    printf("  new sessions: client %d server %d\n", client_new, server_new);
    stats("client", cctx);
    stats("server", sctx);
    /* A connection asks the server's cache. */
    connect_pair(cctx, sctx, first, &c, &s);
    check(run(c, s) == 0, "the handshake");
    {
        unsigned int n;
        const unsigned char *id = SSL_SESSION_get_id(first, &n);
        unsigned char none[32] = { 0 };

        check(SSL_has_matching_session_id(s, id, n) == 1, "SSL_has_matching_session_id");
        check(SSL_has_matching_session_id(s, none, 32) == 0, "an unknown ID");
        check(SSL_has_matching_session_id(s, id, 33) == 0, "an ID too long");
    }
    close_pair(c, s);
    /* The server's cached session expires. */
    printf("  the server's session expires\n");
    SSL_SESSION_set_time_ex(server_last, time(NULL) - 10000);
    third = handshake(cctx, sctx, first, 0);
    stats("server", sctx);
    /* A connection freed without shutting down takes its session out of the cache. */
    printf("  a connection freed without close_notify\n");
    {
        SSL_SESSION *fourth;

        connect_pair(cctx, sctx, third, &c, &s);
        check(run(c, s) == 0 && SSL_session_reused(c) == 1, "resumed");
        SSL_free(c);
        SSL_free(s);
        fourth = handshake(cctx, sctx, third, 0);
        SSL_SESSION_free(fourth);
    }
    SSL_SESSION_free(first);
    SSL_SESSION_free(second);
    SSL_SESSION_free(third);
    quiet_remove = 1;
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    quiet_remove = 0;
    SSL_SESSION_free(client_last);
    client_last = NULL;
    server_last = NULL;
    errors();
}

static void test_tls12_ticket(void)
{
    SSL_CTX *sctx = server_ctx(), *cctx = client_ctx(TLS1_2_VERSION);
    SSL_SESSION *first, *second, *again;
    unsigned char *der = NULL;
    const unsigned char *p;
    int n;

    printf("# TLS 1.2, resumed by ticket\n");
    server_new = client_new = 0;
    first = handshake(cctx, sctx, NULL, 0);
    describe(first);
    printf("  new sessions: client %d server %d\n", client_new, server_new);
    second = handshake(cctx, sctx, first, 1);
    /* An encoded session resumes too. */
    n = i2d_SSL_SESSION(first, &der);
    p = der;
    again = d2i_SSL_SESSION(NULL, &p, n);
    check(again != NULL, "the session decoded");
    SSL_SESSION_free(handshake(cctx, sctx, again, 1));
    OPENSSL_free(der);
    stats("client", cctx);
    stats("server", sctx);
    SSL_SESSION_free(again);
    SSL_SESSION_free(first);
    SSL_SESSION_free(second);
    quiet_remove = 1;
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    quiet_remove = 0;
    SSL_SESSION_free(client_last);
    client_last = NULL;
    server_last = NULL;
    errors();
}

static void test_tls13(void)
{
    SSL_CTX *sctx = server_ctx(), *cctx = client_ctx(TLS1_3_VERSION);
    SSL_SESSION *first, *second, *ticket;

    printf("# TLS 1.3, resumed by ticket\n");
    server_new = client_new = 0;
    first = handshake(cctx, sctx, NULL, 0);
    printf("  new sessions: client %d server %d\n", client_new, server_new);
    check(client_last != NULL, "a ticket's session");
    ticket = client_last;
    SSL_SESSION_up_ref(ticket);
    describe(ticket);
    second = handshake(cctx, sctx, ticket, 1);
    printf("  new sessions: client %d server %d\n", client_new, server_new);
    stats("client", cctx);
    stats("server", sctx);
    SSL_SESSION_free(ticket);
    SSL_SESSION_free(first);
    SSL_SESSION_free(second);
    quiet_remove = 1;
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    quiet_remove = 0;
    SSL_SESSION_free(client_last);
    client_last = NULL;
    server_last = NULL;
    errors();
}

static void test_external(void)
{
    SSL_CTX *sctx = server_ctx(), *cctx = client_ctx(TLS1_2_VERSION);
    SSL_SESSION *first, *second;

    printf("# TLS 1.2, an external cache\n");
    SSL_CTX_set_options(sctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(sctx, SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_INTERNAL);
    SSL_CTX_sess_set_get_cb(sctx, get_cb);
    server_keeps = 1;
    get_calls = 0;
    first = handshake(cctx, sctx, NULL, 0);
    check(SSL_CTX_sess_number(sctx) == 0, "nothing cached inside");
    second = handshake(cctx, sctx, first, 1);
    printf("  get_cb calls %d\n", get_calls);
    stats("server", sctx);
    server_keeps = 0;
    SSL_SESSION_free(first);
    SSL_SESSION_free(second);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    SSL_SESSION_free(client_last);
    client_last = NULL;
    SSL_SESSION_free(server_last);
    server_last = NULL;
    errors();
}

static void test_copy(void)
{
    SSL_CTX *sctx = server_ctx(), *cctx = client_ctx(TLS1_2_VERSION);
    SSL *c, *s, *t;

    printf("# SSL_copy_session_id\n");
    connect_pair(cctx, sctx, NULL, &c, &s);
    check(run(c, s) == 0, "the handshake");
    t = SSL_new(cctx);
    check(SSL_copy_session_id(t, c) == 1, "SSL_copy_session_id");
    check(SSL_get_session(t) == SSL_get_session(c), "the same session");
    check(SSL_get_psk_identity(t) == NULL && SSL_get_psk_identity_hint(t) == NULL,
        "no PSK identity");
    check(SSL_set_session(t, NULL) == 1 && SSL_get_session(t) == NULL, "SSL_set_session(NULL)");
    SSL_free(t);
    close_pair(c, s);
    quiet_remove = 1;
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    quiet_remove = 0;
    SSL_SESSION_free(client_last);
    client_last = NULL;
    server_last = NULL;
    errors();
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    test_cache_api();
    test_tls12_id();
    test_tls12_ticket();
    test_tls13();
    test_external();
    test_copy();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
