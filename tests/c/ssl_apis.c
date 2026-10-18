/*
 * Conformance test for the smaller connection calls: OSSL_default_cipher_list(3),
 * OSSL_default_ciphersuites(3), SSL_rstate_string(3), SSL_rstate_string_long(3),
 * SSL_alloc_buffers(3), SSL_free_buffers(3), SSL_sendfile(3), the certificate compression
 * calls (SSL_CTX_set1_cert_comp_preference(3) and the rest: the default build has no
 * compression algorithm), SSL_CTX_set_client_cert_engine(3), the QUIC domain flags and
 * pending-connection callback on TLS objects, SSL_add_ssl_module(3), SSL_add_expected_rpk(3),
 * SSL_get_handshake_rtt(3), and SSL_dup(3).
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
#include <openssl/conf.h>
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

/* Runs both ends' handshakes in turn until both finish (0), or one fails (its error). */
static int run(SSL *c, SSL *s)
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

static void test_defaults(void)
{
    printf("# default cipher strings\n");
    printf("  list: %s\n", OSSL_default_cipher_list());
    printf("  suites: %s\n", OSSL_default_ciphersuites());
    check(strcmp(OSSL_default_cipher_list(), OSSL_default_cipher_list()) == 0, "stable");
}

static void test_buffers_and_state(int version)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c = SSL_new(cctx), *s = SSL_new(sctx);
    char buf[16];
    size_t n = 0;

    printf("# record state and buffers, version %x\n", version);
    SSL_CTX_set_max_proto_version(cctx, version);
    SSL_set_max_proto_version(c, version);
    printf("  new: %s / %s\n", SSL_rstate_string(c), SSL_rstate_string_long(c));
    check(SSL_alloc_buffers(c) == 1, "SSL_alloc_buffers on a new connection");
    check(SSL_free_buffers(c) == 1, "SSL_free_buffers on a new connection");
    check(SSL_alloc_buffers(NULL) == 0, "SSL_alloc_buffers(NULL)");
    check(SSL_free_buffers(NULL) == 0, "SSL_free_buffers(NULL)");
    pair(c, s);
    check(run(c, s) == 0, "the handshake");
    printf("  connected: %s / %s\n", SSL_rstate_string(s), SSL_rstate_string_long(s));
    check(SSL_free_buffers(c) == 1, "SSL_free_buffers when idle");
    check(SSL_alloc_buffers(c) == 1, "SSL_alloc_buffers again");

    /* Two records: the server reads part of the first. */
    check(SSL_write(c, "hello", 5) == 5 && SSL_write(c, "world", 5) == 5, "two writes");
    check(SSL_read_ex(s, buf, 2, &n) == 1 && n == 2, "a partial read");
    printf("  pending %d, free_buffers %d\n", SSL_pending(s), SSL_free_buffers(s));
    check(SSL_read_ex(s, buf, sizeof(buf), &n) == 1 && n == 3, "the rest of the first");
    printf("  with a record unread: free_buffers %d\n", SSL_free_buffers(s));
    check(SSL_read_ex(s, buf, sizeof(buf), &n) == 1 && n == 5, "the second");
    printf("  drained: free_buffers %d, %s\n", SSL_free_buffers(s), SSL_rstate_string(s));
    check(SSL_write(s, "back", 4) == 4, "a write the other way");
    check(SSL_read_ex(c, buf, sizeof(buf), &n) == 1 && n == 4 && memcmp(buf, "back", 4) == 0,
          "works after freeing the buffers");
    ERR_clear_error();
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void test_sendfile(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c = SSL_new(cctx), *s = SSL_new(sctx);

    printf("# SSL_sendfile\n");
    printf("  before a role: %ld\n", (long)SSL_sendfile(c, 0, 0, 1, 0));
    errors();
    pair(c, s);
    check(run(c, s) == 0, "the handshake");
    printf("  connected: %ld\n", (long)SSL_sendfile(c, 0, 0, 1, 0));
    errors();
    SSL_shutdown(c);
    printf("  after close_notify: %ld\n", (long)SSL_sendfile(c, 0, 0, 1, 0));
    errors();
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void test_cert_comp(void)
{
    SSL_CTX *ctx = server_ctx();
    SSL *s = SSL_new(ctx);
    int algs[] = { TLSEXT_comp_cert_zlib, TLSEXT_comp_cert_brotli };
    unsigned char data[4] = { 1, 2, 3, 4 };
    unsigned char *out = NULL;
    size_t orig = 7;

    printf("# certificate compression\n");
    printf("  CTX preference %d, SSL preference %d\n",
           SSL_CTX_set1_cert_comp_preference(ctx, algs, 2),
           SSL_set1_cert_comp_preference(s, algs, 2));
    errors();
    printf("  CTX compress %d, SSL compress %d, none %d\n",
           SSL_CTX_compress_certs(ctx, TLSEXT_comp_cert_zlib),
           SSL_compress_certs(s, TLSEXT_comp_cert_zlib), SSL_compress_certs(s, 0));
    errors();
    printf("  CTX get1 %zu, SSL get1 %zu (out %s, orig %zu)\n",
           SSL_CTX_get1_compressed_cert(ctx, TLSEXT_comp_cert_zlib, &out, &orig),
           SSL_get1_compressed_cert(s, TLSEXT_comp_cert_zlib, &out, &orig),
           out == NULL ? "NULL" : "set", orig);
    errors();
    printf("  CTX set1 %d, SSL set1 %d\n",
           SSL_CTX_set1_compressed_cert(ctx, TLSEXT_comp_cert_zlib, data, 4, 10),
           SSL_set1_compressed_cert(s, TLSEXT_comp_cert_zlib, data, 4, 10));
    errors();
    SSL_free(s);
    SSL_CTX_free(ctx);
}

static int pending_called = 0;

static int pending_cb(SSL_CTX *ctx, SSL *new_ssl, void *arg)
{
    (void)ctx;
    (void)new_ssl;
    (void)arg;
    pending_called++;
    return 1;
}

static void test_quic_and_misc(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c, *s;
    uint64_t flags = 12345;

    printf("# engines, domain flags, pending connections, the ssl module\n");
    printf("  client cert engine NULL: %d\n", SSL_CTX_set_client_cert_engine(cctx, NULL));
    errors();
    printf("  CTX set domain flags: %d\n",
           SSL_CTX_set_domain_flags(cctx, SSL_DOMAIN_FLAG_MULTI_THREAD));
    errors();
    printf("  CTX get domain flags: %d (%llu)\n", SSL_CTX_get_domain_flags(cctx, &flags),
           (unsigned long long)flags);
    errors();
    c = SSL_new(cctx);
    s = SSL_new(sctx);
    printf("  SSL get domain flags: %d (%llu)\n", SSL_get_domain_flags(c, &flags),
           (unsigned long long)flags);
    errors();
    SSL_CTX_set_new_pending_conn_cb(sctx, pending_cb, NULL);
    SSL_add_ssl_module();
    pair(c, s);
    check(run(c, s) == 0, "a handshake with a pending-connection callback set");
    check(pending_called == 0, "it isn't called for TLS");
    errors();
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void test_expected_rpk(void)
{
    SSL_CTX *ctx = client_ctx();
    SSL *c = SSL_new(ctx);
    EVP_PKEY *k = key(SERVER_KEY_PEM);

    printf("# SSL_add_expected_rpk\n");
    printf("  without DANE: %d\n", SSL_add_expected_rpk(c, k));
    errors();
    check(SSL_CTX_dane_enable(ctx) == 1, "SSL_CTX_dane_enable");
    SSL_free(c);
    c = SSL_new(ctx);
    printf("  DANE on the context only: %d\n", SSL_add_expected_rpk(c, k));
    errors();
    check(SSL_dane_enable(c, NULL) == 1, "SSL_dane_enable");
    printf("  enabled: %d, again: %d\n", SSL_add_expected_rpk(c, k), SSL_add_expected_rpk(c, k));
    errors();
    printf("  NULL key: %d\n", SSL_add_expected_rpk(c, NULL));
    errors();
    {
        uint8_t usage = 9, selector = 9, mtype = 9;
        const unsigned char *data = NULL;
        size_t dlen = 0;

        printf("  SSL_get0_dane_tlsa: %d\n",
               SSL_get0_dane_tlsa(c, &usage, &selector, &mtype, &data, &dlen));
    }
    EVP_PKEY_free(k);
    SSL_free(c);
    SSL_CTX_free(ctx);
}

static void test_rtt(int version)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c = SSL_new(cctx), *s = SSL_new(sctx);
    uint64_t rc = 0, rs = 0;

    printf("# SSL_get_handshake_rtt, version %x\n", version);
    SSL_set_max_proto_version(c, version);
    printf("  NULL: %d\n", SSL_get_handshake_rtt(NULL, &rc));
    printf("  new: %d, %d\n", SSL_get_handshake_rtt(c, &rc), SSL_get_handshake_rtt(s, &rs));
    pair(c, s);
    check(run(c, s) == 0, "the handshake");
    printf("  done: client %d, server %d\n", SSL_get_handshake_rtt(c, &rc),
           SSL_get_handshake_rtt(s, &rs));
    check(rc < 10000000 && rs < 10000000, "under ten seconds");
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static int info_calls = 0;

static void info_cb(const SSL *s, int where, int ret)
{
    (void)s;
    (void)where;
    (void)ret;
    info_calls++;
}

static int verify_cb(int ok, X509_STORE_CTX *x)
{
    (void)x;
    return ok;
}

static void test_dup(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c = SSL_new(cctx), *s = SSL_new(sctx), *d, *d2;
    STACK_OF(X509_NAME) *names = sk_X509_NAME_new_null();
    X509 *ca = cert(CA_PEM);
    SSL_SESSION *sess;
    int idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    static const unsigned char sid[] = "dup-ctx";

    printf("# SSL_dup\n");
    check(SSL_dup(NULL) == NULL, "SSL_dup(NULL)");

    /* A configured client that hasn't started. */
    SSL_set_options(c, SSL_OP_NO_TICKET);
    SSL_set_mode(c, SSL_MODE_AUTO_RETRY | SSL_MODE_RELEASE_BUFFERS);
    SSL_set_min_proto_version(c, TLS1_2_VERSION);
    SSL_set_max_proto_version(c, TLS1_2_VERSION);
    SSL_set_verify(c, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb);
    SSL_set_verify_depth(c, 3);
    SSL_set_read_ahead(c, 1);
    SSL_set_max_cert_list(c, 4096);
    SSL_set_info_callback(c, info_cb);
    SSL_set_session_id_context(c, sid, sizeof(sid) - 1);
    SSL_set_cipher_list(c, "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384");
    SSL_set_ex_data(c, idx, (void *)"app data");
    SSL_set_connect_state(c);
    sk_X509_NAME_push(names, X509_NAME_dup(X509_get_subject_name(ca)));
    SSL_set0_CA_list(c, names);
    SSL_set_tlsext_status_type(c, TLSEXT_STATUSTYPE_ocsp);

    d = SSL_dup(c);
    check(d != NULL && d != c, "a copy of a quiescent connection");
    printf("  options %s, mode %lx, versions %x-%x\n",
           (SSL_get_options(d) & SSL_OP_NO_TICKET) ? "NO_TICKET" : "-",
           (unsigned long)SSL_get_mode(d), (unsigned)SSL_get_min_proto_version(d),
           (unsigned)SSL_get_max_proto_version(d));
    printf("  verify %d depth %d cb %s, read_ahead %d, max_cert_list %ld, info cb %s\n",
           SSL_get_verify_mode(d), SSL_get_verify_depth(d),
           SSL_get_verify_callback(d) == verify_cb ? "same" : "other", SSL_get_read_ahead(d),
           SSL_get_max_cert_list(d), SSL_get_info_callback(d) == info_cb ? "same" : "other");
    printf("  ex_data %s, server %d, ciphers %s, CA names %d, status type %ld\n",
           SSL_get_ex_data(d, idx) != NULL ? (const char *)SSL_get_ex_data(d, idx) : "NULL",
           SSL_is_server(d), SSL_get_cipher_list(d, 0) != NULL ? SSL_get_cipher_list(d, 0) : "-",
           sk_X509_NAME_num(SSL_get0_CA_list(d)), SSL_get_tlsext_status_type(d));
    check(SSL_get0_CA_list(d) != SSL_get0_CA_list(c), "the CA names are copied");
    check(SSL_get_SSL_CTX(d) == cctx, "the same context");
    check(SSL_get_session(d) == NULL, "no session");

    /* The copy connects on its own. */
    pair(d, s);
    check(run(d, s) == 0, "the copy's handshake");
    printf("  version %s, cipher %s, info calls %s\n", SSL_get_version(d),
           SSL_get_cipher_name(d), info_calls > 0 ? "some" : "none");

    /* A connection that has started is shared. */
    d2 = SSL_dup(d);
    check(d2 == d, "a started connection is shared");
    SSL_free(d2);
    check(SSL_is_init_finished(d), "still alive after one free");

    /* A copy of a connection with a session shares the session. */
    sess = SSL_get1_session(d);
    SSL_free(c);
    c = SSL_new(cctx);
    SSL_set_session(c, sess);
    d2 = SSL_dup(c);
    check(d2 != NULL && d2 != c && SSL_get_session(d2) == sess, "the session is shared");
    SSL_free(d2);
    SSL_SESSION_free(sess);

    /* A server copy. */
    SSL_free(s);
    s = SSL_new(sctx);
    SSL_set_accept_state(s);
    d2 = SSL_dup(s);
    check(d2 != NULL && d2 != s && SSL_is_server(d2) == 1, "a server's copy is a server");
    SSL_free(d2);
    ERR_clear_error();
    X509_free(ca);
    SSL_free(c);
    SSL_free(d);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

int main(void)
{
    test_defaults();
    test_buffers_and_state(TLS1_3_VERSION);
    test_buffers_and_state(TLS1_2_VERSION);
    test_sendfile();
    test_cert_comp();
    test_quic_and_misc();
    test_expected_rpk();
    test_rtt(TLS1_3_VERSION);
    test_rtt(TLS1_2_VERSION);
    test_dup();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
