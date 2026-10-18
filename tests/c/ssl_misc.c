/*
 * Conformance test for the rest of the connection surface: the client hello callback's getters
 * (SSL_client_hello_get0_ext(3)), compression (SSL_get_current_compression(3), SSL_COMP_*),
 * asynchronous jobs (SSL_waiting_for_async(3), SSL_get_all_async_fds(3)), the QUIC-oriented
 * calls on a TLS connection (SSL_get_event_timeout(3), SSL_handle_events(3),
 * SSL_net_read_desired(3), SSL_set_blocking_mode(3), SSL_set1_initial_peer_addr(3),
 * SSL_stream_conclude(3)), SSL_trace(3) and SSL_check_chain(3), on a client and a server in one
 * process over a BIO pair.
 *
 * Only deterministic output is printed (no randoms or session IDs).
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

#include <openssl/comp.h>

static int hello_calls;

/* Prints what the client hello getters report, then lets the handshake go on. */
static int hello_cb(SSL *s, int *al, void *arg)
{
    const unsigned char *p;
    size_t n, i;
    int *present = NULL;
    size_t npresent = 0;
    uint16_t order[64];
    size_t norder = 0;

    (void)al;
    (void)arg;
    hello_calls++;
    printf("  isv2 %d, legacy version %#x\n", SSL_client_hello_isv2(s), SSL_client_hello_get0_legacy_version(s));
    n = SSL_client_hello_get0_random(s, &p);
    printf("  random: %zu octets\n", n);
    n = SSL_client_hello_get0_session_id(s, &p);
    printf("  session id: %zu octets\n", n);
    n = SSL_client_hello_get0_ciphers(s, &p);
    printf("  ciphers: %zu octets:", n);
    for (i = 0; i + 1 < n; i += 2)
        printf(" %02x%02x", p[i], p[i + 1]);
    printf("\n");
    n = SSL_client_hello_get0_compression_methods(s, &p);
    printf("  compression methods: %zu (%d)\n", n, n > 0 ? p[0] : -1);
    check(SSL_client_hello_get1_extensions_present(s, &present, &npresent) == 1, "extensions present");
    printf("  present:");
    for (i = 0; i < npresent; i++)
        printf(" %d", present[i]);
    printf("\n");
    OPENSSL_free(present);
    check(SSL_client_hello_get_extension_order(s, NULL, &norder) == 1, "the extension count");
    printf("  count %zu\n", norder);
    check(SSL_client_hello_get_extension_order(s, order, &norder) == 1, "the extension order");
    printf("  order:");
    for (i = 0; i < norder; i++)
        printf(" %u", order[i]);
    printf("\n");
    norder = 1;
    printf("  order into too small an array: %d\n", SSL_client_hello_get_extension_order(s, order, &norder));
    printf("  supported_groups: %d, unknown 4242: %d\n",
        SSL_client_hello_get0_ext(s, TLSEXT_TYPE_supported_groups, &p, &n),
        SSL_client_hello_get0_ext(s, 4242, &p, &n));
    return SSL_CLIENT_HELLO_SUCCESS;
}

static void test_client_hello(int max)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c, *s;
    const unsigned char *p = NULL;

    printf("# client hello getters (max %#x)\n", max);
    SSL_CTX_set_max_proto_version(cctx, max);
    SSL_CTX_set_client_hello_cb(sctx, hello_cb, NULL);
    hello_calls = 0;
    connect_pair(cctx, sctx, &c, &s);
    check(SSL_client_hello_get0_random(s, &p) == 0, "no ClientHello outside the callback");
    check(run(c, s, 0) == 0 && hello_calls == 1, "the handshake, with one callback");
    check(SSL_client_hello_isv2(s) == 0 && SSL_client_hello_get0_legacy_version(s) == 0,
        "nothing after the handshake");
    errors();
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static int npn_select(SSL *s, unsigned char **out, unsigned char *outlen, const unsigned char *in,
    unsigned int inlen, void *arg)
{
    static const unsigned char mine[] = "\x08http/1.1\x02h2";

    (void)s;
    printf("  client select: %u octets offered, arg %s\n", inlen, arg == NULL ? "NULL" : "set");
    return SSL_select_next_proto(out, outlen, in, inlen, mine, sizeof(mine) - 1) == OPENSSL_NPN_NEGOTIATED
        ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_NOACK;
}

static int npn_advertise(SSL *s, const unsigned char **out, unsigned int *outlen, void *arg)
{
    static const unsigned char list[] = "\x02h2\x08http/1.1";

    (void)s;
    (void)arg;
    *out = list;
    *outlen = sizeof(list) - 1;
    printf("  server advertises\n");
    return SSL_TLSEXT_ERR_OK;
}

static void npn_report(const char *who, SSL *x)
{
    const unsigned char *p = NULL;
    unsigned int n = 7;

    SSL_get0_next_proto_negotiated(x, &p, &n);
    printf("  %s: %.*s (%u)\n", who, (int)n, p == NULL ? "" : (const char *)p, n);
}

static void test_npn(int advertise)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c, *s;

    printf("# NPN (TLS 1.2)%s\n", advertise ? "" : ", no advertisement");
    SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION);
    SSL_CTX_set_next_proto_select_cb(cctx, npn_select, NULL);
    if (advertise)
        SSL_CTX_set_next_protos_advertised_cb(sctx, npn_advertise, NULL);
    connect_pair(cctx, sctx, &c, &s);
    npn_report("client before", c);
    check(run(c, s, 0) == 0, "the handshake");
    npn_report("client", c);
    npn_report("server", s);
    errors();
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void srtp_list(const char *what, STACK_OF(SRTP_PROTECTION_PROFILE) *l)
{
    int i;

    printf("  %s:", what);
    if (l == NULL)
        printf(" none");
    for (i = 0; i < sk_SRTP_PROTECTION_PROFILE_num(l); i++) {
        SRTP_PROTECTION_PROFILE *p = sk_SRTP_PROTECTION_PROFILE_value(l, i);

        printf(" %s/%lu", p->name, p->id);
    }
    printf("\n");
}

static void test_srtp(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c, *s;
    SRTP_PROTECTION_PROFILE *p;

    printf("# SRTP profiles\n");
    printf("  unknown: %d\n", SSL_CTX_set_tlsext_use_srtp(cctx, "SRTP_AES128_CM_SHA1_80:NOPE"));
    errors();
    printf("  duplicate: %d\n", SSL_CTX_set_tlsext_use_srtp(cctx, "SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_80"));
    errors();
    printf("  empty: %d\n", SSL_CTX_set_tlsext_use_srtp(cctx, ""));
    errors();
    printf("  good: %d\n", SSL_CTX_set_tlsext_use_srtp(cctx, "SRTP_AEAD_AES_128_GCM:SRTP_AES128_CM_SHA1_80"));
    printf("  server: %d\n", SSL_CTX_set_tlsext_use_srtp(sctx, "SRTP_AES128_CM_SHA1_80:SRTP_AEAD_AES_128_GCM"));
    connect_pair(cctx, sctx, &c, &s);
    srtp_list("client inherits", SSL_get_srtp_profiles(c));
    printf("  connection's own: %d\n", SSL_set_tlsext_use_srtp(c, "SRTP_AEAD_AES_256_GCM:SRTP_AEAD_AES_128_GCM"));
    srtp_list("client", SSL_get_srtp_profiles(c));
    srtp_list("server", SSL_get_srtp_profiles(s));
    check(SSL_get_selected_srtp_profile(c) == NULL, "none selected yet");
    printf("  a TLS handshake (use_srtp is DTLS's): %d\n", run(c, s, 0));
    p = SSL_get_selected_srtp_profile(c);
    printf("  selected over TLS: client %s, server %s\n", p == NULL ? "none" : p->name,
        SSL_get_selected_srtp_profile(s) == NULL ? "none" : SSL_get_selected_srtp_profile(s)->name);
    errors();
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void test_surface(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c, *s;
    STACK_OF(SSL_COMP) *meths, *old;
    struct timeval tv = { 0, 0 };
    int inf = 0;
    size_t n = 5;
    uint64_t v = 7;
    BIO_ADDR *addr = BIO_ADDR_new();

    printf("# compression, async, QUIC calls on TLS\n");
    meths = SSL_COMP_get_compression_methods();
    check(meths != NULL, "a compression method list");
    printf("  methods: %d\n", sk_SSL_COMP_num(meths));
    check(SSL_COMP_get_compression_methods() == meths, "the same list");
    old = SSL_COMP_set0_compression_methods(NULL);
    check(old == meths && SSL_COMP_get_compression_methods() == NULL, "set0 replaces it");
    check(SSL_COMP_set0_compression_methods(old) == NULL, "and puts it back");
    printf("  add without a method: %d\n", SSL_COMP_add_compression_method(200, NULL));
    printf("  SSL_COMP_get_name(NULL): %s\n", SSL_COMP_get_name(NULL) == NULL ? "NULL" : "?");
    printf("  zlib: %s\n", COMP_zlib() == NULL ? "none" : "a method");
    printf("  add zlib: %d, methods %d\n", SSL_COMP_add_compression_method(200, COMP_zlib()), sk_SSL_COMP_num(meths));
    if (sk_SSL_COMP_num(meths) > 0) {
        SSL_COMP *m = sk_SSL_COMP_value(meths, 0);

        printf("  first: %d %s\n", SSL_COMP_get_id(m), SSL_COMP_get0_name(m));
    }
    errors();
    connect_pair(cctx, sctx, &c, &s);
    check(SSL_get_current_compression(c) == NULL && SSL_get_current_expansion(c) == NULL, "none before");
    printf("  net read %d write %d\n", SSL_net_read_desired(c), SSL_net_write_desired(c));
    SSL_do_handshake(c);
    printf("  after a first try: net read %d write %d\n", SSL_net_read_desired(c), SSL_net_write_desired(c));
    check(run(c, s, 0) == 0, "the handshake");
    check(SSL_get_current_compression(c) == NULL && SSL_get_current_expansion(s) == NULL, "none after");
    check(SSL_waiting_for_async(c) == 0, "no async job");
    printf("  async fds: %d %zu\n", SSL_get_all_async_fds(c, NULL, &n), n);
    printf("  changed async fds: %d\n", SSL_get_changed_async_fds(c, NULL, &n, NULL, &n));
    printf("  async status: %d\n", SSL_get_async_status(c, &inf));
    printf("  handle events: %d\n", SSL_handle_events(c));
    printf("  event timeout: %d %ld %ld %d\n", SSL_get_event_timeout(c, &tv, &inf), (long)tv.tv_sec,
        (long)tv.tv_usec, inf);
    printf("  blocking mode: %d %d\n", SSL_set_blocking_mode(c, 1), SSL_get_blocking_mode(c));
    printf("  initial peer addr: %d\n", SSL_set1_initial_peer_addr(c, addr));
    printf("  stream conclude: %d\n", SSL_stream_conclude(c, 0));
    printf("  new stream: %s, accept stream: %s, queue %zu\n", SSL_new_stream(c, 0) == NULL ? "NULL" : "?",
        SSL_accept_stream(c, 0) == NULL ? "NULL" : "?", SSL_get_accept_stream_queue_len(c));
    printf("  connection: %d %d, listener: %d %s, domain: %d %s\n", SSL_get0_connection(c) == c,
        SSL_is_connection(c), SSL_is_listener(c), SSL_get0_listener(c) == NULL ? "NULL" : "?",
        SSL_is_domain(c), SSL_get0_domain(c) == NULL ? "NULL" : "?");
    printf("  stream type %d, id %llu, local %d\n", SSL_get_stream_type(c),
        (unsigned long long)SSL_get_stream_id(c), SSL_is_stream_local(c));
    printf("  stream mode %d, policy %d, reset %d\n", SSL_set_default_stream_mode(c, 0),
        SSL_set_incoming_stream_policy(c, 0, 0), SSL_stream_reset(c, NULL, 0));
    printf("  stream states %d %d, error codes %d %d\n", SSL_get_stream_read_state(c),
        SSL_get_stream_write_state(c), SSL_get_stream_read_error_code(c, &v),
        SSL_get_stream_write_error_code(c, &v));
    printf("  close info %d\n", SSL_get_conn_close_info(c, NULL, 0));
    printf("  listeners: %s %s %s %s %zu %d, domain %s\n", SSL_new_listener(cctx, 0) == NULL ? "NULL" : "?",
        SSL_new_listener_from(c, 0) == NULL ? "NULL" : "?", SSL_new_from_listener(c, 0) == NULL ? "NULL" : "?",
        SSL_accept_connection(c, 0) == NULL ? "NULL" : "?", SSL_get_accept_connection_queue_len(c),
        SSL_listen(c), SSL_new_domain(cctx, 0) == NULL ? "NULL" : "?");
    printf("  value uint: %d %d\n", SSL_get_value_uint(c, 0, 0, &v), SSL_set_value_uint(c, 0, 0, 1));
    errors();
    printf("  shutdown_ex: %d\n", SSL_shutdown_ex(c, 0, NULL, 0));
    check((SSL_get_shutdown(c) & SSL_SENT_SHUTDOWN) != 0, "close_notify sent");
    errors();
    BIO_ADDR_free(addr);
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

int main(void)
{
    test_client_hello(TLS1_3_VERSION);
    test_client_hello(TLS1_2_VERSION);
    test_surface();
    test_npn(1);
    test_npn(0);
    test_srtp();
    (void)CLIENT_PEM;
    (void)CLIENT_KEY_PEM;
    (void)trust_root;
    (void)cn;
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
