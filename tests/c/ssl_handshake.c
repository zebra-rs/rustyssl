/*
 * Conformance test for the TLS handshake (SSL_do_handshake(3), SSL_connect(3), SSL_accept(3),
 * SSL_get_error(3), SSL_CTX_set_info_callback(3), SSL_CTX_set_msg_callback(3),
 * SSL_CTX_set_keylog_callback(3), SSL_get_peer_certificate(3), SSL_get_peer_cert_chain(3),
 * SSL_get_verify_result(3), SSL_get_finished(3), SSL_get_client_random(3),
 * SSL_get_negotiated_group(3), SSL_get_peer_signature_nid(3), SSL_CTX_set_alpn_select_cb(3),
 * SSL_CTX_set_tlsext_servername_callback(3), SSL_CTX_set_cert_cb(3),
 * SSL_CTX_set_client_hello_cb(3)): a client and a server in one process over a BIO pair,
 * TLS 1.3 and 1.2, traced through the info, message and keylog callbacks; what each end reports
 * afterwards; ALPN and SNI; verification failures and their alerts; client certificates, sent
 * and missing; callbacks that suspend the handshake; no common version.
 *
 * Only deterministic output is printed (no keys, randoms or lengths that vary).
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

static void info_cb(const SSL *s, int where, int ret)
{
    printf("  info %s %#x %d %s\n", SSL_is_server((SSL *)s) ? "server" : "client", where, ret,
        SSL_state_string_long(s));
}

/* The message callback: direction, record type, and a handshake message's type. */
static void msg_cb(int write_p, int version, int content_type, const void *buf, size_t len,
    SSL *s, void *arg)
{
    const unsigned char *p = buf;

    (void)arg;
    printf("  msg %s %s %#x %d", SSL_is_server(s) ? "server" : "client", write_p ? "out" : "in",
        version, content_type);
    if ((content_type == SSL3_RT_HANDSHAKE || content_type == SSL3_RT_INNER_CONTENT_TYPE
            || content_type == SSL3_RT_ALERT)
        && len > 0)
        printf(" %d", p[0]);
    if (content_type == SSL3_RT_ALERT && len > 1)
        printf(" %d", p[1]);
    printf("\n");
}

static void keylog_cb(const SSL *s, const char *line)
{
    const char *sp = strchr(line, ' ');

    printf("  keylog %s %.*s\n", SSL_is_server((SSL *)s) ? "server" : "client",
        sp == NULL ? 0 : (int)(sp - line), line);
}

/* What both ends report after a handshake. */
static void report(SSL *c, SSL *s)
{
    char buf[64];
    int i;

    for (i = 0; i < 2; i++) {
        SSL *x = i == 0 ? c : s;
        const char *who = i == 0 ? "client" : "server", *name = NULL;
        X509 *peer = SSL_get0_peer_certificate(x);
        STACK_OF(X509) *chain = SSL_get_peer_cert_chain(x);
        STACK_OF(X509) *verified = SSL_get0_verified_chain(x);
        const SSL_CIPHER *cipher = SSL_get_current_cipher(x);
        int nid = -1, type = -1, hash = -1;

        printf("  %s: %s %s reused=%d verify=%ld\n", who, SSL_get_version(x),
            cipher == NULL ? "(none)" : SSL_CIPHER_get_name(cipher), SSL_session_reused(x),
            SSL_get_verify_result(x));
        printf("  %s: peer %s, sent chain %d, verified chain %d\n", who, cn(peer, buf, sizeof(buf)),
            chain == NULL ? -1 : sk_X509_num(chain), verified == NULL ? -1 : sk_X509_num(verified));
        nid = SSL_get_negotiated_group(x);
        printf("  %s: group %d (%s)\n", who, nid, SSL_group_to_name(x, nid) == NULL ? "?" : SSL_group_to_name(x, nid));
        if (SSL_get_peer_signature_type_nid(x, &type) == 1)
            printf("  %s: peer signature type %d\n", who, type);
        if (SSL_get_peer_signature_nid(x, &hash) == 1)
            printf("  %s: peer signature hash %d\n", who, hash);
        if (SSL_get0_peer_signature_name(x, &name) == 1)
            printf("  %s: peer signature %s\n", who, name);
        type = hash = -1;
        name = NULL;
        if (SSL_get_signature_type_nid(x, &type) == 1)
            printf("  %s: own signature type %d\n", who, type);
        if (SSL_get_signature_nid(x, &hash) == 1)
            printf("  %s: own signature hash %d\n", who, hash);
        if (SSL_get0_signature_name(x, &name) == 1)
            printf("  %s: own signature %s\n", who, name);
        printf("  %s: extms %ld, early data %d\n", who, (long)SSL_get_extms_support(x),
            SSL_get_early_data_status(x));
    }
}

/* Each end's Finished matches what the other end received. */
static void finished(SSL *c, SSL *s)
{
    unsigned char a[64], b[64];
    size_t na = SSL_get_finished(c, a, sizeof(a)), nb = SSL_get_peer_finished(s, b, sizeof(b));

    check(na > 0 && na == nb && memcmp(a, b, na) == 0, "the client's Finished is what the server got");
    na = SSL_get_finished(s, a, sizeof(a));
    nb = SSL_get_peer_finished(c, b, sizeof(b));
    check(na > 0 && na == nb && memcmp(a, b, na) == 0, "the server's Finished is what the client got");
    printf("  finished length %zu\n", na);
}

/* Each end's randoms match the other's. */
static void randoms(SSL *c, SSL *s)
{
    unsigned char a[32], b[32];

    check(SSL_get_client_random(c, a, sizeof(a)) == 32 && SSL_get_client_random(s, b, sizeof(b)) == 32
            && memcmp(a, b, 32) == 0,
        "both ends have the same client random");
    check(SSL_get_server_random(c, a, sizeof(a)) == 32 && SSL_get_server_random(s, b, sizeof(b)) == 32
            && memcmp(a, b, 32) == 0,
        "both ends have the same server random");
}

static void test_tls13_traced(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c, *s;

    SSL_CTX_set_info_callback(cctx, info_cb);
    SSL_CTX_set_info_callback(sctx, info_cb);
    SSL_CTX_set_msg_callback(cctx, msg_cb);
    SSL_CTX_set_msg_callback(sctx, msg_cb);
    SSL_CTX_set_keylog_callback(cctx, keylog_cb);
    SSL_CTX_set_keylog_callback(sctx, keylog_cb);
    /* One ticket keeps the trace short. */
    SSL_CTX_set_num_tickets(sctx, 1);
    connect_pair(cctx, sctx, &c, &s);
    printf("# TLS 1.3, traced\n");
    check(SSL_in_before(c) && SSL_in_init(c) && !SSL_is_init_finished(c), "before the handshake");
    check(run(c, s, 1) == 0, "TLS 1.3 handshake");
    check(!SSL_in_init(c) && SSL_is_init_finished(c) && !SSL_in_before(c), "after the handshake");
    report(c, s);
    finished(c, s);
    randoms(c, s);
    check(SSL_version(c) == TLS1_3_VERSION && SSL_version(s) == TLS1_3_VERSION, "SSL_version");
    check(SSL_get_pending_cipher(c) != NULL, "a pending cipher after the handshake");
    errors();
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void test_tls12_traced(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c, *s;
    EVP_PKEY *tmp = NULL;

    SSL_CTX_set_info_callback(cctx, info_cb);
    SSL_CTX_set_info_callback(sctx, info_cb);
    SSL_CTX_set_msg_callback(cctx, msg_cb);
    SSL_CTX_set_msg_callback(sctx, msg_cb);
    SSL_CTX_set_keylog_callback(cctx, keylog_cb);
    SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION);
    connect_pair(cctx, sctx, &c, &s);
    printf("# TLS 1.2, traced\n");
    check(run(c, s, 1) == 0, "TLS 1.2 handshake");
    report(c, s);
    finished(c, s);
    randoms(c, s);
    check(SSL_get_peer_tmp_key(c, &tmp) == 1 && tmp != NULL, "the client has the server's ECDHE key");
    if (tmp != NULL)
        printf("  peer tmp key %s %d bits\n", EVP_PKEY_get0_type_name(tmp), EVP_PKEY_get_bits(tmp));
    EVP_PKEY_free(tmp);
    errors();
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static int alpn_select(SSL *s, const unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen, void *arg)
{
    static const unsigned char want[] = "\x08http/1.1";

    (void)s;
    (void)arg;
    printf("  alpn offered %u octets\n", inlen);
    if (SSL_select_next_proto((unsigned char **)out, outlen, want, sizeof(want) - 1, in, inlen)
        != OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_NOACK;
    return SSL_TLSEXT_ERR_OK;
}

static int servername_cb(SSL *s, int *al, void *arg)
{
    const char *name = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);

    (void)arg;
    printf("  servername cb: %s, alert %d\n", name == NULL ? "(none)" : name, *al);
    return SSL_TLSEXT_ERR_OK;
}

static void test_alpn_sni(int max)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c, *s;
    const unsigned char *p;
    unsigned int n;
    static const unsigned char offer[] = "\x02h2\x08http/1.1";

    SSL_CTX_set_alpn_select_cb(sctx, alpn_select, NULL);
    SSL_CTX_set_tlsext_servername_callback(sctx, servername_cb);
    SSL_CTX_set_max_proto_version(cctx, max);
    connect_pair(cctx, sctx, &c, &s);
    printf("# ALPN and SNI, %s\n", max == TLS1_2_VERSION ? "TLS 1.2" : "TLS 1.3");
    SSL_set_alpn_protos(c, offer, sizeof(offer) - 1);
    SSL_set_tlsext_host_name(c, "server.example");
    SSL_set1_host(c, "server.example");
    SSL_get0_alpn_selected(c, &p, &n);
    check(p == NULL && n == 0, "no ALPN protocol before the handshake");
    check(SSL_get_servername(s, TLSEXT_NAMETYPE_host_name) == NULL, "no server name before the handshake");
    check(run(c, s, 0) == 0, "handshake");
    SSL_get0_alpn_selected(c, &p, &n);
    printf("  client alpn: %.*s\n", (int)n, p == NULL ? "" : (const char *)p);
    SSL_get0_alpn_selected(s, &p, &n);
    printf("  server alpn: %.*s\n", (int)n, p == NULL ? "" : (const char *)p);
    printf("  server name: client %s, server %s (type %d)\n", SSL_get_servername(c, TLSEXT_NAMETYPE_host_name),
        SSL_get_servername(s, TLSEXT_NAMETYPE_host_name), SSL_get_servername_type(s));
    check(SSL_get_verify_result(c) == X509_V_OK, "the host name matched");
    errors();
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void test_verify_failure(int max)
{
    SSL_CTX *cctx = SSL_CTX_new(TLS_client_method()), *sctx = server_ctx();
    SSL *c, *s;
    int e;

    SSL_CTX_set_verify(cctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_max_proto_version(cctx, max);
    connect_pair(cctx, sctx, &c, &s);
    printf("# an untrusted server, %s\n", max == TLS1_2_VERSION ? "TLS 1.2" : "TLS 1.3");
    e = run(c, s, 0);
    check(e == SSL_ERROR_SSL, "the client fails");
    printf("  client verify %ld\n", SSL_get_verify_result(c));
    errors();
    /* The server gets the client's alert. */
    e = SSL_do_handshake(s);
    printf("  server %d -> %d\n", e, SSL_get_error(s, e));
    errors();
    printf("  after the failure: peer %s, sent chain %d, verified chain %d\n",
        SSL_get0_peer_certificate(c) == NULL ? "none" : "kept",
        SSL_get_peer_cert_chain(c) == NULL ? -1 : sk_X509_num(SSL_get_peer_cert_chain(c)),
        SSL_get0_verified_chain(c) == NULL ? -1 : sk_X509_num(SSL_get0_verified_chain(c)));
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void test_client_cert(int max, int send)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c, *s;
    char buf[64];
    int e;

    trust_root(sctx);
    SSL_CTX_set_verify(sctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_max_proto_version(cctx, max);
    if (send) {
        X509 *x = cert(CLIENT_PEM);
        EVP_PKEY *k = key(CLIENT_KEY_PEM);

        SSL_CTX_use_certificate(cctx, x);
        SSL_CTX_use_PrivateKey(cctx, k);
        X509_free(x);
        EVP_PKEY_free(k);
    }
    connect_pair(cctx, sctx, &c, &s);
    printf("# client certificate %s, %s\n", send ? "sent" : "missing", max == TLS1_2_VERSION ? "TLS 1.2" : "TLS 1.3");
    e = run(c, s, 0);
    if (send) {
        check(e == 0, "handshake");
        printf("  server: peer %s verify %ld chain %d\n", cn(SSL_get0_peer_certificate(s), buf, sizeof(buf)),
            SSL_get_verify_result(s), sk_X509_num(SSL_get_peer_cert_chain(s)));
    } else {
        check(e == SSL_ERROR_SSL, "the server fails");
        errors();
        e = SSL_do_handshake(c);
        printf("  client %d -> %d\n", e, SSL_get_error(c, e));
    }
    errors();
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static int cert_cb_calls;

static int cert_cb(SSL *s, void *arg)
{
    (void)s;
    (void)arg;
    printf("  cert cb %d\n", cert_cb_calls);
    return cert_cb_calls++ == 0 ? -1 : 1;
}

static int hello_calls;

static int hello_cb(SSL *s, int *al, void *arg)
{
    const unsigned char *p;
    size_t n;

    (void)al;
    (void)arg;
    printf("  client hello cb %d: version %#x, %s\n", hello_calls, SSL_client_hello_get0_legacy_version(s),
        SSL_client_hello_get0_ext(s, TLSEXT_TYPE_supported_versions, &p, &n) == 1 ? "supported_versions" : "-");
    return hello_calls++ == 0 ? SSL_CLIENT_HELLO_RETRY : SSL_CLIENT_HELLO_SUCCESS;
}

static void test_suspensions(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c, *s;

    SSL_CTX_set_cert_cb(sctx, cert_cb, NULL);
    SSL_CTX_set_client_hello_cb(sctx, hello_cb, NULL);
    connect_pair(cctx, sctx, &c, &s);
    printf("# callbacks that suspend the handshake\n");
    check(run(c, s, 0) == SSL_ERROR_WANT_CLIENT_HELLO_CB, "the client hello callback suspends");
    check(SSL_want(s) == SSL_CLIENT_HELLO_CB, "SSL_want");
    check(run(c, s, 0) == SSL_ERROR_WANT_X509_LOOKUP, "the certificate callback suspends");
    check(SSL_want_x509_lookup(s), "SSL_want_x509_lookup");
    check(run(c, s, 0) == 0, "then the handshake finishes");
    errors();
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void test_version_mismatch(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c, *s;
    int e;

    SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION);
    SSL_CTX_set_min_proto_version(sctx, TLS1_3_VERSION);
    connect_pair(cctx, sctx, &c, &s);
    printf("# no common version\n");
    check(run(c, s, 0) == SSL_ERROR_SSL, "the server fails");
    errors();
    e = SSL_do_handshake(c);
    printf("  client %d -> %d\n", e, SSL_get_error(c, e));
    errors();
    check(SSL_get_current_cipher(c) == NULL, "no cipher");
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void test_reentrancy_and_order(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c, *s;
    int r;

    connect_pair(cctx, sctx, &c, &s);
    printf("# SSL_connect and SSL_accept\n");
    r = SSL_connect(c);
    check(r == -1 && SSL_get_error(c, r) == SSL_ERROR_WANT_READ, "SSL_connect waits for the server");
    r = SSL_accept(s);
    check(r == -1 && SSL_get_error(s, r) == SSL_ERROR_WANT_READ, "SSL_accept waits for the client");
    check(run(c, s, 0) == 0, "the rest of the handshake");
    check(SSL_do_handshake(c) == 1 && SSL_do_handshake(s) == 1, "SSL_do_handshake again is 1");
    check(SSL_connect(c) == 1, "SSL_connect again is 1");
    errors();
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

int main(void)
{
    test_tls13_traced();
    test_tls12_traced();
    test_alpn_sni(TLS1_3_VERSION);
    test_alpn_sni(TLS1_2_VERSION);
    test_verify_failure(TLS1_3_VERSION);
    test_verify_failure(TLS1_2_VERSION);
    test_client_cert(TLS1_3_VERSION, 1);
    test_client_cert(TLS1_2_VERSION, 1);
    test_client_cert(TLS1_3_VERSION, 0);
    test_client_cert(TLS1_2_VERSION, 0);
    test_suspensions();
    test_version_mismatch();
    test_reentrancy_and_order();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
