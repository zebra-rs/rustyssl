/*
 * Conformance test for what a handshake reads as it goes: the CA names a server sends
 * (SSL_get0_peer_CA_list(3), SSL_get_client_CA_list(3); SSL_CTX_set0_CA_list(3) when the
 * client CA list is empty), the context the servername callback switches to
 * (SSL_set_SSL_CTX(3): its ALPN callback), what the ClientHello callback sets on the
 * connection (SSL_set_max_proto_version(3)), the stapled OCSP response in the client's status
 * callback (SSL_get_tlsext_status_ocsp_resp(3)), SSL_set_retry_verify(3) after a successful
 * verification, and the chain's check against the security level, over a BIO pair.
 *
 * Only deterministic output is printed.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdio.h>
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

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

/* Steps both ends to the end of their handshakes, reporting each stop that isn't a read. */
static int handshake(SSL *c, SSL *s)
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
            if (e == SSL_ERROR_WANT_READ)
                continue;
            printf("  %s: SSL_get_error %d\n", i == 0 ? "client" : "server", e);
            if (e != SSL_ERROR_WANT_RETRY_VERIFY) {
                errors();
                return 0;
            }
        }
    }
    return cdone && sdone;
}

static void pair(SSL_CTX *cctx, SSL_CTX *sctx, SSL **pc, SSL **ps)
{
    BIO *a = NULL, *b = NULL;

    *pc = SSL_new(cctx);
    *ps = SSL_new(sctx);
    BIO_new_bio_pair(&a, 0, &b, 0);
    SSL_set_bio(*pc, a, a);
    SSL_set_bio(*ps, b, b);
    SSL_set_connect_state(*pc);
    SSL_set_accept_state(*ps);
}

static void done(SSL *c, SSL *s, SSL_CTX *cctx, SSL_CTX *sctx)
{
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    ERR_clear_error();
}

/* The CA names a server sends (SSL_CTX_set0_CA_list, with its empty client CA list) arrive. */
static void test_ca_names(int version)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    STACK_OF(X509_NAME) *names = sk_X509_NAME_new_null();
    X509 *ca = cert(CA_PEM);
    SSL *c, *s;

    printf("# CA names, %s\n", version == TLS1_3_VERSION ? "TLS 1.3" : "TLS 1.2");
    sk_X509_NAME_push(names, X509_NAME_dup(X509_get_subject_name(ca)));
    SSL_CTX_set0_CA_list(sctx, names);
    SSL_CTX_set_verify(sctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_max_proto_version(cctx, version);
    pair(cctx, sctx, &c, &s);
    printf("  before: %d\n", sk_X509_NAME_num(SSL_get0_peer_CA_list(c)));
    check(handshake(c, s), "the handshake (no client certificate)");
    printf("  client's peer CA names: %d, client CA list %d\n",
           sk_X509_NAME_num(SSL_get0_peer_CA_list(c)), sk_X509_NAME_num(SSL_get_client_CA_list(c)));
    if (sk_X509_NAME_num(SSL_get0_peer_CA_list(c)) == 1)
        check(X509_NAME_cmp(sk_X509_NAME_value(SSL_get0_peer_CA_list(c), 0),
                            X509_get_subject_name(ca)) == 0, "the root's name");
    X509_free(ca);
    done(c, s, cctx, sctx);
}

static unsigned char proto_foo[] = "\x03" "foo";
static unsigned char proto_bar[] = "\x03" "bar";

static int alpn_cb(SSL *s, const unsigned char **out, unsigned char *outlen,
                   const unsigned char *in, unsigned int inlen, void *arg)
{
    unsigned char *want = arg;

    (void)s;
    if (SSL_select_next_proto((unsigned char **)out, outlen, want, want[0] + 1, in, inlen)
        != OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_NOACK;
    return SSL_TLSEXT_ERR_OK;
}

static SSL_CTX *second = NULL;

static int sni_cb(SSL *s, int *al, void *arg)
{
    (void)al;
    (void)arg;
    SSL_set_SSL_CTX(s, second);
    return SSL_TLSEXT_ERR_OK;
}

/* After the servername callback switches the context, ALPN is the new context's. */
static void test_sni_switch(int first_alpn, int second_alpn)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    const unsigned char *sel = NULL;
    unsigned int len = 0;
    SSL *c, *s;

    printf("# a context switch: ALPN on the first %d, on the second %d\n", first_alpn, second_alpn);
    second = server_ctx();
    if (first_alpn)
        SSL_CTX_set_alpn_select_cb(sctx, alpn_cb, proto_foo);
    if (second_alpn)
        SSL_CTX_set_alpn_select_cb(second, alpn_cb, proto_bar);
    SSL_CTX_set_tlsext_servername_callback(sctx, sni_cb);
    SSL_CTX_set_alpn_protos(cctx, (const unsigned char *)"\x03" "foo" "\x03" "bar", 8);
    pair(cctx, sctx, &c, &s);
    SSL_set_tlsext_host_name(c, "second");
    check(handshake(c, s), "the handshake");
    SSL_get0_alpn_selected(c, &sel, &len);
    printf("  ALPN: %.*s (%u)\n", (int)len, sel != NULL ? (const char *)sel : "", len);
    check(SSL_get_SSL_CTX(s) == second, "the server's context is the second");
    done(c, s, cctx, sctx);
    SSL_CTX_free(second);
}

static int hello_cb(SSL *s, int *al, void *arg)
{
    (void)al;
    (void)arg;
    SSL_set_max_proto_version(s, TLS1_2_VERSION);
    return SSL_CLIENT_HELLO_SUCCESS;
}

/* What the ClientHello callback sets on the connection holds for the handshake. */
static void test_hello_cb(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c, *s;

    printf("# the ClientHello callback limits the version\n");
    SSL_CTX_set_client_hello_cb(sctx, hello_cb, NULL);
    pair(cctx, sctx, &c, &s);
    check(handshake(c, s), "the handshake");
    printf("  version %s\n", SSL_get_version(c));
    done(c, s, cctx, sctx);
}

static unsigned char ocsp_byte = 0x5a;

static int server_status_cb(SSL *s, void *arg)
{
    unsigned char *resp = OPENSSL_malloc(1);

    (void)arg;
    *resp = ocsp_byte;
    SSL_set_tlsext_status_ocsp_resp(s, resp, 1);
    return SSL_TLSEXT_ERR_OK;
}

static int client_status_cb(SSL *s, void *arg)
{
    const unsigned char *resp = NULL;
    long len = SSL_get_tlsext_status_ocsp_resp(s, &resp);

    (void)arg;
    printf("  the client's status callback: %ld octet(s), %s\n", len,
           len == 1 && resp != NULL && *resp == ocsp_byte ? "the server's" : "other");
    return 1;
}

/* A client's status callback reads the stapled response. */
static void test_status(int version)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c, *s;

    printf("# a stapled response, %s\n", version == TLS1_3_VERSION ? "TLS 1.3" : "TLS 1.2");
    SSL_CTX_set_tlsext_status_cb(sctx, server_status_cb);
    SSL_CTX_set_tlsext_status_type(cctx, TLSEXT_STATUSTYPE_ocsp);
    SSL_CTX_set_tlsext_status_cb(cctx, client_status_cb);
    SSL_CTX_set_max_proto_version(cctx, version);
    pair(cctx, sctx, &c, &s);
    check(handshake(c, s), "the handshake");
    done(c, s, cctx, sctx);
}

static int retries = 0;

static int retry_cb(X509_STORE_CTX *ctx, void *arg)
{
    SSL *s = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    int ok = X509_verify_cert(ctx);

    (void)arg;
    printf("  verification: %d, retries left %d\n", ok, retries);
    if (ok > 0 && retries-- > 0)
        return SSL_set_retry_verify(s);
    return ok;
}

/* SSL_set_retry_verify after a verification suspends the handshake once. */
static void test_retry_verify(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c, *s;

    printf("# retry verify\n");
    retries = 1;
    SSL_CTX_set_cert_verify_callback(cctx, retry_cb, NULL);
    pair(cctx, sctx, &c, &s);
    check(handshake(c, s), "the handshake");
    printf("  verify result %ld\n", SSL_get_verify_result(c));
    done(c, s, cctx, sctx);
}

/* A chain below the security level isn't sent: an internal error, and the reason. */
static void test_security(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c, *s;

    printf("# a server certificate below the security level\n");
    SSL_CTX_set_security_level(sctx, 4);
    pair(cctx, sctx, &c, &s);
    check(handshake(c, s) == 0, "the handshake fails");
    done(c, s, cctx, sctx);
}

int main(void)
{
    test_ca_names(TLS1_3_VERSION);
    test_ca_names(TLS1_2_VERSION);
    test_sni_switch(1, 1);
    test_sni_switch(0, 1);
    test_sni_switch(1, 0);
    test_hello_cb();
    test_status(TLS1_3_VERSION);
    test_status(TLS1_2_VERSION);
    test_retry_verify();
    test_security();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
