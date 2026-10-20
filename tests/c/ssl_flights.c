/*
 * Conformance test for how a handshake reaches the network and for engines under TLS:
 * each handshake flight is one write to the BIO (OpenSSL writes a flight through a buffering
 * BIO and flushes it at the state machine's flushes), counted per handshake step for TLS 1.2
 * and TLS 1.3; and an application engine set as the default for AES-128-GCM
 * (ENGINE_set_default(3)) runs a TLS 1.3 connection's record protection,
 * as libssl prefers an engine's cipher (or digest) to a fetched one.
 *
 * Only deterministic output is printed.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/bio.h>
#include <openssl/engine.h>
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


/* ---- Handshake flights: one BIO write each (the buffering BIO) ---- */

static int writes[2];

static long count(BIO *b, int oper, const char *argp, size_t len, int argi, long argl, int ret,
                  size_t *processed)
{
    (void)argp;
    (void)len;
    (void)argi;
    (void)argl;
    (void)processed;
    if (oper == (BIO_CB_WRITE | BIO_CB_RETURN) && ret > 0)
        writes[BIO_get_callback_arg(b) != NULL ? 1 : 0]++;
    return ret;
}

/*
 * Runs both ends' handshakes in turn, printing how many BIO writes each step made: OpenSSL
 * writes a handshake flight through a buffering BIO, so the network gets it in one write, at
 * the state machine's flush.
 */
static int run_counting(SSL *c, SSL *s)
{
    int cdone = 0, sdone = 0, round;

    BIO_set_callback_ex(SSL_get_wbio(c), count);
    BIO_set_callback_arg(SSL_get_wbio(c), NULL);
    BIO_set_callback_ex(SSL_get_wbio(s), count);
    BIO_set_callback_arg(SSL_get_wbio(s), (char *)"server");
    for (round = 0; round < 64 && (!cdone || !sdone); round++) {
        int i;

        for (i = 0; i < 2; i++) {
            SSL *x = i == 0 ? c : s;
            int *done = i == 0 ? &cdone : &sdone, r, e, before = writes[i];

            if (*done)
                continue;
            r = SSL_do_handshake(x);
            if (writes[i] != before)
                printf("  %s: %d write(s)\n", i == 0 ? "client" : "server", writes[i] - before);
            if (r == 1) {
                *done = 1;
                continue;
            }
            e = SSL_get_error(x, r);
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
                printf("  %s stopped: %d\n", i == 0 ? "client" : "server", e);
                errors();
                return e;
            }
        }
    }
    return cdone && sdone ? 0 : -1;
}

static void test_flights(int version)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c, *s;

    printf("# flights, %s\n", version == TLS1_3_VERSION ? "TLS 1.3" : "TLS 1.2");
    SSL_CTX_set_max_proto_version(cctx, version);
    SSL_CTX_set_options(sctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_num_tickets(sctx, 0);
    connect_pair(cctx, sctx, &c, &s);
    writes[0] = writes[1] = 0;
    check(run_counting(c, s) == 0, "the handshake completes");
    printf("  total: client %d, server %d\n", writes[0], writes[1]);
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

/* ---- An engine's cipher runs TLS (`ssl_evp_cipher_fetch`) ---- */

static int cipher_calls;
static EVP_CIPHER *e_gcm;

static int e_gcm_init(EVP_CIPHER_CTX *ctx, const unsigned char *k, const unsigned char *v, int enc)
{
    return EVP_CIPHER_meth_get_init(EVP_aes_128_gcm())(ctx, k, v, enc);
}

static int e_gcm_do(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    cipher_calls++;
    return EVP_CIPHER_meth_get_do_cipher(EVP_aes_128_gcm())(ctx, out, in, inl);
}

static int e_gcm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    return EVP_CIPHER_meth_get_ctrl(EVP_aes_128_gcm())(ctx, type, arg, ptr);
}

static int e_gcm_cleanup(EVP_CIPHER_CTX *ctx)
{
    return EVP_CIPHER_meth_get_cleanup(EVP_aes_128_gcm())(ctx);
}

static int e_ciphers(ENGINE *e, const EVP_CIPHER **c, const int **nids, int nid)
{
    static const int list[] = { NID_aes_128_gcm };

    (void)e;
    if (c == NULL) {
        *nids = list;
        return 1;
    }
    *c = nid == NID_aes_128_gcm ? e_gcm : NULL;
    return *c != NULL;
}


static void test_engine_tls(void)
{
    ENGINE *e = ENGINE_new();
    SSL_CTX *cctx, *sctx;
    SSL *c, *s;
    char buf[16];

    printf("# an engine's AES-128-GCM, the default, under TLS 1.3\n");
    e_gcm = EVP_CIPHER_meth_new(NID_aes_128_gcm, 1, 16);
    check(e_gcm != NULL && EVP_CIPHER_meth_set_iv_length(e_gcm, 12)
              && EVP_CIPHER_meth_set_flags(e_gcm, EVP_CIPHER_get_flags(EVP_aes_128_gcm()))
              && EVP_CIPHER_meth_set_init(e_gcm, e_gcm_init)
              && EVP_CIPHER_meth_set_do_cipher(e_gcm, e_gcm_do)
              && EVP_CIPHER_meth_set_ctrl(e_gcm, e_gcm_ctrl)
              && EVP_CIPHER_meth_set_cleanup(e_gcm, e_gcm_cleanup)
              && EVP_CIPHER_meth_set_impl_ctx_size(e_gcm,
                                                   EVP_CIPHER_impl_ctx_size(EVP_aes_128_gcm())),
          "an AES-128-GCM over the static cipher's functions");
    check(e != NULL && ENGINE_set_id(e, "flights") && ENGINE_set_name(e, "a test engine")
              && ENGINE_set_ciphers(e, e_ciphers)
              && ENGINE_add(e) && ENGINE_init(e)
              && ENGINE_set_default(e, ENGINE_METHOD_CIPHERS),
          "the engine, the default for its cipher");
    cctx = client_ctx();
    sctx = server_ctx();
    SSL_CTX_set_ciphersuites(cctx, "TLS_AES_128_GCM_SHA256");
    SSL_CTX_set_ciphersuites(sctx, "TLS_AES_128_GCM_SHA256");
    SSL_CTX_set_num_tickets(sctx, 0);
    connect_pair(cctx, sctx, &c, &s);
    cipher_calls = 0;
    writes[0] = writes[1] = 0;
    check(run_counting(c, s) == 0, "the handshake completes");
    check(SSL_write(c, "hello", 5) == 5 && SSL_read(s, buf, sizeof(buf)) == 5
              && memcmp(buf, "hello", 5) == 0,
          "application data goes through");
    printf("  engine cipher used: %d\n", cipher_calls > 0);
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    ENGINE_unregister_ciphers(e);
    ENGINE_finish(e);
    ENGINE_remove(e);
    ENGINE_free(e);
    EVP_CIPHER_meth_free(e_gcm);
}

int main(void)
{
    test_flights(TLS1_2_VERSION);
    test_flights(TLS1_3_VERSION);
    test_engine_tls();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
