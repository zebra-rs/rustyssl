/*
 * Conformance test for stateless TLS 1.3 servers (SSL_stateless(3),
 * SSL_CTX_set_stateless_cookie_generate_cb(3), SSL_CTX_set_stateless_cookie_verify_cb(3)): a
 * server answering the first ClientHello with a HelloRetryRequest carrying its state in a
 * cookie, then taking the handshake up from the second, over a BIO pair; with and without the
 * client's compatibility ChangeCipherSpec, with the application's cookie refused, without a
 * generate callback, and for a TLS 1.2 client.
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

static int gen_calls = 0, verify_calls = 0, verify_answer = 1;

static int gen_cookie(SSL *s, unsigned char *cookie, size_t *len)
{
    (void)s;
    gen_calls++;
    memcpy(cookie, "app-cookie", 10);
    *len = 10;
    return 1;
}

static int verify_cookie(SSL *s, const unsigned char *cookie, size_t len)
{
    (void)s;
    verify_calls++;
    printf("  verify \"%.*s\"\n", (int)len, cookie);
    return verify_answer;
}

/*
 * The client and a stateless server: the client's handshake, then SSL_stateless until it
 * returns 1 (or fails with an error), then both handshakes to the end.
 */
static void run(SSL_CTX *cctx, SSL_CTX *sctx, long client_ops_clear, int client_max)
{
    SSL *c = SSL_new(cctx), *s = SSL_new(sctx);
    BIO *a = NULL, *b = NULL;
    int i, r = 0, cdone = 0, sdone = 0;

    gen_calls = verify_calls = 0;
    BIO_new_bio_pair(&a, 0, &b, 0);
    SSL_set_bio(c, a, a);
    SSL_set_bio(s, b, b);
    SSL_set_connect_state(c);
    SSL_clear_options(c, client_ops_clear);
    if (client_max != 0)
        SSL_set_max_proto_version(c, client_max);
    for (i = 0; i < 6; i++) {
        int cr = SSL_do_handshake(c), stop;

        printf("  client: %d (%d)\n", cr, SSL_get_error(c, cr));
        ERR_clear_error();
        r = SSL_stateless(s);
        stop = r == -1 && ERR_peek_error() != 0;
        printf("  SSL_stateless: %d, state %s\n", r, SSL_state_string(s));
        errors();
        if (r == 1 || stop)
            break;
    }
    printf("  callbacks: generate %d, verify %d\n", gen_calls, verify_calls);
    if (r == 1) {
        for (i = 0; i < 16 && (!cdone || !sdone); i++) {
            if (!cdone)
                cdone = SSL_do_handshake(c) == 1;
            if (!sdone)
                sdone = SSL_accept(s) == 1;
        }
        check(cdone && sdone, "both finish");
        printf("  version %s\n", SSL_get_version(c));
        check(SSL_write(c, "hi", 2) == 2, "a write");
        {
            char buf[8];
            int n = SSL_read(s, buf, sizeof(buf));

            check(n == 2 && memcmp(buf, "hi", 2) == 0, "arrives");
        }
    }
    errors();
    SSL_free(c);
    SSL_free(s);
}

int main(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();

    printf("# no generate callback\n");
    run(cctx, sctx, 0, 0);
    SSL_CTX_set_stateless_cookie_generate_cb(sctx, gen_cookie);
    SSL_CTX_set_stateless_cookie_verify_cb(sctx, verify_cookie);
    printf("# stateless, with the compatibility ChangeCipherSpec\n");
    run(cctx, sctx, 0, 0);
    printf("# without it\n");
    run(cctx, sctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT, 0);
    printf("# the application's cookie refused\n");
    verify_answer = 0;
    run(cctx, sctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT, 0);
    verify_answer = 1;
    printf("# a TLS 1.2 client\n");
    run(cctx, sctx, 0, TLS1_2_VERSION);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
