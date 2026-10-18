/*
 * Conformance test for the EAP-FAST hooks (SSL_set_session_ticket_ext(3),
 * SSL_set_session_ticket_ext_cb(3), SSL_set_session_secret_cb(3)): a client sending a
 * PAC-Opaque in its session_ticket extension and both ends resuming with the session secret
 * callbacks' master secret over a BIO pair, the server declining (a full handshake), the
 * ticket extension refused, no extension, and TLS 1.3.
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

static int server_secret = 1, ticket_ok = 1;

static int ticket_ext_cb(SSL *s, const unsigned char *data, int len, void *arg)
{
    printf("  %s ticket extension: \"%.*s\" (%d, arg %s)\n", SSL_is_server(s) ? "server" : "client",
           len, data != NULL ? (const char *)data : "", len, (const char *)arg);
    return ticket_ok;
}

static int secret_cb(SSL *s, void *secret, int *secret_len, STACK_OF(SSL_CIPHER) *peer,
                     const SSL_CIPHER **cipher, void *arg)
{
    int server = SSL_is_server(s);

    printf("  %s secret (room %d, peer suites %s, arg %s)\n", server ? "server" : "client",
           *secret_len, peer != NULL ? (sk_SSL_CIPHER_num(peer) > 0 ? "some" : "none") : "NULL",
           (const char *)arg);
    if (server && !server_secret)
        return 0;
    memset(secret, 0x42, 48);
    *secret_len = 48;
    if (server && peer != NULL)
        *cipher = sk_SSL_CIPHER_value(peer, 0);
    return 1;
}

static void run(int version, int set_ext, const char *what)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c = SSL_new(cctx), *s = SSL_new(sctx);
    BIO *a = NULL, *b = NULL;
    int cdone = 0, sdone = 0, round, failed = 0;

    printf("# %s\n", what);
    BIO_new_bio_pair(&a, 0, &b, 0);
    SSL_set_bio(c, a, a);
    SSL_set_bio(s, b, b);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    SSL_set_max_proto_version(c, version);
    if (set_ext == 1)
        printf("  set: %d\n", SSL_set_session_ticket_ext(c, "PAC-opaque", 10));
    else if (set_ext == 2)
        printf("  set NULL: %d\n", SSL_set_session_ticket_ext(c, NULL, 0));
    printf("  callbacks: %d %d %d\n", SSL_set_session_secret_cb(c, secret_cb, "c"),
           SSL_set_session_secret_cb(s, secret_cb, "s"),
           SSL_set_session_ticket_ext_cb(s, ticket_ext_cb, "s"));
    for (round = 0; round < 32 && (!cdone || !sdone) && !failed; round++) {
        int i;

        for (i = 0; i < 2 && !failed; i++) {
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
                failed = 1;
            }
        }
    }
    errors();
    if (cdone && sdone) {
        char buf[8];

        printf("  done: %s %s, reused %d %d\n", SSL_get_version(c), SSL_get_cipher_name(c),
               SSL_session_reused(c), SSL_session_reused(s));
        check(SSL_write(c, "hi", 2) == 2 && SSL_read(s, buf, sizeof(buf)) == 2, "data");
    }
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

int main(void)
{
    run(TLS1_2_VERSION, 1, "resuming with the session secret");
    server_secret = 0;
    run(TLS1_2_VERSION, 1, "the server declines");
    server_secret = 1;
    ticket_ok = 0;
    run(TLS1_2_VERSION, 1, "the ticket extension refused");
    ticket_ok = 1;
    run(TLS1_2_VERSION, 2, "no extension");
    run(TLS1_2_VERSION, 0, "no PAC");
    run(TLS1_3_VERSION, 1, "TLS 1.3");
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
