/*
 * Conformance test for TLS 1.3 record padding (SSL_CTX_set_record_padding_callback(3),
 * SSL_set_record_padding_callback(3), SSL_CTX_set_block_padding(3),
 * SSL_set_block_padding_ex(3)): the client's records over a BIO pair, as the message callback
 * sees their headers, with no padding, block padding of each kind, and a padding callback
 * whose calls (type and length) and answers (some, the most, more than the most) are shown,
 * set on the context, on the connection, and after the handshake.
 *
 * Only the client's records are printed: their lengths don't depend on the server's
 * signatures.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#include <stdint.h>
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

/* A server context with the server's certificate and key. */
static SSL_CTX *server_ctx(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    BIO *b = BIO_new_mem_buf(SERVER_PEM, -1);
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);
    EVP_PKEY *k;

    BIO_free(b);
    b = BIO_new_mem_buf(SERVER_KEY_PEM, -1);
    k = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
    BIO_free(b);
    if (ctx == NULL || x == NULL || k == NULL || SSL_CTX_use_certificate(ctx, x) != 1
        || SSL_CTX_use_PrivateKey(ctx, k) != 1) {
        printf("Bail out! server context\n");
        exit(1);
    }
    X509_free(x);
    EVP_PKEY_free(k);
    return ctx;
}

/* The client's record headers: content type and length. */
static void msg_cb(int write_p, int version, int content_type, const void *buf, size_t len,
                   SSL *ssl, void *arg)
{
    const unsigned char *h = buf;

    (void)version;
    (void)ssl;
    (void)arg;
    if (write_p && content_type == SSL3_RT_HEADER && len == 5)
        printf("    record %d, %d octets\n", h[0], (h[3] << 8) | h[4]);
}

/* The padding callback: its calls, and answers by call (some, the most, too much, huge). */
static int calls;

static size_t pad_cb(SSL *s, int type, size_t len, void *arg)
{
    size_t answer;

    (void)s;
    switch (calls++) {
    case 0:
        answer = 100;
        break;
    case 1:
        answer = SSL3_RT_MAX_PLAIN_LENGTH - len;
        break;
    case 2:
        answer = SSL3_RT_MAX_PLAIN_LENGTH + 1 - len;
        break;
    case 3:
        answer = SIZE_MAX;
        break;
    default:
        answer = 0;
        break;
    }
    printf("    padding callback (%s): type %d, length %zu\n", (const char *)arg, type, len);
    return answer;
}

/* A TLS 1.3 handshake, then four application writes the server reads back. */
static void run(SSL *c, SSL *s, int callback_after)
{
    BIO *a = NULL, *b = NULL;
    int cdone = 0, sdone = 0, round, i;
    char buf[64];

    BIO_new_bio_pair(&a, 0, &b, 0);
    SSL_set_bio(c, a, a);
    SSL_set_bio(s, b, b);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    SSL_set_msg_callback(c, msg_cb);
    for (round = 0; round < 64 && (!cdone || !sdone); round++) {
        if (!cdone && SSL_do_handshake(c) == 1)
            cdone = 1;
        if (!sdone && SSL_do_handshake(s) == 1)
            sdone = 1;
    }
    check(cdone && sdone, "the handshake");
    if (callback_after) {
        printf("  the callback set now\n");
        SSL_set_record_padding_callback(c, pad_cb);
        SSL_set_record_padding_callback_arg(c, "after");
    }
    calls = 0;
    for (i = 0; i < 4; i++) {
        size_t n = 0;

        check(SSL_write_ex(c, "Hello World", 11, &n) == 1 && n == 11, "a write");
        check(SSL_read_ex(s, buf, sizeof(buf), &n) == 1 && n == 11 && memcmp(buf, "Hello World", 11) == 0,
              "it arrives");
    }
    SSL_free(c);
    SSL_free(s);
}

int main(void)
{
    SSL_CTX *cctx, *sctx = server_ctx();

    SSL_CTX_set_min_proto_version(sctx, TLS1_3_VERSION);

    printf("# no padding\n");
    cctx = SSL_CTX_new(TLS_client_method());
    run(SSL_new(cctx), SSL_new(sctx), 0);
    SSL_CTX_free(cctx);

    printf("# block padding of 512 (the context's)\n");
    cctx = SSL_CTX_new(TLS_client_method());
    check(SSL_CTX_set_block_padding(cctx, 512) == 1, "SSL_CTX_set_block_padding");
    run(SSL_new(cctx), SSL_new(sctx), 0);
    SSL_CTX_free(cctx);

    printf("# handshake and alert records only, to 512 (the connection's)\n");
    cctx = SSL_CTX_new(TLS_client_method());
    {
        SSL *c = SSL_new(cctx);

        check(SSL_set_block_padding_ex(c, 0, 512) == 1, "SSL_set_block_padding_ex");
        run(c, SSL_new(sctx), 0);
    }
    SSL_CTX_free(cctx);

    printf("# application data only, to 64\n");
    cctx = SSL_CTX_new(TLS_client_method());
    check(SSL_CTX_set_block_padding_ex(cctx, 64, 0) == 1, "SSL_CTX_set_block_padding_ex");
    run(SSL_new(cctx), SSL_new(sctx), 0);
    SSL_CTX_free(cctx);

    printf("# the context's callback (over block padding)\n");
    cctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_block_padding(cctx, 512);
    SSL_CTX_set_record_padding_callback(cctx, pad_cb);
    SSL_CTX_set_record_padding_callback_arg(cctx, "context");
    calls = 4;
    run(SSL_new(cctx), SSL_new(sctx), 0);
    SSL_CTX_free(cctx);

    printf("# the connection's callback\n");
    cctx = SSL_CTX_new(TLS_client_method());
    {
        SSL *c = SSL_new(cctx);

        SSL_set_record_padding_callback(c, pad_cb);
        SSL_set_record_padding_callback_arg(c, "connection");
        calls = 4;
        run(c, SSL_new(sctx), 0);
    }
    SSL_CTX_free(cctx);

    printf("# a callback set after the handshake\n");
    cctx = SSL_CTX_new(TLS_client_method());
    run(SSL_new(cctx), SSL_new(sctx), 1);
    SSL_CTX_free(cctx);

    SSL_CTX_free(sctx);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
