/*
 * Conformance test for the record version a flexible TLS client writes: its first ClientHello
 * goes out as TLS 1.0 (for old servers), and the records after it carry the client's highest
 * version (TLS 1.3's as TLS 1.2) until a ServerHello picks one. A TLS_method client that
 * refuses a TLS 1.1 server's ServerHello sends its protocol_version alert that way.
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>

#include <openssl/err.h>
#include <openssl/evp.h>
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

/* Each record's header as the message callback reports it. */
static void msg(int write_p, int version, int ct, const void *buf, size_t len, SSL *s, void *arg)
{
    const unsigned char *p = buf;

    (void)version;
    (void)s;
    if (ct == SSL3_RT_HEADER && len >= 5)
        printf("  %s %s a record: type %d, version %02x%02x\n", (const char *)arg,
               write_p ? "writes" : "reads", p[0], p[1], p[2]);
}

static void errors(const char *who)
{
    unsigned long e;

    printf("  %s errors:", who);
    while ((e = ERR_get_error()) != 0)
        printf(" %d/%d", ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("\n");
}

/* Steps one end; 1 when it stopped (done or failed), with its errors printed. */
static int step(SSL *x, const char *who)
{
    int r = SSL_do_handshake(x), e;

    if (r == 1) {
        printf("  %s: done\n", who);
        return 1;
    }
    e = SSL_get_error(x, r);
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
        return 0;
    printf("  %s: SSL_get_error %d\n", who, e);
    errors(who);
    return 1;
}

/* A TLS 1.2-1.3 client against a fixed-version server (`server_method`). */
static void handshake(const char *name, const SSL_METHOD *server_method)
{
    SSL_CTX *cctx = SSL_CTX_new(TLS_client_method()), *sctx = SSL_CTX_new(server_method);
    EVP_PKEY *pk = EVP_RSA_gen(2048);
    X509 *x = X509_new();
    SSL *c, *s;
    BIO *a = NULL, *b = NULL;
    int round, cdone = 0, sdone = 0;

    printf("# %s\n", name);
    X509_set_pubkey(x, pk);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_sign(x, pk, EVP_sha256());
    SSL_CTX_use_certificate(sctx, x);
    SSL_CTX_use_PrivateKey(sctx, pk);
    SSL_CTX_set_cipher_list(sctx, "ALL@SECLEVEL=0");
    SSL_CTX_set_cipher_list(cctx, "ALL@SECLEVEL=0");
    SSL_CTX_set_min_proto_version(cctx, TLS1_2_VERSION);
    c = SSL_new(cctx);
    s = SSL_new(sctx);
    SSL_set_msg_callback(c, msg);
    SSL_set_msg_callback_arg(c, (void *)"client");
    SSL_set_msg_callback(s, msg);
    SSL_set_msg_callback_arg(s, (void *)"server");
    BIO_new_bio_pair(&a, 0, &b, 0);
    SSL_set_bio(c, a, a);
    SSL_set_bio(s, b, b);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    for (round = 0; round < 8 && !(cdone && sdone); round++) {
        if (!cdone)
            cdone = step(c, "client");
        if (!sdone)
            sdone = step(s, "server");
    }
    check(cdone && sdone, name);
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    X509_free(x);
    EVP_PKEY_free(pk);
}

int main(void)
{
    handshake("a TLS 1.1 server", TLSv1_1_server_method());
    handshake("a TLS 1.0 server", TLSv1_server_method());
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
