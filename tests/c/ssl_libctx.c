/*
 * Conformance test for libssl in a library context of its own (SSL_CTX_new_ex(3)), with the
 * null provider loaded into the default one, as upstream's sslapitest runs: certificates
 * decoded in a context (X509_new_ex(3) then d2i_X509(3), X509_dup(3)) find their keys there,
 * and handshakes between contexts made with SSL_CTX_new_ex decode the peer's certificates and
 * verify them in the contexts' library context (TLS 1.3 and 1.2, both ends authenticated).
 *
 * The client and server talk through memory BIOs. Only deterministic output is printed.
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
#include <openssl/provider.h>
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

/* Prints and clears the error queue. */
static void errors(const char *who)
{
    unsigned long e;
    char buf[256];

    while ((e = ERR_get_error()) != 0) {
        ERR_error_string_n(e, buf, sizeof(buf));
        printf("  %s: %s\n", who, buf);
    }
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

static OSSL_LIB_CTX *libctx;

/* A certificate in the library context. */
static X509 *cert(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509 *x = X509_new_ex(libctx, NULL);

    if (x != NULL && PEM_read_bio_X509(b, &x, NULL, NULL) == NULL) {
        X509_free(x);
        x = NULL;
    }
    BIO_free(b);
    return x;
}

/* A private key in the library context. */
static EVP_PKEY *key(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    EVP_PKEY *k = PEM_read_bio_PrivateKey_ex(b, NULL, NULL, NULL, libctx, NULL);

    BIO_free(b);
    return k;
}

/* The DER of a PEM certificate, decoded with no library context (the PEM layer only). */
static int der_of(const char *pem, unsigned char **der, long *len)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    char *name = NULL, *header = NULL;
    int ok = PEM_read_bio(b, &name, &header, der, len) == 1;

    OPENSSL_free(name);
    OPENSSL_free(header);
    BIO_free(b);
    return ok;
}

static void test_certificates(void)
{
    unsigned char *der = NULL;
    const unsigned char *p;
    long len = 0;
    X509 *x, *y;

    printf("# certificates\n");
    if (!der_of(SERVER_PEM, &der, &len)) {
        printf("Bail out! DER\n");
        exit(1);
    }

    /* The default context has only the null provider: no decoder finds the key. */
    p = der;
    x = d2i_X509(NULL, &p, len);
    check(x != NULL, "d2i_X509 in the default context");
    check(X509_get0_pubkey(x) == NULL, "its key isn't decoded");
    errors("default");
    X509_free(x);

    /* In the library context, the key is there. */
    x = X509_new_ex(libctx, NULL);
    p = der;
    check(x != NULL && d2i_X509(&x, &p, len) == x, "d2i_X509 into X509_new_ex");
    check(X509_get0_pubkey(x) != NULL, "its key is decoded");
    errors("libctx");
    y = X509_dup(x);
    check(y != NULL && X509_get0_pubkey(y) != NULL, "X509_dup keeps the library context");
    errors("dup");
    X509_free(y);
    X509_free(x);

    /* SSL_CTX_use_certificate_ASN1 decodes in the context's library context. */
    {
        SSL_CTX *ctx = SSL_CTX_new_ex(libctx, NULL, TLS_server_method());
        int len_ = (int)len;

        check(ctx != NULL && SSL_CTX_use_certificate_ASN1(ctx, len_, der) == 1,
              "SSL_CTX_use_certificate_ASN1");
        x = SSL_CTX_get0_certificate(ctx);
        check(x != NULL && X509_get0_pubkey(x) != NULL, "its key is decoded");
        errors("use_certificate_ASN1");
        SSL_CTX_free(ctx);
    }
    OPENSSL_free(der);
}

struct link {
    SSL *c, *s;
    BIO *c_in, *c_out, *s_in, *s_out;
};

static BIO *mem(void)
{
    BIO *b = BIO_new(BIO_s_mem());

    BIO_set_mem_eof_return(b, -1);
    return b;
}

static int relay(BIO *from, BIO *to)
{
    unsigned char buf[65536];
    int len = BIO_read(from, buf, sizeof(buf));

    if (len <= 0)
        return 0;
    BIO_write(to, buf, len);
    return 1;
}

/* One end's handshake step: 1 done, 0 wants more, -1 failed. */
static int step(SSL *x, const char *who)
{
    int r = SSL_do_handshake(x), e;

    if (r > 0)
        return 1;
    e = SSL_get_error(x, r);
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
        return 0;
    printf("  %s: stopped, SSL_get_error %d\n", who, e);
    errors(who);
    return -1;
}

static int accept_any(int ok, X509_STORE_CTX *ctx)
{
    (void)ok;
    (void)ctx;
    return 1;
}

static void handshake(const char *name, int version)
{
    SSL_CTX *c = SSL_CTX_new_ex(libctx, NULL, TLS_client_method());
    SSL_CTX *s = SSL_CTX_new_ex(libctx, NULL, TLS_server_method());
    X509 *ca = cert(CA_PEM), *crt = cert(SERVER_PEM), *peer;
    EVP_PKEY *k = key(SERVER_KEY_PEM);
    STACK_OF(X509) *chain;
    struct link l;
    int round, cr = 0, sr = 0;

    printf("# %s\n", name);
    if (c == NULL || s == NULL || ca == NULL || crt == NULL || k == NULL) {
        errors("setup");
        printf("Bail out! contexts\n");
        exit(1);
    }
    check(SSL_CTX_use_certificate(s, crt) == 1 && SSL_CTX_use_PrivateKey(s, k) == 1
              && SSL_CTX_use_certificate(c, crt) == 1 && SSL_CTX_use_PrivateKey(c, k) == 1,
          "certificates and keys");
    X509_STORE_add_cert(SSL_CTX_get_cert_store(c), ca);
    SSL_CTX_set_verify(c, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify(s, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, accept_any);
    SSL_CTX_set_min_proto_version(c, version);
    SSL_CTX_set_max_proto_version(c, version);
    SSL_CTX_set_min_proto_version(s, version);
    SSL_CTX_set_max_proto_version(s, version);

    memset(&l, 0, sizeof(l));
    l.c = SSL_new(c);
    l.s = SSL_new(s);
    l.c_in = mem();
    l.c_out = mem();
    l.s_in = mem();
    l.s_out = mem();
    SSL_set_bio(l.c, l.c_in, l.c_out);
    SSL_set_bio(l.s, l.s_in, l.s_out);
    SSL_set_connect_state(l.c);
    SSL_set_accept_state(l.s);
    for (round = 0; round < 32 && (cr == 0 || sr == 0); round++) {
        if (cr == 0)
            cr = step(l.c, "client");
        relay(l.c_out, l.s_in);
        if (sr == 0)
            sr = step(l.s, "server");
        relay(l.s_out, l.c_in);
        if (cr < 0 || sr < 0)
            break;
    }
    check(cr == 1 && sr == 1, "handshake");
    check(SSL_get_verify_result(l.c) == X509_V_OK, "the client verified the server");
    peer = SSL_get0_peer_certificate(l.c);
    check(peer != NULL && X509_get0_pubkey(peer) != NULL, "the client has the server's key");
    chain = SSL_get_peer_cert_chain(l.c);
    check(chain != NULL && sk_X509_num(chain) == 1
              && X509_get0_pubkey(sk_X509_value(chain, 0)) != NULL,
          "the client's peer chain");
    peer = SSL_get0_peer_certificate(l.s);
    check(peer != NULL && X509_get0_pubkey(peer) != NULL, "the server has the client's key");
    errors("after");

    SSL_free(l.c);
    SSL_free(l.s);
    X509_free(ca);
    X509_free(crt);
    EVP_PKEY_free(k);
    SSL_CTX_free(c);
    SSL_CTX_free(s);
}

int main(void)
{
    OSSL_PROVIDER *null = OSSL_PROVIDER_load(NULL, "null");
    OSSL_PROVIDER *def;

    libctx = OSSL_LIB_CTX_new();
    def = OSSL_PROVIDER_load(libctx, "default");
    if (null == NULL || libctx == NULL || def == NULL) {
        printf("Bail out! providers\n");
        return 1;
    }
    check(!OSSL_PROVIDER_available(NULL, "default"), "the default context has no default");

    test_certificates();
    handshake("TLS 1.3", TLS1_3_VERSION);
    handshake("TLS 1.2", TLS1_2_VERSION);

    OSSL_PROVIDER_unload(def);
    OSSL_LIB_CTX_free(libctx);
    OSSL_PROVIDER_unload(null);
    printf("1..%d\n", number);
    return failures != 0;
}
