/*
 * Conformance test for the ctrl commands about certificates and temporary keys
 * (SSL_get0_certificate_types(3), SSL_CTX_set1_client_certificate_types(3),
 * SSL_get_tmp_key(3), SSL_get_peer_tmp_key(3), SSL_get0_iana_groups(3), SSL_CTX_set_tmp_dh(3),
 * SSL_CTX_build_cert_chain(3)): the certificate types a TLS 1.2 CertificateRequest carries
 * (OpenSSL's default and a configured list), none in TLS 1.3, each end's ephemeral keys after
 * TLS 1.3 and 1.2 handshakes, the peer's supported groups, DH parameters for DHE, and chains
 * built from the store (with each flag, and the errors).
 *
 * Built once against the vendored headers, then run against the reference OpenSSL and against
 * rustyssl: it must pass on both with the same output (TEST_PLAN.md, layer L4).
 */
#define _POSIX_C_SOURCE 200809L
#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
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

/* The errors recorded, with their data. */
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

/* Runs both ends' handshakes until both finish (0) or one fails (its SSL_get_error value). */
static int run(SSL *c, SSL *s)
{
    int cdone = 0, sdone = 0, round;
    BIO *a = NULL, *b = NULL;

    if (BIO_new_bio_pair(&a, 0, &b, 0) != 1) {
        printf("Bail out! BIO pair\n");
        exit(1);
    }
    SSL_set_bio(c, a, a);
    SSL_set_bio(s, b, b);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
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


static void key_info(const char *label, EVP_PKEY *k, int r)
{
    printf("  %s: %d", label, r);
    if (k != NULL)
        printf(" %s %d bits", EVP_PKEY_get0_type_name(k), EVP_PKEY_get_bits(k));
    printf("\n");
}

static void tmp_keys(SSL *c, SSL *s)
{
    EVP_PKEY *k = NULL;
    int r;

    r = (int)SSL_get_tmp_key(c, &k);
    key_info("client tmp key", k, r);
    EVP_PKEY_free(k);
    k = NULL;
    r = (int)SSL_get_peer_tmp_key(c, &k);
    key_info("client peer tmp key", k, r);
    EVP_PKEY_free(k);
    k = NULL;
    r = (int)SSL_get_tmp_key(s, &k);
    key_info("server tmp key", k, r);
    EVP_PKEY_free(k);
    k = NULL;
    r = (int)SSL_get_peer_tmp_key(s, &k);
    key_info("server peer tmp key", k, r);
    EVP_PKEY_free(k);
}

static void ctypes(const char *label, SSL *x)
{
    const unsigned char *p = NULL;
    int n = (int)SSL_get0_certificate_types(x, &p), i;

    printf("  %s certificate types: %d", label, n);
    for (i = 0; p != NULL && i < n; i++)
        printf(" %d", p[i]);
    printf("\n");
}

static void groups(const char *label, SSL *x)
{
    uint16_t *g = NULL;
    int n = SSL_get0_iana_groups(x, &g), i;

    printf("  %s peer groups: %d", label, n);
    for (i = 0; g != NULL && i < n; i++)
        printf(" 0x%04x", g[i]);
    printf("\n");
}

static void handshake(const char *what, int version, const char *groups_list, const unsigned char *types,
                      size_t ntypes)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    SSL *c, *s;

    printf("# %s\n", what);
    SSL_CTX_set_max_proto_version(cctx, version);
    SSL_CTX_set_verify(sctx, SSL_VERIFY_PEER, NULL);
    if (groups_list != NULL)
        SSL_CTX_set1_groups_list(cctx, groups_list);
    if (types != NULL)
        check(SSL_CTX_set1_client_certificate_types(sctx, types, ntypes) == 1,
              "SSL_CTX_set1_client_certificate_types");
    c = SSL_new(cctx);
    s = SSL_new(sctx);
    check(SSL_get0_certificate_types(c, NULL) == 0, "no types before a request");
    check(run(c, s) == 0, "the handshake");
    errors();
    ctypes("client", c);
    ctypes("server", s);
    tmp_keys(c, s);
    groups("client", c);
    groups("server", s);
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void types_errors(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL *c = SSL_new(ctx), *s = SSL_new(ctx);
    unsigned char big[256];

    printf("# certificate type lists\n");
    memset(big, 1, sizeof(big));
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    check(SSL_set1_client_certificate_types(c, big, 2) == 0, "a client can't set them");
    check(SSL_set1_client_certificate_types(s, big, 255) == 1, "255 types");
    check(SSL_set1_client_certificate_types(s, big, 256) == 0, "256 types");
    check(SSL_set1_client_certificate_types(s, NULL, 0) == 1, "back to the default");
    check(SSL_CTX_set1_client_certificate_types(ctx, big, 256) == 0, "256 types on a context");
    errors();
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(ctx);
}

static void dh(void)
{
    SSL_CTX *cctx = client_ctx(), *sctx = server_ctx();
    DH *d = DH_new_by_nid(NID_ffdhe2048);
    SSL *c, *s;
    EVP_PKEY *k = NULL;

    printf("# DH parameters\n");
    check(SSL_CTX_set_tmp_dh(sctx, NULL) == 0, "NULL parameters");
    errors();
    check(SSL_CTX_set_tmp_dh(sctx, d) == 1, "SSL_CTX_set_tmp_dh");
    /* Anonymous DH: the fixtures' certificates are EC, and DHE needs RSA or DSA. */
    SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_cipher_list(cctx, "ADH-AES128-GCM-SHA256:@SECLEVEL=0");
    SSL_CTX_set_cipher_list(sctx, "ADH-AES128-GCM-SHA256:@SECLEVEL=0");
    c = SSL_new(cctx);
    s = SSL_new(sctx);
    check(SSL_set_tmp_dh(s, d) == 1, "SSL_set_tmp_dh");
    check(SSL_set_tmp_dh(s, NULL) == 0, "SSL_set_tmp_dh with NULL");
    errors();
    printf("  handshake: %d\n", run(c, s));
    errors();
    printf("  cipher %s\n",
           SSL_get_current_cipher(c) != NULL ? SSL_CIPHER_get_name(SSL_get_current_cipher(c)) : "(none)");
    {
        int r = (int)SSL_get_peer_tmp_key(c, &k);

        key_info("client peer tmp key", k, r);
    }
    EVP_PKEY_free(k);
    DH_free(d);
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

static void chains(void)
{
    static const long flags[] = { 0,
                                  SSL_BUILD_CHAIN_FLAG_UNTRUSTED,
                                  SSL_BUILD_CHAIN_FLAG_NO_ROOT,
                                  SSL_BUILD_CHAIN_FLAG_CHECK,
                                  SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR,
                                  SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR | SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR };
    size_t i;

    printf("# chains\n");
    {
        SSL_CTX *ctx = SSL_CTX_new(TLS_method());
        SSL *x = SSL_new(ctx);

        check(SSL_CTX_build_cert_chain(ctx, 0) == 0, "no certificate");
        errors();
        check(SSL_build_cert_chain(x, 0) == 0, "no certificate on a connection");
        errors();
        SSL_free(x);
        SSL_CTX_free(ctx);
    }
    for (i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
        int with_ca;

        for (with_ca = 0; with_ca < 2; with_ca++) {
            SSL_CTX *ctx = server_ctx();
            STACK_OF(X509) *chain = NULL;
            long r;

            if (with_ca) {
                X509 *ca = cert(CA_PEM);

                X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), ca);
                X509_free(ca);
            }
            r = SSL_CTX_build_cert_chain(ctx, flags[i]);
            SSL_CTX_get0_chain_certs(ctx, &chain);
            printf("  flags %ld, %s: %ld, chain %d\n", flags[i], with_ca ? "with the root" : "without", r,
                   sk_X509_num(chain));
            errors();
            SSL_CTX_free(ctx);
        }
    }
    {
        SSL_CTX *ctx = server_ctx();
        X509 *ca = cert(CA_PEM);
        SSL *x;
        STACK_OF(X509) *chain = NULL;

        X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), ca);
        X509_free(ca);
        x = SSL_new(ctx);
        check(SSL_build_cert_chain(x, 0) == 1, "SSL_build_cert_chain");
        SSL_get0_chain_certs(x, &chain);
        printf("  connection chain %d\n", sk_X509_num(chain));
        SSL_CTX_get0_chain_certs(ctx, &chain);
        printf("  context chain %d\n", sk_X509_num(chain));
        SSL_free(x);
        SSL_CTX_free(ctx);
    }
}

int main(void)
{
    static const unsigned char types[] = { TLS_CT_ECDSA_SIGN, TLS_CT_RSA_SIGN };

    setvbuf(stdout, NULL, _IONBF, 0);
    handshake("TLS 1.3, X25519", TLS1_3_VERSION, "X25519", NULL, 0);
    handshake("TLS 1.3, P-256", TLS1_3_VERSION, "P-256", NULL, 0);
    handshake("TLS 1.2, P-256", TLS1_2_VERSION, "P-256:X25519", NULL, 0);
    /* A TLS 1.2 ECDSA server needs its certificate's curve among the client's groups. */
    handshake("TLS 1.2, X25519, configured types", TLS1_2_VERSION, "X25519:P-256", types, sizeof(types));
    types_errors();
    dh();
    chains();
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
