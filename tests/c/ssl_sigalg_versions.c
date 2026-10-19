/*
 * Conformance test for the signature algorithms a server lists in its CertificateRequest
 * once the version is negotiated (tls12_copy_sigalgs with tls_sigalg_compat): a flexible
 * method gives way to the negotiated version's, so a TLS 1.2 request leaves out the schemes
 * only TLS 1.3 has (ML-DSA, the brainpool TLS 1.3 ECDSA ones), and a TLS 1.3 request the ones
 * TLS 1.3 forbids (SHA-224, DSA). The client's certificate callback reads the request's list
 * with SSL_get_sigalgs.
 *
 * Found by tlsfuzzer (test-rsa-sigs-on-certificate-verify.py and others: "TLS 1.3 specific
 * signature scheme in an earlier protocol version").
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

static void bail(const char *what)
{
    printf("Bail out! %s\n", what);
    exit(1);
}

/* A self-signed certificate for `k`. */
static X509 *self_signed(EVP_PKEY *k)
{
    X509 *x = X509_new();
    X509_NAME *n = X509_NAME_new();

    if (x == NULL || n == NULL
        || X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)"test", -1,
                                      -1, 0) != 1
        || X509_set_version(x, X509_VERSION_3) != 1
        || ASN1_INTEGER_set(X509_get_serialNumber(x), 1) != 1 || X509_set_subject_name(x, n) != 1
        || X509_set_issuer_name(x, n) != 1
        || X509_gmtime_adj(X509_getm_notBefore(x), -3600) == NULL
        || X509_gmtime_adj(X509_getm_notAfter(x), 86400) == NULL || X509_set_pubkey(x, k) != 1
        || X509_sign(x, k, EVP_sha256()) <= 0)
        bail("certificate");
    X509_NAME_free(n);
    return x;
}

static int accept_any(int ok, X509_STORE_CTX *xs)
{
    (void)ok;
    (void)xs;
    return 1;
}

/* The client's certificate callback: prints the CertificateRequest's signature algorithms. */
static int print_request(SSL *s, void *arg)
{
    int i, n = SSL_get_sigalgs(s, 0, NULL, NULL, NULL, NULL, NULL);

    (void)arg;
    printf("  %s request (%d):", SSL_get_version(s), n);
    for (i = 0; i < n; i++) {
        unsigned char rsig = 0, rhash = 0;

        SSL_get_sigalgs(s, i, NULL, NULL, NULL, &rsig, &rhash);
        printf(" %02x%02x", rhash, rsig);
    }
    printf("\n");
    return 1;
}

/* Runs both ends' handshakes in turn until both finish (1) or one fails (0). */
static int run(SSL *c, SSL *s)
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
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
                printf("  %s stopped: %d\n", i == 0 ? "client" : "server", e);
                ERR_clear_error();
                return 0;
            }
        }
    }
    return cdone && sdone;
}

/* A handshake capped at `max` on the client (the server's method stays flexible). */
static void handshake(const char *name, EVP_PKEY *key, X509 *cert, int max)
{
    SSL_CTX *cctx = SSL_CTX_new(TLS_client_method()), *sctx = SSL_CTX_new(TLS_server_method());
    SSL *c, *s;
    BIO *a = NULL, *b = NULL;

    printf("# %s\n", name);
    if (cctx == NULL || sctx == NULL)
        bail("contexts");
    if (SSL_CTX_use_certificate(sctx, cert) != 1 || SSL_CTX_use_PrivateKey(sctx, key) != 1
        || SSL_CTX_use_certificate(cctx, cert) != 1 || SSL_CTX_use_PrivateKey(cctx, key) != 1)
        bail("keys");
    SSL_CTX_set_verify(sctx, SSL_VERIFY_PEER, accept_any);
    SSL_CTX_set_verify(cctx, SSL_VERIFY_PEER, accept_any);
    SSL_CTX_set_cert_cb(cctx, print_request, NULL);
    SSL_CTX_set_max_proto_version(cctx, max);
    c = SSL_new(cctx);
    s = SSL_new(sctx);
    if (c == NULL || s == NULL || BIO_new_bio_pair(&a, 0, &b, 0) != 1)
        bail("connection");
    SSL_set_bio(c, a, a);
    SSL_set_bio(s, b, b);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    check(run(c, s), name);
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
}

int main(void)
{
    EVP_PKEY *rsa = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    EVP_PKEY *ec = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    X509 *rsa_cert, *ec_cert;

    if (rsa == NULL || ec == NULL)
        bail("keys");
    rsa_cert = self_signed(rsa);
    ec_cert = self_signed(ec);
    handshake("TLS 1.2, RSA", rsa, rsa_cert, TLS1_2_VERSION);
    handshake("TLS 1.3, RSA", rsa, rsa_cert, TLS1_3_VERSION);
    handshake("TLS 1.2, ECDSA", ec, ec_cert, TLS1_2_VERSION);
    handshake("TLS 1.3, ECDSA", ec, ec_cert, TLS1_3_VERSION);
    X509_free(rsa_cert);
    X509_free(ec_cert);
    EVP_PKEY_free(rsa);
    EVP_PKEY_free(ec);
    printf("1..%d\n", number);
    return failures == 0 ? 0 : 1;
}
